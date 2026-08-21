"""
Low-level NTFS / Windows binary-format helpers shared by analyzers.

Provides:
- FILETIME ↔ UTC datetime conversion
- MFTECmd timestamp parsing (handles 7-digit fractional seconds)
- USN Journal reason-flag decoding
- MFT flag helpers (in_use, is_directory)
- Alternate Data Stream (ADS) detection
- Timestomping heuristic (SI vs FN timestamp comparison)
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

# Windows FILETIME epoch (1601-01-01) offset from Unix epoch, in 100ns ticks.
_FILETIME_EPOCH_DELTA: int = 116_444_736_000_000_000
_HUNDRED_NS: int = 10_000_000


def filetime_to_datetime(filetime: int | None) -> datetime | None:
    """Convert a Windows FILETIME (100ns ticks since 1601-01-01) to UTC datetime.

    Returns None for zero or None values (common in empty MFT entries).
    """
    if filetime is None or filetime == 0:
        return None
    unix_ticks = filetime - _FILETIME_EPOCH_DELTA
    seconds = unix_ticks / _HUNDRED_NS
    return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)


def parse_mftecmd_timestamp(value: str | None) -> datetime | None:
    """Parse MFTECmd CSV timestamps into UTC-aware datetimes.

    MFTECmd emits timestamps like ``2024-05-01 13:45:02.1234567`` with
    7-digit fractional seconds (100-nanosecond ticks).  Python's ``%f``
    directive only supports 6 digits (microseconds), so we truncate the
    fractional part to 6 digits before parsing.

    Returns None when the value is blank, whitespace, or unparseable.
    """
    if not value:
        return None
    value = value.strip()
    if not value:
        return None

    # Truncate 7-digit fractional seconds → 6-digit microseconds.
    if "." in value:
        main_part, _, frac_part = value.partition(".")
        frac_part = (frac_part + "000000")[:6]  # pad/truncate to 6 digits
        value = f"{main_part}.{frac_part}"

    fmts = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")
    for fmt in fmts:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# USN Journal reason flags (from winioctl.h USN_REASON_*)
# ---------------------------------------------------------------------------

USN_REASON_FLAGS: dict[int, str] = {
    0x00000001: "DataOverwrite",
    0x00000002: "DataExtend",
    0x00000004: "DataTruncation",
    0x00000010: "NamedDataOverwrite",
    0x00000020: "NamedDataExtend",
    0x00000040: "NamedDataTruncation",
    0x00000100: "FileCreate",
    0x00000200: "FileDelete",
    0x00000400: "EaChange",
    0x00000800: "SecurityChange",
    0x00001000: "RenameOldName",
    0x00002000: "RenameNewName",
    0x00004000: "IndexableChange",
    0x00008000: "BasicInfoChange",
    0x00010000: "HardLinkChange",
    0x00020000: "CompressionChange",
    0x00040000: "EncryptionChange",
    0x00080000: "ObjectIdChange",
    0x00100000: "ReparsePointChange",
    0x00200000: "StreamChange",
    0x00400000: "TransactedChange",
    0x80000000: "Close",
}


def decode_usn_reason(reason_value: int | None) -> list[str]:
    """Decode a USN 'Reason' bitmask int into a list of flag names."""
    if reason_value is None:
        return []
    return [name for bit, name in USN_REASON_FLAGS.items() if reason_value & bit]


def decode_usn_reason_from_string(reason_str: str | None) -> list[str]:
    """Parse MFTECmd pipe/comma-separated USN reason strings.

    MFTECmd CSV writes the Reason column as a pipe or comma separated
    string like ``FileCreate, Close``.  Normalize to our vocabulary.
    """
    if not reason_str:
        return []
    parts = [p.strip() for p in reason_str.replace("|", ",").split(",") if p.strip()]
    return parts


# ---------------------------------------------------------------------------
# MFT flags
# ---------------------------------------------------------------------------

MFT_IN_USE_FLAG: int = 0x0001
MFT_DIRECTORY_FLAG: int = 0x0002


def decode_mft_flags(flag_value: int | None) -> dict[str, bool]:
    """Decode MFT entry flags into a dict of booleans."""
    if flag_value is None:
        return {"in_use": False, "is_directory": False}
    return {
        "in_use": bool(flag_value & MFT_IN_USE_FLAG),
        "is_directory": bool(flag_value & MFT_DIRECTORY_FLAG),
    }


def has_alternate_data_stream(file_name: str | None) -> bool:
    """Detect alternate data streams (ADS) by finding ':' in the file/stream name.

    Drive-letter colons (e.g. ``C:\\``) are stripped out; only
    ``file.txt:hidden`` patterns trigger True.
    """
    if not file_name:
        return False
    # Strip drive letter if present (e.g. "C:\...")
    path_str = file_name
    if len(path_str) >= 2 and path_str[1] == ":" and path_str[0].isalpha():
        path_str = path_str[2:]
    return ":" in path_str


def build_volume_path(parent_path: str | None, file_name: str, volume: str = "") -> str:
    """Join an MFTECmd ParentPath + FileName into a clean, volume-prefixed path.

    MFTECmd emits ``ParentPath`` as ``.`` (or empty) for root-directory
    entries and relative paths for the rest. This normalizes those to a
    proper absolute-looking Windows path:

        build_volume_path(".", "a.txt", "D:")      -> "D:\\a.txt"
        build_volume_path("Users", "a.txt", "D:")  -> "D:\\Users\\a.txt"
        build_volume_path("", "a.txt", "")         -> "a.txt"
    """
    parent = (parent_path or "").strip().strip("\\")
    # MFTECmd prefixes relative parents with ".\" (e.g. ".\System Volume
    # Information") — normalize it away so paths don't render as "X:\.\...".
    if parent == "." or parent.startswith(".\\"):
        parent = parent[2:]
    name = (file_name or "").strip()
    if parent in ("", "."):
        joined = name
    else:
        joined = f"{parent}\\{name}"
    vol = (volume or "").strip().rstrip("\\/")
    if vol and not re.match(r"^[A-Za-z]:", joined):
        joined = f"{vol}\\{joined}"
    return joined


def detect_timestomping(
    si_created: datetime | None,
    si_modified: datetime | None,
    fn_created: datetime | None,
    fn_modified: datetime | None,
) -> bool:
    """Heuristic: detect likely NTFS timestomping.

    NTFS maintains two timestamp sets:
    - ``$STANDARD_INFORMATION`` (SI): user-visible, easily forged by
      tools like timestomp.exe or SetFileTime.
    - ``$FILE_NAME`` (FN): updated only by the kernel filesystem driver on
      file creation, rename or move, much harder to forge from user-mode.

    Only high-signal indicators are used — patterns that the NTFS kernel
    itself can never produce:

    1. SI created NEWER than FN created (>60s). The kernel always records
       the FN entry at (or before) the moment the SI attributes are
       written, so an SI creation "after" the FN record means someone
       rewrote the SI timestamps.
    2. Sub-second zeroing: SI created has exactly .000000 microseconds
       while FN retains precision and the two diverge — the signature of
       timestomp-style whole-second forgery.

    Deliberately NOT flagged (verified against real volumes — these are
    the normal results of file copies):
    - ``si_modified < si_created`` (copy preserves source mtime)
    - ``fn_created - si_created > 60s`` (MFTECmd's own `Copied` column
      shows this is overwhelmingly the copy pattern; callers should skip
      rows where MFTECmd already says Copied=True)
    """
    if not si_created or not fn_created:
        return False

    # 1. SI created is newer than FN created by >60s (kernel-impossible)
    if (si_created - fn_created).total_seconds() > 60:
        return True

    # 2. Whole-second zeroing on SI while FN keeps sub-second precision
    if (
        si_created.microsecond == 0
        and fn_created.microsecond != 0
        and abs((fn_created - si_created).total_seconds()) > 5
    ):
        return True

    return False
