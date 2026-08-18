"""
Intelligent unit tests for Windows-specific forensic capabilities,
filesystem structures, console encoding, and file limits.
"""

from __future__ import annotations

from datetime import datetime, timezone

from helios.display import (
    CONFIDENCE_LABELS,
    EVENT_STYLES,
    SEVERITY_STYLES,
    generate_sun,
    init_windows_console,
)
from helios.models import Confidence, EventType, Severity
from helios.pipeline import MAX_FILES_PER_DRIVE, MAX_HASH_FILE_SIZE
from helios.utils.ntfs import (
    decode_mft_flags,
    decode_usn_reason,
    decode_usn_reason_from_string,
    detect_timestomping,
    filetime_to_datetime,
    has_alternate_data_stream,
    parse_mftecmd_timestamp,
)


def test_windows_file_capacity_limits():
    """Verify that file inventory capacity is 5,000,000 files and 500MB hash limit."""
    assert MAX_FILES_PER_DRIVE >= 5_000_000
    assert MAX_HASH_FILE_SIZE >= 500 * 1024 * 1024


def test_windows_console_initialization():
    """init_windows_console should execute safely without throwing exceptions."""
    init_windows_console()
    # On any OS, calling it multiple times must be idempotent and safe
    init_windows_console()


def test_windows_safe_display_symbols():
    """Verify that terminal display symbols and styles are defined and safe."""
    sun = generate_sun(radius=3)
    assert len(sun) > 0
    # Ensure severity and event styling maps are complete
    assert Severity.CRITICAL in SEVERITY_STYLES
    assert EventType.FILE_ACCESS in EVENT_STYLES
    assert Confidence.HIGH in CONFIDENCE_LABELS


def test_windows_ntfs_filetime_epoch():
    """Test Windows FILETIME tick conversion (100ns ticks since 1601-01-01)."""
    # 1601 epoch zero
    assert filetime_to_datetime(0) is None
    assert filetime_to_datetime(None) is None

    # Unix epoch (1970-01-01 00:00:00 UTC) = 116444736000000000
    epoch_dt = filetime_to_datetime(116444736000000000)
    assert epoch_dt == datetime(1970, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    # Windows 11 release date approximate FILETIME: 2021-10-05 00:00:00 UTC
    # 132778848000000000
    w11_dt = filetime_to_datetime(132778848000000000)
    assert w11_dt is not None
    assert w11_dt.year == 2021
    assert w11_dt.month == 10
    assert w11_dt.day == 5


def test_windows_mftecmd_subsecond_timestamp_parsing():
    """Test MFTECmd 7-digit nanosecond timestamps with truncation to 6-digit microseconds."""
    ts_7digit = "2026-08-18 10:15:30.1234567"
    dt = parse_mftecmd_timestamp(ts_7digit)
    assert dt is not None
    assert dt == datetime(2026, 8, 18, 10, 15, 30, 123456, tzinfo=timezone.utc)

    ts_standard = "2026-08-18 10:15:30"
    dt_std = parse_mftecmd_timestamp(ts_standard)
    assert dt_std == datetime(2026, 8, 18, 10, 15, 30, tzinfo=timezone.utc)

    assert parse_mftecmd_timestamp("") is None
    assert parse_mftecmd_timestamp("malformed") is None


def test_windows_ntfs_timestomping_heuristic():
    """Test timestomping detection comparing $STANDARD_INFORMATION and $FILE_NAME timestamps."""
    normal_si_created = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    normal_si_modified = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    normal_fn_created = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    normal_fn_modified = datetime(2026, 1, 1, 11, 0, 0, tzinfo=timezone.utc)

    # Legitimate timestamps -> False
    assert detect_timestomping(normal_si_created, normal_si_modified, normal_fn_created, normal_fn_modified) is False

    # Timestomped: SI created altered to 2 years before FN created -> True
    tampered_si_created = datetime(2024, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    assert detect_timestomping(tampered_si_created, normal_si_modified, normal_fn_created, normal_fn_modified) is True

    # Tampered: SI modified earlier than SI created -> True
    impossible_si_modified = datetime(2025, 12, 31, 10, 0, 0, tzinfo=timezone.utc)
    assert detect_timestomping(normal_si_created, impossible_si_modified, normal_fn_created, normal_fn_modified) is True


def test_windows_ntfs_alternate_data_streams():
    """Verify that ADS indicators (e.g. payload.exe:hidden) are detected while drive letters are ignored."""
    assert has_alternate_data_stream(r"C:\Windows\System32\notepad.exe") is False
    assert has_alternate_data_stream(r"D:\Data\Document.docx") is False
    assert has_alternate_data_stream(r"C:\Users\Admin\Downloads\invoice.pdf:malware.exe") is True
    assert has_alternate_data_stream("test.txt:stream:$DATA") is True
    assert has_alternate_data_stream(None) is False
    assert has_alternate_data_stream("") is False


def test_windows_usn_reason_flags():
    """Test USN reason bitmask and string decoding."""
    # USN FileCreate (0x100) + Close (0x80000000)
    reasons = decode_usn_reason(0x00000100 | 0x80000000)
    assert "FileCreate" in reasons
    assert "Close" in reasons

    # String decoding
    parsed = decode_usn_reason_from_string("FileCreate | DataExtend | Close")
    assert "FileCreate" in parsed
    assert "DataExtend" in parsed
    assert "Close" in parsed


def test_windows_mft_flags():
    """Test MFT entry flag bitmask decoding (InUse / Directory)."""
    flags_in_use = decode_mft_flags(0x0001)
    assert flags_in_use["in_use"] is True
    assert flags_in_use["is_directory"] is False

    flags_dir = decode_mft_flags(0x0003)
    assert flags_dir["in_use"] is True
    assert flags_dir["is_directory"] is True

    flags_deleted = decode_mft_flags(0x0000)
    assert flags_deleted["in_use"] is False
    assert flags_deleted["is_directory"] is False
