import logging
import os
import re
from pathlib import Path

from helios.adapters.base import ForensicToolAdapter, ToolRunResult, resolve_tool_binary
from helios.models import DataEvent, FileRecord, RecoveryStatus

logger = logging.getLogger(__name__)

_SUPPRESSED = False


def _suppress_windows_error_dialogs() -> None:
    """
    Prevent Windows from showing blocking modal dialogs (e.g. a missing-DLL
    loader error) when spawning bundled tools. Without this, a missing
    libvhdi.dll would hang the scan on a popup until manually dismissed.
    """
    global _SUPPRESSED
    if _SUPPRESSED or os.name != "nt":
        return
    try:
        import ctypes.wintypes  # type: ignore[import-not-found]

        ctypes.windll.kernel32.SetErrorMode(0x8001)  # type: ignore[attr-defined]  # Windows only
        _SUPPRESSED = True
    except Exception:  # noqa: BLE001 - best effort, never crash the pipeline
        _SUPPRESSED = True


def _bundle_linux_lib_dir() -> Path | None:
    """
    Locate the bundled Linux shared-library directory for SleuthKit tools
    (tools/linux64/lib), resolving through the bundle root in frozen mode.
    """
    try:
        from helios.config import get_bundle_root

        lib_dir = get_bundle_root() / "tools" / "linux64" / "lib"
        if lib_dir.is_dir():
            return lib_dir
    except Exception:
        pass

    for base in (Path.cwd(), Path(__file__).resolve().parent.parent.parent.parent):
        candidate = base / "tools" / "linux64" / "lib"
        if candidate.is_dir():
            return candidate
    return None


_SYSTEM_METADATA_RE = re.compile(
    r"^(?:\$MFT|\$MFTMirr|\$LogFile|\$Volume|\$AttrDef|\$Bitmap|\$Boot|\$BadClust|\$Secure|\$UpCase|\$Extend|\$Quota|\$ObjId|\$Reparse|\$UsnJrnl|\$Directory|FVE2?\.|\$Recycle\.Bin|System Volume Information|desktop\.ini|Thumbs\.db)",
    re.IGNORECASE,
)


def _clean_fls_path_and_name(raw_path: str) -> tuple[str, str]:
    """
    Clean TSK fls output artifact tokens from path and extract clean base name.

    Strips TSK stream and allocation suffixes like ($FILE_NAME), ($DATA),
    ($INDEX_ALLOCATION), (deleted), (deleted-realloc), (realloc).
    """
    cleaned_path = re.sub(
        r"\s*\((?:\$FILE_NAME|\$DATA|\$INDEX_ALLOCATION|deleted(?:-realloc)?|realloc)\)",
        "",
        raw_path,
        flags=re.IGNORECASE,
    ).strip()

    base_name = Path(cleaned_path).name or cleaned_path
    base_name = re.sub(
        r"\s*\((?:\$FILE_NAME|\$DATA|\$INDEX_ALLOCATION|deleted(?:-realloc)?|realloc)\)",
        "",
        base_name,
        flags=re.IGNORECASE,
    ).strip()

    return cleaned_path, base_name


def _is_system_metadata(path: str, name: str) -> bool:
    """Check if file is internal NTFS system metadata or OS volume key file."""
    norm_path = path.replace("\\", "/")
    parts = [p for p in norm_path.split("/") if p]
    if any(p.lower() in ("system volume information", "$recycle.bin", "$extend") for p in parts):
        return True
    if any(p.lower().startswith("fve2.{") or p.lower().startswith("fve.{") for p in parts):
        return True
    if _SYSTEM_METADATA_RE.match(name) or (parts and _SYSTEM_METADATA_RE.match(parts[-1])):
        return True
    return False


class SleuthKitAdapter(ForensicToolAdapter):
    """
    Adapter for The Sleuth Kit (TSK) tools.
    Provides a wrapper for the fls (deleted-file listing) and fsstat
    (filesystem metadata) utilities used by deleted-file recovery.
    """

    def __init__(self, fls_path: str = "fls", fsstat_path: str = "fsstat", config: dict | None = None) -> None:
        """
        Initialize the SleuthKitAdapter.

        Args:
            fls_path: The executable name or path for fls. Defaults to 'fls'.
            fsstat_path: The executable name or path for fsstat. Defaults to 'fsstat'.
            config: Optional configuration dictionary.
        """
        super().__init__(config=config or {}, tool_path=fls_path)
        self.fls_path = fls_path
        self.fsstat_path = fsstat_path

    def tool_name(self) -> str:
        """
        Returns the name of the forensic tool.

        Returns:
            str: 'SleuthKit'
        """
        return "SleuthKit"

    def is_available(self) -> bool:
        """
        Checks if the fls binary is available.

        Returns:
            bool: True if available, False otherwise.
        """
        return resolve_tool_binary("fls", self.fls_path) is not None

    def _env(self) -> dict[str, str] | None:
        """
        Build the subprocess environment for bundled SleuthKit binaries.

        The Linux builds shipped under tools/linux64 link against bundled
        shared libraries, so LD_LIBRARY_PATH must point at them on POSIX.
        On Windows, bundled DLLs live next to the executables in tools/;
        suppress loader error dialogs so failures surface cleanly instead of
        as modal popups that block the scan.
        """
        _suppress_windows_error_dialogs()
        if os.name == "nt":
            return None
        lib_dir = _bundle_linux_lib_dir()
        if not lib_dir:
            return None
        env = dict(os.environ)
        existing = env.get("LD_LIBRARY_PATH", "")
        env["LD_LIBRARY_PATH"] = f"{lib_dir}:{existing}" if existing else str(lib_dir)
        return env

    def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
        """Run the fls tool with arguments (generic adapter method)."""
        cmd = [self.get_fls_exe()] + args
        return self.run_subprocess(cmd, timeout=timeout, env=self._env())

    def parse_output(self, raw_output: str) -> list[DataEvent]:
        """Parse raw fls output into DataEvent objects."""
        _, events = self.parse_fls_output(raw_output)
        return events

    def get_fls_exe(self) -> str:
        resolved = resolve_tool_binary("fls", self.fls_path)
        return str(resolved) if resolved else self.fls_path

    def get_fsstat_exe(self) -> str:
        resolved = resolve_tool_binary("fsstat", self.fsstat_path)
        return str(resolved) if resolved else self.fsstat_path

    def run_fls(self, image_or_drive: str, recursive: bool = True, deleted_only: bool = False, offset: str | None = None, mac_format: bool = False) -> str:
        """
        Executes fls to list allocated and/or deleted file entries.

        Args:
            image_or_drive: Path to the disk image or physical drive.
            recursive: If True, recursively list directories (-r).
            deleted_only: If True, list only deleted entries (-d).
            offset: Sector offset for the partition (optional).
            mac_format: If True, output in mactime bodyfile format (-m).

        Returns:
            str: The raw stdout output of the fls command.
            
        Raises:
            RuntimeError: If fls execution fails.
        """
        command = [self.get_fls_exe()]
        if mac_format:
            # -m takes a PATH PREFIX string prepended to every output path,
            # NOT the image/drive path.  Derive a clean prefix:
            #   \\.\C:  → C:/
            #   /dev/sdb1 → /
            #   image.dd → /
            if image_or_drive.startswith("\\\\.\\"):
                prefix = image_or_drive[4:].rstrip(":") + ":/"
            elif image_or_drive.startswith("/dev/"):
                prefix = "/"
            else:
                prefix = "/"
            command.extend(["-m", prefix])
        else:
            command.append("-p")
        if recursive:
            command.append("-r")
        if deleted_only:
            command.append("-d")
        if offset:
            command.extend(["-o", str(offset)])

        command.append(image_or_drive)

        logger.debug(f"Running fls: {' '.join(command)}")
        result = self.run_subprocess(command, timeout=600, env=self._env())
        if result.returncode != 0:
            logger.error(f"fls execution failed: {result.stderr}")
            raise RuntimeError(f"fls execution failed: {result.stderr}")
        return result.stdout

    def parse_fls_output(self, raw_output: str, device_id: str = '', deleted_only: bool = False) -> tuple[list[FileRecord], list[DataEvent]]:
        """
        Parses raw fls output. Supports standard fls format and mactime bodyfile format.

        Args:
            raw_output: The raw string output from the fls command.
            device_id: Optional device identifier to associate with the parsed records.
            deleted_only: When True, marks ALL entries as deleted (used when
                fls was invoked with ``-d``). Otherwise only ``*``-marked
                entries are flagged.

        Returns:
            Tuple[List[FileRecord], List[DataEvent]]: A tuple containing lists of parsed files and associated data events.
        """
        from datetime import datetime as _dt
        from datetime import timezone as _timezone

        file_records: list[FileRecord] = []
        data_events: list[DataEvent] = []
        seen_entries: set[tuple[int | None, str]] = set()

        regex = re.compile(r"^[\+\s]*([a-z\-/]+)\s+(\*?)\s*([\d\-\(\)a-z]+):\s+(.*)$", re.IGNORECASE)

        def _parse_unix_ts(val: str) -> _dt | None:
            try:
                v = int(val.strip())
                if v > 0:
                    return _dt.fromtimestamp(v, tz=_timezone.utc)
            except (ValueError, OverflowError):
                pass
            return None

        for line in raw_output.splitlines():
            line = line.strip()
            if not line:
                continue

            # Check if mactime bodyfile format (11 pipe-separated fields)
            # Example: MD5|file_path|inode|mode|uid|gid|size|atime|mtime|ctime|crtime
            if "|" in line and len(line.split("|")) >= 11:
                parts = line.split("|")
                md5_hash = parts[0].strip() if parts[0].strip() not in ("0", "") else ""
                raw_path = parts[1].strip()
                inode_raw = parts[2].strip()
                mode_str = parts[3].strip()

                clean_path, clean_name = _clean_fls_path_and_name(raw_path)
                if not clean_name:
                    continue

                try:
                    size = int(parts[6].strip())
                except ValueError:
                    size = 0

                atime = _parse_unix_ts(parts[7])
                mtime = _parse_unix_ts(parts[8])
                ctime = _parse_unix_ts(parts[9])
                crtime = _parse_unix_ts(parts[10])

                is_deleted = deleted_only or "*" in mode_str
                first_part = inode_raw.split("-")[0]
                digits_only = re.sub(r"\D", "", first_part)
                inode_num = int(digits_only) if digits_only else None

                dedup_key = (inode_num, clean_path.lower())
                if dedup_key in seen_entries:
                    continue
                seen_entries.add(dedup_key)

                is_sys = _is_system_metadata(clean_path, clean_name)

                record = FileRecord(
                    file_name=clean_name,
                    file_path=clean_path,
                    md5_hash=md5_hash,
                    size=size,
                    created=crtime,
                    modified=mtime or ctime,
                    accessed=atime,
                    is_deleted=is_deleted,
                    is_system=is_sys,
                    mft_entry_number=inode_num,
                    parent_path=str(Path(clean_path).parent),
                    source_device=device_id,
                    recovery_status=RecoveryStatus.RECOVERABLE,
                    notes=[f"Mode: {mode_str}"] if mode_str else [],
                )
                file_records.append(record)
                continue

            # Standard fls output parsing
            match = regex.match(line)
            if match:
                entry_type = match.group(1)
                deleted_marker = match.group(2)
                inode = match.group(3)
                raw_path = match.group(4).strip()

                clean_path, clean_name = _clean_fls_path_and_name(raw_path)
                if not clean_name:
                    continue

                is_deleted = deleted_only or bool(deleted_marker == '*')
                first_part = inode.split('-')[0]
                digits_only = re.sub(r"\D", "", first_part)
                inode_num = int(digits_only) if digits_only else None

                dedup_key = (inode_num, clean_path.lower())
                if dedup_key in seen_entries:
                    continue
                seen_entries.add(dedup_key)

                is_sys = _is_system_metadata(clean_path, clean_name)

                record = FileRecord(
                    file_name=clean_name,
                    file_path=clean_path,
                    is_deleted=is_deleted,
                    is_system=is_sys,
                    mft_entry_number=inode_num,
                    parent_path=str(Path(clean_path).parent),
                    source_device=device_id,
                    recovery_status=RecoveryStatus.RECOVERABLE,
                    notes=[f"Entry type: {entry_type}"] if entry_type else []
                )
                file_records.append(record)

        return file_records, data_events

    def run_fsstat(self, image_or_drive: str, offset: str | None = None) -> dict[str, str]:
        """
        Parses filesystem metadata from fsstat.

        Args:
            image_or_drive: Path to the disk image or physical drive.
            offset: Sector offset for the partition (optional).

        Returns:
            Dict[str, str]: A dictionary containing filesystem metadata.
        """
        if not resolve_tool_binary("fsstat", self.fsstat_path):
            raise RuntimeError(f"Tool not found: {self.fsstat_path}")

        command = [self.get_fsstat_exe()]
        if offset:
            command.extend(["-o", str(offset)])
        command.append(image_or_drive)

        try:
            result = self.run_subprocess(command, timeout=120, env=self._env())
            if result.returncode != 0:
                raise RuntimeError(f"fsstat execution failed: {result.stderr.strip() or result.returncode}")
        except RuntimeError:
            raise
        except Exception as e:
            logger.error("fsstat execution failed: %s", e)
            raise RuntimeError(f"fsstat execution failed: {e}") from e

        metadata = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if ":" in line:
                key, value = line.split(":", 1)
                metadata[key.strip()] = value.strip()
                
        return metadata
