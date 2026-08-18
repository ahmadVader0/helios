"""
Recycle Bin Analyzer.

This module provides the RecycleBinAnalyzer class, responsible for parsing
the Windows Recycle Bin ($Recycle.Bin) to recover metadata about deleted
files by parsing $I and matching them with $R data files.
"""

import logging
import os
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import Confidence, DataEvent, Device, EventType, RecoveryStatus, ScanOptions

logger = logging.getLogger(__name__)

# NTFS Epoch starts at 1601-01-01 UTC
NTFS_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

def filetime_to_datetime(filetime: int) -> datetime | None:
    """
    Convert a 64-bit Windows FILETIME to a Python datetime.

    Args:
        filetime (int): The 64-bit FILETIME value (100-nanosecond intervals since 1601).

    Returns:
        Optional[datetime]: The corresponding datetime object, or None if invalid.
    """
    if filetime == 0:
        return None
    try:
        microseconds = filetime / 10.0
        return NTFS_EPOCH + timedelta(microseconds=microseconds)
    except (ValueError, OverflowError):
        return None


class RecycleBinAnalyzer(AnalyzerBase):
    """
    Analyzer for extracting deleted file metadata from the Windows Recycle Bin.
    """

    def __init__(
        self,
        config: dict | None = None,
        scan_options: ScanOptions | None = None,
        ez_tools_adapter: EZToolsAdapter | None = None,
    ):
        super().__init__(config=config or {}, scan_options=scan_options or ScanOptions())
        self.ez_tools = ez_tools_adapter or EZToolsAdapter(config=self.config)

    def name(self) -> str:
        """Get the human-readable name of the analyzer."""
        return "Recycle Bin Analyzer"

    def can_run(self) -> bool:
        """
        Check if $Recycle.Bin folder is accessible.

        Returns:
            bool: True if the analyzer can run, False otherwise.
        """
        # On a live Windows system, checking the root of C: drive
        if os.name == 'nt':
            return Path("C:\\$Recycle.Bin").exists()
        # Assume true in forensic mode when provided paths
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Scan $Recycle.Bin across all SID directories for $I and $R files.

        Args:
            device (Device): The target device to scan.

        Returns:
            List[RawArtifact]: A list of raw artifacts representing $I and $R files.
        """
        artifacts: list[RawArtifact] = []
        recycle_bin_paths: list[Path] = []
        
        # Check all candidate drive roots on Windows
        if os.name == 'nt':
            candidate_roots = ["C:\\"]
            if device.drive_letter:
                candidate_roots.append(device.drive_letter.rstrip("\\") + "\\")
            if device.mount_point:
                candidate_roots.append(device.mount_point.rstrip("\\") + "\\")
            if hasattr(self, 'scan_options') and self.scan_options and self.scan_options.drives:
                for d in self.scan_options.drives:
                    candidate_roots.append(d.rstrip("\\") + "\\")
            for letter in "DEFGHIJKLMNOPQRSTUVWXYZ":
                candidate_roots.append(f"{letter}:\\")

            for root_dir in candidate_roots:
                try:
                    rb = Path(root_dir) / "$Recycle.Bin"
                    if rb.exists() and rb.is_dir() and rb not in recycle_bin_paths:
                        recycle_bin_paths.append(rb)
                except (OSError, PermissionError):
                    continue
            
        # Check provided scan paths
        if hasattr(self, 'scan_options') and self.scan_options and self.scan_options.paths:
            for base_path in self.scan_options.paths:
                p = Path(base_path) / "$Recycle.Bin"
                if p.exists() and p.is_dir() and p not in recycle_bin_paths:
                    recycle_bin_paths.append(p)
                    
        # Default mock path for non-Windows environments
        if not recycle_bin_paths and os.name != 'nt':
            mock_path = Path("/tmp/$Recycle.Bin")
            if mock_path.exists() and mock_path.is_dir():
                recycle_bin_paths.append(mock_path)

        for rb_dir in recycle_bin_paths:
            if not rb_dir.exists():
                continue

            drive_letter: str = rb_dir.drive if os.name == "nt" and rb_dir.drive else ""

            try:
                # Iterate over SID directories
                for sid_dir in rb_dir.iterdir():
                    if sid_dir.is_dir():
                        # Collect all $I files
                        for i_file in sid_dir.glob("$I*"):
                            artifact = RawArtifact(
                                artifact_id=f"recycle_{device.device_id}_{i_file.name}",
                                artifact_type="recycle_bin_i",
                                source_path=i_file,
                                device_id=device.device_id,
                                collected_at=datetime.now(tz=timezone.utc),
                                metadata={
                                    "sid": sid_dir.name,
                                    "size": i_file.stat().st_size,
                                    "drive_letter": drive_letter,
                                }
                            )
                            artifacts.append(artifact)
                            logger.debug("Collected $I file: %s", i_file)
                            
                        # $R files could also be collected if data recovery is needed,
                        # but for metadata parsing, $I files are the primary focus.
            except OSError as e:
                logger.error("Failed to collect from %s: %s", rb_dir, e)
                
        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """
        Parse $I index files and match with $R data files to emit FILE_DELETE events.

        Args:
            artifacts (List[RawArtifact]): The raw collected $I file artifacts.

        Returns:
            List[DataEvent]: Processed FILE_DELETE events.
        """
        events: list[DataEvent] = []
        seen_names: set[str] = set()
        
        for artifact in artifacts:
            if artifact.artifact_type != "recycle_bin_i":
                continue
                
            try:
                event = self._parse_i_file(artifact)
                if event:
                    events.append(event)
                    seen_names.add(str(event.source_path).lower())
            except Exception as e:
                logger.error("Error parsing $I file %s: %s", artifact.source_path, e)

        events.extend(self._parse_with_rbcmd(artifacts, seen_names))

        return events

    def _parse_with_rbcmd(self, artifacts: list[RawArtifact], seen_names: set[str]) -> list[DataEvent]:
        """
        Run RBCmd over the collected Recycle Bin root directories and convert
        its CSV rows into FILE_DELETE events for entries the built-in $I
        parser did not already cover. Degrades to [] when RBCmd is unavailable.
        """
        if not artifacts:
            return []

        rb_roots = sorted({Path(artifact.source_path).parent.parent for artifact in artifacts})
        extra_events: list[DataEvent] = []
        primary_dev_id = artifacts[0].device_id if artifacts else ""
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                csv_dir = Path(tmp_dir)
                for rb_root in rb_roots:
                    rows = self.ez_tools.run_rbcmd(rb_root, csv_dir)
                    for row in rows:
                        event = self._rbcmd_row_to_event(row, primary_dev_id)
                        if event is None:
                            continue
                        if str(event.source_path).lower() in seen_names:
                            continue
                        extra_events.append(event)
        except Exception as e:
            logger.warning("RBCmd enrichment failed: %s", e)
        return extra_events

    def _rbcmd_row_to_event(self, row: dict, device_id: str) -> DataEvent | None:
        """
        Convert a single RBCmd CSV row into a FILE_DELETE DataEvent.

        Returns None for rows that lack a path or a usable deletion timestamp.
        """
        file_name = str(row.get("FileName", "")).strip()
        directory = str(row.get("Directory", "")).strip()
        if not file_name and not directory:
            return None

        deleted_time = self._parse_ez_timestamp(row.get("DeletedTime"))
        if deleted_time is None:
            return None

        original_path = file_name if not directory else f"{directory}\\{file_name}".replace("\\\\", "\\")
        size = self._as_int(row.get("FileSize")) or 0

        metadata = {
            "original_path": original_path,
            "file_size": size,
            "user_sid": row.get("SID", "Unknown"),
            "drive": row.get("Drive", ""),
            "recovery_status": RecoveryStatus.NOT_RECOVERABLE.value,
            "tool": "RBCmd",
        }
        return DataEvent(
            timestamp=deleted_time,
            event_type=EventType.FILE_DELETE,
            source_device=device_id,
            source_path=original_path,
            confidence=Confidence.HIGH,
            metadata=metadata,
        )

    @staticmethod
    def _as_int(value: object) -> int | None:
        """Best-effort int conversion for RBCmd CSV values."""
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_ez_timestamp(value: object) -> datetime | None:
        """Parse a 'YYYY-MM-DD HH:MM:SS' timestamp from EZ Tools CSV output."""
        if not value:
            return None
        try:
            return datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _parse_i_file(self, artifact: RawArtifact) -> DataEvent | None:
        """
        Parse the binary format of a $I file.
        
        Args:
            artifact (RawArtifact): The $I file artifact.
            
        Returns:
            Optional[DataEvent]: The resulting FILE_DELETE event, or None if parsing fails.
        """
        path = artifact.source_path
        
        with open(path, "rb") as f:
            data = f.read()
            
        if len(data) < 24:
            logger.warning("File %s is too small to be a valid $I file.", path)
            return None
            
        # Parse header
        # Version 1 (Windows 7/8): 8-byte header `0x01`, 8-byte file size, 8-byte FILETIME, 520-byte Unicode path
        # Version 2 (Windows 10/11): 8-byte header `0x02`, 8-byte file size, 8-byte FILETIME, variable length Unicode path
        
        header, size, filetime = struct.unpack("<qqq", data[:24])
        
        deleted_time = filetime_to_datetime(filetime)
        if not deleted_time:
            logger.warning("Invalid FILETIME in %s.", path)
            return None
            
        original_path = ""
        
        if header == 0x01:
            # Windows 7/8 format
            if len(data) >= 544:
                path_bytes = data[24:544]
                # Decode UTF-16LE, truncate at null terminator
                original_path = path_bytes.decode("utf-16le", errors="ignore").split('\x00')[0]
        elif header == 0x02:
            # Windows 10/11 format
            # Path starts at offset 28 in Version 2? Actually, the specification says:
            # 8-byte header, 8-byte size, 8-byte filetime.
            # Then 4-byte path length, followed by path.
            if len(data) >= 28:
                path_len = struct.unpack("<i", data[24:28])[0]
                # Validate bounds: positive length and within the file
                if path_len > 0 and 28 + (path_len * 2) <= len(data):
                    path_bytes = data[28:28 + (path_len * 2)]
                    original_path = path_bytes.decode("utf-16le", errors="ignore").split('\x00')[0]
                else:
                    logger.warning("Invalid path length %s in %s.", path_len, path)
                    return None
        else:
            logger.warning("Unknown $I file version %s in %s.", hex(header), path)
            return None
            
        # Check if corresponding $R file exists
        r_file_path = path.with_name(path.name.replace("$I", "$R", 1))
        recovery_status = RecoveryStatus.RECOVERABLE if r_file_path.exists() else RecoveryStatus.NOT_RECOVERABLE
        
        metadata = {
            "original_path": original_path,
            "file_size": size,
            "user_sid": artifact.metadata.get("sid", "Unknown"),
            "recovery_status": recovery_status.value
        }
        
        event = DataEvent(
            timestamp=deleted_time,
            event_type=EventType.FILE_DELETE,
            source_device=artifact.device_id,
            source_path=original_path,
            confidence=Confidence.HIGH,
            metadata=metadata
        )
        
        return event
