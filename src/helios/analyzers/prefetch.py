import logging
import struct
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import DataEvent, Device, EventType, ScanOptions, Severity

logger = logging.getLogger(__name__)

# FILETIME epoch: 1601-01-01 expressed as 100ns intervals between 1601 and 1970
FILETIME_UNIX_OFFSET_US = 116444736000000000

class PrefetchAnalyzer(AnalyzerBase):
    """
    Analyzes Windows Prefetch files to track application executions,
    including execution counts, timestamps, and referenced files.
    Generates alerts for anti-forensics and data exfiltration tools.
    """
    
    # Known anti-forensics and data exfiltration tools for alerting
    SUSPICIOUS_TOOLS = {
        "anti_forensics": {"sdelete.exe", "eraser.exe", "ccleaner.exe", "cipher.exe", "vssadmin.exe", "wevtutil.exe"},
        "data_exfiltration": {"7z.exe", "winrar.exe", "filezilla.exe", "rclone.exe", "megasync.exe", "curl.exe"}
    }

    def __init__(
        self,
        config: dict | None = None,
        scan_options: ScanOptions | None = None,
        ez_tools_adapter: EZToolsAdapter | None = None,
    ):
        super().__init__(config=config or {}, scan_options=scan_options or ScanOptions())
        self.ez_tools = ez_tools_adapter or EZToolsAdapter(config=self.config)

    def name(self) -> str:
        """Returns the name of the analyzer."""
        return "Prefetch Execution Analyzer"

    def can_run(self) -> bool:
        """
        Checks if Prefetch files can be parsed.
        Returns True indicating analyzer capability.
        """
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect .pf files from %SystemRoot%\\Prefetch.
        
        Args:
            device: The Device model representing the target filesystem.
            
        Returns:
            A list of RawArtifact objects representing Prefetch files.
        """
        artifacts = []
        root = Path(device.mount_point) if device.mount_point else Path.cwd()
        prefetch_dir = root / "Windows" / "Prefetch"
        
        if prefetch_dir.exists() and prefetch_dir.is_dir():
            # Match *.pf case-insensitively (Linux filesystems are case-sensitive
            # and real Windows prefetch files can be created as UPPER.PF).
            pf_files = [p for p in prefetch_dir.iterdir() if p.is_file() and p.suffix.lower() == ".pf"]
            for pf_file in pf_files:
                    artifacts.append(RawArtifact(
                        artifact_id=str(uuid.uuid4()),
                        artifact_type="PrefetchFile",
                        source_path=pf_file,
                        device_id=device.device_id,
                        collected_at=datetime.now(),
                        metadata={"filename": pf_file.name}
                    ))
        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """
        Parse executable name, run count, execution timestamps, and referenced files/volumes.
        Produces APP_EXECUTE DataEvents and critical Alerts for suspicious tools.
        
        Args:
            artifacts: List of collected Prefetch file artifacts.
            
        Returns:
            List of DataEvents detailing application executions.
        """
        events = []

        pecmd_by_name = self._run_pecmd_enrichment(artifacts)

        for artifact in artifacts:
            try:
                parsed_data = self._parse_prefetch(str(artifact.source_path))
                if not parsed_data:
                    continue
                
                executable_name = parsed_data.get("executable_name", "").lower()
                run_count = parsed_data.get("run_count", 0)
                timestamps = parsed_data.get("execution_timestamps", [])
                
                if not timestamps:
                    continue
                primary_ts = timestamps[0]

                prefetch_filename = str(artifact.metadata.get("filename", Path(artifact.source_path).name)).lower()
                pecmd_row = pecmd_by_name.get(prefetch_filename)
                if pecmd_row:
                    pecmd_run_count = self._as_int(pecmd_row.get("RunCount"))
                    if pecmd_run_count is not None:
                        run_count = max(run_count, pecmd_run_count)
                    pecmd_last_run = self._parse_ez_timestamp(pecmd_row.get("LastRunTime"))
                    if pecmd_last_run is not None:
                        primary_ts = pecmd_last_run

                event = DataEvent(
                    timestamp=primary_ts,
                    event_type=EventType.APP_EXECUTE,
                    source_device=artifact.device_id,
                    source_path=str(artifact.source_path),
                    raw_source="Prefetch",
                    metadata={
                        "executable": executable_name,
                        "run_count": run_count,
                        "all_timestamps": [t.isoformat() if isinstance(t, datetime) else str(t) for t in timestamps],
                        "referenced_files": parsed_data.get("referenced_files", []),
                        "referenced_directories": parsed_data.get("referenced_directories", []),
                        "prefetch_file": str(artifact.source_path),
                        "tool": "PECmd" if pecmd_row else "Built-in parser",
                    }
                )
                
                alert_dict = self._detect_suspicious_tools(executable_name, event)
                if alert_dict:
                    event.metadata["alert"] = alert_dict
                    logger.warning(f"Suspicious execution detected: {executable_name}")
                
                events.append(event)
                
            except Exception as e:
                logger.error(f"Failed to analyze Prefetch artifact {artifact.source_path}: {e}")

        return events

    def _run_pecmd_enrichment(self, artifacts: list[RawArtifact]) -> dict[str, dict[str, Any]]:
        """
        Run PECmd once over the Prefetch directory and index its CSV rows by
        prefetch file name (lowercase). Returns an empty dict when PECmd is
        unavailable so the built-in parser remains the fallback.
        """
        if not artifacts:
            return {}
        prefetch_dir = Path(artifacts[0].source_path).parent
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                rows = self.ez_tools.run_pecmd(prefetch_dir, Path(tmp_dir))
        except Exception as e:
            logger.warning("PECmd enrichment failed: %s", e)
            return {}

        indexed: dict[str, dict[str, Any]] = {}
        for row in rows:
            name = str(row.get("FileName", "") or row.get("PrefetchPath", "")).strip()
            if not name:
                continue
            indexed[Path(name).name.lower()] = row
        return indexed

    @staticmethod
    def _as_int(value: Any) -> int | None:
        """Best-effort int conversion for PECmd CSV values."""
        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_ez_timestamp(value: Any) -> datetime | None:
        """Parse a 'YYYY-MM-DD HH:MM:SS' timestamp from EZ Tools CSV output."""
        if not value:
            return None
        try:
            return datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None

    def _parse_prefetch(self, pf_path: str) -> dict[str, Any] | None:
        """
        Parse a Windows 10/11 Prefetch binary (format versions 30/31) to
        extract execution timestamps and run counts.

        Args:
            pf_path: Path to the Prefetch file.

        Returns:
            Dictionary with executable name, run count and timestamps, or
            None when the file cannot be parsed or contains no timestamps.
        """
        try:
            with open(pf_path, "rb") as f:
                data = f.read()
        except OSError as e:
            logger.error("Cannot read prefetch file %s: %s", pf_path, e)
            return None

        if len(data) < 84 or data[:4] != b"MAM\x04":
            logger.debug("Not a valid prefetch file: %s", pf_path)
            return None

        version = struct.unpack("<I", data[4:8])[0]
        file_info_offset = struct.unpack("<I", data[16:20])[0]
        file_info_count = struct.unpack("<I", data[20:24])[0]

        if file_info_offset <= 0 or file_info_count == 0:
            logger.debug("No file info entries in prefetch: %s", pf_path)
            return None

        # File info entries: 200 bytes (v30) or 224 bytes (v31)
        entry_size = 224 if version >= 31 else 200
        metrics_offsets: list[int] = []
        for i in range(file_info_count):
            entry_off = file_info_offset + i * entry_size
            if entry_off + 0x50 > len(data):
                break
            metrics_off = struct.unpack("<I", data[entry_off + 0x40:entry_off + 0x44])[0]
            metrics_count = struct.unpack("<I", data[entry_off + 0x44:entry_off + 0x48])[0]
            if metrics_off <= 0:
                continue
            # Metrics array entries are 132 bytes for v30/v31
            for m in range(metrics_count):
                metrics_offsets.append(metrics_off + m * 132)

        timestamps: list[datetime] = []
        run_count = 0
        for m_off in metrics_offsets:
            if m_off + 8 > len(data):
                continue
            filetime = struct.unpack("<Q", data[m_off:m_off + 8])[0]
            if filetime == 0:
                continue
            unix_us = (filetime - FILETIME_UNIX_OFFSET_US) / 10.0
            try:
                timestamps.append(datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc))
            except (ValueError, OverflowError, OSError):
                continue
            if m_off + 0x70 <= len(data):
                try:
                    run_count = max(run_count, struct.unpack("<I", data[m_off + 0x6C:m_off + 0x70])[0])
                except struct.error:
                    pass

        if not timestamps:
            logger.debug("No execution timestamps in prefetch %s; skipping", pf_path)
            return None

        filename = Path(pf_path).name
        stem = filename.split('-')[0] if '-' in filename else filename
        # Prefetch files look like NOTEPAD.EXE-5F1A0B32.pf; the executable
        # name is the part before the hash. Never append a duplicate ".exe".
        exec_name = stem if stem.lower().endswith(".exe") else f"{stem}.exe"

        return {
            "executable_name": exec_name,
            "run_count": run_count or 1,
            "execution_timestamps": sorted(set(timestamps)),
            "referenced_files": [],
            "referenced_directories": []
        }
        
    def _detect_suspicious_tools(self, executable_name: str, event: DataEvent) -> dict[str, Any] | None:
        """
        Determine if the executed application is known for anti-forensics or exfiltration.
        
        Args:
            executable_name: The name of the executed binary.
            event: The corresponding DataEvent.
            
        Returns:
            A dictionary containing alert details if suspicious, None otherwise.
        """
        if executable_name in self.SUSPICIOUS_TOOLS["anti_forensics"]:
            return {
                "title": "Anti-Forensics Tool Executed",
                "description": f"Evidence destruction tool executed: {executable_name}",
                "severity": Severity.CRITICAL.value,
                "event_id": event.event_id
            }
        elif executable_name in self.SUSPICIOUS_TOOLS["data_exfiltration"]:
            return {
                "title": "Data Exfiltration Tool Executed",
                "description": f"Potential data exfiltration tool executed: {executable_name}",
                "severity": Severity.HIGH.value,
                "event_id": event.event_id
            }
        return None
