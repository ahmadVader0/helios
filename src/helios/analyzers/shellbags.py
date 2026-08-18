"""
ShellBags Analyzer for Helios.
Parses NTUSER.DAT and UsrClass.dat hives to extract folder access history.
"""
import logging
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import DataEvent, Device, EventType, ScanOptions, Severity

logger = logging.getLogger(__name__)

class ShellBagsAnalyzer(AnalyzerBase):
    """
    Analyzes Windows ShellBags (NTUSER.DAT & UsrClass.dat) to reconstruct
    folder browsing history, network locations, and external storage access.
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
        """Returns the name of the analyzer."""
        return "ShellBags Folder Access Analyzer"

    def can_run(self) -> bool:
        """
        Checks if ShellBags registry hives can be parsed.
        Returns True indicating analyzer capability.
        """
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect NTUSER.DAT and UsrClass.dat from user profile directories.
        """
        artifacts: list[RawArtifact] = []
        if device.mount_point:
            root = Path(device.mount_point)
        elif os.name == "nt":
            root = Path(os.environ.get("SystemDrive", "C:") + "\\")
        else:
            root = Path("/")
        user_profiles_dir = root / "Users"
        
        if not user_profiles_dir.exists() or not user_profiles_dir.is_dir():
            return artifacts

        for user_dir in user_profiles_dir.iterdir():
            if user_dir.is_dir():
                ntuser = user_dir / "NTUSER.DAT"
                usrclass = user_dir / "AppData" / "Local" / "Microsoft" / "Windows" / "UsrClass.dat"
                
                if ntuser.exists():
                    artifacts.append(RawArtifact(
                        artifact_id=str(uuid.uuid4()),
                        artifact_type="RegistryHive",
                        source_path=ntuser,
                        device_id=device.device_id,
                        collected_at=datetime.now(),
                        metadata={"user": user_dir.name, "type": "NTUSER.DAT"}
                    ))
                if usrclass.exists():
                    artifacts.append(RawArtifact(
                        artifact_id=str(uuid.uuid4()),
                        artifact_type="RegistryHive",
                        source_path=usrclass,
                        device_id=device.device_id,
                        collected_at=datetime.now(),
                        metadata={"user": user_dir.name, "type": "UsrClass.dat"}
                    ))
        
        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """
        Parse folder browsing history, folder access timestamps, and directory paths.
        Also detects and flags disconnected USB folder browsing.
        """
        events = []
        
        for artifact in artifacts:
            try:
                logger.info(f"Analyzing ShellBags in {artifact.source_path}")
                parsed_entries = self._parse_with_sbecmd(artifact)
                
                for entry in parsed_entries:
                    folder_path = entry.get("path", "")
                    ts = entry.get("last_accessed")
                    if isinstance(ts, str):
                        try:
                            ts = datetime.fromisoformat(ts)
                        except ValueError:
                            ts = None
                    if ts is None:
                        logger.debug("No last_accessed timestamp for bag entry %s; skipping", folder_path)
                        continue
                    
                    event = DataEvent(
                        timestamp=ts,
                        event_type=EventType.FILE_ACCESS,
                        source_device=artifact.device_id,
                        source_path=str(artifact.source_path),
                        raw_source="ShellBags",
                        metadata={
                            "folder_path": folder_path,
                            "hive": str(artifact.source_path),
                            "user": artifact.metadata.get("user", "Unknown"),
                            "creation_time": str(entry.get("creation_time")),
                            "modification_time": str(entry.get("modification_time")),
                            "volume": entry.get("volume", ""),
                            "tool": entry.get("tool", "Built-in parser"),
                        }
                    )
                    
                    # Detect disconnected USB folder browsing
                    if self._is_disconnected_usb_path(folder_path):
                        alert_dict = {
                            "title": "Disconnected USB Folder Browsing",
                            "description": f"Folder accessed on a disconnected USB drive: {folder_path}",
                            "severity": Severity.HIGH.value,
                            "event_id": event.event_id
                        }
                        event.metadata["alert"] = alert_dict
                        logger.warning(f"Suspicious disconnected USB folder access detected: {folder_path}")

                    events.append(event)
            except Exception as e:
                logger.error(f"Failed to analyze ShellBags artifact {artifact.source_path}: {e}")

        return events

    def _parse_with_sbecmd(self, artifact: RawArtifact) -> list[dict[str, Any]]:
        """
        Run SBECmd over the collected registry hive and convert its CSV rows
        into bag entries. Returns [] when SBECmd is unavailable.
        """
        entries: list[dict[str, Any]] = []
        try:
            with tempfile.TemporaryDirectory() as tmp_dir:
                rows = self.ez_tools.run_sbecmd(artifact.source_path, Path(tmp_dir))
            for row in rows:
                folder_path = str(row.get("FolderPath", "")).strip()
                if not folder_path:
                    continue
                # SBECmd emits per-property timestamps; take the first real
                # value available for each semantic slot.
                last_accessed = self._parse_ez_timestamp(
                    row.get("LastAccessed0x20")
                    or row.get("LastModified0x10")
                    or row.get("LastModified0x30")
                )
                modification_time = self._parse_ez_timestamp(
                    row.get("LastModified0x10")
                    or row.get("LastModified0x30")
                    or row.get("LastAccessed0x20")
                )
                creation_time = self._parse_ez_timestamp(
                    row.get("Created0x10")
                    or row.get("Created0x30")
                )
                entries.append({
                    "path": folder_path,
                    "last_accessed": last_accessed,
                    "creation_time": creation_time,
                    "modification_time": modification_time,
                    "volume": str(row.get("Volume", "")).strip(),
                    "tool": "SBECmd",
                })
        except Exception as e:
            logger.warning("SBECmd enrichment failed for %s: %s", artifact.source_path, e)
        return entries

    @staticmethod
    def _parse_ez_timestamp(value: object) -> datetime | None:
        """Parse a 'YYYY-MM-DD HH:MM:SS' timestamp from EZ Tools CSV output."""
        if not value:
            return None
        try:
            return datetime.strptime(str(value).strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            return None
        
    def _is_disconnected_usb_path(self, folder_path: str) -> bool:
        """
        Determine if the folder path corresponds to a disconnected removable drive.
        
        Args:
            folder_path: The directory path extracted from ShellBags.
            
        Returns:
            True if it appears to be a disconnected USB, False otherwise.
        """
        if re.match(r'^[D-Z]:\\', folder_path, re.IGNORECASE):
            drive_letter = folder_path[:3]
            # Verify if the drive is currently unmounted/missing
            if not os.path.exists(drive_letter):
                return True
            
        # Also flag volume GUID paths commonly associated with USBs
        if "\\??\\Volume{" in folder_path or "Removable" in folder_path:
            return True
            
        return False
