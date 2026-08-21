import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import DataEvent, Device, EventType, ScanOptions

logger = logging.getLogger(__name__)


# Enum for drive types commonly found in LNK files
class _LnkDriveType:
    UNKNOWN = "0"
    REMOVABLE = "2"


class LnkJumpListAnalyzer(AnalyzerBase):
    """
    Analyzer for LNK Shortcuts and Jump Lists.
    Extracts evidence of file access, particularly from removable drives.
    """

    def __init__(self, config: dict | None = None, scan_options: ScanOptions | None = None, ez_tools_adapter: EZToolsAdapter | None = None) -> None:
        """
        Initialize the LnkJumpListAnalyzer.

        Args:
            config: Optional configuration dictionary.
            scan_options: Optional scan options.
            ez_tools_adapter: Optional adapter for Eric Zimmerman tools.
        """
        super().__init__(config=config or {}, scan_options=scan_options or ScanOptions())
        self.ez_tools = ez_tools_adapter or EZToolsAdapter()

    def name(self) -> str:
        """Returns the name of the analyzer."""
        return "LNK & Jump Lists Analyzer"

    def can_run(self) -> bool:
        """Check if the analyzer can run. Always True (supports native parsing)."""
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect LNK files and JumpLists from typical locations.
        
        Args:
            device: The target Device object representing the system being analyzed.
            
        Returns:
            A list of RawArtifact objects representing collected files or directories.
        """
        artifacts = []
        
        # Typical LNK locations for standard Windows profiles
        # Note: In a real system we would iterate through User profiles
        system_root = getattr(device, "root_path", None) or Path("C:/")
        if isinstance(system_root, str):
            system_root = Path(system_root)
        
        user_profiles = [system_root / "Users" / user for user in self._get_users(device, system_root)]
        
        for profile in user_profiles:
            # LNK Files
            recent_dir = profile / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            desktop_dir = profile / "Desktop"
            quick_launch_dir = profile / "AppData" / "Roaming" / "Microsoft" / "Internet Explorer" / "Quick Launch"
            
            # Jump Lists
            auto_dest = recent_dir / "AutomaticDestinations"
            cust_dest = recent_dir / "CustomDestinations"
            
            for path in [recent_dir, desktop_dir, quick_launch_dir, auto_dest, cust_dest]:
                if path.exists():
                    logger.debug(f"Collected artifact path: {path}")
                    artifacts.append(RawArtifact(
                        artifact_id=f"lnk_{device.device_id}_{path.name}",
                        artifact_type="LNK_JUMPLIST" if path.name.endswith("Destinations") else "LNK",
                        source_path=path,
                        device_id=device.device_id,
                        collected_at=datetime.now()
                    ))
                    
        return artifacts

    def _get_users(self, device: Device, system_root: Path) -> list[str]:
        """Helper to get user directories from the device."""
        users_dir = system_root / "Users"
        try:
            if users_dir.exists() and users_dir.is_dir():
                return [p.name for p in users_dir.iterdir() if p.is_dir()]
        except OSError:
            logger.debug("Cannot enumerate users directory %s", users_dir)
        user_prof = os.environ.get("USERPROFILE")
        if user_prof:
            return [Path(user_prof).name]
        return []

    def _parse_timestamp(self, ts_str: Any) -> datetime | None:
        """Parse timestamp strings from EZ Tools output."""
        if not ts_str:
            return None
        val_str = str(ts_str).strip()
        if not val_str or val_str in ("N/A", "None", "-"):
            return None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                return datetime.strptime(val_str, fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        try:
            parsed = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """
        Parse collected LNK files and JumpLists and extract DataEvents.
        
        Args:
            artifacts: List of RawArtifact objects.
            
        Returns:
            List of parsed DataEvent objects.
        """
        events = []

        if not artifacts:
            raise RuntimeError(
                "No LNK/JumpList artifacts collected (no user Recent folders found "
                "on the scanned volume)"
            )

        if not self.ez_tools.tool_available("lecmd"):
            raise RuntimeError(
                "LECmd.exe not available on this platform — LNK parsing requires "
                "the bundled Windows binary (run on Windows, not WSL/Linux)"
            )
        if not self.ez_tools.tool_available("jlecmd"):
            raise RuntimeError(
                "JLECmd.exe not available on this platform — JumpList parsing requires "
                "the bundled Windows binary (run on Windows, not WSL/Linux)"
            )

        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_output_dir = Path(tmp_dir)
            
            for artifact in artifacts:
                if artifact.artifact_type == "LNK":
                    # Run LECmd
                    logger.info(f"Parsing LNKs from: {artifact.source_path}")
                    records = self.ez_tools.run_lecmd(artifact.source_path, csv_output_dir)
                    events.extend(self._process_lnk_records(records, str(artifact.source_path), artifact.device_id))

                elif artifact.artifact_type == "LNK_JUMPLIST":
                    # Run JLECmd
                    logger.info(f"Parsing JumpLists from: {artifact.source_path}")
                    records = self.ez_tools.run_jlecmd(artifact.source_path, csv_output_dir)
                    events.extend(self._process_jumplist_records(records, str(artifact.source_path), artifact.device_id))

        return events

    def _process_lnk_records(self, records: list[dict[str, Any]], source_path: str, source_device: str) -> list[DataEvent]:
        """Process raw records from LECmd into DataEvent objects."""
        events = []
        for rec in records:
            # Extract basic LNK data
            target = rec.get("LocalPath", "") or rec.get("NetworkPath", "")
            vol_serial = rec.get("VolumeSerialNumber", "")
            drive_type_str = str(rec.get("DriveType", ""))
            
            # Map known drive types to our constants if needed, LECmd outputs text usually like "Removable" or "Fixed"
            is_removable = (
                "removable" in drive_type_str.lower() or 
                drive_type_str == _LnkDriveType.REMOVABLE
            )
            
            creation_time = self._parse_timestamp(
                rec.get("TargetCreated")
                or rec.get("TargetCreationTime")
                or rec.get("SourceCreated")
            )
            modification_time = self._parse_timestamp(
                rec.get("TargetModified")
                or rec.get("TargetModificationTime")
                or rec.get("SourceModified")
            )
            access_time = self._parse_timestamp(
                rec.get("TargetAccessed")
                or rec.get("TargetAccessTime")
                or rec.get("SourceAccessed")
            )
            
            # LNK creation time itself usually denotes first time the file was accessed via shortcut
            lnk_creation = self._parse_timestamp(
                rec.get("SourceCreated") or rec.get("SourceCreationTime")
            )
            
            timestamp = access_time or lnk_creation or modification_time or creation_time
            if timestamp is None:
                logger.debug("No timestamp in LECmd record; skipping %s", rec.get("SourceFile", ""))
                continue
                
            metadata = {
                "source_file": rec.get("SourceFile", ""),
                "target_path": target,
                "target_creation_time": creation_time.isoformat() if creation_time else None,
                "target_modification_time": modification_time.isoformat() if modification_time else None,
                "volume_serial": vol_serial,
                "drive_type": drive_type_str,
                "tracker": "LECmd"
            }
            
            if is_removable:
                metadata["removable_media_flag"] = True
                
            event = DataEvent(
                timestamp=timestamp,
                event_type=EventType.FILE_ACCESS,
                source_device=source_device,
                source_path=target or source_path,
                raw_source="LECmd",
                metadata=metadata
            )
            events.append(event)
            
        return events

    def _process_jumplist_records(self, records: list[dict[str, Any]], source_path: str, source_device: str) -> list[DataEvent]:
        """Process raw records from JLECmd into DataEvent objects."""
        events = []
        for rec in records:
            target = rec.get("LocalPath", "") or rec.get("NetworkPath", "")
            app_id = rec.get("AppIdDescription", "") or rec.get("AppId", "")
            vol_serial = rec.get("VolumeSerialNumber", "")
            drive_type_str = str(rec.get("DriveType", ""))
            
            is_removable = "removable" in drive_type_str.lower()
            
            access_time = self._parse_timestamp(
                rec.get("TargetAccessed")
                or rec.get("TargetAccessTime")
                or rec.get("LastModified")
                or rec.get("LastAccess")
                or rec.get("SourceAccessed")
                or rec.get("SourceCreated")
                or rec.get("TargetModified")
            )
            
            if access_time is None:
                logger.debug("No timestamp in JLECmd record; skipping %s", rec.get("SourceFile", ""))
                continue
                
            metadata = {
                "source_file": rec.get("SourceFile", ""),
                "app_id": app_id,
                "volume_serial": vol_serial,
                "drive_type": drive_type_str,
                "tracker": "JLECmd",
                "target_path": target
            }
            
            if is_removable:
                metadata["removable_media_flag"] = True
                
            event = DataEvent(
                timestamp=access_time,
                event_type=EventType.FILE_ACCESS,
                source_device=source_device,
                # Show the accessed target when known; the jumplist file
                # itself is only the source artifact.
                source_path=target or str(source_path),
                raw_source="JLECmd",
                metadata=metadata
            )
            events.append(event)
            
        return events
