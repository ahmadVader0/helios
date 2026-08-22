"""
USB Connection History Analyzer.

This module provides the UsbHistoryAnalyzer class, responsible for parsing
system registries, setupapi.dev.log, MountedDevices, and MountPoints2 to
reconstruct the timeline of USB device connections and disconnections.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import Confidence, DataEvent, Device, EventType

logger = logging.getLogger(__name__)


class UsbHistoryAnalyzer(AnalyzerBase):
    """
    Analyzer for extracting USB connection history from system logs and registry.
    Supports both live Windows querying via winreg and offline hive parsing.
    """

    def name(self) -> str:
        """Get the human-readable name of the analyzer."""
        return "USB Connection History Analyzer"

    def can_run(self) -> bool:
        """
        Check if registry files, setupapi logs, or live winreg are available.

        Returns:
            bool: True if required artifacts can be located or live registry is accessible.
        """
        if os.name == "nt":
            return True
        if self.scan_options and self.scan_options.paths:
            return True
        return False

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect SYSTEM registry hive, setupapi.dev.log, MountedDevices, and MountPoints2.

        Args:
            device (Device): The target device to scan.

        Returns:
            List[RawArtifact]: Collected raw artifacts containing USB history data.
        """
        artifacts: list[RawArtifact] = []

        # On live Windows, query in-memory registry via winreg directly
        if os.name == "nt":
            artifacts.append(
                RawArtifact(
                    artifact_id=f"usb_{device.device_id}_live_registry",
                    artifact_type="live_registry",
                    source_path=Path("HKLM\\SYSTEM"),
                    device_id=device.device_id,
                    collected_at=datetime.now(tz=timezone.utc),
                    metadata={"live": True},
                )
            )

        target_paths = [
            Path("C:\\Windows\\System32\\config\\SYSTEM"),
            Path("C:\\Windows\\inf\\setupapi.dev.log"),
        ]

        if os.name == "nt":
            try:
                for p in Path("C:\\Users").glob("*\\NTUSER.DAT"):
                    target_paths.append(p)
            except Exception as e:
                logger.debug("Failed to glob NTUSER.DAT files: %s", e)

        # Auto-discover offline Windows artifacts under every scanned volume
        # (WSL/drvfs or mounted evidence drives): <mount>/Windows/... This
        # is what makes USB history work when scanning D: from WSL instead
        # of silently finding nothing.
        if hasattr(self, "scan_options") and self.scan_options and self.scan_options.drives:
            for d in self.scan_options.drives:
                base = Path(d)
                target_paths.append(base / "Windows" / "System32" / "config" / "SYSTEM")
                target_paths.append(base / "Windows" / "inf" / "setupapi.dev.log")

        # If paths are provided in scan options, look for registry files there
        if hasattr(self, "scan_options") and self.scan_options and self.scan_options.paths:
            for base_path in self.scan_options.paths:
                for target in ["SYSTEM", "setupapi.dev.log"]:
                    p = Path(base_path) / target
                    try:
                        accessible = p.exists() and p.is_file()
                    except OSError:
                        accessible = False
                    if accessible:
                        target_paths.append(p)

        # Default mock paths for non-Windows or test environments
        if os.name != "nt":
            target_paths.append(Path("/tmp/setupapi.dev.log"))
            target_paths.append(Path("/tmp/SYSTEM"))

        seen_paths: set[str] = set()
        unique_paths: list[Path] = []
        for tp in target_paths:
            try:
                key = str(tp.resolve()).lower()
            except OSError:
                key = str(tp).lower()
            if key not in seen_paths:
                seen_paths.add(key)
                unique_paths.append(tp)
        target_paths = unique_paths

        for path in target_paths:
            try:
                if not path.exists() or not path.is_file():
                    continue
            except OSError as e:
                logger.debug("Cannot access %s: %s", path, e)
                continue
            try:
                metadata: dict[str, Any] = {"size": path.stat().st_size}
                if path.name.lower() == "ntuser.dat":
                    artifact_type = "ntuser_registry"
                    metadata["user"] = path.parent.name
                else:
                    artifact_type = "registry" if path.name == "SYSTEM" else "log"

                artifact = RawArtifact(
                    artifact_id=f"usb_{device.device_id}_{path.name}",
                    artifact_type=artifact_type,
                    source_path=path,
                    device_id=device.device_id,
                    collected_at=datetime.now(tz=timezone.utc),
                    metadata=metadata,
                )
                artifacts.append(artifact)
                logger.info("Collected USB history artifact: %s", path)
            except OSError as e:
                logger.debug("Failed to collect %s: %s", path, e)

        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """
        Parse USB connection history and emit USB_CONNECT and USB_DISCONNECT DataEvents.

        Args:
            artifacts (List[RawArtifact]): The raw collected artifacts.

        Returns:
            List[DataEvent]: Processed data events.
        """
        events: list[DataEvent] = []

        # Track which sources have been parsed so the locked-SYSTEM-hive
        # fallback never re-runs a parser that already produced events
        # (this used to duplicate every USBSTOR connect event).
        live_winreg_done = False

        for artifact in artifacts:
            try:
                if artifact.artifact_type == "live_registry":
                    events.extend(self._parse_live_winreg(artifact.device_id))
                    live_winreg_done = True
                elif artifact.source_path.name.lower() == "setupapi.dev.log":
                    events.extend(self._parse_setupapi(artifact))
                elif artifact.source_path.name.lower() == "system":
                    sys_events = self._parse_system_registry(artifact)
                    if not sys_events and os.name == "nt" and not live_winreg_done:
                        sys_events = self._parse_live_winreg(artifact.device_id)
                    events.extend(sys_events)
                elif artifact.source_path.name.lower() == "ntuser.dat":
                    events.extend(self._parse_ntuser_registry(artifact))
            except Exception as e:
                logger.error("Error processing USB artifact %s: %s", artifact.source_path, e)

        # Deduplicate events across live winreg, offline hives, and logs.
        # Identifiers are compared case-insensitively because setupapi.dev.log
        # and the registry frequently differ in casing for the same device.
        seen_events: set[tuple[str, str, str]] = set()
        deduped_events: list[DataEvent] = []
        for evt in events:
            key = (
                str(evt.event_type),
                str(
                    evt.metadata.get("serial_number")
                    or evt.metadata.get("hardware_id")
                    or evt.source_path
                ).lower(),
                evt.timestamp.isoformat() if evt.timestamp else "",
            )
            if key not in seen_events:
                seen_events.add(key)
                deduped_events.append(evt)

        return deduped_events

    def _parse_live_winreg(self, device_id: str) -> list[DataEvent]:
        """
        Parse live Windows registry keys via standard library winreg without file locks.
        """
        if os.name != "nt":
            return []
        try:
            import winreg  # type: ignore[import-not-found]
        except ImportError:
            return []

        events: list[DataEvent] = []

        # 1. Query HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
        for cs in ("CurrentControlSet", "ControlSet001"):
            usbstor_rel = f"SYSTEM\\{cs}\\Enum\\USBSTOR"
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_rel) as usbstor_k:
                    num_subkeys, _, _ = winreg.QueryInfoKey(usbstor_k)
                    for i in range(num_subkeys):
                        hw_id = winreg.EnumKey(usbstor_k, i)
                        with winreg.OpenKey(usbstor_k, hw_id) as dev_k:
                            num_inst, _, _ = winreg.QueryInfoKey(dev_k)
                            for j in range(num_inst):
                                serial = winreg.EnumKey(dev_k, j)
                                friendly_name = ""
                                container_id = ""
                                connect_time: datetime | None = None

                                with winreg.OpenKey(dev_k, serial) as inst_k:
                                    try:
                                        friendly_name, _ = winreg.QueryValueEx(inst_k, "FriendlyName")
                                    except OSError:
                                        pass

                                    # ContainerID is a REG_SZ value under the device instance key
                                    try:
                                        cont_val, _ = winreg.QueryValueEx(inst_k, "ContainerID")
                                        if cont_val:
                                            container_id = str(cont_val)
                                    except OSError:
                                        pass

                                    # Try Properties subkey for InstallTime / FirstInstallDate
                                    try:
                                        with winreg.OpenKey(inst_k, "Properties\\{83da6326-97a6-4088-9453-a1923f573b29}\\0000000000000064") as prop_k:
                                            prop_ft, _ = winreg.QueryValueEx(prop_k, "")
                                            if isinstance(prop_ft, int) and prop_ft > 0:
                                                unix_us = (prop_ft - 116444736000000000) / 10.0
                                                connect_time = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
                                    except OSError:
                                        pass

                                    # Fallback to key LastWriteTime (FILETIME)
                                    if connect_time is None:
                                        try:
                                            _, _, last_write_ft = winreg.QueryInfoKey(inst_k)
                                            if last_write_ft > 0:
                                                unix_us = (last_write_ft - 116444736000000000) / 10.0
                                                connect_time = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
                                        except (OSError, ValueError, OverflowError):
                                            pass

                                if connect_time is not None:
                                    events.append(
                                        DataEvent(
                                            timestamp=connect_time,
                                            event_type=EventType.USB_CONNECT,
                                            source_device=device_id,
                                            source_path=f"HKLM\\{usbstor_rel}\\{hw_id}\\{serial}",
                                            confidence=Confidence.HIGH,
                                            raw_source="Windows Registry (Live winreg)",
                                            metadata={
                                                "hardware_id": hw_id,
                                                "serial_number": serial,
                                                "friendly_name": friendly_name,
                                                "container_id": container_id,
                                                "source": f"HKLM\\{usbstor_rel}",
                                            },
                                        )
                                    )
                if events:
                    break
            except OSError as e:
                logger.debug("Could not read live %s: %s", usbstor_rel, e)

        # 2. Query HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2
        mp_rel = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mp_rel) as mp_k:
                num_subkeys, _, _ = winreg.QueryInfoKey(mp_k)
                for i in range(num_subkeys):
                    name = winreg.EnumKey(mp_k, i)
                    if not (name.startswith("{") and name.endswith("}")) and not name.startswith("##"):
                        continue
                    try:
                        with winreg.OpenKey(mp_k, name) as sub_k:
                            _, _, last_write_ft = winreg.QueryInfoKey(sub_k)
                            if last_write_ft > 0:
                                unix_us = (last_write_ft - 116444736000000000) / 10.0
                                ts = datetime.fromtimestamp(unix_us / 1_000_000, tz=timezone.utc)
                                metadata: dict[str, Any] = {
                                    "mountpoint": name,
                                    "source": f"HKCU\\{mp_rel}",
                                }
                                try:
                                    data_val, _ = winreg.QueryValueEx(sub_k, "_Data")
                                    if isinstance(data_val, bytes) and len(data_val) >= 16:
                                        metadata["volume_serial"] = data_val[8:16].hex()
                                except OSError:
                                    pass
                                events.append(
                                    DataEvent(
                                        timestamp=ts,
                                        event_type=EventType.USB_CONNECT,
                                        source_device=device_id,
                                        source_path=f"HKCU\\{mp_rel}\\{name}",
                                        confidence=Confidence.MEDIUM,
                                        raw_source="Windows Registry (MountPoints2)",
                                        metadata=metadata,
                                    )
                                )
                    except OSError as e:
                        logger.debug("Skipping live MountPoints2 key %s: %s", name, e)
        except OSError as e:
            logger.debug("Could not read live MountPoints2: %s", e)

        return events

    def _parse_ntuser_registry(self, artifact: RawArtifact) -> list[DataEvent]:
        """
        Parse the NTUSER.DAT hive's Explorer\\MountPoints2 keys.

        Each MountPoints2 subkey (volume GUID or drive-letter entry) carries a
        real last-write timestamp from the hive itself — that is the last time
        the volume was mounted, so it is reported as a MEDIUM-confidence
        connect event. No timestamps are invented.
        """
        events: list[DataEvent] = []

        try:
            from Registry import Registry  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("python-registry not installed; skipping NTUSER.DAT hive %s", artifact.source_path)
            return events

        mount_points2 = (
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2"
        )
        try:
            reg = Registry.Registry(str(artifact.source_path))
            mp_key = reg.open(mount_points2)
        except Exception:
            # Some hives lack the MountPoints2 key entirely or are locked.
            return events

        for subkey in mp_key.subkeys():
            try:
                name = subkey.name()
                if not (name.startswith("{") and name.endswith("}")) and not name.startswith("##"):
                    continue
                last_write = subkey.timestamp()
                if last_write is None:
                    continue
                if isinstance(last_write, datetime):
                    ts = last_write if last_write.tzinfo is not None else last_write.replace(tzinfo=timezone.utc)
                else:
                    ts = datetime.fromtimestamp(float(last_write), tz=timezone.utc)
                metadata: dict[str, Any] = {
                    "mountpoint": name,
                    "source": f"NTUSER.DAT\\{mount_points2}",
                }
                try:
                    data_val = subkey.value("_Data").value()
                    serial_bytes = data_val[8:16]
                    if len(serial_bytes) == 8:
                        metadata["volume_serial"] = serial_bytes.hex()
                except Exception:
                    pass
                events.append(DataEvent(
                    timestamp=ts,
                    event_type=EventType.USB_CONNECT,
                    source_device=artifact.device_id,
                    source_path="\\".join(["NTUSER.DAT", mount_points2]),
                    confidence=Confidence.MEDIUM,
                    metadata=metadata,
                ))
            except Exception as e:
                logger.debug("Skipping MountPoints2 key %s: %s", subkey.name(), e)

        return events

    def _parse_setupapi(self, artifact: RawArtifact) -> list[DataEvent]:
        """
        Parse setupapi.dev.log for exact first-connect timestamps.

        Only USB device installs are emitted (the log records installs for
        every device class). Section start timestamps in the log are in
        machine-LOCAL time and are converted to UTC here.

        Args:
            artifact (RawArtifact): The log artifact.

        Returns:
            List[DataEvent]: Connection events extracted from the log.
        """
        events: list[DataEvent] = []

        try:
            with open(artifact.source_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.readlines()

            current_device: dict[str, Any] | None = None
            current_delete: dict[str, Any] | None = None

            for line in content:
                line = line.strip()
                if line.startswith(">>>  [Device Install"):
                    current_delete = None
                    current_device = {}
                    if "-" in line:
                        parts = line.split("-")
                        if len(parts) > 1:
                            hw_id = parts[1].strip().rstrip("]").strip()
                            # Skip non-USB device installs (disk, monitor,
                            # network adapter, software devices, ...)
                            if "usb\\" in hw_id.lower():
                                current_device["hw_id"] = hw_id
                elif line.startswith(">>>  [Device Delete"):
                    # Removal sections carry the disconnect timestamp when
                    # present; not all setupapi versions write them.
                    current_device = None
                    current_delete = {}
                    if "-" in line:
                        parts = line.split("-")
                        if len(parts) > 1:
                            hw_id = parts[1].strip().rstrip("]").strip()
                            if "usb\\" in hw_id.lower():
                                current_delete["hw_id"] = hw_id
                elif line.startswith(">>>  Section start"):
                    time_match = re.search(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})", line)
                    if time_match:
                        try:
                            naive_local = datetime.strptime(time_match.group(1), "%Y/%m/%d %H:%M:%S")
                            # setupapi timestamps are local machine time —
                            # convert to UTC instead of mislabeling them.
                            ts = naive_local.astimezone(timezone.utc)
                            if current_device is not None:
                                current_device["timestamp"] = ts
                            elif current_delete is not None:
                                current_delete["timestamp"] = ts
                        except ValueError:
                            pass
                elif line.startswith("<<<  Section end"):
                    if current_device is not None:
                        if "timestamp" in current_device and "hw_id" in current_device:
                            metadata = {
                                "hardware_id": current_device["hw_id"],
                                "source_log": "setupapi.dev.log",
                            }
                            events.append(DataEvent(
                                timestamp=current_device["timestamp"],
                                event_type=EventType.USB_CONNECT,
                                source_device=artifact.device_id,
                                source_path=artifact.source_path.name,
                                confidence=Confidence.HIGH,
                                metadata=metadata,
                            ))
                        current_device = None
                    elif current_delete is not None:
                        if "timestamp" in current_delete and "hw_id" in current_delete:
                            events.append(DataEvent(
                                timestamp=current_delete["timestamp"],
                                event_type=EventType.USB_DISCONNECT,
                                source_device=artifact.device_id,
                                source_path=artifact.source_path.name,
                                confidence=Confidence.MEDIUM,
                                metadata={
                                    "hardware_id": current_delete["hw_id"],
                                    "source_log": "setupapi.dev.log",
                                },
                            ))
                        current_delete = None

        except Exception as e:
            logger.debug("Failed to parse setupapi.dev.log: %s", e)

        return events

    def _parse_system_registry(self, artifact: RawArtifact) -> list[DataEvent]:
        """
        Parse SYSTEM registry hive for USBSTOR entries.

        Args:
            artifact (RawArtifact): The registry hive artifact.

        Returns:
            List[DataEvent]: Connection events extracted from the registry.
        """
        events: list[DataEvent] = []

        try:
            from Registry import Registry  # type: ignore[import-untyped]
        except ImportError:
            logger.debug("python-registry not installed; skipping SYSTEM hive %s", artifact.source_path)
            return events

        try:
            reg = Registry.Registry(str(artifact.source_path))

            usbstor_path = "ControlSet001\\Enum\\USBSTOR"
            try:
                usbstor_key = reg.open(usbstor_path)
            except Exception:
                try:
                    usbstor_path = "CurrentControlSet\\Enum\\USBSTOR"
                    usbstor_key = reg.open(usbstor_path)
                except Exception:
                    logger.debug("Could not find USBSTOR key in SYSTEM registry %s", artifact.source_path)
                    return events

            for device_key in usbstor_key.subkeys():
                hw_id = device_key.name()
                for instance_key in device_key.subkeys():
                    serial = instance_key.name()
                    friendly_name = ""
                    try:
                        friendly_name = instance_key.value("FriendlyName").value()
                    except Exception:
                        pass
                    connect_time: datetime | None = None
                    container_id = ""
                    try:
                        container_id = instance_key.subkey("ContainerID").name()
                        install_ft = instance_key.subkey("ContainerID").value("InstallTime").value()
                        install_us = (int(install_ft) - 116444736000000000) / 10.0
                        connect_time = datetime.fromtimestamp(install_us / 1_000_000, tz=timezone.utc)
                    except Exception:
                        connect_time = None
                    if connect_time is None:
                        logger.debug("No InstallTime for USB device %s; skipping event", serial)
                        continue
                    metadata = {
                        "hardware_id": hw_id,
                        "serial_number": serial,
                        "friendly_name": friendly_name,
                        "container_id": container_id,
                        "source": f"SYSTEM\\{usbstor_path}",
                    }
                    events.append(
                        DataEvent(
                            timestamp=connect_time,
                            event_type=EventType.USB_CONNECT,
                            source_device=artifact.device_id,
                            source_path=usbstor_path,
                            confidence=Confidence.HIGH,
                            metadata=metadata,
                        )
                    )
        except Exception as e:
            logger.debug("Failed to parse SYSTEM hive %s directly: %s", artifact.source_path, e)

        return events
