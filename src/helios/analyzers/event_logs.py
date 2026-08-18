"""
Windows EVTX Event Logs Analyzer.
"""

import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.chainsaw_adapter import ChainsawAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import (
    Alert,
    Confidence,
    DataEvent,
    Device,
    EventType,
    ScanOptions,
    Severity,
)

logger = logging.getLogger(__name__)


class EventLogsAnalyzer(AnalyzerBase):
    """
    Analyzer for Windows EVTX Event Logs.

    Collects and analyzes Security, System, Software, and Diagnostic logs.
    Maps Event IDs:
    - 4624 / 4625 — logon success / failure (with the logon account)
    - 20001 / 20003 — USB device installation & connection
    - 1102 — audit log cleared (anti-forensics alert)
    - 7045 — new service installed
    """

    def __init__(
        self,
        config: dict | None = None,
        scan_options: ScanOptions | None = None,
        chainsaw_adapter: ChainsawAdapter | None = None,
    ):
        super().__init__(config=config or {}, scan_options=scan_options or ScanOptions())
        self.alerts: list[Alert] = []
        self.chainsaw_adapter = chainsaw_adapter or ChainsawAdapter(config=self.config)

    def name(self) -> str:
        """Return the name of the analyzer."""
        return "Windows Event Logs Analyzer"

    def can_run(self) -> bool:
        """Analyzer availability is decided by profile gating; the module itself always supports parsing."""
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect Security.evtx, System.evtx, Software.evtx, Microsoft-Windows-Partition/Diagnostic.evtx
        from the given device root path.
        """
        artifacts: list[RawArtifact] = []
        if device.mount_point:
            root = Path(device.mount_point)
        elif os.name == "nt":
            root = Path(os.environ.get("SystemDrive", "C:") + "\\")
        else:
            root = Path("/")
        winevt_dir = root / "Windows" / "System32" / "Winevt" / "Logs"

        target_logs = {
            "security.evtx",
            "system.evtx",
            "software.evtx",
            "microsoft-windows-partition%4diagnostic.evtx",
            "microsoft-windows-partition/diagnostic.evtx",
        }

        if winevt_dir.exists() and winevt_dir.is_dir():
            for log_file in winevt_dir.iterdir():
                if log_file.is_file() and log_file.name.lower() in target_logs:
                    artifacts.append(RawArtifact(
                        artifact_id=str(uuid.uuid4()),
                        artifact_type="evtx",
                        source_path=log_file,
                        device_id=device.device_id,
                        collected_at=datetime.now(tz=timezone.utc),
                    ))
                    logger.info(f"Collected event log: {log_file}")
        elif root.exists() and root != Path("/"):
            try:
                for evtx_file in root.glob("*.evtx"):
                    if evtx_file.name.lower() in target_logs:
                        artifacts.append(RawArtifact(
                            artifact_id=str(uuid.uuid4()),
                            artifact_type="evtx",
                            source_path=evtx_file,
                            device_id=device.device_id,
                            collected_at=datetime.now(tz=timezone.utc),
                        ))
                        logger.info(f"Collected exported event log: {evtx_file}")
            except OSError as e:
                logger.debug("Cannot glob EVTX files from %s: %s", root, e)

        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> list[DataEvent]:
        """Parse EVTX records into timeline events and structured alerts."""
        events: list[DataEvent] = []
        alerts: list[Alert] = []
        failed_logons_by_account: dict[str, list[datetime]] = {}

        for artifact in artifacts:
            try:
                records = self._parse_evtx(artifact.source_path)
                for record in records:
                    event_id = record.get("event_id")
                    ts = record.get("timestamp")
                    if ts is None:
                        continue

                    if event_id in (4624, 4625):
                        account = record.get("account") or "Unknown"
                        is_failed = event_id == 4625
                        events.append(DataEvent(
                            timestamp=ts,
                            event_type=EventType.FILE_ACCESS,
                            source_device=artifact.device_id,
                            source_path=str(artifact.source_path),
                            raw_source="EVTX",
                            metadata={
                                "event_id": event_id,
                                "account": account,
                                "status": "Failed" if is_failed else "Success",
                            },
                        ))
                        if is_failed and account != "Unknown":
                            failed_logons_by_account.setdefault(account, []).append(ts)

                    elif event_id in (20001, 20003):
                        device_id = record.get("device") or "Unknown USB device"
                        events.append(DataEvent(
                            timestamp=ts,
                            event_type=EventType.USB_CONNECT,
                            source_device=artifact.device_id,
                            source_path=str(artifact.source_path),
                            raw_source="EVTX",
                            metadata={"event_id": event_id, "device": device_id},
                        ))
                        alerts.append(Alert(
                            severity=Severity.INFO,
                            category="USB Activity",
                            title="USB Device Connected",
                            description=f"USB connection detected: {device_id} (EventID {event_id}).",
                            evidence=[str(artifact.source_path)],
                            device=artifact.device_id,
                            timestamp=ts,
                            confidence=Confidence.HIGH,
                        ))

                    elif event_id == 1102:
                        events.append(DataEvent(
                            timestamp=ts,
                            event_type=EventType.FILE_DELETE,
                            source_device=artifact.device_id,
                            source_path=str(artifact.source_path),
                            raw_source="EVTX",
                            metadata={"event_id": 1102, "alert": "AUDIT_LOG_CLEARED"},
                        ))
                        alerts.append(Alert(
                            severity=Severity.CRITICAL,
                            category="Anti-Forensics",
                            title="Audit Log Cleared",
                            description="Security audit log cleared (EventID 1102) — anti-forensics indicator.",
                            evidence=[str(artifact.source_path)],
                            device=artifact.device_id,
                            timestamp=ts,
                            confidence=Confidence.HIGH,
                        ))

                    elif event_id == 7045:
                        events.append(DataEvent(
                            timestamp=ts,
                            event_type=EventType.APP_EXECUTE,
                            source_device=artifact.device_id,
                            source_path=str(artifact.source_path),
                            raw_source="EVTX",
                            metadata={"event_id": 7045},
                        ))
                        alerts.append(Alert(
                            severity=Severity.INFO,
                            category="Event Log Anomaly",
                            title="New Service Installed",
                            description="A new service was installed (EventID 7045).",
                            evidence=[str(artifact.source_path)],
                            device=artifact.device_id,
                            timestamp=ts,
                            confidence=Confidence.MEDIUM,
                        ))

            except Exception as e:
                logger.error(f"Failed to analyze EVTX artifact {artifact.source_path}: {e}")

        alerts.extend(self._run_chainsaw_sigma_hunts(artifacts))
        self.alerts = alerts
        return events

    def _run_chainsaw_sigma_hunts(self, artifacts: list[RawArtifact]) -> list[Alert]:
        """
        Run Chainsaw Sigma hunts over the collected EVTX files. Degrades
        gracefully (returns []) when Chainsaw or bundled Sigma rules are
        unavailable.
        """
        if not artifacts:
            return []
        if not self.chainsaw_adapter.is_available():
            logger.debug("Chainsaw binary not available; skipping Sigma hunts.")
            return []

        try:
            from helios.config import get_bundle_root

            sigma_rules_dir = get_bundle_root() / "tools" / "sigma_rules"
            if not sigma_rules_dir.is_dir():
                sigma_rules_dir = get_bundle_root() / "sigma_rules"
        except Exception as e:
            logger.debug("Cannot resolve bundled Sigma rules directory: %s", e)
            return []

        if not sigma_rules_dir.is_dir():
            logger.debug("Bundled Sigma rules not found at %s", sigma_rules_dir)
            return []

        alert_dicts: list[Alert] = []
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_json = Path(tmp_dir) / "chainsaw_findings.json"
            for artifact in artifacts:
                try:
                    findings = self.chainsaw_adapter.run_sigma_hunt(
                        artifact.source_path, sigma_rules_dir, output_json
                    )
                except Exception as e:
                    logger.warning(
                        "Chainsaw Sigma hunt failed for %s: %s", artifact.source_path, e
                    )
                    continue
                for finding in findings:
                    if finding.evidence and isinstance(finding.evidence, list):
                        evidence = [str(artifact.source_path)] + [str(e) for e in finding.evidence if e]
                    else:
                        evidence = [str(artifact.source_path)]
                    alert_dicts.append(Alert(
                        title=finding.title,
                        severity=finding.severity,
                        category="Event Log Anomaly",
                        description=finding.description or "Matched Sigma detection rule in Windows Event Logs",
                        evidence=evidence,
                        device=artifact.device_id,
                        timestamp=datetime.now(tz=timezone.utc),
                        confidence=finding.confidence,
                    ))
        logger.info("Chainsaw Sigma hunts produced %d alerts.", len(alert_dicts))
        return alert_dicts

    def _parse_evtx(self, path: Path, _from_wevtutil: bool = False) -> list[dict[str, Any]]:
        """
        Parse binary EVTX file and extract SystemTime, EventID, and key payload data.
        Returns a list of record dicts.
        """
        records: list[dict[str, Any]] = []

        if not path.exists():
            return records

        try:
            import Evtx.Evtx as evtx  # type: ignore[import-untyped]
            import xml.etree.ElementTree as ET

            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            with evtx.Evtx(str(path)) as log:
                for record in log.records():
                    try:
                        xml_string = record.xml_string()
                        if not xml_string:
                            continue
                        root = ET.fromstring(xml_string)

                        system = root.find(".//e:System", ns)
                        if system is None:
                            continue

                        event_id = None
                        event_id_el = system.find("e:EventID", ns)
                        if event_id_el is not None and event_id_el.text is not None:
                            try:
                                event_id = int(event_id_el.text)
                            except ValueError:
                                event_id = None

                        timestamp = None
                        time_el = system.find("e:TimeCreated", ns)
                        if time_el is not None:
                            ts_str = time_el.get("SystemTime", "")
                            if ts_str:
                                try:
                                    parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                                    timestamp = parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
                                except ValueError:
                                    timestamp = None

                        if event_id is None or timestamp is None:
                            continue

                        record_dict: dict[str, Any] = {
                            "event_id": event_id,
                            "timestamp": timestamp,
                        }

                        # Extract accounts and devices if available
                        for tag in ("SubjectUserName", "TargetUserName"):
                            el = root.find(f".//e:EventData/e:Data[@Name='{tag}']", ns)
                            if el is not None and el.text:
                                record_dict["account"] = el.text.strip()
                                break

                        for tag in ("DeviceDescription", "InstanceId", "DeviceName"):
                            el = root.find(f".//e:EventData/e:Data[@Name='{tag}']", ns)
                            if el is not None and el.text:
                                record_dict["device"] = el.text.strip()
                                break

                        records.append(record_dict)
                    except Exception as e:
                        logger.warning(f"Failed to parse an EVTX record from {path}: {e}")
                        continue
        except ImportError:
            logger.debug("python-evtx not installed; skipping binary EVTX parsing.")
        except Exception as e:
            logger.warning(f"Failed to parse EVTX file {path}: {e}")

        # Fallback: try wevtutil export for locked live event logs
        if not records and os.name == "nt" and not _from_wevtutil:
            import subprocess as _sp
            tmp_path: str | None = None
            try:
                with tempfile.NamedTemporaryFile(suffix=".evtx", delete=False) as tmp:
                    tmp_path = tmp.name

                # Try channel name export first (e.g. Security, System)
                channel_name = path.stem
                result = _sp.run(
                    ["wevtutil", "epl", channel_name, tmp_path, "/ow:true"],
                    capture_output=True, timeout=60,
                )
                if result.returncode != 0:
                    # Fallback to direct file path export with /lf:true
                    result = _sp.run(
                        ["wevtutil", "epl", str(path), tmp_path, "/lf:true", "/ow:true"],
                        capture_output=True, timeout=60,
                    )

                if result.returncode == 0:
                    records = self._parse_evtx(Path(tmp_path), _from_wevtutil=True)
                    logger.info("wevtutil fallback parsed %d records from %s", len(records), path)
                else:
                    logger.debug("wevtutil epl failed for %s: rc=%d", path, result.returncode)
            except Exception as wev_e:
                logger.debug("wevtutil fallback failed for %s: %s", path, wev_e)
            finally:
                if tmp_path:
                    try:
                        Path(tmp_path).unlink(missing_ok=True)
                    except Exception:
                        pass

        return records
