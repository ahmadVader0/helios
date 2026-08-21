
from pathlib import Path

from helios.analyzers.event_logs import EventLogsAnalyzer
from helios.analyzers.file_type_verifier import FileTypeVerifierAnalyzer
from helios.analyzers.lnk_jumplists import LnkJumpListAnalyzer
from helios.analyzers.prefetch import PrefetchAnalyzer
from helios.analyzers.shellbags import ShellBagsAnalyzer
from helios.analyzers.usb_history import UsbHistoryAnalyzer
from helios.models import Device, DeviceType, ScanOptions


def test_analyzer_instantiations():
    Device(device_type=DeviceType.PC, device_name="TestPC", serial_number="SERIAL123")

    event_logs = EventLogsAnalyzer()
    lnk = LnkJumpListAnalyzer()
    pf = PrefetchAnalyzer()
    sb = ShellBagsAnalyzer()
    ftv = FileTypeVerifierAnalyzer()

    assert event_logs.name() == "Windows Event Logs Analyzer"
    assert lnk.name() == "LNK & Jump Lists Analyzer"
    assert pf.name() == "Prefetch Execution Analyzer"
    assert sb.name() == "ShellBags Folder Access Analyzer"
    assert ftv.name() == "Magic Bytes File Extension Mismatch Verifier"


def test_usb_history_collect_skips_inaccessible_paths(tmp_path, monkeypatch):
    """Registry hives that raise WinError 5 on stat() must be skipped, not crash."""

    def raise_denied(self, *args, **kwargs):
        raise PermissionError(5, "Access is denied", str(args[0]) if args else "")

    monkeypatch.setattr(Path, "exists", raise_denied)
    monkeypatch.setattr(Path, "is_file", raise_denied)

    analyzer = UsbHistoryAnalyzer()
    device = Device(device_type=DeviceType.PC, device_name="TestPC", serial_number="SERIAL123")
    artifacts = analyzer.collect(device)
    assert artifacts == []


def test_usb_history_can_run_requires_evidence_paths_offline():
    """On non-Windows hosts, USB history must only run when evidence paths
    were supplied — the old always-True branch was dead code."""
    assert UsbHistoryAnalyzer().can_run() is False
    assert UsbHistoryAnalyzer(scan_options=ScanOptions(paths=["/evidence"])).can_run() is True


def test_usb_history_analyze_parses_setupapi_log(tmp_path):
    from datetime import datetime

    from helios.analyzers.base import RawArtifact
    from helios.models import EventType

    log = tmp_path / "setupapi.dev.log"
    log.write_text(
        ">>>  [Device Install (Hardware initiated) - USB\\VID_0951&PID_1666]\n"
        ">>>  Section start 2023/10/05 14:32:01.123\n"
        "     cmd: \"C:\\Windows\\system32\\usbinst.dll\"\n"
        "<<<  Section end 2023/10/05 14:32:05.000\n",
        encoding="utf-8",
    )
    artifact = RawArtifact(
        artifact_id="usb-1",
        artifact_type="log",
        source_path=log,
        device_id="PC-1",
        collected_at=datetime.now(),
    )

    from datetime import datetime, timezone

    events = UsbHistoryAnalyzer().analyze([artifact])
    assert len(events) == 1
    assert events[0].event_type == EventType.USB_CONNECT
    # setupapi timestamps are machine-LOCAL time; Helios converts to UTC.
    naive_local = datetime(2023, 10, 5, 14, 32, 1)
    assert events[0].timestamp == naive_local.astimezone(timezone.utc)
    assert events[0].metadata["hardware_id"] == "USB\\VID_0951&PID_1666"


def test_usb_history_analyze_ignores_non_usb_artifacts(tmp_path):
    from datetime import datetime

    from helios.analyzers.base import RawArtifact

    plain = tmp_path / "notes.txt"
    plain.write_text("not a usb artifact", encoding="utf-8")
    artifact = RawArtifact(
        artifact_id="usb-2",
        artifact_type="registry",
        source_path=plain,
        device_id="PC-1",
        collected_at=datetime.now(),
    )

    assert UsbHistoryAnalyzer().analyze([artifact]) == []


def test_suspicious_detector_handles_mixed_naive_aware_timestamps():
    from datetime import datetime, timezone

    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer
    from helios.models import Confidence, DataEvent, EventType

    rules = {
        "mass_deletion": {
            "enabled": True,
            "threshold_count": 2,
            "time_window_minutes": 5,
        },
        "after_hours_usb": {
            "enabled": True,
        },
    }
    detector = SuspiciousDetectorAnalyzer(config={"rules": rules})

    # Mix of naive and UTC-aware timestamps
    naive_dt = datetime(2026, 8, 18, 14, 0, 0)
    aware_dt = datetime(2026, 8, 18, 14, 1, 0, tzinfo=timezone.utc)

    events = [
        DataEvent(
            timestamp=naive_dt,
            event_type=EventType.FILE_DELETE,
            source_device="DEV-1",
            source_path=r"C:\test1.docx",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=aware_dt,
            event_type=EventType.FILE_DELETE,
            source_device="DEV-1",
            source_path=r"C:\test2.docx",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=datetime(2026, 8, 18, 22, 30, 0),  # After hours
            event_type=EventType.USB_CONNECT,
            source_device="DEV-1",
            source_path="E:",
            confidence=Confidence.HIGH,
        ),
    ]

    alerts = detector.analyze_events(events, working_hours={"start": "09:00", "end": "17:00"})
    assert len(alerts) >= 1
    # Ensure no TypeError was raised and mass deletion / after-hours alerts were generated
    alert_categories = [a.category for a in alerts]
    assert "Mass Deletion" in alert_categories or "After-Hours Activity" in alert_categories


def test_usb_history_graceful_on_missing_registry_package(tmp_path):
    """Offline parsing must fail cleanly when Registry package is not available or file is locked."""
    from datetime import datetime, timezone
    from helios.analyzers.base import RawArtifact
    from helios.analyzers.usb_history import UsbHistoryAnalyzer

    analyzer = UsbHistoryAnalyzer()
    dummy_hive = tmp_path / "SYSTEM"
    dummy_hive.write_bytes(b"dummy corrupted hive")

    artifact = RawArtifact(
        artifact_id="test_reg",
        artifact_type="registry",
        source_path=dummy_hive,
        device_id="DEV-PC",
        collected_at=datetime.now(timezone.utc),
    )
    events = analyzer.analyze([artifact])
    # Must not raise an unhandled exception
    assert isinstance(events, list)


def test_report_generator_segregates_deletions_from_transfers():
    """Deleted files in correlation chains must be routed to deletions list, not transfers."""
    from datetime import datetime, timezone

    from helios.models import Device, DeviceType
    from helios.reporting.report_generator import build_movement_rows

    dev = Device(device_id="DEV-PC", device_name="DeathStar", device_type=DeviceType.PC)

    correlations = [
        {
            "file_name": "X.pdf",
            "sha256_hash": "abc1234",
            "source_device": "DEV-PC",
            "target_devices": ["RecycleBin"],
            "event_type": "FILE_DELETE",
            "hops": [(datetime(2026, 8, 17, 19, 46, 18, tzinfo=timezone.utc), "DEV-PC", "RecycleBin", "deleted")],
        },
        {
            "file_name": "TransferredDoc.docx",
            "sha256_hash": "def5678",
            "source_device": "DEV-PC",
            "target_devices": ["USB-DRIVE"],
            "event_type": "FILE_COPY",
            "hops": [(datetime(2026, 8, 17, 18, 0, 0, tzinfo=timezone.utc), "DEV-PC", "USB-DRIVE", "copied")],
        },
    ]

    transfers, deletions = build_movement_rows(correlations, [dev], events=[])

    assert len(transfers) == 1
    assert transfers[0]["file_name"] == "TransferredDoc.docx"
    assert transfers[0]["target"] == "USB-DRIVE"

    assert len(deletions) == 1
    assert deletions[0]["file_name"] == "X.pdf"
    assert deletions[0]["target"] == "RecycleBin"


