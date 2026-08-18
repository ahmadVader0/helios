"""
Unit tests for strict HTML report profile isolation.

Validates that each investigation profile renders ONLY the sections, tables,
and metrics promised by that scan type, without leaking disabled module data.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from helios.config import load_config
from helios.models import (
    Alert,
    Confidence,
    DataEvent,
    Device,
    DeviceType,
    DriveInfo,
    DriveType,
    EventType,
    FileRecord,
    Investigation,
    RecoveryStatus,
    Severity,
)
from helios.reporting.report_generator import ReportGenerator

_PROFILE_MODULE_RESULTS = {
    "exfiltration": [
        {"key": "usb_transfers", "status": "ran", "label": "USB History", "events": 1, "alerts": 0},
        {"key": "file_deletions", "status": "ran", "label": "Recycle Bin", "events": 1, "alerts": 0},
        {"key": "cross_device_matching", "status": "ran", "label": "Correlator", "events": 1, "alerts": 1},
        {"key": "suspicious_files", "status": "ran", "label": "Suspicious Detector", "events": 0, "alerts": 0},
        {"key": "program_execution", "status": "disabled", "label": "Prefetch", "events": 0, "alerts": 0},
        {"key": "event_logs", "status": "disabled", "label": "Event Logs", "events": 0, "alerts": 0},
        {"key": "recent_file_access", "status": "disabled", "label": "LNK", "events": 0, "alerts": 0},
        {"key": "deleted_file_recovery", "status": "disabled", "label": "SleuthKit", "events": 0, "alerts": 0},
    ],
    "employee_exit": [
        {"key": "usb_transfers", "status": "ran", "label": "USB History", "events": 1, "alerts": 0},
        {"key": "file_deletions", "status": "ran", "label": "Recycle Bin", "events": 1, "alerts": 0},
        {"key": "recent_file_access", "status": "ran", "label": "LNK / JumpLists", "events": 1, "alerts": 0},
        {"key": "shellbags", "status": "ran", "label": "ShellBags", "events": 1, "alerts": 0},
        {"key": "deleted_file_recovery", "status": "ran", "label": "SleuthKit", "events": 0, "alerts": 0},
        {"key": "suspicious_files", "status": "ran", "label": "Suspicious Detector", "events": 0, "alerts": 0},
        {"key": "cross_device_matching", "status": "ran", "label": "Correlator", "events": 1, "alerts": 1},
        {"key": "program_execution", "status": "disabled", "label": "Prefetch", "events": 0, "alerts": 0},
        {"key": "event_logs", "status": "disabled", "label": "Event Logs", "events": 0, "alerts": 0},
    ],
    "incident_response": [
        {"key": "program_execution", "status": "ran", "label": "Prefetch Execution", "events": 1, "alerts": 0},
        {"key": "event_logs", "status": "ran", "label": "Event Logs", "events": 1, "alerts": 0},
        {"key": "shellbags", "status": "ran", "label": "ShellBags", "events": 1, "alerts": 0},
        {"key": "file_deletions", "status": "ran", "label": "Recycle Bin", "events": 1, "alerts": 0},
        {"key": "deleted_file_recovery", "status": "ran", "label": "SleuthKit", "events": 0, "alerts": 0},
        {"key": "suspicious_files", "status": "ran", "label": "Suspicious Detector", "events": 0, "alerts": 0},
        {"key": "usb_transfers", "status": "disabled", "label": "USB History", "events": 0, "alerts": 0},
        {"key": "cross_device_matching", "status": "disabled", "label": "Correlator", "events": 0, "alerts": 0},
        {"key": "recent_file_access", "status": "disabled", "label": "LNK", "events": 0, "alerts": 0},
    ],
    "full": [
        {"key": "usb_transfers", "status": "ran", "label": "USB History", "events": 1, "alerts": 0},
        {"key": "file_deletions", "status": "ran", "label": "Recycle Bin", "events": 1, "alerts": 0},
        {"key": "recent_file_access", "status": "ran", "label": "LNK / JumpLists", "events": 1, "alerts": 0},
        {"key": "event_logs", "status": "ran", "label": "Event Logs", "events": 1, "alerts": 0},
        {"key": "program_execution", "status": "ran", "label": "Prefetch Execution", "events": 1, "alerts": 0},
        {"key": "shellbags", "status": "ran", "label": "ShellBags", "events": 1, "alerts": 0},
        {"key": "deleted_file_recovery", "status": "ran", "label": "SleuthKit", "events": 0, "alerts": 0},
        {"key": "suspicious_files", "status": "ran", "label": "Suspicious Detector", "events": 0, "alerts": 0},
        {"key": "cross_device_matching", "status": "ran", "label": "Correlator", "events": 1, "alerts": 1},
    ],
}


def _build_test_investigation(profile_name: str) -> Investigation:
    pc = Device(
        device_id="DEV-PC",
        device_type=DeviceType.PC,
        device_name="Workstation-01",
        serial_number="PC-SN-1234",
    )
    usb = Device(
        device_id="DEV-USB",
        device_type=DeviceType.USB,
        device_name="Kingston USB",
        serial_number="USB-SN-9999",
    )
    drive_c = DriveInfo(
        drive_letter="C:",
        label="Windows",
        filesystem="NTFS",
        total_size=500 * (1024**3),
        free_space=250 * (1024**3),
        is_removable=False,
        drive_type=DriveType.HDD,
    )
    drive_e = DriveInfo(
        drive_letter="E:",
        label="External",
        filesystem="FAT32",
        total_size=64 * (1024**3),
        free_space=32 * (1024**3),
        is_removable=True,
        drive_type=DriveType.USB,
    )

    now = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)

    events = [
        DataEvent(
            timestamp=now,
            event_type=EventType.USB_CONNECT,
            source_device="DEV-PC",
            source_path="E:",
            raw_source="SetupAPI",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.FILE_ACCESS,
            source_device="DEV-PC",
            source_path=r"C:\Users\Admin\Documents\confidential.docx",
            raw_source="LECmd",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.APP_EXECUTE,
            source_device="DEV-PC",
            source_path=r"C:\Windows\System32\cmd.exe",
            raw_source="PECmd",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.FILE_ACCESS,
            source_device="DEV-PC",
            source_path=r"C:\Users\Admin\Downloads",
            raw_source="SBECmd",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.DEVICE_CONNECT,
            source_device="DEV-PC",
            source_path="EventID: 20001",
            raw_source="python-evtx",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.FILE_COPY,
            source_device="DEV-PC",
            source_path=r"C:\Secret\finances.xlsx",
            destination_path=r"E:\finances.xlsx",
            file_hash="abcd1234efgh5678",
            raw_source="Cross-Device Matching",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=now,
            event_type=EventType.FILE_DELETE,
            source_device="DEV-PC",
            source_path=r"C:\Secret\finances.xlsx",
            raw_source="Recycle Bin",
            confidence=Confidence.HIGH,
        ),
    ]

    files = [
        FileRecord(
            file_path=r"C:\Secret\finances.xlsx",
            file_name="finances.xlsx",
            size=10240,
            extension="xlsx",
            sha256_hash="abcd1234efgh5678",
            created=now,
            modified=now,
        ),
        FileRecord(
            file_path=r"C:\Secret\deleted_plan.pdf",
            file_name="deleted_plan.pdf",
            size=2048,
            extension="pdf",
            sha256_hash="9999888877776666",
            created=now,
            modified=now,
            is_deleted=True,
            recovery_status=RecoveryStatus.RECOVERABLE,
        ),
    ]

    alerts = [
        Alert(
            severity=Severity.CRITICAL,
            category="Exfiltration",
            title="Sensitive Document Transferred to USB",
            description="finances.xlsx was copied to E: then deleted from source",
            evidence=[r"C:\Secret\finances.xlsx"],
            device="DEV-PC",
            timestamp=now,
            confidence=Confidence.HIGH,
        )
    ]

    correlations = [
        {
            "file_name": "finances.xlsx",
            "sha256_hash": "abcd1234efgh5678",
            "source_device": "DEV-PC",
            "target_devices": ["DEV-USB"],
            "event_type": "FILE_COPY",
            "timestamp": now,
        }
    ]

    return Investigation(
        case_name=f"Test-Case-{profile_name}",
        investigator="Ahmad",
        profile_name=profile_name,
        devices=[pc, usb],
        drives_scanned=[drive_c, drive_e],
        events=events,
        file_records=files,
        alerts=alerts,
        correlations=correlations,
        module_results=_PROFILE_MODULE_RESULTS.get(profile_name, []),
    )


def test_exfiltration_report_strictness(tmp_path: Path):
    inv = _build_test_investigation("exfiltration")
    config = load_config()
    gen = ReportGenerator(inv, config)
    out_file = tmp_path / "exfil_report.html"
    gen.generate_html_report(out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Exfiltration promises: Data Movement, File Transfers, USB connections, Exfil alerts
    assert "Exfiltration Summary" in content
    assert "File Transfers (Cross-Device Match)" in content
    assert "Exfiltration Deletions" in content

    # Should NOT contain disabled module cards:
    assert "Recovered Deleted Files (SleuthKit)" not in content
    assert "Executed Programs (Prefetch" not in content
    assert "Windows Event Logs &amp; Sigma" not in content


def test_employee_exit_report_strictness(tmp_path: Path):
    inv = _build_test_investigation("employee_exit")
    config = load_config()
    gen = ReportGenerator(inv, config)
    out_file = tmp_path / "exit_report.html"
    gen.generate_html_report(out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Employee Exit promises: Recently Accessed Files (LNK), ShellBags, Transfers, Deleted Files
    assert "Exit Review Summary" in content
    assert "Recently Accessed Files (LNK / JumpLists)" in content
    assert "Folder Browsing History (ShellBags)" in content
    assert "Recovered Deleted Files" in content

    # Should NOT contain disabled modules:
    assert "Executed Programs (Prefetch" not in content
    assert "Windows Event Logs &amp; Sigma" not in content


def test_incident_response_report_strictness(tmp_path: Path):
    inv = _build_test_investigation("incident_response")
    config = load_config()
    gen = ReportGenerator(inv, config)
    out_file = tmp_path / "ir_report.html"
    gen.generate_html_report(out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Incident Response promises: Executed Programs, Windows Event Logs & Sigma, Shift+Deleted Files
    assert "Incident Response Summary" in content
    assert "Executed Programs (Prefetch" in content
    assert "Windows Event Logs &amp; Sigma" in content
    assert "Recovered Shift+Deleted Files" in content

    # Should NOT contain disabled modules:
    assert "data-panel=\"tab-movement\"" not in content
    assert "Recently Accessed Files (LNK / JumpLists)" not in content


def test_full_report_contains_all_available_modules(tmp_path: Path):
    inv = _build_test_investigation("full")
    config = load_config()
    gen = ReportGenerator(inv, config)
    out_file = tmp_path / "full_report.html"
    gen.generate_html_report(out_file)

    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")

    # Full report should contain all summary and movement sections
    assert "Executive Summary" in content
    assert "Data Movement" in content
    assert "Timeline &amp; Activity" in content
    assert "Security Alerts" in content
    assert "Evidence &amp; Chain of Custody" in content
