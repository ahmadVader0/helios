from datetime import datetime, timedelta

from helios.core.correlator import CrossDeviceCorrelator
from helios.models import (
    Device,
    DeviceType,
    FileRecord,
    Investigation,
)


def test_cross_device_correlator(tmp_path):
    dev_pc = Device(device_type=DeviceType.PC, device_name="Workstation", serial_number="PC01")
    dev_usb = Device(device_type=DeviceType.USB, device_name="KingstonUSB", serial_number="USB01")

    rec_pc = FileRecord(
        file_path="/C/docs/secret.pdf",
        file_name="secret.pdf",
        sha256_hash="ABCDEF1234567890",
        created=datetime.now() - timedelta(hours=2),
        source_device=dev_pc.device_id
    )

    rec_usb = FileRecord(
        file_path="/E/secret.pdf",
        file_name="secret.pdf",
        sha256_hash="ABCDEF1234567890",
        created=datetime.now() - timedelta(hours=1),
        source_device=dev_usb.device_id
    )

    inv = Investigation(
        case_name="Case-001",
        devices=[dev_pc, dev_usb],
        file_records=[rec_pc, rec_usb]
    )

    correlator = CrossDeviceCorrelator(inv)
    results = correlator.correlate()
    assert len(results) == 4
    assert correlator.movement_chains[0].file_name == "secret.pdf"


def test_profile_manager_fail_closed_for_unknown_profile():
    """An unknown/typo'd profile must NOT enable every module — it must
    disable them so the report never invents activity."""
    from helios.config import load_config
    from helios.core.investigation import ProfileManager

    mgr = ProfileManager(load_config().investigation_profiles or {})
    assert mgr.enabled_modules("not-a-real-profile") == []


def test_profile_manager_full_profile_enables_everything():
    from helios.config import load_config
    from helios.core.investigation import ProfileManager

    mgr = ProfileManager(load_config().investigation_profiles or {})
    enabled = mgr.enabled_modules("full")
    for module in ("helios.analyzers.usb_history", "helios.analyzers.recycle_bin",
                   "helios.analyzers.lnk_jumplists", "helios.analyzers.event_logs",
                   "helios.analyzers.prefetch", "helios.analyzers.shellbags",
                   "helios.adapters.sleuthkit_adapter", "helios.analyzers.suspicious_detector",
                   "helios.core.correlator"):
        assert module in enabled


def test_keyword_search_engine_finds_name_and_content(tmp_path):
    from helios.core.keyword_search import KeywordSearchEngine

    hit = tmp_path / "passwords.txt"
    hit.write_text("The backup archive contains exfiltration data.\n", encoding="utf-8")
    rec = FileRecord(
        file_path=str(hit),
        file_name="passwords.txt",
        extension=".txt",
        size=hit.stat().st_size,
        source_device="PC-1",
    )

    inv = Investigation(case_name="k", investigator="t", file_records=[rec])
    matches = KeywordSearchEngine().search(inv, keywords=["exfiltration"], search_content=True)
    assert len(matches) == 1
    assert matches[0].file_name == "passwords.txt"
    assert matches[0].match_type in ("content", "name")
    assert "exfiltration" in matches[0].match_context.lower()
    assert isinstance(matches[0].to_dict(), dict)


def test_keyword_search_engine_skips_binary_content(tmp_path):
    from helios.core.keyword_search import KeywordSearchEngine

    binary = tmp_path / "photo.jpg"
    binary.write_bytes(b"\xff\xd8\xff\xe0exfiltration" * 100)
    rec = FileRecord(
        file_path=str(binary),
        file_name="photo.jpg",
        extension=".jpg",
        size=binary.stat().st_size,
        source_device="PC-1",
    )

    inv = Investigation(case_name="k", investigator="t", file_records=[rec])
    matches = KeywordSearchEngine().search(inv, keywords=["exfiltration"], search_content=True)
    assert matches == []  # media content is never opened


def test_keyword_search_engine_caps_hits_per_file(tmp_path):
    from helios.core.keyword_search import KeywordSearchEngine

    big = tmp_path / "log.txt"
    big.write_text(("exfiltration " * 500) + "\n", encoding="utf-8")
    rec = FileRecord(
        file_path=str(big),
        file_name="log.txt",
        extension=".txt",
        size=big.stat().st_size,
        source_device="PC-1",
    )

    inv = Investigation(case_name="k", investigator="t", file_records=[rec])
    matches = KeywordSearchEngine().search(inv, keywords=["exfiltration"], search_content=True)
    assert 0 < len(matches) <= 20
    assert all(m.line_number is not None for m in matches)


def test_profile_sections_from_module_log():
    from helios.reporting.report_generator import _profile_sections

    ran = {"key": "x", "status": "ran"}

    # Full profile: everything shown
    full = _profile_sections([
        {**ran, "key": "cross_device_matching"},
        {**ran, "key": "file_deletions"},
        {**ran, "key": "usb_transfers"},
    ], "full")
    assert full == {"transfers": True, "deletions": True, "data_movement": True, "deletion_chart": True}

    # Incident response: no cross-device matching -> no transfers section
    ir = _profile_sections([
        {**ran, "key": "file_deletions"},
        {**ran, "key": "event_logs"},
        {"key": "cross_device_matching", "status": "disabled"},
        {"key": "usb_transfers", "status": "disabled"},
    ], "incident_response")
    assert ir["transfers"] is False
    assert ir["deletions"] is True
    assert ir["data_movement"] is True

    # Disabled modules do not count as ran
    only_disabled = _profile_sections([
        {"key": "cross_device_matching", "status": "disabled"},
    ], "employee_exit")
    assert only_disabled["transfers"] is False

    # No module log (demo/legacy) -> show everything
    legacy = _profile_sections([], "")
    assert legacy == {"transfers": True, "deletions": True, "data_movement": True, "deletion_chart": True}


def test_alerts_table_includes_artifact_path():
    from helios.models import Alert, Confidence, Severity
    from helios.reporting.table_builder import HTMLTableBuilder

    alert = Alert(
        severity=Severity.HIGH,
        category="Obfuscation",
        title="Double Extension Detected",
        description="spoofed",
        evidence=["C:\\Users\\tester\\Downloads\\invoice.pdf.exe", "extra"],
        device="PC-1",
        timestamp=datetime.now(),
        confidence=Confidence.HIGH,
    )
    html = HTMLTableBuilder.build_alerts_table([alert])
    assert "Artifact Path" in html
    assert "invoice.pdf.exe" in html


def test_profile_template_resolution():
    from helios.reporting.report_generator import _resolve_template

    assert _resolve_template("exfiltration") == "exfiltration_report.html.j2"
    assert _resolve_template("employee_exit") == "employee_exit_report.html.j2"
    assert _resolve_template("incident_response") == "incident_response_report.html.j2"
    assert _resolve_template("full") == "full_report.html.j2"
    assert _resolve_template("") == "full_report.html.j2"
    assert _resolve_template(None) == "full_report.html.j2"


def test_build_event_rows_sorted_and_capped():
    from helios.models import Confidence, DataEvent, EventType
    from helios.reporting.report_generator import _build_event_rows

    events = [
        DataEvent(
            timestamp=datetime(2026, 8, 2, 10, 0, 0),
            event_type=EventType.USB_CONNECT,
            source_device="USB-1",
            source_path="",
            raw_source="EVTX",
            confidence=Confidence.HIGH,
        ),
        DataEvent(
            timestamp=datetime(2026, 8, 2, 9, 0, 0),
            event_type=EventType.FILE_COPY,
            source_device="PC-1",
            source_path="C:\\docs\\x.pdf",
            destination_path="E:\\x.pdf",
            raw_source="Live Filesystem Scanner",
            confidence=Confidence.MEDIUM,
        ),
    ]
    rows = _build_event_rows(events, max_rows=1)
    assert len(rows) == 1
    assert rows[0]["type"] == "USB_CONNECT"  # newest first
    assert rows[0]["timestamp"] == "2026-08-02 10:00:00"
    assert rows[0]["path"] == ""


def test_profile_report_renders_distinct_content(tmp_path):
    """Each profile template must render and stay distinct from the others."""
    from helios.demo import load_demo_investigation
    from helios.reporting.report_generator import ReportGenerator

    inv = load_demo_investigation()
    gen = ReportGenerator(inv, type("Cfg", (), {})())

    profiles = ["exfiltration", "employee_exit", "incident_response", "full"]
    rendered = {}
    for prof in profiles:
        inv.profile_name = prof
        path = gen.generate_html_report(tmp_path / f"{prof}.html")
        rendered[prof] = path.read_text(encoding="utf-8")

    # Each profile gets its own template with profile-specific branding
    assert "Exfiltration" in rendered["exfiltration"]
    assert "Employee Exit" in rendered["employee_exit"]
    assert "Incident Response" in rendered["incident_response"]
    assert "Full System Forensics" in rendered["full"]

    # The four reports are not byte-identical
    contents = set(rendered.values())
    assert len(contents) == 4

    # Incident response has no Data Movement tab (no USB/cross-device modules)
    assert 'data-panel="tab-movement"' not in rendered["incident_response"]
    assert 'data-panel="tab-movement"' in rendered["full"]

    # Event log table renders real event rows
    assert "Event Log" in rendered["full"]
    assert "<th>Event Type</th>" in rendered["full"]
