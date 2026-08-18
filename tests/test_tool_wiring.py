"""
Unit tests for the automatic external-tool wiring inside analyzers.

External binaries are never executed; adapter behaviors are faked with
SimpleNamespace stand-ins, per the project testing convention.
"""

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace


from helios.analyzers.event_logs import EventLogsAnalyzer
from helios.analyzers.file_type_verifier import FileTypeVerifierAnalyzer
from helios.analyzers.prefetch import PrefetchAnalyzer
from helios.analyzers.recycle_bin import RecycleBinAnalyzer
from helios.analyzers.shellbags import ShellBagsAnalyzer
from helios.analyzers.base import RawArtifact
from helios.models import Alert, EventType, FileRecord, ScanOptions, Severity
from helios.pipeline import _resolve_fls_source


def make_artifact(source_path: Path, artifact_type: str = "evtx", device_id: str = "dev-1") -> RawArtifact:
    return RawArtifact(
        artifact_id="art-1",
        artifact_type=artifact_type,
        source_path=source_path,
        device_id=device_id,
        collected_at=datetime.now(),
    )


def make_file_record(path: Path, extension: str) -> FileRecord:
    return FileRecord(
        file_path=str(path),
        file_name=path.name,
        extension=extension,
        size=path.stat().st_size,
        source_device="dev-1",
    )


def test_event_logs_chainsaw_sigma_alerts(tmp_path, monkeypatch):
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"\x00\x01")
    artifact = make_artifact(evtx_file)

    fake_finding = Alert(
        severity=Severity.HIGH,
        category="Event Log Anomaly",
        title="Failed Logons",
        description="Brute-force pattern detected",
        evidence=["EventID 4625"],
    )
    fake_chainsaw = SimpleNamespace(
        is_available=lambda: True,
        run_sigma_hunt=lambda evtx_dir, rules_dir, out_json: [fake_finding],
    )

    def fake_get_bundle_root() -> Path:
        rules = tmp_path / "sigma_rules"
        rules.mkdir(exist_ok=True)
        return tmp_path

    monkeypatch.setattr("helios.config.get_bundle_root", fake_get_bundle_root)

    analyzer = EventLogsAnalyzer()
    analyzer.chainsaw_adapter = fake_chainsaw

    events = analyzer.analyze([artifact])
    assert events == []
    assert any(
        a.title == "Failed Logons"
        and a.severity == Severity.HIGH
        and str(evtx_file) in a.evidence
        for a in analyzer.alerts
    )


def test_event_logs_chainsaw_skipped_when_unavailable(tmp_path):
    evtx_file = tmp_path / "System.evtx"
    evtx_file.write_bytes(b"\x00\x01")
    artifact = make_artifact(evtx_file)

    analyzer = EventLogsAnalyzer()
    analyzer.chainsaw_adapter = SimpleNamespace(is_available=lambda: False)
    analyzer.analyze([artifact])
    assert analyzer.alerts == []


def test_file_type_verifier_exiftool_mismatch(tmp_path, monkeypatch):
    fake_file = tmp_path / "report.doc"
    fake_file.write_bytes(b"plain text with no magic signature")
    record = make_file_record(fake_file, ".doc")

    fake_exiftool = SimpleNamespace(
        get_file_type=lambda path: ("txt", {"MIMEType": "text/plain"}),
    )

    analyzer = FileTypeVerifierAnalyzer()
    analyzer.exiftool = fake_exiftool

    artifact = RawArtifact(
        artifact_id="art-2",
        artifact_type="FILE_RECORD",
        source_path=fake_file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data={"file_record": record},
    )

    alerts = analyzer.analyze([artifact])
    assert len(alerts) == 1
    assert "exiftool" in alerts[0].description


def test_file_type_verifier_exiftool_alias_not_flagged(tmp_path, monkeypatch):
    fake_file = tmp_path / "photo.jpeg"
    fake_file.write_bytes(b"not a real jpeg but exiftool says so")
    record = make_file_record(fake_file, ".jpeg")

    analyzer = FileTypeVerifierAnalyzer()
    analyzer.exiftool = SimpleNamespace(get_file_type=lambda path: ("jpg", {}))

    artifact = RawArtifact(
        artifact_id="art-3",
        artifact_type="FILE_RECORD",
        source_path=fake_file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data={"file_record": record},
    )
    assert analyzer.analyze([artifact]) == []


def test_file_type_verifier_uses_single_batched_exiftool_call(tmp_path):
    """Unresolved files must be verified in ONE batched exiftool pass,
    never one subprocess per file (that made live scans crawl)."""
    from helios.analyzers.file_type_verifier import FileTypeVerifierAnalyzer

    calls = []

    def fake_get_file_types(paths):
        calls.append(list(paths))
        return {str(p): ("txt", {"MIMEType": "text/plain"}) for p in paths}

    analyzer = FileTypeVerifierAnalyzer()
    analyzer.exiftool = SimpleNamespace(get_file_types=fake_get_file_types)

    artifacts = []
    for i in range(5):
        f = tmp_path / f"report{i}.doc"
        f.write_bytes(b"plain text, no magic signature")
        record = make_file_record(f, ".doc")
        artifacts.append(RawArtifact(
            artifact_id=f"art-b{i}",
            artifact_type="FILE_RECORD",
            source_path=f,
            device_id="dev-1",
            collected_at=datetime.now(),
            raw_data=record,
        ))

    alerts = analyzer.analyze(artifacts)
    assert len(calls) == 1, "Expected exactly one batched exiftool invocation"
    assert len(calls[0]) == 5
    assert len(alerts) == 5
    assert all("exiftool" in a.description for a in alerts)


def test_prefetch_pecmd_enrichment(tmp_path, monkeypatch):
    pf_dir = tmp_path / "Prefetch"
    pf_dir.mkdir()
    pf_file = pf_dir / "NOTEPAD.EXE-1A2B3C4D.pf"
    pf_file.write_bytes(b"\x00")
    artifact = make_artifact(pf_file, artifact_type="PrefetchFile")
    artifact.metadata["filename"] = "NOTEPAD.EXE-1A2B3C4D.pf"

    fake_ez = SimpleNamespace(
        run_pecmd=lambda prefetch_dir, csv_dir: [
            {
                "FileName": "NOTEPAD.EXE-1A2B3C4D.pf",
                "RunCount": "17",
                "LastRunTime": "2026-07-01 09:30:00",
            }
        ],
    )

    analyzer = PrefetchAnalyzer()
    analyzer.ez_tools = fake_ez
    monkeypatch.setattr(
        analyzer,
        "_parse_prefetch",
        lambda pf_path: {
            "executable_name": "NOTEPAD.EXE",
            "run_count": 3,
            "execution_timestamps": [datetime(2026, 1, 1, 10, 0, 0)],
            "referenced_files": [],
            "referenced_directories": [],
        },
    )

    events = analyzer.analyze([artifact])
    assert len(events) == 1
    assert events[0].metadata["run_count"] == 17
    assert events[0].metadata["tool"] == "PECmd"
    assert events[0].timestamp == datetime(2026, 7, 1, 9, 30, 0, tzinfo=timezone.utc)


def test_prefetch_builtin_fallback_without_pecmd(tmp_path, monkeypatch):
    pf_file = tmp_path / "WINWORD.EXE-4E2B9F0A.pf"
    pf_file.write_bytes(b"\x00")
    artifact = make_artifact(pf_file, artifact_type="PrefetchFile")
    artifact.metadata["filename"] = "WINWORD.EXE-4E2B9F0A.pf"

    analyzer = PrefetchAnalyzer()
    analyzer.ez_tools = SimpleNamespace(run_pecmd=lambda d, o: [])

    monkeypatch.setattr(
        analyzer,
        "_parse_prefetch",
        lambda pf_path: {
            "executable_name": "WINWORD.EXE",
            "run_count": 5,
            "execution_timestamps": [datetime(2026, 1, 1, 10, 0, 0)],
            "referenced_files": [],
            "referenced_directories": [],
        },
    )

    events = analyzer.analyze([artifact])
    assert len(events) == 1
    assert events[0].metadata["run_count"] == 5
    assert events[0].metadata["tool"] == "Built-in parser"


def test_recycle_bin_rbcmd_events(tmp_path, monkeypatch):
    sid_dir = tmp_path / "$Recycle.Bin" / "S-1-5-21-123"
    sid_dir.mkdir(parents=True)
    i_file = sid_dir / "$I1234567.txt"
    i_file.write_bytes(b"\x00" * 32)
    artifact = make_artifact(i_file, artifact_type="recycle_bin_i")

    fake_ez = SimpleNamespace(
        run_rbcmd=lambda rb_root, csv_dir: [
            {
                "FileName": "secret_notes.txt",
                "FileSize": "4096",
                "DeletedTime": "2026-05-10 14:20:00",
                "Directory": "C:\\Users\\alice\\Desktop",
                "SID": "S-1-5-21-123",
                "Drive": "C:",
            }
        ],
    )

    analyzer = RecycleBinAnalyzer()
    analyzer.ez_tools = fake_ez
    monkeypatch.setattr(analyzer, "_parse_i_file", lambda artifact: None)

    events = analyzer.analyze([artifact])
    assert len(events) == 1
    assert events[0].event_type == EventType.FILE_DELETE
    assert events[0].source_path == "C:\\Users\\alice\\Desktop\\secret_notes.txt"
    assert events[0].metadata["tool"] == "RBCmd"
    assert events[0].metadata["user_sid"] == "S-1-5-21-123"


def test_shellbags_sbecmd_events(tmp_path, monkeypatch):
    hive = tmp_path / "NTUSER.DAT"
    hive.write_bytes(b"\x00" * 64)
    artifact = make_artifact(hive, artifact_type="RegistryHive")
    artifact.metadata["user"] = "alice"

    fake_ez = SimpleNamespace(
        run_sbecmd=lambda hive_path, csv_dir: [
            {
                "FolderPath": "D:\\Projects",
                "Created0x10": "2026-04-01 08:00:00",
                "LastModified0x30": "2026-04-15 18:45:00",
                "LastAccessed0x20": "2026-04-15 18:45:00",
                "Volume": "D:",
            }
        ],
    )

    analyzer = ShellBagsAnalyzer()
    analyzer.ez_tools = fake_ez

    events = analyzer.analyze([artifact])
    assert len(events) == 1
    assert events[0].metadata["folder_path"] == "D:\\Projects"
    assert events[0].metadata["tool"] == "SBECmd"
    assert events[0].timestamp == datetime(2026, 4, 15, 18, 45, 0, tzinfo=timezone.utc)


def test_resolve_fls_source_from_image_path(tmp_path):
    image = tmp_path / "evidence.dd"
    image.write_bytes(b"\x00" * 1024)

    drive = SimpleNamespace(drive_letter="/media/evidence")
    scan_options = ScanOptions(paths=[str(image)])

    assert _resolve_fls_source(drive, scan_options) == str(image)


def test_resolve_fls_source_returns_none_without_sources(tmp_path):
    drive = SimpleNamespace(drive_letter=str(tmp_path / "missing"))
    assert _resolve_fls_source(drive, ScanOptions(paths=[])) is None


def test_block_device_mount_mapping_is_safe():
    from helios.pipeline import _block_device_for_mount

    result = _block_device_for_mount(Path("/nonexistent-mount-xyz"))
    assert result is None or result.startswith("/dev/")


def test_sleuthkit_env_ld_library_path(tmp_path, monkeypatch):
    from helios.adapters.sleuthkit_adapter import SleuthKitAdapter

    lib_dir = tmp_path / "linux64" / "lib"
    lib_dir.mkdir(parents=True)

    monkeypatch.setattr(
        "helios.adapters.sleuthkit_adapter._bundle_linux_lib_dir",
        lambda: lib_dir,
    )

    sk = SleuthKitAdapter(config={})
    env = sk._env()
    assert env is not None
    assert lib_dir.as_posix() in env["LD_LIBRARY_PATH"]

    monkeypatch.setattr(
        "helios.adapters.sleuthkit_adapter._bundle_linux_lib_dir",
        lambda: None,
    )
    assert sk._env() is None


def test_bundled_tools_layout():
    """Guard the curated tool bundle layout shipped with Helios."""
    tools_dir = Path(__file__).resolve().parent.parent / "tools"

    for expected in (
        tools_dir / "LECmd.exe",
        tools_dir / "JLECmd.exe",
        tools_dir / "PECmd.exe",
        tools_dir / "RBCmd.exe",
        tools_dir / "SBECmd.exe",
        tools_dir / "chainsaw.exe",
        tools_dir / "adb.exe",
        tools_dir / "exiftool.exe",
        tools_dir / "exiftool_files",
        tools_dir / "fls.exe",
        tools_dir / "fsstat.exe",
        tools_dir / "fls",
        tools_dir / "exiftool",
        tools_dir / "lib",
        tools_dir / "sigma_rules",
    ):
        assert expected.exists(), f"Missing bundled tool: {expected}"

    assert list((tools_dir / "sigma_rules").glob("*.yml")), "No Sigma rules bundled"
    assert list((tools_dir / "linux64" / "lib").glob("*.so*")), "No Linux TSK shared libs"

    # Deleted tool bundles must stay deleted (dead code sweep)
    for removed in ("MFTECmd.exe", "icat.exe", "mmls.exe", "icat", "mmls"):
        assert not (tools_dir / removed).exists(), f"Stale bundled tool: {removed}"


def test_suspicious_detector_flags_vbs_in_user_content(tmp_path):
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer

    file = tmp_path / "invoice.pdf.vbs"
    file.write_bytes(b"MZ" + b"\x90" * 64)
    record = make_file_record(file, ".vbs")
    artifact = RawArtifact(
        artifact_id="art-s1",
        artifact_type="FILE_RECORD",
        source_path=file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data=record,
    )

    alerts = SuspiciousDetectorAnalyzer(config={}).analyze([artifact])
    titles = [a.title for a in alerts]
    assert "Script Extension Masks a Compiled Binary" in titles
    assert any(a.severity == Severity.HIGH for a in alerts)


def test_suspicious_detector_flags_double_extension_script(tmp_path):
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer

    file = tmp_path / "photo.jpg.bat"
    file.write_bytes(b"@echo off\n")
    record = make_file_record(file, ".bat")
    artifact = RawArtifact(
        artifact_id="art-s2",
        artifact_type="FILE_RECORD",
        source_path=file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data=record,
    )

    alerts = SuspiciousDetectorAnalyzer(config={}).analyze([artifact])
    assert any("Double Extension" in a.title for a in alerts)


def test_suspicious_detector_ignores_benign_script(tmp_path):
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer

    file = tmp_path / "cleanup.cmd"
    file.write_text("echo ok\n")
    record = make_file_record(file, ".cmd")
    record.file_path = r"C:\Windows\System32\cleanup.cmd"  # benign system location
    record.file_name = "cleanup.cmd"
    artifact = RawArtifact(
        artifact_id="art-s3",
        artifact_type="FILE_RECORD",
        source_path=file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data=record,
    )

    alerts = SuspiciousDetectorAnalyzer(config={}).analyze([artifact])
    assert alerts == []


def test_suspicious_detector_flags_bat_outside_system_dirs(tmp_path):
    """A .bat sitting outside system dirs (e.g. scan root, USB, user folder)
    must be flagged as a warning."""
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer

    file = tmp_path / "test.bat"
    file.write_text("@echo off\n")
    record = make_file_record(file, ".bat")
    record.file_path = r"C:\Users\alice\test.bat"
    record.file_name = "test.bat"
    artifact = RawArtifact(
        artifact_id="art-s4",
        artifact_type="FILE_RECORD",
        source_path=file,
        device_id="dev-1",
        collected_at=datetime.now(),
        raw_data=record,
    )

    alerts = SuspiciousDetectorAnalyzer(config={}).analyze([artifact])
    assert any("Script File Outside System Directories" in a.title for a in alerts)


def test_correlator_flags_exfiltration_to_usb():
    from datetime import timedelta

    from helios.core.correlator import CrossDeviceCorrelator
    from helios.models import Device, DeviceType, Investigation

    pc = Device(device_type=DeviceType.PC, device_name="Workstation", device_id="PC-1")
    usb = Device(device_type=DeviceType.USB, device_name="USB-DRIVE", device_id="USB-1")
    inv = Investigation(case_name="t", devices=[pc, usb])
    inv.file_records = [
        FileRecord(
            file_path="/c/doc/secret.pdf",
            file_name="secret.pdf",
            extension=".pdf",
            sha256_hash="H1",
            source_device="PC-1",
            created=datetime.now() - timedelta(hours=2),
        ),
        FileRecord(
            file_path="/mnt/usb/secret.pdf",
            file_name="secret.pdf",
            extension=".pdf",
            sha256_hash="H1",
            source_device="USB-1",
            created=datetime.now() - timedelta(hours=1),
        ),
    ]

    chains = CrossDeviceCorrelator(inv).match_files_by_hash()
    assert len(chains) == 1
    assert chains[0].source_device == "PC-1"
    assert chains[0].target_devices == ["USB-1"]
    assert chains[0].exfiltrated is True


def test_standard_fls_command_includes_p_flag():
    from helios.adapters.sleuthkit_adapter import SleuthKitAdapter
    sk = SleuthKitAdapter()
    # Intercept run_subprocess
    captured = []
    sk.run_subprocess = lambda cmd, timeout=300, env=None: captured.append(cmd) or SimpleNamespace(returncode=0, stdout="")
    sk.run_fls("/dev/sda1", recursive=True, deleted_only=True, mac_format=False)
    assert len(captured) == 1
    assert "-p" in captured[0]
    assert "-d" in captured[0]
    assert "-r" in captured[0]


def test_deleted_file_records_preserved_under_date_filtering():
    from datetime import datetime, timedelta
    from helios.models import FileRecord

    d_from = datetime.now() - timedelta(days=2)
    old_ts = datetime.now() - timedelta(days=365)

    rec1 = FileRecord(
        file_path="/c/old_deleted.txt",
        file_name="old_deleted.txt",
        created=old_ts,
        modified=old_ts,
        is_deleted=True,
    )
    rec2 = FileRecord(
        file_path="/c/old_active.txt",
        file_name="old_active.txt",
        created=old_ts,
        modified=old_ts,
        is_deleted=False,
    )

    # Test filtering condition directly
    def _ts_in_range(ts: datetime | None) -> bool:
        if ts is None:
            return True
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        if d_from and ts < d_from:
            return False
        return True

    records = [rec1, rec2]
    filtered = [
        f for f in records
        if getattr(f, "is_deleted", False)
        or _ts_in_range(getattr(f, "modified", None))
        or _ts_in_range(getattr(f, "created", None))
    ]

    assert rec1 in filtered  # Old deleted file MUST be preserved
    assert rec2 not in filtered  # Old active file is filtered out

