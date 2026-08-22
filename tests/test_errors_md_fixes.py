from __future__ import annotations

import inspect
import struct
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

from conftest import use_bundle_root

from helios.adapters.base import ToolRunResult, resolve_tool_binary
from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.adapters.exiftool_adapter import ExifToolAdapter
from helios.adapters.sleuthkit_adapter import SleuthKitAdapter
from helios.analyzers.base import RawArtifact
from helios.analyzers.file_type_verifier import FileTypeVerifierAnalyzer
from helios.analyzers.lnk_jumplists import LnkJumpListAnalyzer
from helios.analyzers.prefetch import PrefetchAnalyzer
from helios.analyzers.shellbags import ShellBagsAnalyzer
from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer
from helios.config import load_config
from helios.core.correlator import CrossDeviceCorrelator
from helios.core.hasher import hash_file
from helios.core.snapshot import Snapshot, SnapshotEngine
from helios.models import (
    DataEvent,
    Device,
    DeviceType,
    EventType,
    FileRecord,
    Investigation,
)
from helios.utils.ntfs import detect_timestomping


def test_resolve_tool_binary_bundle_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Adapters must resolve binaries in get_bundle_root() / 'tools'."""
    tools_dir = tmp_path / "tools"
    tools_dir.mkdir()
    fake_exe = tools_dir / "fls"
    fake_exe.write_text("#!/bin/sh\nexit 0")
    fake_exe.chmod(0o755)

    use_bundle_root(monkeypatch, tmp_path)

    found = resolve_tool_binary("fls")
    assert found is not None
    assert Path(found).resolve() == fake_exe.resolve()


def test_ez_tools_csv_glob_with_timestamp_prefix(tmp_path: Path) -> None:
    """EZToolsAdapter must pick up CSVs with {timestamp}_{Tool}_Output.csv filenames."""
    adapter = EZToolsAdapter()
    out_dir = tmp_path / "ez_out"
    out_dir.mkdir()

    csv_file = out_dir / "20260818221530_SBECmd_Output.csv"
    csv_file.write_text("AbsolutePath,AccessedOn\nC:\\Users\\Analyst\\Documents,2026-08-18 20:00:00\n", encoding="utf-8")

    rows = adapter._parse_csv(csv_file)
    assert len(rows) == 1
    assert rows[0]["AbsolutePath"] == "C:\\Users\\Analyst\\Documents"


def test_exiftool_path_normalization(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ExifToolAdapter must normalize path lookups for Windows/Unix paths."""
    adapter = ExifToolAdapter()
    sample_file = tmp_path / "doc.pdf"
    sample_file.write_bytes(b"%PDF-1.4 test")

    norm_path = str(sample_file.resolve())
    mock_json = f'[{{"SourceFile": "{norm_path}", "FileTypeExtension": "pdf", "FileType": "PDF"}}]'

    mock_run = MagicMock()
    mock_run.return_value = MagicMock(is_success=lambda: True, stdout=mock_json)
    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "run", mock_run)

    results = adapter.get_file_types([sample_file])
    assert str(sample_file) in results
    ext, _ = results[str(sample_file)]
    assert ext == "pdf"


def test_sleuthkit_fls_timeout_parameter(monkeypatch: pytest.MonkeyPatch) -> None:
    """run_fls must accept a configurable timeout defaulting to 1800s (30m)
    and pass it through to the subprocess layer unchanged."""
    adapter = SleuthKitAdapter()

    sig = inspect.signature(adapter.run_fls)
    assert "timeout" in sig.parameters
    assert sig.parameters["timeout"].default == 1800

    captured: dict[str, Any] = {}

    def fake_run_subprocess(command: list[str], timeout: int = 300, env=None) -> ToolRunResult:
        captured["command"] = list(command)
        captured["timeout"] = timeout
        return ToolRunResult(returncode=0, stdout="", stderr="", execution_time=0.01, command=command)

    monkeypatch.setattr(adapter, "run_subprocess", fake_run_subprocess)

    adapter.run_fls("/dev/sdz")  # default timeout path
    assert captured["timeout"] == 1800

    adapter.run_fls("/dev/sdz", timeout=42)  # explicit override
    assert captured["timeout"] == 42
    assert "/dev/sdz" in captured["command"]


def test_shellbags_real_column_names_and_timestamp_parsing() -> None:
    """ShellBagsAnalyzer must parse SBECmd columns and multi-format timestamps."""
    analyzer = ShellBagsAnalyzer()
    parsed_ts = analyzer._parse_ez_timestamp("2026-08-18 19:45:00")
    assert parsed_ts == datetime(2026, 8, 18, 19, 45, 0, tzinfo=timezone.utc)

    iso_ts = analyzer._parse_ez_timestamp("2026-08-18T19:45:00Z")
    assert iso_ts == datetime(2026, 8, 18, 19, 45, 0, tzinfo=timezone.utc)


def test_lnk_jumplist_real_column_names() -> None:
    """LnkJumpListAnalyzer must parse LECmd/JLECmd real column names."""
    analyzer = LnkJumpListAnalyzer()
    row = {
        "LocalPath": "C:\\Users\\Admin\\secret.docx",
        "TargetCreated": "2026-08-18 10:00:00",
        "TargetModified": "2026-08-18 12:00:00",
        "TargetAccessed": "2026-08-18 14:00:00",
    }
    events = analyzer._process_lnk_records([row], "C:\\Users\\Admin\\Desktop\\secret.lnk", "PC-1")
    assert len(events) >= 1
    access_evts = [e for e in events if e.event_type == EventType.FILE_ACCESS]
    assert len(access_evts) == 1
    assert access_evts[0].source_path == "C:\\Users\\Admin\\secret.docx"


def test_prefetch_mam_and_scca_header_parsing(tmp_path: Path) -> None:
    """PrefetchAnalyzer must parse uncompressed SCCA v30/31 prefetch binary."""
    analyzer = PrefetchAnalyzer()
    pf_file = tmp_path / "CMD.EXE-A1B2C3D4.pf"

    # Build synthetic SCCA v30 header
    exec_name_bytes = "CMD.EXE\x00".encode("utf-16le").ljust(60, b"\x00")
    header = struct.pack("<I", 30) + b"SCCA" + b"\x00" * 8 + exec_name_bytes
    header = header.ljust(128, b"\x00")
    dt = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
    unix_s = dt.timestamp()
    ft = int(unix_s * 10_000_000 + 116444736000000000)
    ts_array = struct.pack("<Q", ft) + struct.pack("<Q", 0) * 7
    body = ts_array.ljust(80, b"\x00") + struct.pack("<I", 5)
    pf_file.write_bytes(header + body)

    parsed = analyzer._parse_prefetch(str(pf_file))
    assert parsed is not None
    assert parsed["executable_name"] == "CMD.EXE"
    assert parsed["run_count"] == 5
    assert len(parsed["execution_timestamps"]) == 1
    assert parsed["execution_timestamps"][0] == dt


def test_pe_binary_magic_byte_verifier() -> None:
    """FileTypeVerifier must not flag valid PE files (.dll, .sys) with MZ header."""
    analyzer = FileTypeVerifierAnalyzer()
    record = FileRecord(
        file_path="/system/driver.sys",
        file_name="driver.sys",
        extension=".sys",
        size=1024,
        source_device="PC-1",
    )
    artifact = RawArtifact(
        artifact_id="art-1",
        artifact_type="file",
        source_path=Path("/system/driver.sys"),
        device_id="PC-1",
        collected_at=datetime.now(tz=timezone.utc),
        raw_data={"file_record": record},
    )

    with tempfile.NamedTemporaryFile(suffix=".sys", delete=False) as tmp:
        tmp.write(b"MZ\x90\x00" + b"\x00" * 500)
        tmp_path = tmp.name

    try:
        record.file_path = tmp_path
        alerts = analyzer.analyze([artifact])
        assert len(alerts) == 0
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_suspicious_crypto_containers_rule_toggle() -> None:
    """SuspiciousDetectorAnalyzer must honor crypto_containers enable/disable flag."""
    cfg = {"rules": {"crypto_containers": {"enabled": False, "extensions": [".hc", ".tc", ".vc"]}}}
    analyzer = SuspiciousDetectorAnalyzer(config=cfg)
    record = FileRecord(
        file_path="/data/vault.vc",
        file_name="vault.vc",
        extension=".vc",
        size=1024,
        source_device="PC-1",
    )
    artifact = RawArtifact(
        artifact_id="art-1",
        artifact_type="file",
        source_path=Path("/data/vault.vc"),
        device_id="PC-1",
        collected_at=datetime.now(tz=timezone.utc),
        raw_data={"file_record": record},
    )
    alerts = analyzer.analyze([artifact])
    crypto_alerts = [a for a in alerts if a.category == "Encryption"]
    assert len(crypto_alerts) == 0


def test_correlator_usb_target_filtering() -> None:
    """Correlator must not treat host C: file creations as USB transfers."""
    inv = Investigation(case_name="USB-Test", investigator="Analyst")
    host_dev = Device(device_id="HOST-1", device_name="Workstation", device_type=DeviceType.PC)
    usb_dev = Device(device_id="USB-1", device_name="FlashDrive", device_type=DeviceType.USB, mount_point="E:\\")
    inv.devices = [host_dev, usb_dev]

    now = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    inv.events = [
        DataEvent(
            event_id="usb-conn",
            timestamp=now,
            event_type=EventType.USB_CONNECT,
            source_device="USB-1",
            source_path="E:\\",
        ),
        # Host C: drive file creation during USB session — NOT a transfer!
        DataEvent(
            event_id="host-file",
            timestamp=now + timedelta(minutes=10),
            event_type=EventType.FILE_CREATE,
            source_device="HOST-1",
            source_path="C:\\Users\\Analyst\\local_notes.txt",
        ),
        # Removable E: drive file creation — IS a transfer!
        DataEvent(
            event_id="usb-file",
            timestamp=now + timedelta(minutes=15),
            event_type=EventType.FILE_CREATE,
            source_device="USB-1",
            source_path="E:\\exfil.zip",
        ),
    ]

    correlator = CrossDeviceCorrelator(inv)
    transfers = correlator.detect_usb_transfers()
    assert len(transfers) == 1
    assert "exfil.zip" in transfers[0].source_path


def test_ntfs_timestomping_copy_not_flagged() -> None:
    """Normal file copy with si_modified < si_created must NOT be flagged as timestomping."""
    created = datetime(2026, 8, 18, 12, 0, 0)
    modified = datetime(2025, 1, 1, 12, 0, 0)  # Preserved original modification time
    fn_created = datetime(2026, 8, 18, 12, 0, 0)
    fn_modified = datetime(2025, 1, 1, 12, 0, 0)

    # Standard file copy: SI and FN created match; SI modification is older than creation
    assert detect_timestomping(created, modified, fn_created, fn_modified) is False

    # Copy pattern (FN created later than SI) is also not flagged — it is the
    # normal NTFS copy signature and previously flooded reports with FPs.
    si_copy_created = datetime(2020, 1, 1, 0, 0, 0)
    assert detect_timestomping(si_copy_created, modified, fn_created, fn_modified) is False

    # Actual timestomping: SI created forged NEWER than FN created
    si_stomp_created = datetime(2026, 8, 18, 14, 0, 0)
    assert detect_timestomping(si_stomp_created, modified, fn_created, fn_modified) is True


def test_snapshot_duplicate_hash_rename_detection() -> None:
    """Snapshot rename matching must handle duplicate file hashes cleanly without KeyError."""
    now = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    snap_a = Snapshot(name="snap_a", base_path="/dir", timestamp=now)
    snap_b = Snapshot(name="snap_b", base_path="/dir", timestamp=now)

    # Snap A has 2 identical files with hash "AAA"
    snap_a.files["/dir/file1.txt"] = FileRecord(file_path="/dir/file1.txt", file_name="file1.txt", sha256_hash="AAA")
    snap_a.files["/dir/file2.txt"] = FileRecord(file_path="/dir/file2.txt", file_name="file2.txt", sha256_hash="AAA")

    # Snap B renamed file1.txt to file1_renamed.txt, kept file2.txt
    snap_b.files["/dir/file1_renamed.txt"] = FileRecord(file_path="/dir/file1_renamed.txt", file_name="file1_renamed.txt", sha256_hash="AAA")
    snap_b.files["/dir/file2.txt"] = FileRecord(file_path="/dir/file2.txt", file_name="file2.txt", sha256_hash="AAA")

    engine = SnapshotEngine()
    diff = engine.compare_snapshots(snap_a, snap_b)
    assert len(diff.renamed_files) == 1
    assert diff.renamed_files[0][0].file_path == "/dir/file1.txt"
    assert diff.renamed_files[0][1].file_path == "/dir/file1_renamed.txt"
    assert len(diff.added_files) == 0
    assert len(diff.deleted_files) == 0


def test_hasher_chunk_size_and_output(tmp_path: Path) -> None:
    """Hasher must hash correctly with default 64KB chunk size."""
    test_file = tmp_path / "large_sample.bin"
    content = b"HELIOS FORENSICS TEST DATA " * 5000
    test_file.write_bytes(content)

    h1 = hash_file(test_file, "sha256")
    h2 = hash_file(test_file, "sha256", chunk_size=65536)
    assert len(h1) == 64
    assert h1 == h2


def test_config_merges_tool_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """HeliosConfig must merge user tool_paths from YAML."""
    config_yaml = tmp_path / "config.yaml"
    config_yaml.write_text("tool_paths:\n  sleuthkit: /custom/bin/fls\n", encoding="utf-8")

    use_bundle_root(monkeypatch, tmp_path)

    cfg = load_config(tmp_path)
    assert cfg.tool_paths.get("sleuthkit") == "/custom/bin/fls"


def test_chainsaw_adapter_passes_mapping_arg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ChainsawAdapter must pass --mapping <path> when running sigma hunt."""
    from helios.adapters.chainsaw_adapter import ChainsawAdapter

    adapter = ChainsawAdapter()
    evtx_file = tmp_path / "Security.evtx"
    evtx_file.write_bytes(b"ElfFile\x00")
    rules_dir = tmp_path / "sigma_rules"
    rules_dir.mkdir()
    (rules_dir / "rule.yml").write_text("title: Test Rule\n", encoding="utf-8")
    mapping_file = tmp_path / "mappings" / "sigma-event-logs-all.yml"
    mapping_file.parent.mkdir(parents=True, exist_ok=True)
    mapping_file.write_text("name: Test Mapping\n", encoding="utf-8")
    out_json = tmp_path / "out.json"

    captured_cmd: list[str] = []

    def mock_run_subprocess(cmd: list[str], timeout: int = 300):
        captured_cmd.extend(cmd)
        from helios.adapters.base import ToolRunResult
        return ToolRunResult(returncode=0, stdout="[]", stderr="", execution_time=0.01, command=cmd)

    monkeypatch.setattr(adapter, "is_available", lambda: True)
    monkeypatch.setattr(adapter, "run_subprocess", mock_run_subprocess)

    adapter.run_sigma_hunt(evtx_file, rules_dir, out_json, mapping_file=mapping_file)
    assert "--mapping" in captured_cmd
    idx = captured_cmd.index("--mapping")
    assert captured_cmd[idx + 1] == str(mapping_file)


def test_subprocess_utf8_decoding_non_ascii_and_binary() -> None:
    """run_subprocess must decode non-ASCII and invalid UTF-8 bytes safely without UnicodeDecodeError."""
    import sys
    from helios.adapters.base import ForensicToolAdapter

    class DummyAdapter(ForensicToolAdapter):
        def tool_name(self) -> str:
            return "dummy"
        def is_available(self) -> bool:
            return True
        def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
            return self.run_subprocess([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'\\x90\\xff\\xfeHELLO\\n')"])
        def parse_output(self, raw_output: str) -> list[Any]:
            return []

    adapter = DummyAdapter()
    result = adapter.run([])
    assert result.is_success()
    assert "HELLO" in result.stdout
    assert result.stderr == ""


