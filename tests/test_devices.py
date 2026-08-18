
from helios.devices.detector import _os_description, get_local_device
from helios.evidence import HELIOS_VERSION, ChainOfCustodyLog
from helios.models import DeviceType


def test_get_local_device():
    dev = get_local_device()
    assert dev.device_type in (DeviceType.PC, DeviceType.LAPTOP)
    assert len(dev.device_name) > 0


def test_os_description_windows_11_build(monkeypatch):
    """Windows 11 reports NT 10.0 — the build number must discriminate."""
    monkeypatch.setattr("helios.devices.detector.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "helios.devices.detector.sys.getwindowsversion",
        lambda: type("W", (), {"build": 22631})(),
        raising=False,
    )
    assert _os_description() == "Windows 11 (build 22631)"


def test_os_description_windows_10_build(monkeypatch):
    monkeypatch.setattr("helios.devices.detector.platform.system", lambda: "Windows")
    monkeypatch.setattr(
        "helios.devices.detector.sys.getwindowsversion",
        lambda: type("W", (), {"build": 19045})(),
        raising=False,
    )
    assert _os_description() == "Windows 10 (build 19045)"


def test_os_description_posix(monkeypatch):
    monkeypatch.setattr("helios.devices.detector.platform.system", lambda: "Linux")
    monkeypatch.setattr("helios.devices.detector.platform.release", lambda: "6.8.0")
    assert _os_description() == "Linux 6.8.0"


def test_detect_android_devices_uses_bundle_resolver(tmp_path, monkeypatch):
    """adb must be resolved via the bundle-aware resolver, and a missing
    binary must produce an honest status instead of a silent empty list."""

    from helios.devices import detector

    calls = []

    def fake_resolve(name):
        calls.append(name)
        return None

    monkeypatch.setattr(detector, "resolve_tool_binary", fake_resolve, raising=False)
    monkeypatch.setattr(
        "helios.adapters.base.resolve_tool_binary", fake_resolve
    )

    devices = detector.detect_android_devices()
    assert devices == []
    assert "adb" in calls
    assert "not found" in detector.last_adb_status()


def test_detect_android_devices_reports_unauthorized(tmp_path, monkeypatch):
    """A connected-but-unauthorized device must be surfaced, not dropped."""
    import subprocess
    from types import SimpleNamespace

    from helios.devices import detector

    fake_adb = tmp_path / "adb"
    fake_adb.write_text("")
    fake_adb.chmod(0o755)

    monkeypatch.setattr(
        detector, "resolve_tool_binary", lambda name: fake_adb, raising=False
    )
    monkeypatch.setattr(
        "helios.adapters.base.resolve_tool_binary", lambda name: fake_adb
    )

    def fake_run(args, **kwargs):
        if len(args) > 1 and args[1] == "devices":
            return SimpleNamespace(
                returncode=0,
                stdout="List of devices attached\nABC12345\tunauthorized\n",
                stderr="",
            )
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(detector.subprocess, "run", fake_run)

    devices = detector.detect_android_devices()
    assert devices == []
    assert "unauthorized" in detector.last_adb_status()


def test_chain_of_custody_log(tmp_path):
    coc = ChainOfCustodyLog(case_id="TEST-001", investigator="Auditor")
    coc.log("Acquisition", target="C:\\Users\\alice", result="Captured", tool_name="Helios")

    assert len(coc.entries) == 1
    assert coc.entries[0].action == "Acquisition"
    assert coc.to_dict()["case_id"] == "TEST-001"
    assert coc.to_dict()["entry_count"] == 1

    out = tmp_path / "custody" / "coc.json"
    written = coc.to_json(out)
    assert written.exists()
    assert "Acquisition" in written.read_text(encoding="utf-8")


def test_helios_version_constant():
    assert HELIOS_VERSION == "0.1.0"
