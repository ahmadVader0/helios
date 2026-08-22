"""
Tests guarding recently added Helios features:

- ``ModuleSkipped`` contract on analyzers with empty artifact sets and its
  "skipped" booking in pipeline ``module_results``,
- ``CrossDeviceCorrelator.infer_historical_transfers`` confidence ladder
  (session-window / volume-serial / uncorroborated removable access),
- ``report_generator._build_events_payload`` cap, ordering and row fields,
- POSIX drive-detector skip rules for virtual/WSL filesystems.
"""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

from helios.analyzers.base import ModuleSkipped
from helios.analyzers.prefetch import PrefetchAnalyzer
from helios.analyzers.shellbags import ShellBagsAnalyzer
from helios.core.correlator import CrossDeviceCorrelator
from helios.devices import detector
from helios.models import (
    Confidence,
    DataEvent,
    Device,
    DeviceType,
    EventType,
    Investigation,
)
from helios.reporting.report_generator import (
    _MAX_EVENT_PAYLOAD,
    _build_events_payload,
)


# ---------------------------------------------------------------------------
# ModuleSkipped — analyzer level
# ---------------------------------------------------------------------------

def test_prefetch_analyzer_raises_module_skipped_on_empty_artifacts() -> None:
    """No Prefetch artifacts = 'skipped' signal, not an error or silence."""
    with pytest.raises(ModuleSkipped):
        PrefetchAnalyzer().analyze([])


def test_shellbags_analyzer_raises_module_skipped_on_empty_artifacts() -> None:
    """No registry hives collected = 'skipped' signal."""
    with pytest.raises(ModuleSkipped):
        ShellBagsAnalyzer().analyze([])


# ---------------------------------------------------------------------------
# CrossDeviceCorrelator.infer_historical_transfers
# ---------------------------------------------------------------------------

def _historical_investigation(events: list[DataEvent]) -> Investigation:
    pc = Device(device_type=DeviceType.PC, device_name="Workstation", device_id="PC-1")
    usb = Device(device_type=DeviceType.USB, device_name="USB DRIVE", device_id="USB-1")
    return Investigation(case_name="historical", devices=[pc, usb], events=events)


def _lnk_access(ts: datetime, target: str, **meta) -> DataEvent:
    payload = {"removable_media_flag": True, "target_path": target, "tracker": "LECmd"}
    payload.update(meta)
    return DataEvent(
        timestamp=ts,
        event_type=EventType.FILE_ACCESS,
        source_device="PC-1",
        source_path=target,
        raw_source="LECmd",
        metadata=payload,
    )


def test_historical_transfer_inside_usb_session_is_medium_confidence() -> None:
    base = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    inv = _historical_investigation([
        DataEvent(
            timestamp=base,
            event_type=EventType.USB_CONNECT,
            source_device="USB-1",
            source_path="E:\\",
            metadata={"friendly_name": "Kingston", "hardware_id": "0930&0A00"},
        ),
        _lnk_access(base + timedelta(minutes=30), r"E:\cases\ledger.xlsx"),
    ])

    transfers = CrossDeviceCorrelator(inv).infer_historical_transfers()

    assert len(transfers) == 1
    t = transfers[0]
    assert t.event_type == EventType.FILE_COPY
    assert t.confidence == Confidence.MEDIUM
    assert t.source_path == r"E:\cases\ledger.xlsx"
    assert t.metadata["inference"] == "removable-access inside USB session"


def test_historical_transfer_serial_match_only_is_medium_confidence() -> None:
    base = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    inv = _historical_investigation([
        # MountPoints2 proves which volume serial was really mounted...
        DataEvent(
            timestamp=base - timedelta(hours=1),
            event_type=EventType.DEVICE_CONNECT,
            source_device="PC-1",
            source_path="MountPoints2",
            metadata={"volume_serial": "A4C2-1B03", "mountpoint": "E:\\"},
        ),
        # ...but the LNK access happened long after any USB session window.
        _lnk_access(base + timedelta(days=2), r"E:\exports\plan.docx",
                    volume_serial="A4C21B03"),
    ])

    transfers = CrossDeviceCorrelator(inv).infer_historical_transfers()

    assert len(transfers) == 1
    t = transfers[0]
    assert t.event_type == EventType.FILE_COPY
    assert t.confidence == Confidence.MEDIUM
    assert t.metadata["inference"].startswith("volume-serial match")
    assert "A4C21B03" in t.metadata["volume_serial"].upper()


def test_historical_transfer_without_corroboration_is_low_confidence() -> None:
    base = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    inv = _historical_investigation([
        # A session exists but ended days before the LNK access...
        DataEvent(
            timestamp=base,
            event_type=EventType.USB_CONNECT,
            source_device="USB-1",
            source_path="E:\\",
        ),
        # ...and the access carries no volume serial at all.
        _lnk_access(base + timedelta(days=3), r"F:\mystery\file.txt"),
    ])

    transfers = CrossDeviceCorrelator(inv).infer_historical_transfers()

    assert len(transfers) == 1
    t = transfers[0]
    assert t.event_type == EventType.FILE_COPY
    assert t.confidence == Confidence.LOW
    assert t.metadata["inference"] == "removable-access (no corroboration)"


def test_historical_transfers_deduplicate_same_target_and_timestamp() -> None:
    base = datetime(2026, 8, 18, 12, 0, 0, tzinfo=timezone.utc)
    duplicate_access = _lnk_access(base, r"E:\dup.txt")
    inv = _historical_investigation([
        DataEvent(timestamp=base, event_type=EventType.USB_CONNECT,
                  source_device="USB-1", source_path="E:\\"),
        duplicate_access,
        _lnk_access(base, r"E:\dup.txt"),  # same target+ts → one inference only
    ])

    transfers = CrossDeviceCorrelator(inv).infer_historical_transfers()
    assert len(transfers) == 1


# ---------------------------------------------------------------------------
# report_generator._build_events_payload
# ---------------------------------------------------------------------------

def _payload_event(day: int, path: str, device: str = "PC-1") -> SimpleNamespace:
    return SimpleNamespace(
        event_id=f"evt-{day}-{path}",
        timestamp=datetime(2026, 8, day, 10, 30, 0, tzinfo=timezone.utc),
        event_type=EventType.FILE_COPY,
        source_device=device,
        source_path=path,
        destination_path=path + ".dst",
        confidence=Confidence.HIGH,
        raw_source="UnitTest",
        metadata={"account": "alice", "inference": "session-window"},
    )


def test_build_events_payload_respects_cap() -> None:
    events = [_payload_event(1 + i % 20, f"/f{i}.txt") for i in range(_MAX_EVENT_PAYLOAD + 25)]
    payload = _build_events_payload(events, {})
    assert len(payload) == _MAX_EVENT_PAYLOAD


def test_build_events_payload_explicit_max_rows() -> None:
    events = [_payload_event(2, f"/f{i}.txt") for i in range(10)]
    assert len(_build_events_payload(events, {}, max_rows=4)) == 4
    assert len(_build_events_payload(events, {}, max_rows=100)) == 10


def test_build_events_payload_sorts_newest_first_and_has_fields() -> None:
    events = [
        _payload_event(5, "/mid.txt", device="DEV-X"),
        _payload_event(1, "/oldest.txt"),
        _payload_event(9, "/newest.txt"),
    ]
    name_map = {"PC-1": "Workstation", "DEV-X": "Laptop"}
    payload = _build_events_payload(events, name_map)

    ts_values = [row["ts"] for row in payload]
    assert ts_values == sorted(ts_values, reverse=True)
    assert payload[0]["path"] == "/newest.txt"
    assert payload[-1]["path"] == "/oldest.txt"

    expected_fields = {"id", "ts", "type", "device", "path", "dst", "conf", "src", "basis", "user", "inference"}
    for row in payload:
        assert expected_fields <= set(row.keys())
    mid = next(r for r in payload if r["path"] == "/mid.txt")
    assert mid["device"] == "Laptop"          # name_map applied
    assert mid["type"] == "FILE_COPY"
    assert mid["user"] == "alice"
    assert mid["inference"] == "session-window"
    assert mid["conf"] == Confidence.HIGH.value
    assert mid["src"] == "UnitTest"


# ---------------------------------------------------------------------------
# devices.detector._detect_drives_proc_mounts skip rules
# ---------------------------------------------------------------------------

_PROC_MOUNTS_SAMPLE = "\n".join([
    # WSL drvfs Windows volume — MUST be kept (the whole point of WSL scans)
    "/dev/sdc1 /mnt/c drvfs rw,relatime,uid=1000,gid=1000 0 0",
    # WSL internal plumbing mounts — skipped by mount-prefix rule even
    # though their fstype would otherwise be acceptable
    "wslmount /mnt/wsl 9p rw,relatime 0 0",
    "wslg /mnt/wslg drvfs rw,relatime 0 0",
    # Virtual/special filesystems — skipped by fstype rule
    "overlay / overlay rw,relatime 0 0",
    "/dev/root / rootfs ro 0 0",
    "none /swap swap sw 0 0",
    "init /init iso9660 ro 0 0",
    # Ordinary real mounts — kept
    "/dev/sdb1 /media/usb ext4 rw,relatime 0 0",
]) + "\n"


def test_detect_drives_proc_mounts_skip_rules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    real_open = open

    def fake_open(file, *args, **kwargs):
        if str(file) == "/proc/mounts":
            return io.StringIO(_PROC_MOUNTS_SAMPLE)
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr("builtins.open", fake_open)

    drives = detector._detect_drives_proc_mounts()
    letters = {d.drive_letter for d in drives}

    # Kept
    assert "/mnt/c" in letters
    assert "/media/usb" in letters
    mnt_c = next(d for d in drives if d.drive_letter == "/mnt/c")
    assert mnt_c.filesystem == "drvfs"

    # Skipped: WSL plumbing prefixes, virtual fstypes, special roots
    for skipped in ("/mnt/wsl", "/mnt/wslg", "/", "/swap", "/init"):
        assert skipped not in letters, skipped
