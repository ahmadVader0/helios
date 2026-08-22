"""
Shared fixtures & helpers for the Helios test-suite.

Consolidates:
- ``make_artifact`` / ``make_file_record`` builders (previously duplicated
  across test modules),
- a session-cached ``helios_config`` fixture (``load_config()`` resolves
  every bundled tool binary, so it should only run once per session),
- a reusable monkeypatch helper for faking ``get_bundle_root``,
- a driver that runs the REAL investigation pipeline with every external
  analyzer module stubbed out (no binaries executed, nothing scanned).

Per project convention, external binaries are never executed in tests.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import pytest

import helios.pipeline as pipeline_mod
from helios.analyzers.base import RawArtifact
from helios.config import HeliosConfig
from helios.models import (
    DataEvent,
    Device,
    DeviceType,
    DriveInfo,
    DriveType,
    FileRecord,
)


# ---------------------------------------------------------------------------
# Artifact / record builders
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def helios_config() -> HeliosConfig:
    """``load_config()`` computed once per session and shared read-only."""
    from helios.config import load_config

    return load_config()


def use_bundle_root(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    """Point ``helios.config.get_bundle_root`` at ``root`` for the current test.

    Returns ``root`` so callers can chain ``rules = use_bundle_root(mp, tmp) / "x"``.
    """
    import helios.config

    monkeypatch.setattr(helios.config, "get_bundle_root", lambda: root)
    return root


# ---------------------------------------------------------------------------
# Real-pipeline driver with stubbed analyzer modules
# ---------------------------------------------------------------------------

# module_results key -> helios.pipeline module-level function name
_PIPELINE_MODULE_ATTRS: dict[str, str] = {
    "usb_transfers": "_usb_history_module",
    "file_deletions": "_recycle_bin_module",
    "recent_file_access": "_lnk_jumplist_module",
    "event_logs": "_event_logs_module",
    "program_execution": "_prefetch_module",
    "shellbags": "_shellbags_module",
    "mft_analysis": "_mft_module",
    "usn_journal": "_usn_journal_module",
    "deleted_file_recovery": "_sleuthkit_module",
    "suspicious_files": "_suspicious_module",
    "cross_device_matching": "_correlator_module",
}


def drive_pipeline_with_stub_modules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    events: list[DataEvent] | None = None,
    file_records: list[FileRecord] | None = None,
    module_behaviors: dict[str, Callable[..., None]] | None = None,
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    case_name: str = "Stubbed Pipeline Case",
) -> dict[str, Any]:
    """Run the REAL ``run_investigation_pipeline`` with every heavy edge stubbed.

    - Drive detection returns one fake volume bound to ``tmp_path``.
    - The live filesystem walk is replaced by an injector for the supplied
      ``events`` / ``file_records`` (so tests control exactly what reaches
      the post-processing blocks under test).
    - Every gated analyzer module becomes a no-op unless ``module_behaviors``
      maps its ``module_results`` key to a callable (e.g. one raising
      ``ModuleSkipped`` to exercise skip bookkeeping).
    - Report rendering runs for real into ``tmp_path/reports``.

    Returns the pipeline result dict (``{"investigation": ..., ...}``).
    """
    behaviors = dict(module_behaviors or {})
    injected_events = list(events or [])
    injected_records = list(file_records or [])
    mount = str(tmp_path / "evidence_volume")

    def fake_run_walk(target_drives, drive_devices, records_out, events_out, on_progress, scan_options=None):
        records_out.extend(injected_records)
        events_out.extend(injected_events)
        return False

    monkeypatch.setattr(pipeline_mod, "_run_walk", fake_run_walk)

    for key, attr in _PIPELINE_MODULE_ATTRS.items():
        behavior = behaviors.get(key)
        if behavior is None:
            behavior = lambda *a, **kw: None  # noqa: E731 - deliberate stub
        monkeypatch.setattr(pipeline_mod, attr, behavior)

    fake_drives = [
        DriveInfo(
            drive_letter=mount,
            label="Evidence Volume",
            filesystem="ext4",
            drive_type=DriveType.HDD,
            is_removable=False,
        )
    ]
    monkeypatch.setattr(pipeline_mod.detector, "detect_drives", lambda: fake_drives)
    monkeypatch.setattr(
        pipeline_mod.detector,
        "get_local_device",
        lambda: Device(
            device_type=DeviceType.PC,
            device_name="Test Host",
            device_id="HOST-1",
            drive_letter=mount,
        ),
    )

    # Minimal profile where every module key is enabled (empty modules body).
    config = HeliosConfig(investigation_profiles={"full": {"description": "test stub"}})

    return pipeline_mod.run_investigation_pipeline(
        case_name=case_name,
        investigator="pytest",
        selected_drive_letters=[mount],
        profile_name="full",
        date_from=date_from,
        date_to=date_to,
        report_dir=tmp_path / "reports",
        config=config,
    )
