"""
Helios Investigation Pipeline — the single execution path for live scans.

Both the interactive wizard (helios.menu) and the non-interactive CLI
(``helios investigate``) run the same gated forensic pipeline:

    1. Live filesystem walk (SHA-256 hashes + timeline events)
    2. Profile-driven analyzer modules (USB history, Recycle Bin, LNK/JumpLists,
       event logs, prefetch, ShellBags, SleuthKit deleted-file recovery,
       suspicious heuristics, cross-device correlation)
    3. Chain-of-custody log and profile-specific HTML report

Every module runs through ``_run_module`` which records the REAL outcome
(ran / failed / disabled) in ``module_results`` — the report never shows
fabricated activity.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from helios.analyzers.base import ModuleSkipped
from helios.config import HeliosConfig, load_config
from helios.core.investigation import ProfileManager
from helios.devices import detector
from helios.models import (
    Confidence,
    CustodyEntry,
    DataEvent,
    Device,
    DeviceType,
    DriveInfo,
    DriveType,
    EventType,
    FileRecord,
    Investigation,
    ScanOptions,
)

logger = logging.getLogger(__name__)

# Tools whose resolution is logged once at scan start so field users can
# see at a glance WHY a module produced nothing (binary missing = skipped).
_TOOL_INVENTORY = (
    ("MFTECmd", "MFT + USN Journal analysis"),
    ("LECmd", "LNK parsing"),
    ("JLECmd", "JumpList parsing"),
    ("SBECmd", "ShellBags"),
    ("PECmd", "Prefetch enrichment"),
    ("RBCmd", "Recycle Bin enrichment"),
    ("fls", "SleuthKit deleted-file recovery"),
    ("chainsaw", "Sigma event-log hunt"),
    ("exiftool", "file-type verification"),
)


def log_tool_inventory() -> None:
    """Log which forensic binaries resolved, once per scan (INFO level).

    Run with ``helios --verbose`` to see it; this converts the most common
    'empty report' complaints into one-glance diagnoses.
    """
    import platform

    from helios.adapters.base import resolve_tool_binary

    logger.info(
        "Helios scan start — host=%s python=%s cwd=%s",
        platform.platform(), platform.python_version(), Path.cwd(),
    )
    for tool, purpose in _TOOL_INVENTORY:
        resolved = resolve_tool_binary(tool)
        if resolved:
            logger.info("tool %-10s OK   %s (%s)", tool, resolved, purpose)
        else:
            logger.warning("tool %-10s MISSING — %s will be limited/skipped", tool, purpose)


def sanitize_filename(name: str) -> str:
    """Make an arbitrary case name safe for use inside output file paths.

    Only spaces are replaced otherwise — ``Case: Q3/Final`` would crash the
    report write AFTER a potentially hours-long scan (``:`` and ``/`` are
    illegal or path-traversing on both platforms).
    """
    cleaned = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(name or "")).strip().rstrip(".")
    return cleaned[:120] or "case"

# Disk-image extensions that SleuthKit can enumerate directly.
FLS_IMAGE_EXTENSIONS = {".dd", ".raw", ".img", ".e01", ".ex01", ".001", ".vhd", ".vhdx"}

# Live walk caps the number of hashed/indexed files per drive.
# Set to 5,000,000 (5 Million) files per drive so that large drives
# and external media are scanned completely without premature truncation.
MAX_FILES_PER_DRIVE = 5_000_000

# Files larger than this are listed but not hashed during the live walk.
# Set to 500 MB so that cross-device hash matching works for real
# documents, presentations, databases, and media files.
MAX_HASH_FILE_SIZE = 500 * 1024 * 1024

# Callback contract: on_stage(label: str, percent: float) with percent 0-100.
ProgressCallback = Callable[[str, float], None]


def _resolve_fls_source(drv: DriveInfo, scan_options: ScanOptions) -> str | None:
    """
    Resolve a raw volume or image source that fls can enumerate for the given
    drive. Returns None when no accessible source exists (e.g., permissions).
    """
    # 1. Explicit disk-image paths supplied via scan options.
    if scan_options.paths:
        for raw_path in scan_options.paths:
            p = Path(raw_path)
            if p.is_file() and p.suffix.lower() in FLS_IMAGE_EXTENSIONS:
                return str(p)

    # 2. Raw volume on Windows (e.g. \\.\C:) — requires administrator rights.
    if os.name == "nt" and drv.drive_letter:
        letter = drv.drive_letter.rstrip(":\\")
        if letter and len(letter) == 1:
            return f"\\\\.\\{letter}:"

    # 3. On POSIX, map the drive's mount point to its block device node and
    #    only use it when the current user can read it.
    mount_path = Path(drv.drive_letter) if drv.drive_letter else None
    if mount_path and mount_path.exists():
        dev_node = _block_device_for_mount(mount_path)
        if dev_node and os.access(dev_node, os.R_OK):
            return dev_node
    return None


def _block_device_for_mount(mount_point: Path) -> str | None:
    """Map a mount point to its /dev node via /proc/self/mountinfo."""
    try:
        mount_point = mount_point.resolve()
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 6:
                    continue
                raw_mount = parts[4].replace("\\040", " ").replace("\\011", "\t")
                if Path(raw_mount).resolve() == mount_point:
                    major_minor = parts[2]
                    link = os.readlink(f"/sys/dev/block/{major_minor}")
                    return os.path.join("/dev", os.path.basename(link))
    except (OSError, ValueError):
        return None
    return None


def _usb_history_module(scan_options, device, events: list) -> None:
    """Run USB history analysis (registry/setupapi)."""
    from helios.analyzers.usb_history import UsbHistoryAnalyzer
    usb_an = UsbHistoryAnalyzer(config={}, scan_options=scan_options)
    raw_arts = usb_an.collect(device)
    events.extend(usb_an.analyze(raw_arts))


def _host_system_drive(drv: DriveInfo) -> bool:
    """True when this drive IS the live host's own system volume.

    Artifact analyzers may fall back to host roots only for this drive;
    every OTHER scanned volume must be parsed in its own scope so a D: scan
    never reports the analyst's C:\\Users artifacts.
    """
    if os.name == "nt":
        sys_drive = os.environ.get("SystemDrive", "C:").upper()
        return str(drv.drive_letter).upper().rstrip("\\") == sys_drive.rstrip(":\\") + ":" or \
            str(drv.drive_letter).upper().rstrip("\\") == sys_drive.rstrip(":\\")
    return Path(str(drv.drive_letter)) == Path("/")


def _scope_devices(
    target_drives: list[DriveInfo],
    drive_devices: dict[str, Device],
    local_device: Device,
) -> list[Device]:
    """Build one artifact-collection Device per scanned drive.

    Non-host volumes get a copy of the device model with ``mount_point`` /
    ``drive_letter`` bound to the scanned volume, so analyzers enumerate
    ``<volume>\\Users``, ``<volume>\\Windows\\Prefetch`` … on the evidence
    drive instead of silently parsing the host system root.
    """
    devices: list[Device] = []
    seen: set[str] = set()
    from dataclasses import replace as _dc_replace

    for drv in target_drives:
        key = str(drv.drive_letter)
        if not key or key in seen:
            continue
        seen.add(key)
        base = drive_devices.get(key, local_device)
        if _host_system_drive(drv):
            devices.append(base)
        else:
            devices.append(_dc_replace(
                base,
                drive_letter=key,
                mount_point=key,
            ))
    return devices


def _recycle_bin_module(scan_options, device, events: list) -> None:
    """Run Recycle Bin analyzer."""
    from helios.analyzers.recycle_bin import RecycleBinAnalyzer
    rb_an = RecycleBinAnalyzer(config={}, scan_options=scan_options)
    raw_arts = rb_an.collect(device)
    events.extend(rb_an.analyze(raw_arts))


def _lnk_jumplist_module(scan_options, devices: list, events: list) -> None:
    """Run LNK & JumpLists analyzer across every scoped volume."""
    from helios.analyzers.lnk_jumplists import LnkJumpListAnalyzer
    lnk_an = LnkJumpListAnalyzer(config={}, scan_options=scan_options)
    collected: list = []
    for dev in devices:
        collected.extend(lnk_an.collect(dev))
    events.extend(lnk_an.analyze(collected))


def _event_logs_module(scan_options, devices: list, events: list, alerts: list) -> None:
    """Run Windows Event Logs analyzer across every scoped volume."""
    from helios.analyzers.event_logs import EventLogsAnalyzer
    evl_an = EventLogsAnalyzer(config={}, scan_options=scan_options)
    collected: list = []
    for dev in devices:
        collected.extend(evl_an.collect(dev))
    events.extend(evl_an.analyze(collected))
    alerts.extend(evl_an.alerts)


def _prefetch_module(scan_options, devices: list, events: list, alerts: list | None = None) -> None:
    """Run Prefetch execution analyzer across every scoped volume."""
    from helios.analyzers.prefetch import PrefetchAnalyzer
    pf_an = PrefetchAnalyzer(config={}, scan_options=scan_options)
    collected: list = []
    for dev in devices:
        collected.extend(pf_an.collect(dev))
    events.extend(pf_an.analyze(collected))
    if alerts is not None:
        alerts.extend(pf_an.alerts)


def _shellbags_module(scan_options, devices: list, events: list, alerts: list | None = None) -> None:
    """Run ShellBags analyzer across every scoped volume."""
    from helios.analyzers.shellbags import ShellBagsAnalyzer
    sb_an = ShellBagsAnalyzer(config={}, scan_options=scan_options)
    collected: list = []
    for dev in devices:
        collected.extend(sb_an.collect(dev))
    events.extend(sb_an.analyze(collected))
    if alerts is not None:
        alerts.extend(sb_an.alerts)


def _mft_module(
    scan_options: ScanOptions,
    target_drives: list[DriveInfo],
    drive_devices: dict[str, Device],
    events: list[DataEvent],
    alerts: list,
    report_dir: Path | None = None,
) -> None:
    """Run MFT analysis on NTFS volumes using MFTECmd.

    Parses the raw $MFT into CSV and feeds it through MFTAnalyzer for
    timestomping detection and comprehensive file enumeration.
    Falls back gracefully when MFTECmd is not installed.
    """
    from helios.adapters.mftecmd_adapter import MFTECmdAdapter
    from helios.analyzers.base import RawArtifact
    from helios.analyzers.mft_analyzer import MFTAnalyzer

    adapter = MFTECmdAdapter(config={})
    if not adapter.is_available():
        logger.debug("MFTECmd binary not available; skipping MFT analysis.")
        return

    analyzer = MFTAnalyzer(config={}, scan_options=scan_options)
    output_dir = (report_dir or Path.cwd() / "reports") / "mft_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    for drv in target_drives:
        if not drv.filesystem or drv.filesystem.upper() != "NTFS":
            continue
        mft_path = Path(drv.drive_letter) / "$MFT"
        if os.name == "nt":
            mft_path = Path(f"{drv.drive_letter}\\$MFT")

        src_dev = drive_devices.get(drv.drive_letter)
        device_id = src_dev.device_id if src_dev else ""
        drv_clean = drv.drive_letter.replace(":", "").replace("/", "_").replace("\\", "_")

        try:
            csv_path = adapter.parse_mft(mft_path, output_dir, out_name=f"mft_dump_{drv_clean}")
            artifact = RawArtifact(
                artifact_id=f"mft-{drv.drive_letter}",
                artifact_type="MFT_CSV",
                source_path=mft_path,
                device_id=device_id,
                collected_at=datetime.now(tz=timezone.utc),
                raw_data=csv_path,
                metadata={"volume": drv.drive_letter},
            )
            results = analyzer.analyze([artifact])
            for r in results:
                if isinstance(r, DataEvent):
                    events.append(r)
                else:
                    alerts.append(r)
            logger.info("MFT analysis on %s produced %d results", drv.drive_letter, len(results))
        except Exception:
            logger.exception("MFT analysis failed on %s", drv.drive_letter)


def _usn_journal_module(
    scan_options: ScanOptions,
    target_drives: list[DriveInfo],
    drive_devices: dict[str, Device],
    events: list[DataEvent],
    report_dir: Path | None = None,
) -> None:
    """Run USN Journal analysis on NTFS volumes using MFTECmd.

    Parses the $UsnJrnl:$J change journal for file create/delete/rename/modify
    activity with precise timestamps.
    Falls back gracefully when MFTECmd is not installed.
    """
    from helios.adapters.mftecmd_adapter import MFTECmdAdapter
    from helios.analyzers.base import RawArtifact
    from helios.analyzers.usn_journal import USNJournalAnalyzer

    adapter = MFTECmdAdapter(config={})
    if not adapter.is_available():
        logger.debug("MFTECmd binary not available; skipping USN Journal analysis.")
        return

    analyzer = USNJournalAnalyzer(config={}, scan_options=scan_options)
    output_dir = (report_dir or Path.cwd() / "reports") / "usn_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    for drv in target_drives:
        if not drv.filesystem or drv.filesystem.upper() != "NTFS":
            continue

        # USN Journal location varies
        usn_path = Path(drv.drive_letter) / "$Extend" / "$UsnJrnl:$J"
        mft_path = Path(drv.drive_letter) / "$MFT"
        if os.name == "nt":
            usn_path = Path(f"{drv.drive_letter}\\$Extend\\$UsnJrnl:$J")
            mft_path = Path(f"{drv.drive_letter}\\$MFT")

        src_dev = drive_devices.get(drv.drive_letter)
        device_id = src_dev.device_id if src_dev else ""
        drv_clean = drv.drive_letter.replace(":", "").replace("/", "_").replace("\\", "_")

        try:
            csv_path = adapter.parse_usn_journal(
                usn_path,
                output_dir,
                out_name=f"usn_dump_{drv_clean}",
                mft_file=mft_path,
            )
            artifact = RawArtifact(
                artifact_id=f"usn-{drv.drive_letter}",
                artifact_type="USN_CSV",
                source_path=usn_path,
                device_id=device_id,
                collected_at=datetime.now(tz=timezone.utc),
                raw_data=csv_path,
                metadata={"volume": drv.drive_letter},
            )
            results = analyzer.analyze([artifact])
            for r in results:
                if isinstance(r, DataEvent):
                    events.append(r)
            logger.info("USN Journal analysis on %s produced %d events", drv.drive_letter, len(results))
        except Exception:
            logger.exception("USN Journal analysis failed on %s", drv.drive_letter)


def _sleuthkit_module(scan_options, target_drives, local_device, file_records: list, events: list, drive_devices: dict) -> None:
    """Run SleuthKit deleted-file recovery (fls/fsstat)."""
    from helios.adapters.sleuthkit_adapter import SleuthKitAdapter
    sk = SleuthKitAdapter(config={})
    if not sk.is_available():
        raise RuntimeError("SleuthKit binaries (fls/fsstat) not available")
    processed = 0
    for drv in target_drives:
        fls_source = _resolve_fls_source(drv, scan_options)
        if not fls_source:
            continue
        src_dev = drive_devices.get(drv.drive_letter, local_device)
        # fsstat is informational only — don't let its failure block fls recovery
        try:
            fs_info = sk.run_fsstat(fls_source)
            if fs_info:
                logger.info("SleuthKit fsstat on %s: %s", fls_source, fs_info.get("File System Type", "unknown"))
        except Exception:  # noqa: BLE001
            logger.warning("fsstat failed on %s — proceeding with fls anyway", fls_source)
        raw = ""
        try:
            raw = sk.run_fls(fls_source, recursive=True, deleted_only=True, mac_format=True)
        except Exception:  # noqa: BLE001
            pass
        if not raw.strip():
            try:
                raw = sk.run_fls(fls_source, recursive=True, deleted_only=True)
            except Exception as exc:  # noqa: BLE001
                logger.warning("fls failed on %s: %s", fls_source, exc)
                continue

        all_lines = raw.splitlines()
        # Filter out Windows OS noise — but NOT $OrphanFiles which contain
        # old deleted files whose parent directory was overwritten (the exact
        # entries Autopsy finds via deep MFT scanning).
        _NOISE_TOKENS = ("winsxs", "softwaredistribution", "windows/temp", "appdata/local/temp")
        filtered_lines = [
            line for line in all_lines
            if not any(noise in line.lower() for noise in _NOISE_TOKENS)
        ]
        deleted_lines = (filtered_lines if filtered_lines else all_lines)[:500000]
        if not deleted_lines:
            continue
        records, _ = sk.parse_fls_output("\n".join(deleted_lines), device_id=src_dev.device_id, deleted_only=True)
        clean_drive = drv.drive_letter if drv.drive_letter else ""
        sep = "\\" if os.name == "nt" else "/"
        if clean_drive and not clean_drive.endswith(("\\", "/")):
            clean_drive_prefix = clean_drive + sep
        else:
            clean_drive_prefix = clean_drive

        for rec in records:
            norm_path = rec.file_path.replace("/", "\\") if os.name == "nt" else rec.file_path.replace("\\", "/")
            if re.match(r"^[a-zA-Z]:[\\/]", norm_path):
                rec.file_path = norm_path
            elif clean_drive_prefix:
                clean_rel_path = norm_path.lstrip("\\/")
                rec.file_path = clean_drive_prefix + clean_rel_path
            else:
                rec.file_path = norm_path

            # Emit a FILE_DELETE event for non-system files with timestamps.
            # Internal NTFS metadata and BitLocker keys (is_system=True) are skipped.
            if not getattr(rec, "is_system", False):
                rec_ts = rec.modified or rec.created or rec.accessed
                if rec_ts is not None:
                    events.append(
                        DataEvent(
                            timestamp=rec_ts,
                            event_type=EventType.FILE_DELETE,
                            source_device=src_dev.device_id,
                            source_path=rec.file_path,
                            file_size=rec.size,
                            confidence=Confidence.HIGH,
                            raw_source="SleuthKit fls",
                            metadata={
                                "file_name": rec.file_name,
                                "mft_entry": rec.mft_entry_number,
                                "has_real_timestamp": True,
                                "recovery_status": rec.recovery_status.value if hasattr(rec.recovery_status, "value") else str(rec.recovery_status),
                            },
                        )
                    )
        file_records.extend(records)
        processed += 1
        logger.info("SleuthKit recovered %d deleted entries from %s", len(records), fls_source)

    if processed == 0 and target_drives:
        raise RuntimeError("SleuthKit: raw volume access requires admin/root — all drives skipped")


def _suspicious_module(
    scan_options,
    file_records: list,
    alerts: list,
    events: list,
    device_types: dict[str, str],
    config: HeliosConfig,
) -> None:
    """Run suspicious-detector heuristics, file-type verification and event rules."""
    from datetime import datetime as _dt

    from helios.analyzers.base import RawArtifact
    from helios.analyzers.file_type_verifier import FileTypeVerifierAnalyzer
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer
    susp_an = SuspiciousDetectorAnalyzer(config={}, scan_options=scan_options)
    raw_arts = [
        RawArtifact(
            artifact_id=f"rec-{idx}",
            artifact_type="FILE_RECORD",
            source_path=Path(r.file_path),
            device_id=r.source_device,
            collected_at=_dt.now(),
            raw_data=r,
        )
        for idx, r in enumerate(file_records)
    ]
    alerts.extend(susp_an.analyze(raw_arts, device_types=device_types))

    ftv_an = FileTypeVerifierAnalyzer(config={}, scan_options=scan_options)
    alerts.extend(ftv_an.analyze(raw_arts))

    # Event-timeline rules: mass deletion, after-hours USB connections
    alerts.extend(
        susp_an.analyze_events(events, working_hours=config.working_hours or {})
    )


def _correlator_module(case_name, investigator, device_list, target_drives, events: list, file_records: list, alerts: list, correlations: list, module_results: list) -> None:
    """Run cross-device correlation and build movement chains."""
    from helios.core.correlator import CrossDeviceCorrelator
    from helios.models import Investigation as _Investigation
    temp_inv = _Investigation(
        case_name=case_name,
        investigator=investigator,
        devices=device_list,
        drives_scanned=target_drives,
        events=events,
        file_records=file_records,
        alerts=alerts,
    )
    correlator = CrossDeviceCorrelator(temp_inv)
    corr_events = correlator.detect_usb_transfers()
    events.extend(corr_events)
    historical = correlator.infer_historical_transfers()
    events.extend(historical)
    exfil_alerts = correlator.detect_exfiltration_patterns()
    alerts.extend(exfil_alerts)

    chains = correlator.match_files_by_hash()
    for c in chains:
        raw_hops = getattr(c, "hops", [])
        # Preserve hops for timestamp extraction in build_movement_rows.
        # Each hop is (datetime, source_device_id, target_device_id, action).
        first_ts = raw_hops[0][0] if raw_hops else None
        correlations.append({
            "file_name": c.file_name,
            "sha256_hash": c.sha256_hash,
            "source_device": c.source_device,
            "target_devices": getattr(c, "target_devices", ["External Volume"]),
            "hops": raw_hops,
            "timestamp": first_ts,
            "hops_summary": f"Correlated across {len(raw_hops)} hop(s)",
            "exfiltrated": getattr(c, "exfiltrated", False),
        })
    module_results.append({
        "key": "movement_chains",
        "label": "Data Movement Chains",
        "status": "ran",
        "events": len(corr_events) + len(historical),
        "alerts": len(exfil_alerts),
        "detail": f"{len(chains)} hash chain(s), {len(historical)} historic transfer(s) inferred",
    })


def _run_walk(
    target_drives: list[DriveInfo],
    drive_devices: dict[str, Device],
    file_records: list[FileRecord],
    events: list[DataEvent],
    on_progress: ProgressCallback | None,
    scan_options: ScanOptions | None = None,
) -> bool:
    """Live filesystem walk with real SHA-256 hashing and timeline events.

    Honors user scan options when provided:
    - ``excluded_paths``: path prefixes skipped entirely
    - ``max_depth``: directory depth limit relative to the drive root
    - ``skip_media``: large media extensions listed but not hashed

    Returns True when any drive hit the per-drive file cap.
    """
    from datetime import timezone

    from helios.core.hasher import hash_file

    excluded = [str(p).rstrip("\\/").lower() for p in (scan_options.excluded_paths if scan_options else []) if p]
    max_depth = getattr(scan_options, "max_depth", None) if scan_options else None
    skip_media = bool(getattr(scan_options, "skip_media", False)) if scan_options else False
    media_exts = {".mkv", ".mp4", ".avi", ".mov", ".wmv", ".iso", ".vmdk", ".mp3", ".flac"}

    def _is_excluded(path_text: str) -> bool:
        lowered = str(path_text).lower()
        return any(lowered == p or lowered.startswith(p + os.sep) or lowered.startswith(p + "\\") for p in excluded)

    any_capped = False
    total_drives = max(1, len(target_drives))
    for drv_idx, drv in enumerate(target_drives):
        try:
            root_path = Path(f"{drv.drive_letter}\\") if os.name == "nt" else Path(drv.drive_letter)
            if not root_path.exists():
                continue
            scanned_count = 0
            walk_capped = False
            src_dev = drive_devices.get(drv.drive_letter)
            if on_progress:
                on_progress(f"Walking {drv.drive_letter}", 2.0 + (drv_idx / total_drives) * 16.0)
            root_depth = len(root_path.parts)
            for p in root_path.rglob("*"):
                if scanned_count >= MAX_FILES_PER_DRIVE:
                    walk_capped = True
                    break
                # Heartbeat every 500 files so long walks don't look frozen.
                if scanned_count and scanned_count % 500 == 0 and on_progress:
                    pct = 2.0 + ((drv_idx + min(scanned_count / MAX_FILES_PER_DRIVE, 1.0)) / total_drives) * 16.0
                    on_progress(f"Walking {drv.drive_letter} ({scanned_count:,} files)", pct)
                if not p.is_file():
                    continue
                if excluded and _is_excluded(str(p)):
                    continue
                if max_depth is not None and (len(p.parts) - root_depth) > max_depth:
                    continue
                try:
                    st = p.stat()
                    too_big = st.st_size > MAX_HASH_FILE_SIZE
                    if skip_media and p.suffix.lower() in media_exts:
                        file_hash = ""
                    else:
                        file_hash = hash_file(p, algorithm="sha256") if not too_big else ""

                    # All timestamps MUST be UTC-aware — never naive local
                    m_time = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc)
                    a_time = datetime.fromtimestamp(st.st_atime, tz=timezone.utc)

                    # Creation time handling:
                    # - Windows: st_ctime IS the file creation time
                    # - Linux: st_ctime is inode CHANGE time (metadata mod),
                    #   NOT creation. Use st_birthtime (Python 3.12+) if
                    #   available, else approximate as min(st_ctime, st_mtime).
                    approximated_creation = False
                    if os.name == "nt":
                        c_time = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc)
                    else:
                        birth = getattr(st, "st_birthtime", None)
                        if birth is not None:
                            c_time = datetime.fromtimestamp(birth, tz=timezone.utc)
                        else:
                            # Best approximation: the earlier of inode-change
                            # and last-modify is closest to the real creation.
                            approximated_creation = True
                            c_time = datetime.fromtimestamp(
                                min(st.st_ctime, st.st_mtime), tz=timezone.utc
                            )

                    device_id = src_dev.device_id if src_dev else ""

                    file_records.append(FileRecord(
                        file_path=str(p),
                        file_name=p.name,
                        extension=p.suffix.lower(),
                        size=st.st_size,
                        sha256_hash=file_hash,
                        created=c_time,
                        modified=m_time,
                        accessed=a_time,
                        is_deleted=False,
                        source_device=device_id,
                    ))

                    # Emit real creation and modification events for the timeline.
                    # FILE_ACCESS is NOT emitted from filesystem st_atime because stat/read
                    # updates atime during scans; genuine file access events are derived
                    # from forensic artifacts (LNK shortcuts, JumpLists, ShellBags, Prefetch).
                    #
                    # Honesty rule: when creation had to be approximated AND it equals
                    # mtime, there is no independent creation signal — emitting a
                    # FILE_CREATE would fabricate an event, so only the record is kept.
                    if not (approximated_creation and c_time == m_time):
                        create_meta = (
                            {"creation_approximated": True} if approximated_creation else {}
                        )
                        events.append(
                            DataEvent(
                                timestamp=c_time,
                                event_type=EventType.FILE_CREATE,
                                source_device=device_id,
                                source_path=str(p),
                                file_size=st.st_size,
                                file_hash=file_hash or None,
                                confidence=Confidence.HIGH if not approximated_creation else Confidence.MEDIUM,
                                raw_source="Live Filesystem Scanner",
                                metadata=create_meta,
                            )
                        )
                    if m_time != c_time:
                        events.append(
                            DataEvent(
                                timestamp=m_time,
                                event_type=EventType.FILE_MODIFY,
                                source_device=device_id,
                                source_path=str(p),
                                file_size=st.st_size,
                                file_hash=file_hash or None,
                                confidence=Confidence.HIGH,
                                raw_source="Live Filesystem Scanner",
                            )
                        )
                    scanned_count += 1
                except Exception:
                    continue
            if walk_capped:
                any_capped = True
                logger.info(
                    "File inventory on %s capped at %d files; files beyond that "
                    "limit were not indexed.",
                    drv.drive_letter, MAX_FILES_PER_DRIVE,
                )
        except Exception:
            continue
    if on_progress:
        on_progress("Live Filesystem Walk", 20.0)
    return any_capped


def run_investigation_pipeline(
    case_name: str,
    investigator: str,
    selected_drive_letters: list[str] | None = None,
    selected_android: list | None = None,
    profile_name: str = "full",
    date_from: datetime | None = None,
    date_to: datetime | None = None,
    extra_paths: list[str] | None = None,
    report_dir: Path | None = None,
    config: HeliosConfig | None = None,
    on_progress: ProgressCallback | None = None,
    excluded_paths: list[str] | None = None,
    max_depth: int | None = None,
    skip_media: bool = False,
) -> dict[str, Any]:
    """
    Run the complete gated forensic pipeline.

    Args:
        case_name: Case identifier.
        investigator: Primary analyst name.
        selected_drive_letters: Drive letters/mounts to scan; None scans all.
        profile_name: Investigation profile ('exfiltration', 'employee_exit',
            'incident_response' or 'full').
        date_from / date_to: Optional event date boundaries.
        extra_paths: Additional paths (e.g. disk images for fls recovery).
        report_dir: Directory for the HTML report (defaults to ./reports).
        config: HeliosConfig; loaded when None.
        on_progress: Optional callback (label, percent 0-100).

    Returns:
        Dict with 'investigation' and 'report_path'.
    """
    config = config or load_config()
    log_tool_inventory()

    if on_progress:
        on_progress("Detecting drives & devices", 2.0)

    all_drives = detector.detect_drives()
    if selected_drive_letters:
        target_drives = [d for d in all_drives if d.drive_letter in selected_drive_letters]
    else:
        target_drives = all_drives
    local_device = detector.get_local_device()

    events: list[DataEvent] = []
    alerts: list = []
    file_records: list[FileRecord] = []
    correlations: list[dict[str, Any]] = []

    scan_options = ScanOptions(
        drives=[d.drive_letter for d in target_drives],
        paths=extra_paths or [],
        date_from=date_from,
        date_to=date_to,
        profile_name=profile_name,
        excluded_paths=excluded_paths or [],
        max_depth=max_depth,
        skip_media=skip_media,
    )

    # Profile-driven module gating
    profile_mgr = ProfileManager(config.investigation_profiles or {})
    profile_modules = profile_mgr.enabled_modules(profile_name)
    scan_options.modules_enabled = profile_modules
    module_enabled = lambda key: profile_mgr.is_module_enabled(profile_name, key)

    module_results: list[dict[str, Any]] = []

    def _run_module(key: str, label: str, events_out: list, alerts_out: list, fn, file_records_out: list | None = None) -> None:
        """Execute one gated module and record its outcome in module_results."""
        if not module_enabled(key):
            module_results.append({
                "key": key, "label": label, "status": "disabled",
                "events": 0, "alerts": 0, "files": 0, "detail": "Module not part of the selected profile",
            })
            return
        before_e, before_a = len(events_out), len(alerts_out)
        before_f = len(file_records_out) if file_records_out is not None else 0
        try:
            fn()
            files_found = (len(file_records_out) - before_f) if file_records_out is not None else 0
            detail = f"{files_found} file(s) recovered" if files_found > 0 else ""
            module_results.append({
                "key": key, "label": label, "status": "ran",
                "events": len(events_out) - before_e,
                "alerts": len(alerts_out) - before_a,
                "files": files_found,
                "detail": detail,
            })
        except ModuleSkipped as exc:
            # The scanned volume simply doesn't contain this artifact type —
            # not an error. Recorded distinctly so the report explains WHY
            # a section is empty without looking like a malfunction.
            logger.info("Module %s (%s) skipped: %s", key, label, exc)
            module_results.append({
                "key": key, "label": label, "status": "skipped",
                "events": 0, "alerts": 0, "files": 0,
                "detail": str(exc),
            })
        except Exception as exc:  # noqa: BLE001 - pipeline must never abort
            logger.warning("Module %s (%s) encountered an issue: %s", key, label, exc)
            logger.debug("Traceback for module %s (%s):", key, label, exc_info=True)
            module_results.append({
                "key": key, "label": label, "status": "failed",
                "events": len(events_out) - before_e,
                "alerts": len(alerts_out) - before_a,
                "files": 0,
                "detail": f"{type(exc).__name__}: {exc}",
            })

    # Map scanned drives to Device objects so files found on removable
    # media are attributed to a real USB device. Without this,
    # cross-device hash matching can never trigger and the data
    # movement graph stays empty.
    drive_devices: dict[str, Device] = {}
    device_list: list[Device] = [local_device]
    # Include Android devices selected by the user
    if selected_android:
        for android_dev in selected_android:
            if android_dev not in device_list:
                device_list.append(android_dev)
    for drv in target_drives:
        if drv.drive_letter == local_device.drive_letter:
            drive_devices[drv.drive_letter] = local_device
            continue
        if drv.is_removable or drv.drive_type == DriveType.USB:
            usb_dev = Device(
                device_type=DeviceType.USB,
                device_name=drv.label or f"USB Drive {drv.drive_letter}",
                serial_number=drv.device_serial or "",
                drive_letter=drv.drive_letter,
                mount_point=drv.drive_letter,
                filesystem_type=drv.filesystem,
                capacity=drv.total_size,
            )
            drive_devices[drv.drive_letter] = usb_dev
            device_list.append(usb_dev)
        else:
            drive_devices[drv.drive_letter] = local_device

    device_types: dict[str, str] = {
        d.device_id: d.device_type.value for d in device_list
    }

    # One artifact-collection scope per scanned volume so analyzers parse
    # the evidence drive's own Users/Prefetch/Winevt directories instead of
    # silently falling back to the host system root.
    artifact_scope = _scope_devices(target_drives, drive_devices, local_device)

    # 1. Live filesystem walk
    walk_capped = _run_walk(target_drives, drive_devices, file_records, events, on_progress, scan_options)

    # 2-8. Gated analyzer modules
    _run_module("usb_transfers", "USB History Analyzer", events, alerts,
                lambda: _usb_history_module(scan_options, local_device, events))
    if on_progress:
        on_progress("Analyzing Windows artifacts", 35.0)

    _run_module("file_deletions", "Recycle Bin Analyzer", events, alerts,
                lambda: _recycle_bin_module(scan_options, local_device, events))
    _run_module("recent_file_access", "LNK & JumpLists Analyzer", events, alerts,
                lambda: _lnk_jumplist_module(scan_options, artifact_scope, events))
    _run_module("event_logs", "Event Logs Analyzer", events, alerts,
                lambda: _event_logs_module(scan_options, artifact_scope, events, alerts))
    _run_module("program_execution", "Prefetch Execution Analyzer", events, alerts,
                lambda: _prefetch_module(scan_options, artifact_scope, events, alerts))
    _run_module("shellbags", "ShellBags Analyzer", events, alerts,
                lambda: _shellbags_module(scan_options, artifact_scope, events, alerts))

    # Resolve report directory early so MFT/USN modules write to the
    # investigation output directory rather than the process CWD.
    reports_dir = report_dir or (Path.cwd() / "reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # MFT + USN Journal (NTFS deep analysis — requires MFTECmd)
    _run_module("mft_analysis", "MFT Analyzer (MFTECmd)", events, alerts,
                lambda: _mft_module(scan_options, target_drives, drive_devices, events, alerts, report_dir=reports_dir))
    _run_module("usn_journal", "USN Journal Analyzer (MFTECmd)", events, alerts,
                lambda: _usn_journal_module(scan_options, target_drives, drive_devices, events, report_dir=reports_dir))

    _run_module("deleted_file_recovery", "SleuthKit Deleted-File Recovery", events, alerts,
                lambda: _sleuthkit_module(scan_options, target_drives, local_device, file_records, events, drive_devices),
                file_records_out=file_records)

    # 9. Suspicious heuristics + event rules
    _run_module("suspicious_files", "Suspicious Files & File-Type Verifier", events, alerts,
                lambda: _suspicious_module(scan_options, file_records, alerts, events, device_types, config))
    if on_progress:
        on_progress("Correlating events & building report", 70.0)

    # 10. Cross-device correlation
    _run_module("cross_device_matching", "Cross-Device Correlator", events, alerts,
                lambda: _correlator_module(case_name, investigator, device_list, target_drives, events, file_records, alerts, correlations, module_results))

    # Filter events and file_records by user-specified date range (date_from / date_to)
    if scan_options.date_from or scan_options.date_to:
        d_from = scan_options.date_from
        d_to = scan_options.date_to
        if d_from and d_from.tzinfo is not None:
            d_from = d_from.replace(tzinfo=None)
        if d_to and d_to.tzinfo is not None:
            d_to = d_to.replace(tzinfo=None)

        def _ts_in_range(ts: datetime | None) -> bool:
            if ts is None:
                return True
            if ts.tzinfo is not None:
                ts = ts.replace(tzinfo=None)
            if d_from and ts < d_from:
                return False
            if d_to and ts > d_to:
                return False
            return True

        events[:] = [e for e in events if _ts_in_range(getattr(e, "timestamp", None))]
        file_records[:] = [
            f for f in file_records
            if getattr(f, "is_deleted", False)
            or _ts_in_range(getattr(f, "modified", None))
            or _ts_in_range(getattr(f, "created", None))
            or _ts_in_range(getattr(f, "accessed", None))
        ]

    # Populate Chain of Custody entries
    now = datetime.now(tz=timezone.utc)
    ran_modules = [m for m in module_results if m.get("status") == "ran"]
    custody_log = [
        CustodyEntry(
            action="Case Initialization & Drive Selection",
            timestamp=now,
            target=", ".join([d.drive_letter for d in target_drives]) or "No drives",
            result=f"Scanned {len(file_records)} active files and {len(events)} timeline events",
            tool_name="Helios Forensic Engine",
        ),
        CustodyEntry(
            action="Cryptographic Hashing & SHA-256 Digest Verification",
            timestamp=now,
            target=f"{len(file_records)} files on drive {', '.join([d.drive_letter for d in target_drives])}",
            result="SHA-256 digests generated and stored in evidence manifest",
            tool_name="helios.core.hasher (SHA-256)",
        ),
        CustodyEntry(
            action=f"Investigation Profile '{profile_name}' — Module Execution",
            timestamp=now,
            target=f"{len(ran_modules)}/{len(module_results)} modules executed",
            result="; ".join(f"{m['label']}: {m['status']}" for m in module_results) or "No modules configured",
            tool_name="ProfileManager",
        ),
        CustodyEntry(
            action="Cross-Device Correlation & Data Movement Graph Generation",
            timestamp=now,
            target=f"Case: {case_name}",
            result=f"Correlated {len(events)} events across scanned drives",
            tool_name="CrossDeviceCorrelator",
        ),
    ]

    investigation = Investigation(
        case_name=case_name,
        investigator=investigator,
        devices=device_list,
        drives_scanned=target_drives,
        events=events,
        file_records=file_records,
        alerts=alerts,
        correlations=correlations,
        chain_of_custody=custody_log,
        module_results=module_results,
        profile_name=profile_name,
        scan_options=scan_options,
    )

    # 11. Profile-specific HTML report
    from helios.reporting.report_generator import ReportGenerator

    report_file = reports_dir / f"helios_report_{sanitize_filename(case_name).replace(' ', '_')}_{profile_name}.html"

    generator = ReportGenerator(investigation, config)
    generator.generate_html_report(report_file)

    if on_progress:
        on_progress("Report generated", 100.0)

    return {"investigation": investigation, "report_path": report_file, "walk_capped": walk_capped}
