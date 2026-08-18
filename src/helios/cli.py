"""
Helios CLI Entry Point — Supports direct command flags and interactive menu mode.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import click

from helios.display import (
    print_alerts,
    print_banner,
    print_devices_table,
    print_drives_table,
    print_event_timeline,
    print_investigation_summary,
    print_progress_header,
    print_scan_summary,
    print_status,
)
from helios.models import (
    Device,
    ScanOptions,
)


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """Helios — Data Movement Forensics across live devices."""
    if ctx.invoked_subcommand is None:
        from helios.menu import run_main_menu
        run_main_menu()


@main.command("menu")
def menu_cmd() -> None:
    """Launch the interactive numbered menu."""
    from helios.menu import run_main_menu
    run_main_menu()


# ── drives ──────────────────────────────────────────────────────────────────

@main.command("drives")
def drives_cmd() -> None:
    """Detect and display all mounted drives and partitions."""
    print_banner()
    try:
        from helios.devices.detector import detect_drives

        drives = detect_drives()
        if drives:
            print_drives_table(drives)
        else:
            print_status("No drives detected.", "warning")
    except ImportError:
        print_status("Device detector module not available.", "error")
    except Exception as exc:
        print_status(f"Error detecting drives: {exc}", "error")


# ── devices ─────────────────────────────────────────────────────────────────

@main.command("devices")
def devices_cmd() -> None:
    """Detect and display all connected devices (PC, USB, Android)."""
    print_banner()
    try:
        from helios.devices.detector import detect_all_devices, get_local_device, last_adb_status

        local = get_local_device()
        drives, android_devices = detect_all_devices()
        all_devices: list[Device] = [local] + android_devices

        print_progress_header("Connected Devices")
        print_devices_table(all_devices)
        adb_status = last_adb_status()
        if adb_status:
            print_status(f"Android status: {adb_status}", "warning")

        print_progress_header("Mounted Drives")
        print_drives_table(drives)
    except ImportError:
        print_status("Device detector module not available.", "error")
    except Exception as exc:
        print_status(f"Error detecting devices: {exc}", "error")


# ── investigate ─────────────────────────────────────────────────────────────

@main.command("investigate")
@click.option("--case", "-c", required=True, help="Case name.")
@click.option("--drives", "-d", default=None, help="Comma-separated drive letters / mount points.")
@click.option("--path", "-p", default=None, help="Specific folder path to scan.")
@click.option("--from-date", default=None, help="Start date (YYYY-MM-DD).")
@click.option("--to-date", default=None, help="End date (YYYY-MM-DD).")
@click.option("--filetypes", "-t", default=None, help="Comma-separated file extensions.")
@click.option("--keywords", "-k", default=None, help="Comma-separated keywords to search.")
@click.option("--exclude", default=None, help="Comma-separated paths to exclude.")
@click.option("--depth", type=int, default=None, help="Max directory depth.")
@click.option("--skip-media", is_flag=True, default=False, help="Skip large media files.")
@click.option(
    "--profile",
    type=click.Choice(["exfiltration", "employee-exit", "incident-response", "full"]),
    default="full",
    help="Investigation profile.",
)
@click.option("--all-devices", is_flag=True, default=False, help="Scan all connected devices.")
@click.option("--interactive", "-i", is_flag=True, default=False, help="Launch interactive wizard.")
def investigate_cmd(
    case: str,
    drives: str | None,
    path: str | None,
    from_date: str | None,
    to_date: str | None,
    filetypes: str | None,
    keywords: str | None,
    exclude: str | None,
    depth: int | None,
    skip_media: bool,
    profile: str,
    all_devices: bool,
    interactive: bool,
) -> None:
    """Start a forensic investigation on selected devices and drives."""
    if interactive:
        from helios.config import load_config
        from helios.menu import menu_new_investigation
        menu_new_investigation(load_config())
        return

    print_banner()

    # CLI accepts dash-forms ('incident-response'); profile keys use underscores.
    profile = profile.replace("-", "_")

    date_from = datetime.strptime(from_date, "%Y-%m-%d") if from_date else None
    date_to = datetime.strptime(to_date, "%Y-%m-%d") if to_date else None

    drive_list = drives.split(",") if drives else None
    if drive_list:
        drive_list = [d.strip().upper().rstrip(":\\") + ":" for d in drive_list if d.strip()]
        if not drive_list:
            click.echo("Error: no valid drive letters after normalization.", err=True)
            raise SystemExit(1)
    path_list = path.split(",") if path else []
    extra_paths = path_list or None

    scan_options = ScanOptions(
        drives=drive_list or [],
        paths=path_list,
        date_from=date_from,
        date_to=date_to,
        file_types=filetypes.split(",") if filetypes else [],
        keywords=keywords.split(",") if keywords else [],
        excluded_paths=exclude.split(",") if exclude else [],
        max_depth=depth,
        skip_media=skip_media,
        profile_name=profile,
    )

    print_progress_header(f"Investigation: {case}")
    print_scan_summary(scan_options)

    from helios.pipeline import run_investigation_pipeline

    def _on_progress(label: str, percent: float) -> None:
        print_status(f"[{percent:3.0f}%] {label}", "info")

    result = run_investigation_pipeline(
        case_name=case,
        investigator="Analyst",
        selected_drive_letters=drive_list if drive_list and not all_devices else None,
        profile_name=profile,
        date_from=date_from,
        date_to=date_to,
        extra_paths=extra_paths,
        config=None,
        on_progress=_on_progress,
    )

    investigation = result["investigation"]

    print_progress_header("Detected Drives")
    print_drives_table(investigation.drives_scanned)

    print_progress_header("Connected Devices")
    print_devices_table(investigation.devices)

    print_progress_header("Event Timeline")
    print_event_timeline(investigation.events)

    print_progress_header("Alerts")
    print_alerts(investigation.alerts)

    print_progress_header("Investigation Summary")
    print_investigation_summary(investigation)

    if result.get("walk_capped"):
        print_status("Warning: file walk hit the per-drive cap -- results may be partial.", "warning")
    print_status(f"HTML report: {result['report_path']}", "success")


# ── keyword-search ──────────────────────────────────────────────────────────

@main.command("keyword-search")
@click.option("--keywords", "-k", required=True, help="Comma-separated keywords to search.")
@click.option("--path", "-p", required=True, help="Folder path to search.")
@click.option("--output", "-o", default=None, help="Output directory for report + JSON (defaults to ./reports).")
@click.option("--title", default=None, help="Optional search title for the report.")
def keyword_search_cmd(keywords: str, path: str, output: str | None, title: str | None) -> None:
    """Search a folder for exfiltration-related keywords and produce an evidence report."""
    from helios.core.keyword_search import KeywordSearchEngine
    from helios.devices import detector
    from helios.models import FileRecord, Investigation
    from helios.reporting.report_generator import ReportGenerator

    print_banner()
    kw = [k.strip() for k in keywords.split(",") if k.strip()]
    target = Path(path)
    if not kw:
        raise click.UsageError("At least one keyword is required.")
    if not target.is_dir():
        raise click.UsageError(f"Search path is not a directory: {path}")

    local_device = detector.get_local_device()
    file_records: list[FileRecord] = []
    for p in target.rglob("*"):
        if p.is_file():
            try:
                st = p.stat()
                file_records.append(
                    FileRecord(
                        file_path=str(p),
                        file_name=p.name,
                        extension=p.suffix.lower(),
                        size=st.st_size,
                        sha256_hash="",
                        created=datetime.fromtimestamp(st.st_ctime),
                        modified=datetime.fromtimestamp(st.st_mtime),
                        accessed=datetime.fromtimestamp(st.st_atime),
                        source_device=local_device.device_id,
                    )
                )
            except Exception:
                continue

    inv = Investigation(
        case_name="Keyword_Search",
        investigator="Analyst",
        devices=[local_device],
        file_records=file_records,
    )
    matches = KeywordSearchEngine().search(inv, keywords=kw, search_content=True)

    out_dir = Path(output) if output else Path.cwd() / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    label = title or kw[0]
    report_path = out_dir / f"helios_keyword_search_{stamp}_{label.replace(' ', '_')}.html"
    ReportGenerator(inv, None).generate_keyword_report(
        matches,
        meta={
            "search_title": label,
            "search_target": str(target),
            "keywords": kw,
            "files_scanned": len(file_records),
        },
        output_path=report_path,
    )

    import json as _json
    json_path = out_dir / f"helios_keyword_search_{stamp}.json"
    with json_path.open("w", encoding="utf-8") as f:
        _json.dump(
            {
                "search_title": label,
                "search_target": str(target),
                "keywords": kw,
                "files_scanned": len(file_records),
                "total_hits": len(matches),
                "matches": [m.to_dict() for m in matches],
            },
            f, indent=2,
        )

    print_progress_header("Keyword Search Matches")
    for m in matches:
        print_status(f"{m.match_type.upper():>10} | {m.file_path} | {m.match_context[:120]}", "info")
    print_status(f"Total matches: {len(matches)} of {len(file_records)} files scanned", "success")
    print_status(f"HTML report: {report_path}", "success")
    print_status(f"JSON export: {json_path}", "success")


# ── demo ────────────────────────────────────────────────────────────────────

@main.command("demo")
@click.option("--output", "-o", default=None, help="Output directory for demo report and exports.")
def demo_cmd(output: str | None) -> None:
    """Run demo mode with sample data to preview Helios output."""
    from helios.demo import run_demo_pipeline

    print_banner()

    output_dir = Path(output) if output else None
    result = run_demo_pipeline(output_dir)
    investigation = result["investigation"]
    events = investigation.events
    alerts = investigation.alerts
    file_records = investigation.file_records
    devices = investigation.devices
    drives = investigation.drives_scanned

    print_progress_header("Detected Drives")
    print_drives_table(drives)

    print_progress_header("Connected Devices")
    print_devices_table(devices)

    print_progress_header("Event Timeline")
    print_event_timeline(events)

    print_progress_header("Alerts")
    print_alerts(alerts)

    print_progress_header("Investigation Summary")
    print_investigation_summary(investigation)

    print_status(f"Demo pipeline complete -- {len(events)} events, {len(alerts)} alerts, {len(file_records)} files indexed.", "success")
    print_status(f"HTML report: {result['report_path']}", "success")
    print_status(f"Exports: {result['exports_dir']} | Evidence ZIP: {result['zip_path']} | Custody log: {result['custody_path']}", "success")


if __name__ == "__main__":
    import sys
    try:
        main()
    except Exception as err:
        import traceback
        print("\n" + "=" * 60)
        print("  HELIOS FATAL ERROR LOGGED")
        print("=" * 60)
        print(f"Error: {err}\n")
        traceback.print_exc()
        print("=" * 60)
        try:
            input("\nPress Enter to exit...")
        except (EOFError, KeyboardInterrupt):
            pass
    else:
        if getattr(sys, "frozen", False):
            try:
                input("\nPress Enter to exit...")
            except (EOFError, KeyboardInterrupt):
                pass
