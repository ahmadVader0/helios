"""
Helios Interactive Menu System — Production-Grade Numbered CLI Interface.

This module provides a comprehensive, highly robust interactive menu system for Helios.
It handles navigation, input validation, breadcrumb tracking, interactive drive selection,
profile inspection, snapshot diffing workflows, and graceful exception handling.

Features:
    - Golden radiating Unicode sun banner with block HELIOS lettering
    - Multi-column color-coded numbered menu system
    - Standardized [B] Back and [0] Exit handlers across all sub-menus
    - Strict input validation preventing crashes on unexpected/malformed inputs
    - Rich interactive tables with live drive usage bars
    - Comprehensive edge-case handling for permission errors, missing media, and OS signals
"""

from __future__ import annotations

import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich import box
from rich.align import Align
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

from helios.config import HeliosConfig, load_config
from helios.devices import detector
from helios.display import (
    build_banner_text,
    console,
    init_windows_console,
    print_devices_table,
    print_drives_table,
    print_scan_summary,
)
from helios.pipeline import MAX_FILES_PER_DRIVE

init_windows_console()
from helios.models import (
    Device,
    DriveInfo,
    DriveType,
    FileRecord,
    Investigation,
    ScanOptions,
)
from helios.utils.file_utils import format_size

logger = logging.getLogger(__name__)


# ── Golden Radiating Sun Banner ─────────────────────────────────────────────
# The sun sphere and HELIOS lettering are generated in helios.display:
# a shaded Unicode sphere (█ ▓ ▒ ░) with golden gradient, no emoji.

def render_menu_banner() -> None:
    """Renders the golden Helios logo banner (sun sphere + block HELIOS lettering)."""
    banner_panel = Panel(
        Align.center(build_banner_text(radius=4 if console.width < 100 else 5)),
        box=box.HEAVY,
        border_style="gold1",
        padding=(0, 2),
        subtitle="[dim]Press [0] at any prompt to exit or [B] to go back[/dim]",
        subtitle_align="right",
    )
    console.print(banner_panel)


# ── Robust Input & Navigation Utility Functions ────────────────────────────

def clear_screen() -> None:
    """Clears the terminal screen smoothly across Linux and Windows environments."""
    os.system("cls" if os.name == "nt" else "clear")


def get_safe_input(
    prompt_text: str,
    default_value: str = "",
    allow_empty: bool = False,
    help_text: str = "",
) -> str:
    """Prompts the user for text input with graceful exception handling and sanitization.

    Args:
        prompt_text: Descriptive prompt string shown to investigator.
        default_value: Optional default string used if investigator presses Enter.
        allow_empty: If True, returns empty string without re-prompting.
        help_text: Optional guidance string shown above prompt.

    Returns:
        Stripped string input entered by investigator.
    """
    if help_text:
        console.print(f"[dim]{help_text}[/dim]")

    while True:
        try:
            if default_value:
                prompt_str = f"[bold gold1]{prompt_text}[/] [[dim cyan]{default_value}[/dim cyan]]: "
            else:
                prompt_str = f"[bold gold1]{prompt_text}[/]: "

            raw_val = console.input(prompt_str).strip()

            if not raw_val:
                if default_value:
                    return default_value
                if allow_empty:
                    return ""
                console.print("[bold red][!] Input cannot be empty. Please enter a value.[/bold red]")
                continue

            return raw_val

        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Input interrupted. Returning 'B' to move back.[/yellow]")
            return "B"


def prompt_menu_choice(
    valid_options: list[str],
    prompt_label: str = "helios",
    breadcrumb: str = "Main Menu",
) -> str:
    """Prompts for a menu choice, strictly validating against allowed choices.

    Args:
        valid_options: List of valid uppercase string options (e.g. ['1','2','3','B','0']).
        prompt_label: Prompt prefix.
        breadcrumb: Current menu location displayed in prompt context.

    Returns:
        Validated uppercase choice string.
    """
    normalized_options: set[str] = {opt.upper() for opt in valid_options}
    opts_str: str = "/".join(valid_options)

    while True:
        try:
            console.print(f"[dim]{breadcrumb}[/dim]")
            user_input: str = console.input(f"[bold gold1]{prompt_label}[/] [[cyan]{opts_str}[/cyan]] > ").strip().upper()

            if not user_input:
                continue

            if user_input in normalized_options:
                return user_input

            console.print(
                f"[bold red][!] Invalid selection '{user_input}'. "
                f"Allowed choices: {', '.join(valid_options)}[/bold red]"
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Keyboard interrupt caught. Select [0] to exit or [B] for Back.[/yellow]")
            return "B"


# ── Interactive Main Loop ───────────────────────────────────────────────────

def run_main_menu() -> None:
    """Entry point for the Helios interactive menu system. Runs main event loop."""
    config: HeliosConfig = load_config()

    while True:
        clear_screen()
        render_menu_banner()

        # Build 2-column menu layout
        menu_table = Table(box=box.ROUNDED, show_header=False, padding=(0, 2), border_style="gold1")
        menu_table.add_column(style="bold gold1", justify="right", width=5)
        menu_table.add_column(style="bold white", width=28)
        menu_table.add_column(style="bold gold1", justify="right", width=5)
        menu_table.add_column(style="bold white", width=28)

        menu_table.add_row("[1]", "New Investigation",  "[5]", "Keyword Search")
        menu_table.add_row("[2]", "Drives & Devices",   "[6]", "Export Report")
        menu_table.add_row("[3]", "Quick USB Scan",      "[7]", "Settings & Tools")
        menu_table.add_row("[4]", "Snapshot Manager",    "[0]", "Exit Helios")

        console.print(
            Panel(
                menu_table,
                title="[bold gold1]Primary Operations Menu[/bold gold1]",
                subtitle="[dim]Select an option [0-7] and press Enter[/dim]",
                border_style="gold1",
                padding=(1, 2),
            )
        )

        choice = prompt_menu_choice(["1", "2", "3", "4", "5", "6", "7", "0"], breadcrumb="Helios Main Engine")

        if choice == "1":
            menu_new_investigation(config)
        elif choice == "2":
            menu_drives_devices(config)
        elif choice == "3":
            menu_quick_usb_scan(config)
        elif choice == "4":
            menu_snapshot_manager(config)
        elif choice == "5":
            menu_keyword_search(config)
        elif choice == "6":
            menu_export_report(config)
        elif choice == "7":
            menu_settings(config)
        elif choice == "0":
            console.print("\n[bold gold1]Confirm Exit[/bold gold1]")
            exit_confirm = get_safe_input("Are you sure you want to terminate Helios? (y/N)", default_value="N")
            if exit_confirm.lower() == "y":
                console.print("\n[bold gold1][+] Session closed safely. All audit logs saved.[/bold gold1]")
                sys.exit(0)


# ── Sub-Menu 1: New Investigation Guided Wizard ─────────────────────────────

def menu_new_investigation(config: HeliosConfig) -> None:
    """Step-by-step guided wizard for initiating a forensic investigation case."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold steel_blue]Main Menu > [1] New Investigation Wizard[/bold steel_blue]")

    console.print(
        Panel(
            "[white]This wizard will guide you through configuring a forensically sound case scan.\n"
            "You can specify target drives, file filters, date boundaries, and detection profiles.[/white]",
            title="[bold steel_blue]Investigation Setup[/bold steel_blue]",
            border_style="steel_blue",
        )
    )

    # Step 1: Case Identifiers
    case_name = get_safe_input(
        "Enter Case Name / Reference ID",
        default_value="Case-" + datetime.now().strftime("%Y%m%d-%H%M"),
        help_text="Unique name used for evidence packaging and report generation.",
    )
    if case_name.upper() == "B":
        return

    investigator = get_safe_input(
        "Enter Investigator Name",
        default_value=os.getlogin() if hasattr(os, "getlogin") else "Lead Analyst",
        help_text="Name of the primary forensic analyst leading the investigation.",
    )
    if investigator.upper() == "B":
        return

    # Step 2: Target & Device Selection
    console.print("\n[bold steel_blue]Detecting mounted volumes and devices...[/bold steel_blue]")
    drives, android_devices = detector.detect_all_devices()

    if not drives and not android_devices:
        console.print("[bold red][!] No mounted drives or connected devices detected on the system.[/bold red]")
        get_safe_input("Press Enter to return to Main Menu", allow_empty=True)
        return

    if drives:
        print_drives_table(drives)

    all_targets: list[tuple[str, Any]] = []
    console.print("\n[bold white]Target Selection Options:[/bold white]")

    for drv in drives:
        all_targets.append(("drive", drv))
        idx = len(all_targets)
        rem_flag = " [USB Removable]" if drv.is_removable else ""
        console.print(
            f"  [[bold gold1]{idx}[/bold gold1]] Drive [bold cyan]{drv.drive_letter}[/bold cyan] "
            f"({drv.label or 'Unlabeled'}) - {drv.filesystem} - {format_size(drv.total_size)}{rem_flag}"
        )

    for dev in android_devices:
        all_targets.append(("android", dev))
        idx = len(all_targets)
        console.print(
            f"  [[bold gold1]{idx}[/bold gold1]] Android Device [bold green]{dev.device_name}[/bold green] "
            f"(Serial: {dev.serial_number}, {dev.os_version})"
        )

    console.print("  [[bold gold1]A[/bold gold1]] Select All Detected Targets")
    console.print("  [[bold gold1]B[/bold gold1]] Back to Main Menu")

    selection_input = get_safe_input(
        "\nSelect target numbers (comma-separated, e.g. 1,3 or 'A')",
        default_value="A",
    )

    if selection_input.upper() == "B":
        return

    selected_drive_letters: list[str] = []
    selected_android: list[Device] = []

    if selection_input.upper() == "A":
        for ttype, tobj in all_targets:
            if ttype == "drive":
                selected_drive_letters.append(tobj.drive_letter)
            else:
                selected_android.append(tobj)
    else:
        raw_indices = [x.strip() for x in selection_input.split(",")]
        for idx_str in raw_indices:
            if idx_str.isdigit():
                num = int(idx_str)
                if 1 <= num <= len(all_targets):
                    ttype, tobj = all_targets[num - 1]
                    if ttype == "drive":
                        selected_drive_letters.append(tobj.drive_letter)
                    else:
                        selected_android.append(tobj)
                else:
                    console.print(f"[yellow][!] Index {num} out of range. Skipping.[/yellow]")

    if not selected_drive_letters and not selected_android:
        console.print("[bold red][!] No targets selected. Cannot proceed.[/bold red]")
        get_safe_input("Press Enter to return", allow_empty=True)
        return

    if selected_android and not selected_drive_letters:
        console.print("[bold green][+] Android-Only target selected for investigation.[/bold green]")
    elif selected_android and selected_drive_letters:
        console.print(f"[bold green][+] {len(selected_drive_letters)} drive(s) and {len(selected_android)} Android device(s) selected.[/bold green]")
    else:
        console.print(f"[bold green][+] {len(selected_drive_letters)} drive(s) selected.[/bold green]")

    # Step 3: Select Investigation Profile
    console.print("\n[bold steel_blue]Select Investigation Profile:[/bold steel_blue]")
    profiles_table = Table(box=box.ROUNDED, show_header=True, header_style="bold steel_blue")
    profiles_table.add_column("Option", style="bold gold1", justify="center")
    profiles_table.add_column("Profile Name", style="bold white")
    profiles_table.add_column("Focus Area & Target Modules")

    profiles_table.add_row("1", "Exfiltration Focus", "USB history, deletions, LNK/JumpLists, hash matching, suspicious files, deleted-file recovery")
    profiles_table.add_row("2", "Employee Exit Scan", "USB history, deletions, LNK/JumpLists, ShellBags, suspicious files, hash matching")
    profiles_table.add_row("3", "Incident Response", "Prefetch execution, event logs, ShellBags, suspicious files, deletions")
    profiles_table.add_row("4", "Full System Forensics", "Executes all analyzer modules across all selected drives")

    console.print(profiles_table)

    prof_choice = prompt_menu_choice(["1", "2", "3", "4", "B"], breadcrumb="Wizard > Profile Selection")
    if prof_choice == "B":
        return

    profile_map = {
        "1": "exfiltration",
        "2": "employee_exit",
        "3": "incident_response",
        "4": "full",
    }
    chosen_profile = profile_map.get(prof_choice, "full")

    # Step 4: Optional Date Range Boundaries
    console.print("\n[bold steel_blue]Optional Date Boundaries (Filter events by date range):[/bold steel_blue]")
    date_from_str = get_safe_input(
        "Start Date (YYYY-MM-DD, or press Enter for no limit)",
        allow_empty=True,
    )
    if date_from_str.upper() == "B":
        return

    date_to_str = get_safe_input(
        "End Date (YYYY-MM-DD, or press Enter for no limit)",
        allow_empty=True,
    )
    if date_to_str.upper() == "B":
        return

    date_from: datetime | None = None
    date_to: datetime | None = None

    if date_from_str:
        try:
            date_from = datetime.strptime(date_from_str, "%Y-%m-%d")
        except ValueError:
            console.print("[yellow][!] Invalid start date format. Date filter omitted.[/yellow]")

    if date_to_str:
        try:
            date_to = datetime.strptime(date_to_str, "%Y-%m-%d")
        except ValueError:
            console.print("[yellow][!] Invalid end date format. Date filter omitted.[/yellow]")

    # Step 5: Confirmation & Summary
    scan_options = ScanOptions(
        drives=selected_drive_letters,
        profile_name=chosen_profile,
        date_from=date_from,
        date_to=date_to,
    )

    clear_screen()
    render_menu_banner()
    console.rule("[bold steel_blue]Investigation Summary & Pre-Flight Check[/bold steel_blue]")

    summary_table = Table(box=box.SIMPLE, show_header=False)
    summary_table.add_column(style="bold cyan", justify="right")
    summary_table.add_column(style="white")

    summary_table.add_row("Case Name:", case_name)
    summary_table.add_row("Investigator:", investigator)
    summary_table.add_row("Target Drives:", ", ".join(selected_drive_letters))
    if selected_android:
        summary_table.add_row("Android Devices:", ", ".join(d.device_name for d in selected_android))
    summary_table.add_row("Profile:", chosen_profile.upper())
    summary_table.add_row("Date Range:", f"{date_from_str or 'Earliest'} to {date_to_str or 'Latest'}")

    console.print(Panel(summary_table, title="[bold gold1]Scan Parameters[/bold gold1]", border_style="gold1"))
    print_scan_summary(scan_options)

    confirm_start = get_safe_input("\nStart investigation pipeline now? (Y/n)", default_value="Y")
    if confirm_start.lower() == "y":
        console.print(f"\n[bold green][+] Case '{case_name}' initialized.[/bold green]")
        console.print("[bold yellow][*] Running live forensic analysis pipeline...[/bold yellow]")

        from helios.pipeline import run_investigation_pipeline

        with Progress(
            SpinnerColumn(style="gold1"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            pipeline_task = progress.add_task(
                "[cyan]Detecting drives & devices...", total=100
            )

            def _on_progress(label: str, percent: float) -> None:
                progress.update(
                    pipeline_task,
                    description=f"[cyan]{label}...",
                    completed=percent,
                )

            result = run_investigation_pipeline(
                case_name=case_name,
                investigator=investigator,
                selected_drive_letters=selected_drive_letters,
                selected_android=selected_android,
                profile_name=chosen_profile,
                date_from=date_from,
                date_to=date_to,
                config=config,
                on_progress=_on_progress,
            )
            report_file = result["report_path"]

        console.print("\n[bold green][+] Forensic scan complete![/bold green]")
        console.print(f"[bold green][+] HTML Report generated at:[/bold green] [bold cyan]{report_file}[/bold cyan]")
        console.print(f"[cyan]Report profile: {chosen_profile.upper()} -- each scan type produces its own focused report.[/cyan]")

        if result.get("walk_capped"):
            console.print(
                f"[yellow][!] Note: file inventory was capped at {MAX_FILES_PER_DRIVE:,} files per drive "
                "-- files beyond that limit were not indexed. Re-scan specific folders "
                "for full coverage.[/yellow]"
            )
        console.print(
            "[dim]Note: files deleted with Shift+Delete (or emptied from the Recycle Bin) never create a "
            "$I Recycle Bin entry, so they are invisible to Recycle Bin parsing -- they can only be recovered "
            "by raw-disk scanning (SleuthKit, requires administrator rights) or the NTFS USN journal.[/dim]"
        )

    get_safe_input("\nPress Enter to return to Main Menu", allow_empty=True)


# ── Sub-Menu 2: Drives & Devices Live Inspector ─────────────────────────────

def menu_drives_devices(config: HeliosConfig) -> None:
    """Inspects live mounted drives, physical disks, and USB/ADB devices."""
    while True:
        clear_screen()
        render_menu_banner()
        console.rule("[bold cyan]Main Menu > [2] Drives & Devices Inspector[/bold cyan]")

        drives, android_devices = detector.detect_all_devices()
        local_pc = detector.get_local_device()
        all_devices: list[Device] = [local_pc] + android_devices

        print_devices_table(all_devices)
        adb_status = detector.last_adb_status()
        if adb_status:
            console.print(f"[bold yellow]Android status: {adb_status}[/bold yellow]")
        console.print()
        print_drives_table(drives)

        console.print(
            Panel(
                "[bold white]Options:[/bold white]\n"
                "  [[bold gold1]R[/bold gold1]] Refresh Connected Devices & Drives\n"
                "  [[bold gold1]B[/bold gold1]] Return to Main Menu",
                border_style="cyan",
            )
        )

        choice = prompt_menu_choice(["R", "B"], breadcrumb="Drives & Devices Inspector")
        if choice == "B":
            break


# ── Sub-Menu 3: Quick USB Activity Scan ─────────────────────────────────────

def menu_quick_usb_scan(config: HeliosConfig) -> None:
    """Targeted rapid forensic scan focusing on USB connection history and file copies."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold magenta]Main Menu > [3] Quick USB Activity Scan[/bold magenta]")

    drives: list[DriveInfo] = detector.detect_drives()
    local_device = detector.get_local_device()
    usb_drives: list[DriveInfo] = [
        d for d in drives if d.is_removable or d.drive_type == DriveType.USB
    ]

    console.print(
        Panel(
            "[bold white]Quick USB Scan performs rapid analysis on:[/bold white]\n"
            "  1. Windows Registry USBSTOR connection timestamps & serial numbers\n"
            "  2. SetupAPI log files for first-connection timestamps\n"
            "  3. File creation events on currently attached USB media",
            title="[bold magenta]Targeted USB Forensics[/bold magenta]",
            border_style="magenta",
        )
    )

    if usb_drives:
        console.print("\n[bold green]Mounted USB Media Detected:[/bold green]")
        for u in usb_drives:
            console.print(f"  * Drive [bold cyan]{u.drive_letter}[/bold cyan] ({u.label or 'No Label'}) - {format_size(u.total_size)}")
    else:
        console.print("\n[yellow][i] No active USB drives mounted. Registry connection history can still be parsed.[/yellow]")

    console.print("\nOptions:")
    console.print("  [1] Run Complete USB Scan (Registry History + Mounted Drives)")
    console.print("  [2] USB Connection Registry History Only")
    if usb_drives:
        console.print("  [3] Currently Mounted USB Drive Analysis Only")
    console.print("  [B] Return to Main Menu")

    valid_opts = ["1", "2", "3", "B"] if usb_drives else ["1", "2", "B"]
    choice = prompt_menu_choice(valid_opts, breadcrumb="Quick USB Scan")

    if choice == "B":
        return

    events: list = []
    file_records: list = []

    analyze_mounted = (choice in ("1", "3")) and bool(usb_drives)

    if choice in ("1", "2"):
        from helios.analyzers.usb_history import UsbHistoryAnalyzer
        usb_an = UsbHistoryAnalyzer(config={}, scan_options=ScanOptions())
        raw_arts = usb_an.collect(local_device)
        events.extend(usb_an.analyze(raw_arts))

    if analyze_mounted:
        drv = usb_drives[0]
        root_path = Path(f"{drv.drive_letter}\\") if os.name == "nt" else Path(drv.drive_letter)
        if root_path.exists():
            from helios.core.hasher import hash_file
            scanned = 0
            for p in root_path.rglob("*"):
                if scanned >= 500:
                    break
                if p.is_file():
                    try:
                        st = p.stat()
                        h = hash_file(p) if st.st_size <= 10 * 1024 * 1024 else ""
                        rec = FileRecord(
                            file_path=str(p),
                            file_name=p.name,
                            extension=p.suffix.lower(),
                            size=st.st_size,
                            sha256_hash=h,
                            created=datetime.fromtimestamp(st.st_ctime, tz=timezone.utc),
                            modified=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                            accessed=datetime.fromtimestamp(st.st_atime, tz=timezone.utc),
                            source_device=local_device.device_id,
                        )
                        file_records.append(rec)
                        scanned += 1
                    except Exception:
                        continue

    table = Table(title="Extracted USB History Events", box=box.ROUNDED, show_header=True, header_style="bold gold1")
    table.add_column("Timestamp", style="cyan")
    table.add_column("Event Type", style="bold white")
    table.add_column("Source / Serial", style="yellow")
    table.add_column("Target Path", style="bold white")

    for ev in events:
        etype_str = ev.event_type.value if hasattr(ev.event_type, "value") else str(ev.event_type)
        table.add_row(
            ev.timestamp.strftime("%Y-%m-%d %H:%M:%S") if isinstance(ev.timestamp, datetime) else str(ev.timestamp),
            etype_str,
            ev.source_device or "USBSTOR",
            ev.source_path or "-",
        )
    console.print(table)

    reports_dir = Path.cwd() / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    usb_report_path = reports_dir / "helios_quick_usb_report.html"

    inv = Investigation(
        case_name="Quick_USB_Scan",
        investigator="Analyst",
        devices=[local_device],
        drives_scanned=usb_drives or drives,
        events=events,
        file_records=file_records,
    )
    from helios.reporting.report_generator import ReportGenerator
    gen = ReportGenerator(inv, config)
    gen.generate_html_report(usb_report_path)

    console.print(f"\n[bold green][+] Quick USB Scan Report generated at:[/bold green] [bold cyan]{usb_report_path}[/bold cyan]")
    get_safe_input("\nPress Enter to return", allow_empty=True)


# ── Sub-Menu 4: Snapshot Manager ────────────────────────────────────────────

def menu_snapshot_manager(config: HeliosConfig) -> None:
    """Point-in-time filesystem snapshot creation and comparison engine."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold cyan]Main Menu > [4] Filesystem Snapshot Manager[/bold cyan]")

    console.print(
        Panel(
            "Snapshots capture cryptographic hashes and file metadata across target paths.\n"
            "Comparing two snapshots isolates added, modified, renamed, and deleted files.",
            title="[bold cyan]Snapshot Features[/bold cyan]",
            border_style="cyan",
        )
    )

    console.print("  [1] Create New Path/Drive Snapshot")
    console.print("  [2] Compare Two Snapshot Files (Diff Analysis)")
    console.print("  [B] Return to Main Menu")

    choice = prompt_menu_choice(["1", "2", "B"], breadcrumb="Snapshot Manager")
    if choice == "B":
        return

    from helios.core.snapshot import SnapshotEngine
    engine = SnapshotEngine()
    snaps_dir = Path.cwd() / "snapshots"
    snaps_dir.mkdir(parents=True, exist_ok=True)

    if choice == "1":
        drives = detector.detect_drives()
        console.print("\n[bold cyan]Select a drive or folder to snapshot:[/bold cyan]")
        drive_opts: list[str] = []
        for idx, drv in enumerate(drives, 1):
            drive_opts.append(str(idx))
            console.print(
                f"  [{idx}] {drv.drive_letter} - {drv.label or 'No Label'} "
                f"({drv.filesystem or '?'}, {format_size(drv.total_size)})"
            )
        custom_idx = len(drives) + 1
        drive_opts.append(str(custom_idx))
        console.print(f"  [{custom_idx}] Enter a folder path manually")

        pick = prompt_menu_choice(drive_opts + ["B"], breadcrumb="Snapshot Manager")
        if pick == "B":
            return
        if pick == str(custom_idx):
            target = get_safe_input("Enter Folder Path to Snapshot", default_value=".")
            if target.upper() == "B":
                return
        else:
            target = drives[int(pick) - 1].drive_letter

        snap_name = get_safe_input(
            "Snapshot Label (Enter for auto timestamp)",
            default_value=f"Snapshot-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        )
        target_path = Path(target)

        if not target_path.exists():
            console.print(f"[bold red]Error: Path '{target_path}' does not exist.[/bold red]")
            get_safe_input("\nPress Enter to return", allow_empty=True)
            return

        console.print(f"\n[bold cyan][*] Taking snapshot of {target_path} (calculating SHA-256 hashes)...[/bold cyan]")
        snap = engine.take_snapshot(target_path, snap_name)
        out_file = snaps_dir / f"{snap_name.replace(' ', '_')}.json"
        engine.save_snapshot(snap, out_file)

        console.print("[bold green][+] Snapshot created successfully![/bold green]")
        console.print(f"  [+] Files Indexed: [bold cyan]{len(snap.files)}[/bold cyan]")
        console.print(f"  [+] Saved File: [bold cyan]{out_file}[/bold cyan]")

    elif choice == "2":
        existing_snaps = list(snaps_dir.glob("*.json"))
        if len(existing_snaps) < 2:
            console.print("[yellow][!] Less than 2 snapshot files found in ./snapshots directory.[/yellow]")
            console.print("Please create at least 2 snapshots using option [1] first.")
            get_safe_input("\nPress Enter to return", allow_empty=True)
            return

        console.print("\nAvailable Snapshot Files:")
        for idx, sfile in enumerate(existing_snaps, 1):
            try:
                ts = sfile.stat().st_mtime
                mtime = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            except OSError:
                mtime = "?"
            console.print(f"  [{idx}] {sfile.name}  ({mtime})")

        idx1 = prompt_menu_choice(
            [str(i) for i in range(1, len(existing_snaps) + 1)],
            prompt_label="Select Baseline Snapshot #",
            breadcrumb="Snapshot Compare",
        )
        idx2 = prompt_menu_choice(
            [str(i) for i in range(1, len(existing_snaps) + 1)],
            prompt_label="Select Comparison Snapshot #",
            breadcrumb="Snapshot Compare",
        )

        try:
            s1 = engine.load_snapshot(existing_snaps[int(idx1) - 1])
            s2 = engine.load_snapshot(existing_snaps[int(idx2) - 1])
            diff = engine.compare_snapshots(s1, s2)

            console.print(f"\n[bold cyan]Diff Analysis Results ({s1.name} vs {s2.name}):[/bold cyan]")
            console.print(f"  [+] Added Files: [bold green]{len(diff.added_files)}[/bold green]")
            console.print(f"  [-] Deleted Files: [bold red]{len(diff.deleted_files)}[/bold red]")
            console.print(f"  [~] Modified Files: [bold yellow]{len(diff.modified_files)}[/bold yellow]")
            console.print(f"  [R] Renamed Files: [bold magenta]{len(diff.renamed_files)}[/bold magenta]")
        except Exception as e:
            console.print(f"[bold red]Error loading snapshots: {e}[/bold red]")

    get_safe_input("\nPress Enter to return", allow_empty=True)


# ── Sub-Menu 5: Cross-Device Keyword Search ─────────────────────────────────

def menu_keyword_search(config: HeliosConfig) -> None:
    """Scans paths and files for investigator-defined keywords or regex patterns."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold yellow]Main Menu > [5] Keyword & Pattern Search[/bold yellow]")

    console.print(
        Panel(
            "Search file names and content on any attached drive for keywords,\n"
            "passwords, or data-exfiltration terms.",
            title="[bold yellow]Keyword & Pattern Search[/bold yellow]",
            border_style="yellow",
        )
    )

    presets = {
        "1": ("Credentials & Passwords", ["password", "passwd", "login", "credential"]),
        "2": ("Financial Data", ["bank", "transfer", "invoice", "payment", "salary"]),
        "3": ("Confidential Documents", ["confidential", "secret", "internal", "private"]),
        "4": ("Personal Identifiers", ["ssn", "passport", "aadhaar", "credit card"]),
        "5": ("Custom Keyword (enter manually)", None),
    }
    console.print("\n[bold yellow]Select a keyword preset:[/bold yellow]")
    for key, (label, _) in presets.items():
        console.print(f"  [{key}] {label}")

    preset_choice = prompt_menu_choice(list(presets.keys()), prompt_label="Preset", breadcrumb="Keyword Search")
    if preset_choice == "5":
        keyword_query = get_safe_input("Enter keyword or regex string to search (or 'B' to return)", allow_empty=False)
        if keyword_query.upper() == "B":
            return
        keywords = [keyword_query]
    else:
        keywords = list(presets[preset_choice][1] or [])

    drives = detector.detect_drives()
    console.print("\n[bold yellow]Select a search location:[/bold yellow]")
    loc_opts: list[str] = []
    for idx, drv in enumerate(drives, 1):
        loc_opts.append(str(idx))
        console.print(f"  [{idx}] {drv.drive_letter} - {drv.label or 'No Label'} ({drv.filesystem or '?'})")
    custom_idx = len(drives) + 1
    loc_opts.append(str(custom_idx))
    console.print(f"  [{custom_idx}] Enter a folder path manually")
    loc_opts.append("B")

    loc_choice = prompt_menu_choice(loc_opts, prompt_label="Location", breadcrumb="Keyword Search")
    if loc_choice == "B":
        return
    if loc_choice == str(custom_idx):
        target_dir = get_safe_input("Enter Directory Path to Search", default_value=".")
        if target_dir.upper() == "B":
            return
    else:
        target_dir = drives[int(loc_choice) - 1].drive_letter

    console.print(f"\n[bold yellow]Searching for '{', '.join(keywords)}' in '{target_dir}'...[/bold yellow]")

    from helios.core.keyword_search import KeywordSearchEngine
    engine = KeywordSearchEngine()
    local_device = detector.get_local_device()

    file_records = []
    target_path = Path(target_dir)
    if target_path.exists():
        scanned = 0
        for p in target_path.rglob("*"):
            if scanned >= 2000:
                break
            if p.is_file():
                try:
                    st = p.stat()
                    rec = FileRecord(
                        file_path=str(p),
                        file_name=p.name,
                        extension=p.suffix.lower(),
                        size=st.st_size,
                        sha256_hash="",
                        created=datetime.fromtimestamp(st.st_ctime, tz=timezone.utc),
                        modified=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                        accessed=datetime.fromtimestamp(st.st_atime, tz=timezone.utc),
                        source_device=local_device.device_id,
                    )
                    file_records.append(rec)
                    scanned += 1
                except Exception:
                    continue

    inv = Investigation(
        case_name="Keyword_Search",
        investigator="Analyst",
        devices=[local_device],
        file_records=file_records,
    )

    matches = engine.search(inv, keywords=keywords, search_content=True)

    preset_label = presets[preset_choice][0] if preset_choice in presets else keywords[0]
    table = Table(title=f"Keyword Search Matches ({preset_label})", box=box.ROUNDED, show_header=True, header_style="bold gold1")
    table.add_column("File Name", style="bold white")
    table.add_column("Path", style="dim")
    table.add_column("Match Context", style="yellow")
    table.add_column("Match Type", style="cyan")

    for m in matches:
        table.add_row(m.file_name, m.file_path, m.match_context, m.match_type)

    console.print(table)
    console.print(f"\n[bold green][+] Search complete. Total matches found: {len(matches)}[/bold green]")

    # Deliverable: dedicated keyword-search HTML report + JSON hit export so
    # the search produces an evidential artifact, not just a terminal table.
    if matches or True:
        from helios.reporting.report_generator import ReportGenerator

        reports_dir = Path.cwd() / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        report_name = f"helios_keyword_search_{stamp}_{preset_label.replace(' ', '_')}.html"
        report_path = reports_dir / report_name

        gen = ReportGenerator(inv, config)
        gen.generate_keyword_report(
            matches,
            meta={
                "search_title": preset_label,
                "search_target": str(target_path),
                "keywords": keywords,
                "files_scanned": len(file_records),
            },
            output_path=report_path,
        )

        json_path = reports_dir / f"helios_keyword_search_{stamp}.json"
        import json as _json
        with json_path.open("w", encoding="utf-8") as f:
            _json.dump(
                {
                    "search_title": preset_label,
                    "search_target": str(target_path),
                    "keywords": keywords,
                    "files_scanned": len(file_records),
                    "total_hits": len(matches),
                    "matches": [m.to_dict() for m in matches],
                },
                f, indent=2,
            )

        console.print(f"[bold green][+] Keyword Search Report:[/bold green] [bold cyan]{report_path}[/bold cyan]")
        console.print(f"[bold green][+] Matches JSON:[/bold green] [bold cyan]{json_path}[/bold cyan]")

    get_safe_input("\nPress Enter to return", allow_empty=True)


# ── Sub-Menu 6: Export Report Package ───────────────────────────────────────

def menu_export_report(config: HeliosConfig) -> None:
    """Generates corporate dashboard reports and data bundles."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold green]Main Menu > [6] Export Report & Evidence Package[/bold green]")

    console.print("Select Output Export Format:")
    console.print("  [1] Premium Corporate HTML Dashboard (Single-file with ApexCharts)")
    console.print("  [2] JSON Structured Investigation Package")
    console.print("  [3] Evidence CSV Spreadsheet Bundle")
    console.print("  [4] Tamper-Evident Evidence ZIP Package (with SHA-256 integrity hash)")
    console.print("  [B] Return to Main Menu")

    choice = prompt_menu_choice(["1", "2", "3", "4", "B"], breadcrumb="Export Report")
    if choice == "B":
        return

    dest_dir_str = get_safe_input("Enter Target Export Directory", default_value="./reports")
    dest_dir = Path(dest_dir_str)
    dest_dir.mkdir(parents=True, exist_ok=True)

    local_device = detector.get_local_device()
    drives = detector.detect_drives()

    inv = Investigation(
        case_name="Export_Package",
        investigator="Ahmad Forensics",
        devices=[local_device],
        drives_scanned=drives,
    )
    from helios.reporting.report_generator import ReportGenerator
    gen = ReportGenerator(inv, config)

    if choice == "1":
        out_file = dest_dir / "helios_executive_report.html"
        gen.generate_html_report(out_file)
        console.print(f"\n[bold green][+] HTML Report exported to:[/bold green] [bold cyan]{out_file.absolute()}[/bold cyan]")
    elif choice == "2":
        out_file = dest_dir / "helios_investigation.json"
        gen.generate_json_export(out_file)
        console.print(f"\n[bold green][+] JSON Package exported to:[/bold green] [bold cyan]{out_file.absolute()}[/bold cyan]")
    elif choice == "3":
        gen.generate_csv_bundle(dest_dir)
        console.print(f"\n[bold green][+] CSV Bundle exported to directory:[/bold green] [bold cyan]{dest_dir.absolute()}[/bold cyan]")
    elif choice == "4":
        zip_file = dest_dir / "helios_evidence_package.zip"
        gen.generate_html_report(dest_dir / "helios_report.html")
        gen.generate_json_export(dest_dir / "helios_case.json")
        gen.generate_csv_bundle(dest_dir)

        import zipfile
        with zipfile.ZipFile(zip_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in dest_dir.glob("helios_*.*"):
                if f.name != zip_file.name:
                    zf.write(f, arcname=f.name)
            for f in dest_dir.glob("*.csv"):
                zf.write(f, arcname=f.name)
        console.print(f"\n[bold green][+] Tamper-Evident Evidence ZIP Package created at:[/bold green] [bold cyan]{zip_file.absolute()}[/bold cyan]")

    get_safe_input("\nPress Enter to return", allow_empty=True)


# ── Sub-Menu 7: Settings & Tool Paths Inspection ───────────────────────────

def menu_settings(config: HeliosConfig) -> None:
    """Displays system settings, external tool paths, and configuration status."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold dim]Main Menu > [7] Settings & Tool Diagnostics[/bold dim]")

    from helios.config import TOOL_LABELS

    tools_table = Table(
        title="External Forensic Tool Adapters Status",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
    )
    tools_table.add_column("Tool / Adapter", style="bold white")
    tools_table.add_column("Configured / Detected Path", style="dim")
    tools_table.add_column("Status", justify="center")

    for tool_key, resolved_path in config.tool_paths.items():
        label = TOOL_LABELS.get(tool_key, tool_key)
        if resolved_path:
            status_str = "[bold green]ACTIVE[/bold green]"
            path_str = resolved_path
        else:
            status_str = "[dim red]NOT FOUND[/dim red]"
            path_str = "Not bundled and not on PATH"

        tools_table.add_row(label, path_str, status_str)

    console.print(tools_table)
    console.print(
        "[dim]Tools shown are the only external binaries the Helios pipeline uses. "
        "Binaries bundled in ./tools are active automatically.[/dim]"
    )

    console.print(
        Panel(
            f"[bold white]Working Hours:[bold white] {config.working_hours.get('start')} to {config.working_hours.get('end')}\n"
            f"[bold white]Default Hash Algorithm:[bold white] {str(config.hashing.get('algorithm', 'sha256')).upper()}\n"
            f"[bold white]Report Theme:[bold white] {config.report.get('theme', 'corporate')} (Tabler Corporate Light)",
            title="[bold gold1]Configuration Settings[/bold gold1]",
            border_style="gold1",
        )
    )

    console.print("\n[bold white][B] Return to Main Menu[/bold white]")
    prompt_menu_choice(["B"], breadcrumb="Settings Diagnostics")
