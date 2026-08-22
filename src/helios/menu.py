"""
Helios Interactive Menu System — Production-Grade Numbered CLI Interface.

Interactive menu system for Helios.
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
    build_banner_panel,
    console,
    init_windows_console,
    print_devices_table,
    print_drives_table,
    print_scan_summary,
)

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
# a shaded Unicode sphere (█ ▓ ▒ ░) with golden gradient and responsive layout.

def render_menu_banner() -> None:
    """Renders the golden Helios logo banner with adaptive terminal sizing.

    The first draw of the session plays a brief shimmer animation across
    the sun/logo; every later draw is the classic static banner. Disable
    entirely with HELIOS_NO_ANIM=1.
    """
    from helios.display import animate_banner_once, _BANNER_ANIM_PLAYED

    if not _BANNER_ANIM_PLAYED:
        animate_banner_once()
    console.print(build_banner_panel())


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

def _safe_get_username() -> str:
    """Safely obtain current username without raising OSError in headless/TTY-less environments."""
    try:
        import getpass
        user = getpass.getuser()
        if user:
            return user
    except Exception:
        pass
    try:
        if hasattr(os, "getlogin"):
            user = os.getlogin()
            if user:
                return user
    except Exception:
        pass
    return os.environ.get("USERNAME") or os.environ.get("USER") or "Lead Analyst"


def menu_new_investigation(config: HeliosConfig) -> None:
    """Guided wizard: B goes back one step; every parameter stays editable
    from the summary screen. Invalid input re-prompts — never exits."""
    clear_screen()
    render_menu_banner()
    console.rule("[bold steel_blue]Main Menu > [1] New Investigation Wizard[/bold steel_blue]")
    console.print(
        Panel(
            "[white]Configure the case: target volumes, date bounds, detection profile.\n"
            "Enter B at any prompt to change an earlier answer.[/white]",
            title="[bold steel_blue]Investigation Setup[/bold steel_blue]",
            border_style="steel_blue",
        )
    )

    case_name = ""
    investigator = ""
    selected_drive_letters: list[str] = []
    selected_android: list[Device] = []
    chosen_profile = "full"
    date_from_str = ""
    date_to_str = ""

    labels = {0: "Case info", 1: "Targets", 2: "Profile", 3: "Dates"}
    step = 0
    back_to_summary = False

    while True:
        if step == 0:
            new_case = get_safe_input(
                "Case Name / Reference ID",
                default_value=case_name or ("Case-" + datetime.now().strftime("%Y%m%d-%H%M")),
                help_text="Used in report/evidence filenames.",
            )
            if new_case.upper() == "B":
                if back_to_summary:
                    step = 4
                    continue
                return
            who = get_safe_input("Investigator Name", default_value=investigator or _safe_get_username())
            if who.upper() == "B":
                continue  # re-ask case name
            case_name, investigator = new_case, who
            step = 1 if not back_to_summary else 4

        elif step == 1:
            console.print("\n[bold steel_blue]Detecting mounted volumes and devices...[/bold steel_blue]")
            drives, android_devices = detector.detect_all_devices()
            if not drives and not android_devices:
                console.print("[bold red][!] No mounted drives or devices detected.[/bold red]")
                get_safe_input("Press Enter to go back", allow_empty=True)
                step = 0
                continue
            all_targets: list[tuple[str, Any]] = []
            for drv in drives:
                all_targets.append(("drive", drv))
                idx = len(all_targets)
                rem = " [USB Removable]" if drv.is_removable else ""
                console.print(f"  [[bold gold1]{idx}[/bold gold1]] Drive [bold cyan]{drv.drive_letter}[/cyan] ({drv.label or 'Unlabeled'}) - {drv.filesystem} - {format_size(drv.total_size)}{rem}")
            for dev in android_devices:
                all_targets.append(("android", dev))
                console.print(f"  [[bold gold1]{len(all_targets)}[/bold gold1]] Android [bold green]{dev.device_name}[/green] ({dev.serial_number})")
            console.print("  [[bold gold1]A[/bold gold1]] All of the above")

            while True:
                sel = get_safe_input("Select targets (comma-separated, e.g. 1,3 - or A)", default_value="A")
                if sel.upper() == "B":
                    break
                raw = [x.strip() for x in sel.split(",")] if sel.upper() != "A" else []
                if sel.upper() != "A" and not raw:
                    console.print("[red][!] Enter at least one target number.[/red]")
                    continue
                picked_drives: list[str] = []
                picked_android: list[Device] = []
                bad = False
                for tok in (["A"] if sel.upper() == "A" else raw):
                    if tok.upper() == "A":
                        for ttype, tobj in all_targets:
                            (picked_drives if ttype == "drive" else picked_android).append(tobj.drive_letter if ttype == "drive" else tobj)
                        continue
                    if not tok.isdigit() or not (1 <= int(tok) <= len(all_targets)):
                        console.print(f"[red][!] '{tok}' is not a valid target number (1-{len(all_targets)}).[/red]")
                        bad = True
                        break
                    ttype, tobj = all_targets[int(tok) - 1]
                    if ttype == "drive":
                        picked_drives.append(tobj.drive_letter)
                    else:
                        picked_android.append(tobj)
                if bad:
                    continue
                selected_drive_letters, selected_android = picked_drives, picked_android
                break
            else:
                pass
            if sel.upper() == "B":
                step = 0 if not back_to_summary else 4
                continue
            if not selected_drive_letters and not selected_android:
                continue  # re-prompt same step
            step = 2 if not back_to_summary else 4

        elif step == 2:
            console.print("\n[bold steel_blue]Detection Profile:[/bold steel_blue]")
            prof_table = Table(box=box.ROUNDED, show_header=True, header_style="bold steel_blue")
            prof_table.add_column("Option", justify="center", style="bold gold1")
            prof_table.add_column("Profile", style="bold white")
            prof_table.add_column("Modules")
            prof_table.add_row("1", "Exfiltration Focus", "USB history, deletions, LNK/JumpLists, hash matching")
            prof_table.add_row("2", "Employee Exit Scan", "USB history, deletions, LNK/JumpLists, ShellBags")
            prof_table.add_row("3", "Incident Response", "Prefetch, event logs, ShellBags, deletions")
            prof_table.add_row("4", "Full System Forensics", "All modules on all selected drives")
            console.print(prof_table)
            pc = prompt_menu_choice(["1", "2", "3", "4", "B"], prompt_label="Profile", breadcrumb="Wizard")
            if pc == "B":
                step = 1 if not back_to_summary else 4
                continue
            chosen_profile = {"1": "exfiltration", "2": "employee_exit", "3": "incident_response", "4": "full"}[pc]
            step = 3 if not back_to_summary else 4

        elif step == 3:
            while True:
                d1 = get_safe_input("Start Date YYYY-MM-DD (Enter = no limit)", default_value=date_from_str, allow_empty=True)
                if d1.upper() == "B":
                    break
                d2 = get_safe_input("End Date YYYY-MM-DD (Enter = no limit)", default_value=date_to_str, allow_empty=True)
                if d2.upper() == "B":
                    break
                ok = True
                for label, val in (("Start", d1), ("End", d2)):
                    if val:
                        try:
                            datetime.strptime(val, "%Y-%m-%d")
                        except ValueError:
                            console.print(f"[red][!] {label} date '{val}' is not YYYY-MM-DD — try again.[/red]")
                            ok = False
                if not ok:
                    continue
                date_from_str, date_to_str = d1, d2
                break
            else:
                pass
            if d1.upper() == "B" or d2.upper() == "B":
                step = 2 if not back_to_summary else 4
                continue
            step = 4

        else:  # summary
            scan_options = ScanOptions(
                drives=selected_drive_letters,
                profile_name=chosen_profile,
                date_from=datetime.strptime(date_from_str, "%Y-%m-%d") if date_from_str else None,
                date_to=datetime.strptime(date_to_str, "%Y-%m-%d") if date_to_str else None,
            )
            clear_screen()
            render_menu_banner()
            console.rule("[bold steel_blue]Summary — press Enter to run, or pick a number to change it[/bold steel_blue]")
            st = Table(box=box.SIMPLE, show_header=False)
            st.add_column(style="bold cyan", justify="right")
            st.add_column(style="white")
            st.add_row("[1] Case:", f"{case_name}  ({investigator})")
            st.add_row("[2] Targets:", ", ".join(selected_drive_letters) + (", " + ", ".join(d.device_name for d in selected_android) if selected_android else ""))
            st.add_row("[3] Profile:", chosen_profile.upper())
            st.add_row("[4] Dates:", f"{date_from_str or 'Earliest'} to {date_to_str or 'Latest'}")
            console.print(Panel(st, title="[bold gold1]Scan Parameters[/gold1]", border_style="gold1"))
            print_scan_summary(scan_options)

            ans = get_safe_input("Press Enter to start, 1-4 to change a setting, C to cancel", default_value="", allow_empty=True)
            if ans.upper() == "C":
                return
            if ans in ("1", "2", "3", "4"):
                back_to_summary = True
                step = int(ans) - 1
                continue
            back_to_summary = False
            date_from = datetime.strptime(date_from_str, "%Y-%m-%d") if date_from_str else None
            date_to = datetime.strptime(date_to_str, "%Y-%m-%d") if date_to_str else None

            console.print(f"\n[bold green][+] Case '{case_name}' initialized.[/bold green]")
            from helios.pipeline import run_investigation_pipeline

            with Progress(SpinnerColumn(style="gold1"), TextColumn("[progress.description]{task.description}"), BarColumn(bar_width=40), TimeElapsedColumn(), console=console) as progress:
                task = progress.add_task("[cyan]Detecting drives & devices...", total=100)
                def _on_progress(label: str, percent: float) -> None:
                    progress.update(task, description=f"[cyan]{label}...", completed=percent)
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

            console.print("\n[bold green][+] Scan complete![/bold green]")
            console.print(f"[bold green][+] Report:[/bold green] [bold cyan]{report_file}[/bold cyan]")
            get_safe_input("\nPress Enter to return to Main Menu", allow_empty=True)
            return


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
            "Snapshot Label (Enter for auto timestamp, or 'B' to go back)",
            default_value=f"Snapshot-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        )
        if snap_name.upper() == "B":
            return
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
            [str(i) for i in range(1, len(existing_snaps) + 1)] + ["B"],
            prompt_label="Select Baseline Snapshot # (B to go back)",
            breadcrumb="Snapshot Compare",
        )
        if idx1 == "B":
            return
        idx2 = prompt_menu_choice(
            [str(i) for i in range(1, len(existing_snaps) + 1)] + ["B"],
            prompt_label="Select Comparison Snapshot # (B to go back)",
            breadcrumb="Snapshot Compare",
        )
        if idx2 == "B":
            return

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
    console.print("  [B] Return to Main Menu")

    preset_choice = prompt_menu_choice(list(presets.keys()) + ["B"], prompt_label="Preset", breadcrumb="Keyword Search")
    if preset_choice == "B":
        return
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
        from helios.display import esc_markup

        table.add_row(esc_markup(m.file_name), esc_markup(m.file_path), esc_markup(m.match_context), esc_markup(m.match_type))

    console.print(table)
    console.print(f"\n[bold green][+] Search complete. Total matches found: {len(matches)}[/bold green]")

    # Deliverable: dedicated keyword-search HTML report + JSON hit export so
    # the search produces an evidential artifact, not just a terminal table.
    if matches:
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
    console.print("  [1] HTML Report (single file, charts embedded)")
    console.print("  [2] JSON Structured Investigation Package")
    console.print("  [3] Evidence CSV Spreadsheet Bundle")
    console.print("  [4] Tamper-Evident Evidence ZIP Package (with SHA-256 integrity hash)")
    console.print("  [B] Return to Main Menu")

    choice = prompt_menu_choice(["1", "2", "3", "4", "B"], breadcrumb="Export Report")
    if choice == "B":
        return

    dest_dir_str = get_safe_input("Enter Target Export Directory (or 'B' to go back)", default_value="./reports")
    if dest_dir_str.upper() == "B":
        return
    dest_dir = Path(dest_dir_str)
    dest_dir.mkdir(parents=True, exist_ok=True)

    local_device = detector.get_local_device()
    drives = detector.detect_drives()

    inv = Investigation(
        case_name="Export_Package",
        investigator="Unknown Analyst",
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
