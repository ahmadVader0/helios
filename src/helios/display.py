"""Helios display module — Rich terminal output for forensic data."""

from __future__ import annotations

import math
import sys

from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from helios.models import (
    Alert,
    Confidence,
    DataEvent,
    Device,
    DriveInfo,
    EventType,
    FileRecord,
    Investigation,
    RecoveryStatus,
    ScanOptions,
    Severity,
)
from helios.utils.file_utils import format_size


# ── Windows Console UTF-8 Initializer ──────────────────────────────────────

def init_windows_console() -> None:
    """Ensure Windows console is configured for UTF-8 code page (65001).

    Prevents Unicode characters and icons from rendering as question marks '?'
    on standard Windows CMD, PowerShell, and compiled PyInstaller executables.
    """
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleOutputCP(65001)
            ctypes.windll.kernel32.SetConsoleCP(65001)
        except Exception:
            pass
        try:
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            if hasattr(sys.stdin, "reconfigure"):
                sys.stdin.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


init_windows_console()

# ── Module-level console ────────────────────────────────────────────────────

console = Console(highlight=False, legacy_windows=False)

# ── Color maps ──────────────────────────────────────────────────────────────

SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

EVENT_STYLES: dict[EventType, str] = {
    EventType.FILE_CREATE: "green",
    EventType.FILE_DELETE: "red",
    EventType.FILE_MOVE: "yellow",
    EventType.FILE_RENAME: "bright_yellow",
    EventType.FILE_MODIFY: "white",
    EventType.FILE_COPY: "cyan",
    EventType.FILE_ACCESS: "bright_cyan",
    EventType.USB_CONNECT: "magenta",
    EventType.USB_DISCONNECT: "bright_magenta",
    EventType.APP_EXECUTE: "bright_blue",
    EventType.DEVICE_CONNECT: "bright_green",
}

CONFIDENCE_LABELS: dict[Confidence, str] = {
    Confidence.HIGH: "[green]HIGH[/]",
    Confidence.MEDIUM: "[yellow]MED[/]",
    Confidence.LOW: "[red]LOW[/]",
}


# ── Banner ──────────────────────────────────────────────────────────────────

def generate_sun(radius: int = 5) -> list[str]:
    """Generate a visually round sun sphere from block elements.

    Monospace terminal font characters are roughly twice as tall as they are wide (2:1 aspect ratio).
    To render a visually round circle on screen, horizontal steps are doubled
    (width = 4*radius + 1, height = 2*radius + 1).
    """
    height = radius * 2 + 1
    width_radius = radius * 2
    width = width_radius * 2 + 1
    grid: list[list[str]] = [[" "] * width for _ in range(height)]

    for y in range(-radius, radius + 1):
        for x in range(-width_radius, width_radius + 1):
            norm_x = x / 2.0
            if norm_x * norm_x + y * y > (radius + 0.2) ** 2:
                continue
            light = 1 - math.hypot(norm_x + radius * 0.3, y + radius * 0.3) / (radius * 1.35)
            if light > 0.66:
                shade = "█"
            elif light > 0.45:
                shade = "▓"
            elif light > 0.24:
                shade = "▒"
            else:
                shade = "░"
            grid[radius + y][width_radius + x] = shade

    return ["".join(row) for row in grid]


_HELIOS_GLYPHS: dict[str, tuple[str, ...]] = {
    "H": ("█   █", "█   █", "█████", "█   █", "█   █", "█   █"),
    "E": ("█████", "█    ", "███  ", "█    ", "█    ", "█████"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█    ", "█████"),
    "I": (" ███ ", "  █  ", "  █  ", "  █  ", "  █  ", " ███ "),
    "O": ("█████", "█   █", "█   █", "█   █", "█   █", "█████"),
    "S": ("█████", "█    ", "█████", "    █", "█   █", "█████"),
}


def _build_helios_art() -> str:
    """Compose the 6-row block-letter HELIOS title from per-letter glyphs."""
    return "\n".join(" ".join(_HELIOS_GLYPHS[ch][row] for ch in "HELIOS") for row in range(6))


HELIOS_ART: str = _build_helios_art()

BANNER_ART_FULL: list[str] = [
    r"           ▓▓▒▒▒",
    r"       ▓▓▓▓▓▓▓▓▓▒▒▒░",
    r"     ▓▓███████▓▓▓▒▒▒░░                       ▄        ▄      ▄█▄",
    r"    ▓▓█████████▓▓▓▒▒▒░░   ▄████   ████▄        ▄██       ▄██    ▀███▀      ▄██████▄     ▄██████▄",
    r"   ▓▓▓█████████▓▓▓▒▒▒░░░  █▓▓▓█\ /█████   ▄████████▄    ▄███     ▀█▀     ▄███▀▀▀▀███▄ ▄███▀▀  ▀▀",
    r"   ▒▓▓▓███████▓▓▓▒▒▒░░░░  █▒▒▒█ ░ █████  ▄██▀▀▀▀▀███    ▐███    ▄███▄    ███▌\ \ ▐███ ▀██████▄▄",
    r"   ▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒░░░░░  █████████████  ███████████     ███    ██▓██    ███▌ \ \▐███    ▀▀██████▄",
    r"    ▒▒▒▒▓▓▓▓▓▒▒▒▒▒░░░░░   █▓▓▓█   █████  ███▄▄▄▄▄▄▄▄     ███    ██▓██    ▀███▄▄▄▄███▀ ▄▄▄   ▄▄███▀",
    r"     ░▒▒▒▒▒▒▒▒▒░░░░░░░     ▀███▀   ▀███▀   ▀████████▀    ▄███▄   ▀███▀      ▀██████▀   ▀████████▀",
    r"       ░░░░░░░░░░░░░",
    r"           ░░░░░",
]

SUN_COMPACT: list[str] = [
    "        ▓▓▒▒▒",
    "    ▓▓▓▓▓▓▓▓▓▒▒▒░",
    "  ▓▓███████▓▓▓▒▒▒░░",
    " ▓▓█████████▓▓▓▒▒▒░░",
    "▓▓▓█████████▓▓▓▒▒▒░░░",
    "▒▓▓▓███████▓▓▓▒▒▒░░░░",
    "▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒░░░░░",
    " ▒▒▒▒▓▓▓▓▓▒▒▒▒▒░░░░░",
    "  ░▒▒▒▒▒▒▒▒▒░░░░░░░",
    "    ░░░░░░░░░░░░░",
    "        ░░░░░",
]

HELIOS_ART_MED: list[str] = [
    r"                      ▄        ▄      ▄█▄",
    r"▄████   ████▄        ▄██       ▄██    ▀███▀      ▄██████▄     ▄██████▄",
    r"█▓▓▓█\ /█████   ▄████████▄    ▄███     ▀█▀     ▄███▀▀▀▀███▄ ▄███▀▀  ▀▀",
    r"█▒▒▒█ ░ █████  ▄██▀▀▀▀▀███    ▐███    ▄███▄    ███▌\ \ ▐███ ▀██████▄▄",
    r"█████████████  ███████████     ███    ██▓██    ███▌ \ \▐███    ▀▀██████▄",
    r"█▓▓▓█   █████  ███▄▄▄▄▄▄▄▄     ███    ██▓██    ▀███▄▄▄▄███▀ ▄▄▄   ▄▄███▀",
    r"▀███▀   ▀███▀   ▀████████▀    ▄███▄   ▀███▀      ▀██████▀   ▀████████▀",
]

HELIOS_ART_COMPACT: list[str] = [
    "█   █ ████ █    ███  ███  ████",
    "█   █ █    █     █  █   █ █   ",
    "█████ ███  █     █  █   █ ████",
    "█   █ █    █     █  █   █    █",
    "█   █ ████ ████ ███  ███  ████",
]

TAGLINE = "Data Movement Forensics"
BANNER_SUBTITLE = "Press [0] at any prompt to exit or [B] to go back"

_GOLD_STYLE = "bold gold1"


def build_banner_text(
    radius: int | None = None,
    include_tagline: bool = True,
    width: int | None = None,
) -> Text:
    """Compose the golden Helios logo banner with adaptive terminal-width responsiveness.

    - Wide terminals (>= 110 cols): renders full side-by-side sun sphere + stylized HELIOS art.
    - Medium terminals (80 - 109 cols): renders stacked sun sphere + stylized HELIOS art.
    - Narrow terminals (< 80 cols): renders compact block HELIOS art to prevent wrapping.
    """
    cur_width = width if width is not None else console.width

    banner = Text(no_wrap=True)
    if cur_width >= 110:
        for line in BANNER_ART_FULL:
            banner.append(line, style=_GOLD_STYLE)
            banner.append("\n", style="")
        if include_tagline:
            banner.append("\n", style="")
            banner.append(TAGLINE.center(98), style=_GOLD_STYLE)
    elif cur_width >= 80:
        for s in SUN_COMPACT:
            banner.append(s.center(74), style=_GOLD_STYLE)
            banner.append("\n", style="")
        banner.append("\n", style="")
        for h in HELIOS_ART_MED:
            banner.append(h, style=_GOLD_STYLE)
            banner.append("\n", style="")
        if include_tagline:
            banner.append("\n", style="")
            banner.append(TAGLINE.center(74), style=_GOLD_STYLE)
    else:
        for c in HELIOS_ART_COMPACT:
            banner.append(c.center(min(34, max(1, cur_width - 6))), style=_GOLD_STYLE)
            banner.append("\n", style="")
        if include_tagline:
            banner.append("\n", style="")
            banner.append(TAGLINE.center(min(34, max(1, cur_width - 6))), style=_GOLD_STYLE)

    return banner


def build_banner_panel(
    radius: int | None = None,
    width: int | None = None,
    subtitle: str | None = BANNER_SUBTITLE,
) -> Panel:
    """Build the golden Helios logo panel with adaptive sizing and heavy borders."""
    cur_width = width if width is not None else console.width
    text = build_banner_text(radius=radius, width=cur_width)
    padding = (0, 2) if cur_width >= 110 else (0, 1)

    sub_text = f"[dim]{subtitle}[/dim]" if (subtitle and cur_width >= 65) else None

    return Panel(
        Align.center(text),
        box=box.HEAVY,
        border_style="gold1",
        padding=padding,
        subtitle=sub_text,
        subtitle_align="right",
    )


def print_banner() -> None:
    """Print the Helios golden banner (radiating sun + HELIOS lettering)."""
    console.print(build_banner_panel())


# ── Banner intro animation ──────────────────────────────────────────────────

_BANNER_ANIM_PLAYED = False

_SHADE_DIM = {"█": "▓", "▓": "▒", "▒": "░", "░": "░"}


def _banner_source_lines(width: int) -> list[str]:
    """Return the EXACT padded art lines the static banner renders at `width`."""
    lines: list[str] = []
    if width >= 110:
        lines.extend(BANNER_ART_FULL)
    elif width >= 80:
        lines.extend(s.center(74) for s in SUN_COMPACT)
        lines.append("")
        lines.extend(HELIOS_ART_MED)
    else:
        pad = min(34, max(1, width - 6))
        lines.extend(c.center(pad) for c in HELIOS_ART_COMPACT)
    return lines


def _banner_wave_frame(lines: list[str], center: int | None, band: int = 6) -> Text:
    """One animation frame.

    ``center`` marks the wave position — chars near it render bright white,
    everything else stays gold but one shade dimmer. ``center=None``
    renders the fully-lit artwork (identical glyphs to the static banner).
    """
    text = Text(no_wrap=True)
    for line in lines:
        for col, ch in enumerate(line):
            if ch == " ":
                text.append(" ")
            elif center is None or abs(col - center) <= band:
                text.append(ch, style="bold white" if center is not None else _GOLD_STYLE)
            else:
                text.append(_SHADE_DIM.get(ch, ch), style=_GOLD_STYLE)
        text.append("\n")
    return text


def animate_banner_once() -> None:
    """Play a short shimmer sweep across the sun/logo, then settle on the
    exact static artwork (the caller prints it right after). Runs once per
    process; skipped on non-TTY output or HELIOS_NO_ANIM=1.
    """
    global _BANNER_ANIM_PLAYED
    _BANNER_ANIM_PLAYED = True

    import os as _os
    import time as _time

    if _os.environ.get("HELIOS_NO_ANIM") == "1" or not sys.stdout.isatty():
        return

    from rich.live import Live

    try:
        width = console.width
        lines = _banner_source_lines(width)
        span = max((len(line) for line in lines), default=40) + 8

        with Live(console=console, refresh_per_second=30, transient=True) as live:
            # Brightness sweep left→right, then two fully-lit frames before
            # the transient region is erased and the static banner prints.
            for cx in range(-8, span + 8, 4):
                live.update(_banner_wave_frame(lines, cx))
                _time.sleep(0.04)
            for _ in range(2):
                live.update(_banner_wave_frame(lines, None))
                _time.sleep(0.08)
    except Exception:
        # Animation is cosmetic — never break the TUI over it.
        pass


# ── Drives ──────────────────────────────────────────────────────────────────

def print_drives_table(drives: list[DriveInfo]) -> None:
    """Display a table of detected drives/partitions."""
    table = Table(
        title="Mounted Drives",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
        border_style="bright_black",
    )
    table.add_column("Mount", style="bold")
    table.add_column("Label")
    table.add_column("Filesystem")
    table.add_column("Total Size", justify="right")
    table.add_column("Free Space", justify="right")
    table.add_column("Type")
    table.add_column("Removable", justify="center")

    for d in drives:
        removable = "[bold green][+] Yes[/]" if d.is_removable else "[dim][-] No[/]"
        drive_type_str = d.drive_type.value if hasattr(d.drive_type, "value") else str(d.drive_type)
        table.add_row(
            d.drive_letter,
            d.label or "-",
            d.filesystem or "-",
            format_size(d.total_size),
            format_size(d.free_space),
            drive_type_str,
            removable,
        )
    console.print(table)


# ── Devices ─────────────────────────────────────────────────────────────────

def print_devices_table(devices: list[Device]) -> None:
    """Display a table of detected devices."""
    table = Table(
        title="Devices",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
        border_style="bright_black",
    )
    table.add_column("Type", style="bold")
    table.add_column("Name")
    table.add_column("Serial")
    table.add_column("Model")
    table.add_column("OS / Info")

    for dev in devices:
        dev_type = dev.device_type.value if hasattr(dev.device_type, "value") else str(dev.device_type)
        table.add_row(
            dev_type,
            dev.device_name,
            dev.serial_number or "-",
            dev.model or "-",
            dev.os_version or "-",
        )
    console.print(table)


# ── Investigation Summary ───────────────────────────────────────────────────

def print_investigation_summary(investigation: Investigation) -> None:
    """Display an investigation overview panel."""
    t = Text()
    t.append("Case:         ", style="bold")
    t.append(f"{investigation.case_name}\n")
    t.append("Investigator: ", style="bold")
    t.append(f"{investigation.investigator}\n")
    t.append("Created:      ", style="bold")
    t.append(f"{investigation.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
    t.append("\n")
    t.append("Devices:      ", style="bold")
    t.append(f"{len(investigation.devices)}\n")
    t.append("Drives:       ", style="bold")
    t.append(f"{len(investigation.drives_scanned)}\n")
    t.append("Events:       ", style="bold")
    t.append(f"{len(investigation.events)}\n")
    t.append("Files:        ", style="bold")
    t.append(f"{len(investigation.file_records)}\n")
    t.append("Alerts:       ", style="bold")
    t.append(f"{len(investigation.alerts)}\n")

    # Count alerts by severity
    if investigation.alerts:
        t.append("\n")
        severity_counts: dict[str, int] = {}
        for a in investigation.alerts:
            key = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            severity_counts[key] = severity_counts.get(key, 0) + 1
        for sev_name, count in severity_counts.items():
            style = "red" if "CRITICAL" in sev_name else "dark_orange" if "HIGH" in sev_name else "yellow"
            t.append(f"  {sev_name}: ", style=style)
            t.append(f"{count}\n")

    console.print(
        Panel(t, title="[bold gold1]Investigation Summary[/]", box=box.ROUNDED, border_style="gold1")
    )


# ── Alerts ──────────────────────────────────────────────────────────────────

def print_alerts(alerts: list[Alert]) -> None:
    """Display a table of alerts sorted by severity (CRITICAL first)."""
    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
    sorted_alerts = sorted(alerts, key=lambda a: severity_order.get(a.severity, 5))

    table = Table(
        title="Alerts",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
        border_style="bright_black",
    )
    table.add_column("Severity", justify="center")
    table.add_column("Category")
    table.add_column("Title")
    table.add_column("Confidence", justify="center")

    for alert in sorted_alerts:
        sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        style = SEVERITY_STYLES.get(alert.severity, "white")
        conf = CONFIDENCE_LABELS.get(alert.confidence, str(alert.confidence))
        table.add_row(
            f"[{style}]* {sev_name}[/]",
            alert.category,
            alert.title,
            conf,
        )
    console.print(table)


def print_alert_detail(alert: Alert) -> None:
    """Display full details of a single alert."""
    t = Text()
    sev_name = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
    style = SEVERITY_STYLES.get(alert.severity, "white")

    t.append(f"[{style}]* {sev_name}[/]  ", style=style)
    t.append(alert.title, style="bold")
    t.append("\n\n")
    t.append("Category:    ", style="bold")
    t.append(f"{alert.category}\n")
    t.append("Confidence:  ", style="bold")
    conf_name = alert.confidence.value if hasattr(alert.confidence, "value") else str(alert.confidence)
    t.append(f"{conf_name}\n")
    if alert.timestamp:
        t.append("Timestamp:   ", style="bold")
        t.append(f"{alert.timestamp.strftime('%Y-%m-%d %H:%M:%S')}\n")
    t.append("\n")
    t.append("Description:\n", style="bold")
    t.append(alert.description or "No description provided.")

    console.print(
        Panel(t, title="[bold]Alert Detail[/]", box=box.ROUNDED, border_style=style.split()[-1])
    )


# ── Event Timeline ──────────────────────────────────────────────────────────

def print_event_timeline(events: list[DataEvent], limit: int = 50) -> None:
    """Display a chronological event timeline table."""
    sorted_events = sorted(events, key=lambda e: e.timestamp)

    table = Table(
        title="Event Timeline",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
        border_style="bright_black",
    )
    table.add_column("Timestamp", style="dim")
    table.add_column("Event", justify="center")
    table.add_column("Source Path")
    table.add_column("Destination")
    table.add_column("Source")
    table.add_column("Conf", justify="center")

    for event in sorted_events[:limit]:
        evt_name = event.event_type.value if hasattr(event.event_type, "value") else str(event.event_type)
        style = EVENT_STYLES.get(event.event_type, "white")
        conf = CONFIDENCE_LABELS.get(event.confidence, "-")

        table.add_row(
            event.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            f"[{style}]{evt_name}[/]",
            event.source_path or "-",
            event.destination_path or "-",
            event.raw_source or "-",
            conf,
        )

    console.print(table)
    if len(events) > limit:
        console.print(f"[dim]  ... and {len(events) - limit} more events[/]")


# ── File Records ────────────────────────────────────────────────────────────

def print_file_records(records: list[FileRecord], limit: int = 50) -> None:
    """Display a table of file records."""
    table = Table(
        title="File Records",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold gold1",
        border_style="bright_black",
    )
    table.add_column("File Name", style="bold")
    table.add_column("Path")
    table.add_column("Size", justify="right")
    table.add_column("SHA-256", max_width=20)
    table.add_column("Deleted", justify="center")
    table.add_column("Recovery", justify="center")
    table.add_column("Tags")

    for rec in records[:limit]:
        deleted = "[bold red]YES[/]" if rec.is_deleted else "[dim]no[/]"
        recovery = rec.recovery_status.value if hasattr(rec.recovery_status, "value") else str(rec.recovery_status)
        if rec.recovery_status == RecoveryStatus.RECOVERABLE:
            recovery = f"[green]{recovery}[/]"
        elif rec.recovery_status == RecoveryStatus.NOT_RECOVERABLE:
            recovery = f"[red]{recovery}[/]"
        hash_display = (rec.sha256_hash[:18] + "...") if rec.sha256_hash and len(rec.sha256_hash) > 18 else (rec.sha256_hash or "-")
        tags = ", ".join(rec.tags) if rec.tags else "-"

        table.add_row(
            rec.file_name,
            rec.file_path,
            format_size(rec.size),
            hash_display,
            deleted,
            recovery,
            tags,
        )

    console.print(table)
    if len(records) > limit:
        console.print(f"[dim]  ... and {len(records) - limit} more records[/]")


# ── Scan Summary ────────────────────────────────────────────────────────────

def print_scan_summary(scan_options: ScanOptions) -> None:
    """Display what will be scanned."""
    t = Text()
    t.append("Profile:     ", style="bold")
    t.append(f"{scan_options.profile_name}\n")
    t.append("Drives:      ", style="bold")
    t.append(f"{', '.join(scan_options.drives) if scan_options.drives else '(all detected)'}\n")
    t.append("Paths:       ", style="bold")
    t.append(f"{', '.join(scan_options.paths) if scan_options.paths else '(full drives)'}\n")
    if scan_options.date_from or scan_options.date_to:
        t.append("Date Range:  ", style="bold")
        fr = scan_options.date_from.strftime("%Y-%m-%d") if scan_options.date_from else "-"
        to = scan_options.date_to.strftime("%Y-%m-%d") if scan_options.date_to else "-"
        t.append(f"{fr}  ->  {to}\n")
    if scan_options.file_types:
        t.append("File Types:  ", style="bold")
        t.append(f"{', '.join(scan_options.file_types)}\n")
    if scan_options.keywords:
        t.append("Keywords:    ", style="bold")
        t.append(f"{', '.join(scan_options.keywords)}\n")
    if scan_options.skip_media:
        t.append("Skip Media:  ", style="bold")
        t.append("Yes\n")

    console.print(
        Panel(t, title="[bold gold1]Scan Configuration[/]", box=box.ROUNDED, border_style="gold1")
    )


# ── Utility displays ───────────────────────────────────────────────────────

def print_status(message: str, style: str = "info") -> None:
    """Print a status message with a colored prefix tag."""
    icons = {
        "success": "[bold green][+][/bold green]",
        "warning": "[bold yellow][!][/bold yellow]",
        "error": "[bold red][-][/bold red]",
        "info": "[bold blue][*][/bold blue]",
        "progress": "[bold cyan][>][/bold cyan]",
    }
    console.print(f"{icons.get(style, icons['info'])} {message}")


def esc_markup(text: object) -> str:
    """Escape Rich markup so evidence/user strings render literally.

    Keyword hits, artifact paths and case names can contain bracket
    sequences (``[/]``, ``[red]``) that Rich parses as markup — crashing
    the TUI with MarkupError or silently restyling output. Anything that
    originates outside Helios goes through this before console rendering.
    """
    from rich.markup import escape as _escape

    return _escape(str(text if text is not None else ""))


def print_progress_header(title: str) -> None:
    """Print a section divider with a title."""
    console.print()
    console.rule(f"[bold gold1]{title}[/]")
    console.print()


def create_progress() -> Progress:
    """Create a configured Rich progress bar for Helios."""
    return Progress(
        SpinnerColumn(style="gold1"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )
