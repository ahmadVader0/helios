"""
Report Generation Engine for Helios.
"""

import csv
import datetime
import json
import logging
import re
from pathlib import Path
from typing import Any

import jinja2

from .chart_builder import ApexChartBuilder
from .table_builder import HTMLTableBuilder

logger = logging.getLogger(__name__)


def _enum_value(rs: Any) -> str:
    """Render an enum-like recovery status value as its string form."""
    if rs is not None and hasattr(rs, "value"):
        return str(rs.value)
    return str(rs or "")


def _profile_sections(module_results: list[Any], profile_name: str | None) -> dict[str, bool]:
    """
    Decide which report sections are relevant for the executed profile.

    Sections are derived from the REAL module execution log (keys + status),
    so each scan type renders only what that profile actually ran. A report
    without a module log (demo / legacy investigations) falls back to
    showing everything.

    Returns:
        A dict of boolean section flags: transfers, deletions,
        data_movement (tab), deletion_chart (summary chart).
    """
    ran_keys = {
        m.get("key") for m in module_results
        if isinstance(m, dict) and m.get("status") == "ran"
    }
    if not ran_keys and not module_results:
        return {"transfers": True, "deletions": True, "data_movement": True, "deletion_chart": True}

    transfers = "cross_device_matching" in ran_keys or "usb_transfers" in ran_keys
    deletions = "file_deletions" in ran_keys or "deleted_file_recovery" in ran_keys
    return {
        "transfers": transfers,
        "deletions": deletions,
        "data_movement": transfers or deletions,
        "deletion_chart": deletions,
    }


def _chain_get(chain: Any, key: str, default: Any = "") -> Any:
    """Read a field from a correlation dict or MovementChain object."""
    if isinstance(chain, dict):
        return chain.get(key, default)
    return getattr(chain, key, default)


def _device_name_map(devices: list[Any]) -> dict[str, str]:
    """Map device IDs to display names (falling back to the ID itself)."""
    names: dict[str, str] = {}
    for dev in devices:
        dev_id = getattr(dev, "device_id", None)
        if dev_id:
            names[dev_id] = getattr(dev, "device_name", "") or dev_id
    return names


def _display_name(device_id: Any, name_map: dict[str, str]) -> str:
    """Return the friendly device name for an ID/path, or the raw value."""
    value = str(device_id or "")
    if not value:
        return "Unknown"
    return name_map.get(value, value)


def _format_timestamp(value: Any) -> str:
    """Format a timestamp (datetime, ISO string, or list/dict) for display."""
    if isinstance(value, (list, tuple)):
        value = value[0] if value else None
    if isinstance(value, dict):
        value = value.get("timestamp") or value.get("time")
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S")
    text = str(value or "")
    return text[:19].replace("T", " ")


def _path_basename(value: Any) -> str:
    """Extract the final path component, splitting on both separators."""
    text = str(value or "")
    return [p for p in re.split(r"[\\/]", text) if p][-1] if text else ""


def _build_event_index(events: list[Any]) -> dict[str, list[Any]]:
    """Index file events by source-path basename for timestamp lookup."""
    index: dict[str, list[Any]] = {}
    for evt in events:
        etype = getattr(evt, "event_type", None)
        etype_val = etype.value if etype is not None and hasattr(etype, "value") else str(etype or "")
        if etype_val not in ("FILE_COPY", "FILE_MOVE", "FILE_DELETE", "FILE_CREATE"):
            continue
        name = _path_basename(getattr(evt, "source_path", ""))
        if name:
            index.setdefault(name.lower(), []).append(evt)
    return index


_EVENT_PREFERENCE = {"FILE_COPY": 0, "FILE_MOVE": 1, "FILE_CREATE": 2, "FILE_DELETE": 3}

# Profile-specific report templates: each scan type renders a genuinely
# different report focused on what that profile actually analyzes.
_PROFILE_TEMPLATES: dict[str, str] = {
    "exfiltration": "exfiltration_report.html.j2",
    "employee_exit": "employee_exit_report.html.j2",
    "incident_response": "incident_response_report.html.j2",
    "full": "full_report.html.j2",
}

_DEFAULT_TEMPLATE = "full_report.html.j2"

# LNK/JumpList analyzers mark access events with these raw sources.
_LNK_RAW_SOURCES = ("LECmd", "JLECmd")


def _resolve_template(profile_name: str | None) -> str:
    """Pick the report template for an investigation profile."""
    return _PROFILE_TEMPLATES.get((profile_name or "").lower(), _DEFAULT_TEMPLATE)


def _build_event_rows(events: list[Any], max_rows: int = 500) -> list[dict[str, Any]]:
    """Flatten events into display rows for the report's event log tables."""
    rows: list[dict[str, Any]] = []
    for e in events:
        etype = getattr(e, "event_type", None)
        rows.append({
            "timestamp": _format_timestamp(getattr(e, "timestamp", None)),
            "type": etype.value if etype is not None and hasattr(etype, "value") else str(etype or ""),
            "source": _display_name(getattr(e, "source_device", ""), {}),
            "path": getattr(e, "source_path", ""),
            "destination": getattr(e, "destination_path", "") or "",
            "confidence": getattr(e, "confidence", ""),
            "raw_source": getattr(e, "raw_source", ""),
        })
    rows.sort(key=lambda r: r["timestamp"], reverse=True)
    return rows[:max_rows]


def _event_type_str(event: Any) -> str:
    etype = getattr(event, "event_type", None)
    return etype.value if etype is not None and hasattr(etype, "value") else str(etype or "")


def _pick_match(matches: list[Any]) -> Any | None:
    """Choose the most relevant event: preferred type first, else earliest."""
    if not matches:
        return None
    preferred = sorted(matches, key=lambda e: _EVENT_PREFERENCE.get(_event_type_str(e), 4))
    return preferred[0]


def build_movement_rows(
    correlations: list[Any], devices: list[Any], events: list[Any] | None = None
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Build clean, deduplicated rows for the Data Movement section.

    Transfers (copies/moves to a real target) and deletions (RecycleBin /
    FILE_DELETE chains) are split into two lists so the report only shows
    meaningful movement. Timestamps and full source paths are enriched from
    the matching file events when correlations only carry summary fields.

    Returns:
        (transfers, deletions): lists of row dicts.
    """
    name_map = _device_name_map(devices)
    event_index = _build_event_index(events or [])
    transfers: list[dict[str, Any]] = []
    deletions: list[dict[str, Any]] = []
    seen_transfers: set[tuple[str, str, str]] = set()
    seen_deletions: set[tuple[str, str, str]] = set()

    for chain in correlations:
        file_name = str(_chain_get(chain, "file_name") or "Unknown")
        file_hash = str(_chain_get(chain, "sha256_hash") or "")
        if not file_hash or file_hash == "Correlated Event":
            file_hash = str(_chain_get(chain, "file_hash") or "")
        source = _display_name(_chain_get(chain, "source_device"), name_map)
        targets = _chain_get(chain, "target_devices") or []
        target_raw = targets[0] if isinstance(targets, (list, tuple)) and targets else targets

        etype = str(_chain_get(chain, "event_type") or "")
        target_str = str(target_raw or "")
        is_delete = (
            target_str in ("RecycleBin", "RecycleBin/External", "Deleted")
            or "$recycle.bin" in target_str.lower()
            or "delete" in etype.lower()
        )

        matching: list[Any] = []
        for lookup_key in (file_name.lower(), _path_basename(file_name).lower()):
            if lookup_key and lookup_key in event_index:
                matching = event_index[lookup_key]
                break
        if is_delete:
            delete_matches = [e for e in matching if _event_type_str(e) == "FILE_DELETE"]
            match = delete_matches[0] if delete_matches else None
        else:
            match = _pick_match(matching)
        # Extract timestamp from hops or direct timestamp field
        raw_hops = _chain_get(chain, "hops")
        raw_ts = None
        if raw_hops and isinstance(raw_hops, (list, tuple)) and len(raw_hops) > 0:
            hop = raw_hops[0]
            if isinstance(hop, (list, tuple)) and len(hop) > 0:
                raw_ts = hop[0]  # First element of hop tuple is the datetime
            else:
                raw_ts = hop
        if raw_ts is None:
            raw_ts = _chain_get(chain, "timestamp")
        # Filter out sentinel datetime.max values from _safe_ts
        import datetime as _dt
        if isinstance(raw_ts, _dt.datetime) and raw_ts.year >= 9000:
            raw_ts = None
        timestamp = _format_timestamp(raw_ts)
        if (not timestamp or timestamp.startswith("9999")) and match is not None:
            timestamp = _format_timestamp(getattr(match, "timestamp", None))
        source_path = getattr(match, "source_path", "") if match is not None else ""
        display_name = _path_basename(source_path) or _path_basename(file_name) or file_name

        row = {
            "file_name": display_name or file_name,
            "hash": file_hash[:16] if file_hash else "",
            "source": source,
            "source_path": source_path,
            "target": str(target_raw or "External"),
            "timestamp": timestamp,
        }

        if is_delete:
            key = (file_name, source, str(timestamp))
            if key not in seen_deletions:
                seen_deletions.add(key)
                deletions.append(row)
            continue

        target = _display_name(target_raw, name_map)
        if not target:
            target = str(target_raw or "External Media")
        row["target"] = target
        if target == source and source not in ("External Media", "USB Storage"):
            continue
        key = (file_name.lower(), str(source_path).lower(), str(timestamp))
        if key in seen_transfers:
            continue
        seen_transfers.add(key)
        transfers.append(row)

    # Supplement transfers with FILE_COPY / FILE_MOVE events from the events list
    # (e.g. inferred USB transfers, USN Journal copies, LNK transfers).
    for evt in (events or []):
        evt_type = getattr(evt, "event_type", None)
        etype_val = evt_type.value if evt_type is not None and hasattr(evt_type, "value") else str(evt_type or "")
        if etype_val not in ("FILE_COPY", "FILE_MOVE"):
            continue
        src_path = str(getattr(evt, "source_path", ""))
        dst_path = str(getattr(evt, "destination_path", "") or src_path)
        meta = getattr(evt, "metadata", {}) or {}
        raw_fname = meta.get("file_name") if isinstance(meta, dict) else None
        fname = str(raw_fname) if raw_fname else (_path_basename(dst_path) or _path_basename(src_path))
        if not fname:
            continue

        meta = getattr(evt, "metadata", {}) or {}
        src_dev_id = getattr(evt, "source_device", "") or "Host PC"
        dst_dev_id = meta.get("target_device") or getattr(evt, "destination_device", "")
        if not dst_dev_id:
            sp_drive = Path(src_path).drive if src_path else ""
            dp_drive = Path(dst_path).drive if dst_path else ""
            if dp_drive and dp_drive != sp_drive:
                dst_dev_id = dp_drive
            elif "usb" in str(getattr(evt, "raw_source", "")).lower():
                dst_dev_id = "USB Storage"
            else:
                dst_dev_id = "External Media"

        src_disp = _display_name(src_dev_id, name_map)
        dst_disp = _display_name(dst_dev_id, name_map)

        if src_disp == dst_disp and dst_disp not in ("External Media", "USB Storage"):
            continue

        ts = _format_timestamp(getattr(evt, "timestamp", None))
        key = (fname.lower(), str(src_path).lower(), str(ts))
        if key in seen_transfers:
            continue
        seen_transfers.add(key)
        transfers.append({
            "file_name": fname,
            "hash": getattr(evt, "file_hash", "") or "",
            "source": src_disp,
            "source_path": src_path,
            "target": dst_disp,
            "timestamp": ts,
        })

    transfers.sort(key=lambda r: r["timestamp"])
    deletions.sort(key=lambda r: r["timestamp"])
    return transfers, deletions


class ReportGenerator:
    """Generates comprehensive forensic reports in HTML, JSON, and CSV formats."""

    def __init__(self, investigation: Any, config: Any):
        """
        Initialize the ReportGenerator.

        Args:
            investigation: The Investigation model containing all forensic data.
            config: The HeliosConfig instance.
        """
        self.investigation = investigation
        self.config = config

        # Set up Jinja2 environment
        template_dir = Path(__file__).parent / "templates"
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(str(template_dir)),
            autoescape=jinja2.select_autoescape(["html", "xml"]),
        )
        self.jinja_env.globals.update(now=datetime.datetime.now)

    def generate_html_report(self, output_path: Path, template_name: str | None = None) -> Path:
        """
        Render a Jinja2 template into a self-contained HTML file.

        Args:
            output_path: The file path to save the generated HTML report.
            template_name: The name of the Jinja2 template to use. When
                omitted, the template is chosen from the investigation's
                profile (each scan type gets a distinct report).

        Returns:
            The Path where the report was saved.
        """
        if template_name is None:
            template_name = _resolve_template(getattr(self.investigation, "profile_name", ""))
        template = self.jinja_env.get_template(template_name)

        events = getattr(self.investigation, "events", [])
        alerts = getattr(self.investigation, "alerts", [])
        file_records = getattr(self.investigation, "file_records", [])
        devices = getattr(self.investigation, "devices", [])
        drives = getattr(self.investigation, "drives_scanned", [])
        correlations = getattr(self.investigation, "correlations", [])
        heatmap_matrix = getattr(self.investigation, "heatmap_matrix", {})

        timeline_chart = ApexChartBuilder.build_timeline_chart(events)
        heatmap_chart = ApexChartBuilder.build_heatmap_chart(heatmap_matrix)
        filetype_chart = ApexChartBuilder.build_filetype_donut(file_records)
        deletion_chart = ApexChartBuilder.build_deletion_bar_chart(events)
        data_flow_chart = ApexChartBuilder.build_data_flow_chart(correlations, devices)

        alerts_table = HTMLTableBuilder.build_alerts_table(alerts)

        movements, deletions = build_movement_rows(correlations, devices, events)

        # Supplement deletions with FILE_DELETE events from the events list
        # that aren't already captured by the correlator (e.g. Recycle Bin entries).
        _SYS_NOISE_TOKENS = ("system volume information", "$extend", "fve2.{", "fve.{")
        _del_seen = {(d["file_name"], d.get("timestamp", "")) for d in deletions}
        name_map = _device_name_map(devices)
        for evt in events:
            etype = getattr(evt, "event_type", None)
            etype_val = etype.value if etype is not None and hasattr(etype, "value") else str(etype or "")
            if etype_val != "FILE_DELETE":
                continue
            src_path = str(getattr(evt, "source_path", ""))
            if any(tok in src_path.lower() for tok in _SYS_NOISE_TOKENS):
                continue
            fname = _path_basename(src_path)
            if not fname or fname.lower() in ("$recycle.bin", "$extend", "system volume information") or (fname, "") in _del_seen:
                continue
            ts = _format_timestamp(getattr(evt, "timestamp", None))
            if (fname, ts) in _del_seen:
                continue
            _del_seen.add((fname, ts))
            deletions.append({
                "file_name": fname,
                "hash": "",
                "source": _display_name(getattr(evt, "source_device", ""), name_map),
                "source_path": src_path,
                "target": "Deleted",
                "timestamp": ts,
            })

        for fr in file_records:
            if not getattr(fr, "is_deleted", False) or getattr(fr, "is_system", False):
                continue
            fr_path = str(getattr(fr, "file_path", ""))
            if any(tok in fr_path.lower() for tok in _SYS_NOISE_TOKENS):
                continue
            fname = getattr(fr, "file_name", "") or _path_basename(fr_path)
            if not fname or fname.lower() in ("$recycle.bin", "$extend", "system volume information"):
                continue
            ts = _format_timestamp(getattr(fr, "modified", None) or getattr(fr, "created", None))
            if (fname, ts) in _del_seen:
                continue
            _del_seen.add((fname, ts))
            deletions.append({
                "file_name": fname,
                "hash": str(getattr(fr, "sha256_hash", "") or "")[:16],
                "source": _display_name(getattr(fr, "source_device", ""), name_map),
                "source_path": fr_path,
                "target": "Deleted (SleuthKit)",
                "timestamp": ts,
            })

        deletions.sort(key=lambda r: r["timestamp"], reverse=True)

        now_str = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        sections = _profile_sections(
            getattr(self.investigation, "module_results", []),
            getattr(self.investigation, "profile_name", ""),
        )

        timeline_rows = _build_event_rows(events)
        # Build access_rows from ALL events (not just the capped 500)
        all_event_rows = _build_event_rows(events, max_rows=len(events))
        access_rows = [r for r in all_event_rows if r["raw_source"] in _LNK_RAW_SOURCES]

        # Build deleted file records list for templates
        deleted_files = [
            {
                "file_name": getattr(fr, "file_name", ""),
                "file_path": getattr(fr, "file_path", ""),
                "size": getattr(fr, "size", 0),
                "extension": getattr(fr, "extension", ""),
                "created": _format_timestamp(getattr(fr, "created", None)),
                "modified": _format_timestamp(getattr(fr, "modified", None)),
                "recovery_status": _enum_value(getattr(fr, "recovery_status", "")),
                "source_device": _display_name(getattr(fr, "source_device", ""), _device_name_map(devices)),
            }
            for fr in file_records
            if getattr(fr, "is_deleted", False)
            and not getattr(fr, "is_system", False)
            and not any(tok in str(getattr(fr, "file_path", "")).lower() for tok in _SYS_NOISE_TOKENS)
            and getattr(fr, "file_name", "").lower() not in ("$recycle.bin", "$extend", "system volume information")
        ]

        # Build specialized row lists
        _PREFETCH_SOURCES = ("PECmd", "Prefetch")
        executed_programs = [r for r in all_event_rows if r["raw_source"] in _PREFETCH_SOURCES]

        _SHELLBAGS_SOURCES = ("SBECmd", "ShellBags")
        shellbags_rows = [r for r in all_event_rows if r["raw_source"] in _SHELLBAGS_SOURCES]

        _EVTX_SOURCES = ("python-evtx", "Chainsaw", "Event Logs", "Security.evtx", "System.evtx")
        event_log_rows = [r for r in all_event_rows if r["raw_source"] in _EVTX_SOURCES or r["type"] == "EVENT_LOG"]

        _USB_TYPES = ("USB_CONNECT", "USB_DISCONNECT", "DEVICE_CONNECT")
        _USB_SOURCES = ("SetupAPI", "USBSTOR", "MountPoints2")
        usb_rows = [
            r for r in all_event_rows
            if r["type"] in _USB_TYPES or r["raw_source"] in _USB_SOURCES
        ]

        context = {
            "investigation": self.investigation,
            "config": self.config,
            "generated_at": now_str,
            "deleted_files": deleted_files,
            "executed_programs": executed_programs,
            "shellbags_rows": shellbags_rows,
            "event_log_rows": event_log_rows,
            "usb_rows": usb_rows,
            "devices": devices,
            "drives": drives,
            "sections": sections,
            "timeline_rows": timeline_rows,
            "access_rows": access_rows,
            "timeline_chart_json": json.dumps(timeline_chart),
            "heatmap_chart_json": json.dumps(heatmap_chart),
            "filetype_chart_json": json.dumps(filetype_chart),
            "deletion_chart_json": json.dumps(deletion_chart),
            "data_flow_chart_json": json.dumps(data_flow_chart),
            "alerts_table_html": alerts_table,
            "movements": movements,
            "deletions": deletions,
            "top_alerts": alerts[:8],
        }

        rendered_html = template.render(**context)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(rendered_html)

        return output_path

    def generate_keyword_report(
        self,
        results: list[Any],
        meta: dict[str, Any],
        output_path: Path,
    ) -> Path:
        """Render a dedicated keyword-search triage report.

        Args:
            results: List of SearchResult objects (or dicts) from the
                KeywordSearchEngine.
            meta: Metadata about the search: search_title, search_target,
                keywords, files_scanned, max_content_size_mb, max_lines,
                max_hits_per_file.
            output_path: The file path to save the generated HTML report.

        Returns:
            The Path where the report was saved.
        """
        rows: list[dict[str, Any]] = []
        for r in results:
            if isinstance(r, dict):
                rows.append({
                    "match_type": r.get("match_type", ""),
                    "keyword": r.get("keyword", ""),
                    "file_name": r.get("file_name", ""),
                    "file_path": r.get("file_path", ""),
                    "match_context": r.get("match_context", ""),
                    "line_number": r.get("line_number"),
                })
            else:
                rows.append({
                    "match_type": getattr(r, "match_type", ""),
                    "keyword": getattr(r, "keyword", ""),
                    "file_name": getattr(r, "file_name", ""),
                    "file_path": getattr(r, "file_path", ""),
                    "match_context": getattr(r, "match_context", ""),
                    "line_number": getattr(r, "line_number", None),
                })

        count_by_type: dict[str, int] = {"name": 0, "path": 0, "content": 0}
        for row in rows:
            t = row["match_type"]
            if t in count_by_type:
                count_by_type[t] += 1

        keywords = meta.get("keywords", [])
        if isinstance(keywords, str):
            keywords = [keywords]

        template = self.jinja_env.get_template("keyword_search_report.html.j2")
        context = {
            "search_title": meta.get("search_title", "Keyword Search"),
            "search_target": meta.get("search_target", ""),
            "keywords": [k for k in keywords if k],
            "files_scanned": meta.get("files_scanned", 0),
            "max_content_size_mb": meta.get("max_content_size_mb", 10),
            "max_lines": meta.get("max_lines", 500),
            "max_hits_per_file": meta.get("max_hits_per_file", 20),
            "generated_at": datetime.datetime.now(tz=datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "total_hits": len(rows),
            "count_by_type": count_by_type,
            "results": rows,
        }
        rendered_html = template.render(**context)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            f.write(rendered_html)
        return output_path

    def generate_json_export(self, output_path: Path) -> Path:
        """Serialize the full Investigation to a JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if hasattr(self.investigation, "to_dict"):
            data = self.investigation.to_dict()
        else:
            data = {"case_name": getattr(self.investigation, "case_name", "Forensic Investigation")}

        with output_path.open("w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        return output_path

    def generate_csv_bundle(self, output_dir: Path) -> list[Path]:
        """Export events.csv, alerts.csv, file_records.csv, and devices.csv."""
        output_dir.mkdir(parents=True, exist_ok=True)
        exported = []

        # events.csv
        events_path = output_dir / "events.csv"
        events = getattr(self.investigation, "events", [])
        with events_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Timestamp", "EventType", "SourceDevice", "SourcePath", "DestinationPath", "Hash", "Confidence"])
            for e in events:
                writer.writerow([
                    getattr(e, "timestamp", ""),
                    getattr(e, "event_type", ""),
                    getattr(e, "source_device", ""),
                    getattr(e, "source_path", ""),
                    getattr(e, "destination_path", ""),
                    getattr(e, "file_hash", ""),
                    getattr(e, "confidence", ""),
                ])
        exported.append(events_path)

        # alerts.csv
        alerts_path = output_dir / "alerts.csv"
        alerts = getattr(self.investigation, "alerts", [])
        with alerts_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["Severity", "Category", "Title", "Description", "Confidence"])
            for a in alerts:
                writer.writerow([
                    getattr(a, "severity", ""),
                    getattr(a, "category", ""),
                    getattr(a, "title", ""),
                    getattr(a, "description", ""),
                    getattr(a, "confidence", ""),
                ])
        exported.append(alerts_path)

        # file_records.csv
        files_path = output_dir / "file_records.csv"
        file_records = getattr(self.investigation, "file_records", [])
        with files_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["FileName", "FilePath", "Size", "SHA256", "IsDeleted", "RecoveryStatus"])
            for fr in file_records:
                writer.writerow([
                    getattr(fr, "file_name", ""),
                    getattr(fr, "file_path", ""),
                    getattr(fr, "size", 0),
                    getattr(fr, "sha256_hash", ""),
                    getattr(fr, "is_deleted", False),
                    getattr(fr, "recovery_status", ""),
                ])
        exported.append(files_path)

        return exported
