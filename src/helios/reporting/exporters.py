"""
Exporters for Investigation data.

Provides JSON export (full Investigation object), separate CSV exports for
events, files, alerts and correlations, a combined bundle, and a ZIP archive
of all exports.
"""

from __future__ import annotations

import csv
import dataclasses
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

EVENT_CSV_COLUMNS = [
    "event_id", "timestamp", "event_type", "source_device", "source_path",
    "destination_path", "file_hash", "file_size", "user_account",
    "confidence", "raw_source", "metadata",
]

FILE_CSV_COLUMNS = [
    "file_path", "file_name", "extension", "actual_type", "size",
    "sha256_hash", "md5_hash", "created", "modified", "accessed",
    "entry_modified", "is_deleted", "is_hidden", "is_system",
    "is_encrypted", "mft_entry_number", "parent_path", "source_device",
    "recovery_status", "tags",
]

ALERT_CSV_COLUMNS = [
    "alert_id", "severity", "category", "title", "description",
    "evidence", "device", "timestamp", "confidence",
]


def export_investigation_json(investigation: Any, output_path: Path) -> Path:
    """Serialize the full Investigation object as JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = investigation.to_dict() if hasattr(investigation, "to_dict") else {"case_name": "Forensic Investigation"}
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)
    logger.info("Investigation JSON exported to %s", output_path)
    return output_path


def _write_csv(output_path: Path, columns: list[str], rows: list[dict[str, Any]]) -> Path:
    """Write rows to a CSV file using the given column order."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return output_path


def _flatten_cell(value: Any) -> str:
    """Flatten non-scalar CSV cells to a JSON string."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return json.dumps(value)


def export_events_csv(investigation: Any, output_path: Path) -> Path:
    """Export all DataEvents as events.csv."""
    events = getattr(investigation, "events", [])
    rows: list[dict[str, Any]] = []
    for event in events:
        row = event.to_dict() if hasattr(event, "to_dict") else {}
        row["metadata"] = _flatten_cell(row.get("metadata"))
        rows.append(row)
    return _write_csv(output_path, EVENT_CSV_COLUMNS, rows)


def export_alerts_csv(investigation: Any, output_path: Path) -> Path:
    """Export all Alerts as alerts.csv."""
    alerts = getattr(investigation, "alerts", [])
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        row = alert.to_dict() if hasattr(alert, "to_dict") else {}
        row["evidence"] = _flatten_cell(row.get("evidence"))
        rows.append(row)
    return _write_csv(output_path, ALERT_CSV_COLUMNS, rows)


def export_files_csv(investigation: Any, output_path: Path) -> Path:
    """Export all FileRecords as files.csv."""
    records = getattr(investigation, "file_records", [])
    rows: list[dict[str, Any]] = []
    for record in records:
        row = record.to_dict() if hasattr(record, "to_dict") else {}
        row["tags"] = _flatten_cell(row.get("tags"))
        rows.append(row)
    return _write_csv(output_path, FILE_CSV_COLUMNS, rows)


def export_correlations_csv(investigation: Any, output_path: Path) -> Path:
    """Export cross-device correlations as correlations.csv."""
    correlations = getattr(investigation, "correlations", [])
    normalized = []
    for corr in correlations:
        if isinstance(corr, dict):
            normalized.append(corr)
        elif dataclasses.is_dataclass(corr) and not isinstance(corr, type):
            normalized.append(dataclasses.asdict(corr))
        else:
            try:
                normalized.append(vars(corr))
            except TypeError:
                continue
    columns: list[str] = []
    for corr in normalized:
        for key in corr:
            if key not in columns:
                columns.append(key)
    rows = [{k: _flatten_cell(v) for k, v in corr.items()} for corr in normalized]
    if not columns:
        columns = ["file_name", "sha256_hash", "source_device"]
    return _write_csv(output_path, columns, rows)


def export_bundle(investigation: Any, output_dir: Path) -> list[Path]:
    """Export JSON + CSV exports for the investigation into one directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    exported = [
        export_investigation_json(investigation, output_dir / "investigation.json"),
        export_events_csv(investigation, output_dir / "events.csv"),
        export_alerts_csv(investigation, output_dir / "alerts.csv"),
        export_files_csv(investigation, output_dir / "files.csv"),
        export_correlations_csv(investigation, output_dir / "correlations.csv"),
    ]
    return exported


def export_zip(investigation: Any, output_path: Path) -> Path:
    """Package all exports into a single ZIP archive."""
    if output_path.suffix != ".zip":
        output_path = output_path.with_suffix(".zip")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    staging = output_path.parent / f"export_staging_{output_path.stem}"
    staging.mkdir(parents=True, exist_ok=True)
    try:
        export_bundle(investigation, staging)
        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for item in sorted(staging.iterdir()):
                if item.is_file():
                    zf.write(item, arcname=item.name)
    finally:
        import shutil

        shutil.rmtree(staging, ignore_errors=True)

    logger.info("Export ZIP created at %s", output_path)
    return output_path
