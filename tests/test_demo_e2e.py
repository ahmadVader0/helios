"""End-to-end tests for demo mode: sample data in, valid HTML report out."""

from __future__ import annotations

import csv
import json
import zipfile
from pathlib import Path

from helios.demo import load_demo_investigation, run_demo_pipeline
from helios.models import EventType


def test_demo_investigation_covers_multiple_artifact_types() -> None:
    """Demo data must span devices, drives, events, files, alerts, custody."""
    inv = load_demo_investigation()

    assert len(inv.devices) >= 3
    assert len(inv.drives_scanned) >= 1
    assert len(inv.events) >= 15
    assert len(inv.file_records) >= 5
    assert len(inv.alerts) >= 3
    assert len(inv.chain_of_custody) >= 3

    event_types = {e.event_type for e in inv.events}
    assert EventType.USB_CONNECT in event_types
    assert EventType.FILE_COPY in event_types
    assert EventType.FILE_DELETE in event_types

    # All events carry real timestamps (round-tripped from JSON)
    assert all(e.timestamp is not None for e in inv.events)


def test_demo_pipeline_generates_valid_html_report(tmp_path: Path) -> None:
    """Demo mode must produce a clean, self-contained report with exports."""
    result = run_demo_pipeline(tmp_path)

    report = result["report_path"]
    assert report.exists()
    html = report.read_text(encoding="utf-8")
    assert "<html" in html.lower()
    assert "Data Movement" in html
    assert "dataFlowChart" in html
    assert "timelineChart" in html
    assert "Chain of Custody" in html
    # Movement rows are populated from correlations with device names
    assert "Kingston DataTraveler" in html
    # Removed retro/explorer machinery
    assert "helios_static" not in html
    assert "helios-timeline-strip" not in html
    assert "global-search" not in html
    assert "directory_tree" not in html

    # JSON export parses back into the investigation
    inv_json = tmp_path / "exports" / "investigation.json"
    assert inv_json.exists()
    data = json.loads(inv_json.read_text(encoding="utf-8"))
    assert data["case_name"] == "CASE-2026-0042 — Employee Exit Investigation"
    assert len(data["events"]) >= 15

    # CSV exports present with headers and rows
    for csv_name, min_rows in (("events.csv", 15), ("alerts.csv", 3), ("files.csv", 5), ("correlations.csv", 0)):
        csv_path = tmp_path / "exports" / csv_name
        assert csv_path.exists(), csv_name
        with csv_path.open(encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
        assert len(rows) >= min_rows, csv_name

    # Evidence ZIP contains the exports
    zip_path = result["zip_path"]
    assert zip_path.exists()
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        assert "investigation.json" in names
        assert "events.csv" in names

    # Chain of custody exported as JSON
    custody_path = result["custody_path"]
    assert custody_path.exists()
    custody = json.loads(custody_path.read_text(encoding="utf-8"))
    assert custody["investigator"]
    assert len(custody["entries"]) >= 5
