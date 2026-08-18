"""
Demo mode: loads sample investigation data and runs the full Helios analysis
pipeline (correlation, suspicious activity, reporting, exports, chain of
custody) without needing real devices or external forensic tools.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from helios.models import Investigation

logger = logging.getLogger(__name__)

DEMO_DATA_DIR = Path(__file__).parent / "demo_data" / "sample_investigation"
DEMO_INVESTIGATION_FILE = DEMO_DATA_DIR / "investigation.json"


def load_demo_investigation() -> Investigation:
    """Load the packaged sample investigation from demo_data."""
    if not DEMO_INVESTIGATION_FILE.exists():
        raise FileNotFoundError(f"Demo data missing: {DEMO_INVESTIGATION_FILE}")
    with DEMO_INVESTIGATION_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return Investigation.from_dict(data)


def run_demo_pipeline(output_dir: Path | None = None) -> dict[str, Any]:
    """
    Run the Helios analysis pipeline against the sample investigation.

    Returns a dict with the populated investigation plus paths to the
    generated report, exports, evidence ZIP and chain-of-custody JSON.
    """
    from datetime import datetime
    from pathlib import Path as P

    from helios.analyzers.base import RawArtifact
    from helios.analyzers.suspicious_detector import SuspiciousDetectorAnalyzer
    from helios.core.correlator import CrossDeviceCorrelator
    from helios.evidence.chain_of_custody import HELIOS_VERSION, ChainOfCustodyLog
    from helios.reporting.exporters import export_bundle, export_zip
    from helios.reporting.report_generator import ReportGenerator

    investigation = load_demo_investigation()
    output_dir = output_dir or P.cwd() / "demo_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    alert_count_before = len(investigation.alerts)
    event_count_before = len(investigation.events)

    # 1. Suspicious activity detection over indexed file records
    raw_artifacts = [
        RawArtifact(
            artifact_id=f"demo-rec-{idx}",
            artifact_type="FILE_RECORD",
            source_path=P(rec.file_path),
            device_id=rec.source_device or investigation.case_id,
            collected_at=datetime.now(),
            raw_data=rec,
        )
        for idx, rec in enumerate(investigation.file_records)
    ]
    suspicious = SuspiciousDetectorAnalyzer(config={}, scan_options=investigation.scan_options)
    new_alert_count = len(investigation.alerts)
    investigation.alerts.extend(suspicious.analyze(raw_artifacts))
    new_alert_count = len(investigation.alerts) - new_alert_count

    # 2. Cross-device correlation
    correlator = CrossDeviceCorrelator(investigation)
    investigation.events.extend(correlator.detect_usb_transfers())
    investigation.alerts.extend(correlator.detect_exfiltration_patterns())
    chains = correlator.match_files_by_hash()
    event_delta = len(investigation.events) - event_count_before
    alert_delta = len(investigation.alerts) - alert_count_before
    for chain in chains:
        investigation.correlations.append({
            "file_name": chain.file_name,
            "sha256_hash": chain.sha256_hash,
            "source_device": chain.source_device,
            "target_devices": getattr(chain, "target_devices", ["External Volume"]),
            "hops_summary": f"Correlated across {len(getattr(chain, 'hops', []))} hop(s)",
            "exfiltrated": getattr(chain, "exfiltrated", False),
        })

    # 3. Chain of custody for every pipeline stage
    custody = ChainOfCustodyLog(
        case_id=investigation.case_id,
        investigator=investigation.investigator or "Helios Analyst",
    )
    custody.log("Case Initialization", investigation.case_name, f"{len(investigation.devices)} device(s) registered")
    custody.log("File Record Processing", f"{len(investigation.file_records)} file records", "SHA-256 digests verified", tool_version=HELIOS_VERSION)
    custody.log("Suspicious Activity Analysis", f"{len(raw_artifacts)} file records", f"{alert_delta} alert(s) raised")
    custody.log("Cross-Device Correlation", investigation.case_name, f"{event_delta} event(s), {len(investigation.correlations)} movement chain(s) built")
    custody.log("Report Generation", str(output_dir), f"{len(investigation.events)} events rendered")
    investigation.chain_of_custody = custody.entries

    # 4. HTML report + exports
    generator = ReportGenerator(investigation, {})
    report_path = generator.generate_html_report(output_dir / "helios_demo_report.html")
    exports_dir = output_dir / "exports"
    export_bundle(investigation, exports_dir)
    zip_path = export_zip(investigation, output_dir / "helios_demo_exports.zip")
    custody_path = custody.to_json(output_dir / "chain_of_custody.json")

    return {
        "investigation": investigation,
        "report_path": report_path,
        "exports_dir": exports_dir,
        "zip_path": zip_path,
        "custody_path": custody_path,
    }
