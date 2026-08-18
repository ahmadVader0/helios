"""
MFT Analyzer — parses MFTECmd's $MFT CSV output into DataEvents.

Detects:
- File creation / deletion (InUse flag)
- Timestomping (SI vs FN timestamp mismatch)
- Alternate data streams (ADS)
"""

from __future__ import annotations

import csv
import logging
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.mftecmd_adapter import MFTECmdAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact, ScanOptions
from helios.models import Alert, Confidence, DataEvent, Device, EventType, Severity
from helios.utils.ntfs import (
    detect_timestomping,
    has_alternate_data_stream,
    parse_mftecmd_timestamp,
)

logger = logging.getLogger(__name__)


class MFTAnalyzer(AnalyzerBase):
    """
    Analyzer for NTFS $MFT files. Uses MFTECmd to parse the MFT into CSV,
    then processes the output to detect files, timestomping, and ADS.
    """

    def __init__(self, config: dict[str, Any] | None = None, scan_options: ScanOptions | None = None) -> None:
        super().__init__(config, scan_options)
        self.adapter: MFTECmdAdapter = MFTECmdAdapter(config=self.config.get("tools", {}).get("mftecmd"))

    def name(self) -> str:
        return "MFT Analyzer"

    def can_run(self) -> bool:
        return self.adapter.is_available()

    def collect(self, device: Device) -> list[RawArtifact]:
        """Collects and parses the $MFT from the given device."""
        if not device.drive_letter:
            return []

        mft_path: Path = Path(device.drive_letter) / "$MFT"

        output_dir: Path = Path(self.config.get("output_dir", "/tmp/helios/mft"))
        try:
            csv_path: Path = self.adapter.parse_mft(
                mft_file=mft_path,
                output_dir=output_dir,
                out_name="mft_dump",
            )
            return [
                RawArtifact(
                    artifact_id="mft_csv",
                    artifact_type="mft",
                    source_path=csv_path,
                    device_id=device.device_id,
                    collected_at=datetime.now(timezone.utc),
                    raw_data=csv_path,
                )
            ]
        except Exception as e:
            logger.error(f"Failed to collect MFT artifact: {e}")
            return []

    def analyze(self, artifacts: list[RawArtifact]) -> Sequence[DataEvent | Alert]:
        """Analyzes parsed MFT CSVs to generate events and alerts."""
        results: list[DataEvent | Alert] = []
        for artifact in artifacts:
            csv_path = artifact.raw_data if isinstance(artifact.raw_data, Path) else artifact.source_path
            if not csv_path or not isinstance(csv_path, Path) or not csv_path.exists():
                continue

            try:
                with open(csv_path, mode="r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        file_name: str = row.get("FileName", "")
                        parent_path: str = row.get("ParentPath", "")
                        full_path: str = f"{parent_path}\\{file_name}" if parent_path else file_name

                        in_use_str: str = row.get("InUse", "True").strip()
                        in_use: bool = in_use_str.lower() == "true"

                        has_ads_str: str = row.get("HasAds", "False").strip()
                        has_ads: bool = has_ads_str.lower() == "true" or has_alternate_data_stream(has_ads_str)

                        created_si_str: str = row.get("Created0x10", "")
                        created_fn_str: str = row.get("Created0x30", "")
                        modified_si_str: str = row.get("LastModified0x10", "")
                        modified_fn_str: str = row.get("LastModified0x30", "")

                        created_si: datetime | None = parse_mftecmd_timestamp(created_si_str)
                        created_fn: datetime | None = parse_mftecmd_timestamp(created_fn_str)
                        modified_si: datetime | None = parse_mftecmd_timestamp(modified_si_str)
                        modified_fn: datetime | None = parse_mftecmd_timestamp(modified_fn_str)

                        device_id = artifact.device_id or self.name()

                        if in_use:
                            # Skip event emission for in-use files (covered by live walk)
                            # But still check timestomping and ADS below
                            pass
                        else:
                            # Deleted file — use modified_si as best approximation
                            del_ts = modified_si or modified_fn or created_si or created_fn
                            if del_ts is None:
                                continue
                            timestamp: datetime = del_ts if del_ts.tzinfo is not None else del_ts.replace(tzinfo=timezone.utc)
                            event = DataEvent(
                                timestamp=timestamp,
                                event_type=EventType.FILE_DELETE,
                                source_device=device_id,
                                source_path=full_path,
                                raw_source="MFTECmd $MFT",
                                confidence=Confidence.MEDIUM,
                                metadata={
                                    "description": f"MFT record inactive (deletion time unknown): {full_path}",
                                    "in_use": False,
                                    "has_ads": has_ads,
                                },
                            )
                            results.append(event)

                        is_timestomped = detect_timestomping(created_si, modified_si, created_fn, modified_fn)
                        if is_timestomped:
                            alert = Alert(
                                severity=Severity.HIGH,
                                category="Timestomping",
                                title="Potential timestomping detected",
                                description=(
                                    f"Potential timestomping detected on {full_path}. "
                                    f"SI Created: {created_si}, FN Created: {created_fn}"
                                ),
                                evidence=[full_path],
                                device=device_id,
                                timestamp=timestamp,
                                confidence=Confidence.HIGH,
                            )
                            results.append(alert)

                        if has_ads:
                            alert = Alert(
                                severity=Severity.MEDIUM,
                                category="Alternate Data Stream",
                                title="Alternate Data Stream detected",
                                description=f"Alternate Data Stream detected on {full_path}",
                                evidence=[full_path],
                                device=device_id,
                                timestamp=timestamp,
                                confidence=Confidence.HIGH,
                            )
                            results.append(alert)

            except Exception as e:
                logger.error(f"Failed to analyze MFT artifact {csv_path}: {e}")

        return results
