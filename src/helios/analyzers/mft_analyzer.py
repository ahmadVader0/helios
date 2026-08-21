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
import re
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from helios.adapters.mftecmd_adapter import MFTECmdAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact, ScanOptions
from helios.models import Alert, Confidence, DataEvent, Device, EventType, Severity
from helios.utils.ntfs import (
    build_volume_path,
    detect_timestomping,
    parse_mftecmd_timestamp,
)

logger = logging.getLogger(__name__)

# NTFS system-internal entries that must never generate user-facing
# alerts (ADS / timestomping) — they always "look" anomalous.
_SYSTEM_ENTRY_RE = re.compile(
    r"^(\$MFT|\$MFTMirr|\$LogFile|\$Volume|\$AttrDef|\$Bitmap|\$Boot|"
    r"\$BadClus|\$Secure|\$UpCase|\$Extend|FVE2?\.|\$Directory)",
    re.IGNORECASE,
)


def _as_bool(value: str | None) -> bool:
    return str(value or "").strip().lower() == "true"


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
        ads_paths: list[tuple[str, datetime, str]] = []
        for artifact in artifacts:
            csv_path = artifact.raw_data if isinstance(artifact.raw_data, Path) else artifact.source_path
            if not csv_path or not isinstance(csv_path, Path) or not csv_path.exists():
                continue

            try:
                volume = str((artifact.metadata or {}).get("volume", "") or "")
                with open(csv_path, mode="r", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        file_name: str = row.get("FileName", "")
                        parent_path: str = row.get("ParentPath", "")
                        full_path: str = build_volume_path(parent_path, file_name, volume)

                        in_use_str: str = row.get("InUse", "True").strip()
                        in_use: bool = in_use_str.lower() == "true"

                        has_ads_str: str = row.get("HasAds", "False").strip()
                        has_ads: bool = (
                            _as_bool(has_ads_str)
                            and not _SYSTEM_ENTRY_RE.match(file_name)
                            and not has_ads_str.lower().endswith("zone.identifier")
                        )

                        created_si_str: str = row.get("Created0x10", "")
                        created_fn_str: str = row.get("Created0x30", "")
                        modified_si_str: str = row.get("LastModified0x10", "")
                        modified_fn_str: str = row.get("LastModified0x30", "")

                        created_si: datetime | None = parse_mftecmd_timestamp(created_si_str)
                        created_fn: datetime | None = parse_mftecmd_timestamp(created_fn_str)
                        modified_si: datetime | None = parse_mftecmd_timestamp(modified_si_str)
                        modified_fn: datetime | None = parse_mftecmd_timestamp(modified_fn_str)

                        device_id = artifact.device_id or self.name()

                        best_ts: datetime | None = modified_si or modified_fn or created_si or created_fn
                        if best_ts is None:
                            continue
                        timestamp: datetime = best_ts if best_ts.tzinfo is not None else best_ts.replace(tzinfo=timezone.utc)

                        if in_use:
                            # Skip event emission for in-use files (covered by live walk)
                            # But still check timestomping and ADS below
                            pass
                        else:
                            # Deleted file — use modified_si as best approximation
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

                        # MFTECmd pre-computes copy indicators. A large
                        # FN-vs-SI created gap is the NORMAL result of
                        # copying a file onto an NTFS volume; only treat it
                        # as timestomping when MFTECmd does not attribute
                        # the mismatch to a copy.
                        is_copied = _as_bool(row.get("Copied")) or _as_bool(row.get("CopyFlag"))
                        is_system_entry = bool(_SYSTEM_ENTRY_RE.match(file_name))

                        is_timestomped = (
                            not is_copied
                            and not is_system_entry
                            and detect_timestomping(created_si, modified_si, created_fn, modified_fn)
                        )
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
                            ads_paths.append((full_path, timestamp, device_id))

            except Exception as e:
                logger.error(f"Failed to analyze MFT artifact {csv_path}: {e}")

        # ADS findings are extremely common (every downloaded file carries a
        # Zone.Identifier stream). Emit individual LOW-severity alerts for the
        # first few and aggregate the remainder into one summary alert so the
        # report stays readable without hiding the signal.
        _ADS_INDIVIDUAL_LIMIT = 25
        for full_path, timestamp, device_id in ads_paths[:_ADS_INDIVIDUAL_LIMIT]:
            results.append(Alert(
                severity=Severity.LOW,
                category="Alternate Data Stream",
                title="Alternate Data Stream detected",
                description=f"Alternate Data Stream detected on {full_path}",
                evidence=[full_path],
                device=device_id,
                timestamp=timestamp,
                confidence=Confidence.MEDIUM,
            ))
        if len(ads_paths) > _ADS_INDIVIDUAL_LIMIT:
            sample = ", ".join(p for p, _, _ in ads_paths[_ADS_INDIVIDUAL_LIMIT:_ADS_INDIVIDUAL_LIMIT + 5])
            results.append(Alert(
                severity=Severity.LOW,
                category="Alternate Data Stream",
                title=f"{len(ads_paths)} files with alternate data streams",
                description=(
                    f"{len(ads_paths)} files carry ADS (commonly Zone.Identifier from "
                    f"internet downloads). Samples beyond the first "
                    f"{_ADS_INDIVIDUAL_LIMIT}: {sample}"
                ),
                evidence=[p for p, _, _ in ads_paths[:_ADS_INDIVIDUAL_LIMIT]],
                device=ads_paths[0][2] if ads_paths else "",
                timestamp=ads_paths[0][1] if ads_paths else None,
                confidence=Confidence.MEDIUM,
            ))

        return results
