"""
USN Journal Analyzer — parses MFTECmd's $UsnJrnl CSV output into DataEvents.

The NTFS USN Journal ($UsnJrnl:$J) records every file-system operation
with precise timestamps.  MFTECmd exports this into CSV with columns
like UpdateTimestamp, ParentPath, Name, UpdateReasons, etc.

This analyzer maps USN reasons to Helios EventTypes with priority:
    FileDelete > FileCreate > Rename > Modify
"""

from __future__ import annotations

import csv
import logging
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import (
    Alert,
    Confidence,
    DataEvent,
    Device,
    EventType,
    ScanOptions,
)
from helios.utils.ntfs import (
    build_volume_path,
    decode_usn_reason_from_string,
    parse_mftecmd_timestamp,
)

logger = logging.getLogger(__name__)

# Map MFTECmd USN reason strings to Helios EventTypes.
_REASON_TO_EVENT_TYPE: dict[str, EventType] = {
    "FileCreate": EventType.FILE_CREATE,
    "FileDelete": EventType.FILE_DELETE,
    "RenameNewName": EventType.FILE_RENAME,
    "RenameOldName": EventType.FILE_RENAME,
    "DataExtend": EventType.FILE_MODIFY,
    "DataOverwrite": EventType.FILE_MODIFY,
    "DataTruncation": EventType.FILE_MODIFY,
    "SecurityChange": EventType.FILE_MODIFY,
    "BasicInfoChange": EventType.FILE_MODIFY,
}

# Priority order: if a record has multiple reasons, pick the most
# forensically interesting one.
_PRIORITY: list[str] = [
    "FileDelete", "FileCreate", "RenameNewName", "RenameOldName",
    "DataOverwrite", "DataExtend", "DataTruncation",
    "SecurityChange", "BasicInfoChange",
]


def _classify(reasons: list[str]) -> EventType | None:
    """Pick the highest-priority EventType from a list of USN reasons."""
    for candidate in _PRIORITY:
        if candidate in reasons:
            return _REASON_TO_EVENT_TYPE[candidate]
    return None


class USNJournalAnalyzer(AnalyzerBase):
    """Parses MFTECmd $UsnJrnl CSV output into DataEvents.

    This analyzer expects ``RawArtifact`` objects whose ``raw_data``
    field is a ``Path`` to a MFTECmd-generated USN CSV.
    """

    def __init__(
        self,
        config: dict[str, Any] | None = None,
        scan_options: ScanOptions | None = None,
    ) -> None:
        super().__init__(config=config, scan_options=scan_options)

    def name(self) -> str:
        """Return the human-readable analyzer name."""
        return "USN Journal Analyzer"

    def can_run(self) -> bool:
        """USN analysis requires a pre-generated CSV; always runnable."""
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """Collect is a no-op — the pipeline invokes MFTECmd externally."""
        return []

    def analyze(self, artifacts: list[RawArtifact]) -> Sequence[DataEvent | Alert]:
        """Parse MFTECmd USN CSV rows into DataEvents.

        Each row with a forensically interesting reason (create, delete,
        rename, modify) maps to one DataEvent.  Rows with only
        uninteresting reasons (Close, IndexableChange) are skipped.
        """
        results: list[DataEvent | Alert] = []

        for artifact in artifacts:
            csv_path = artifact.raw_data
            if not isinstance(csv_path, Path) or not csv_path.exists():
                continue

            device_id = artifact.device_id
            volume = str((artifact.metadata or {}).get("volume", "") or "")

            try:
                with open(csv_path, newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        event = self._row_to_event(row, device_id, volume)
                        if event is not None:
                            results.append(event)
            except Exception:
                logger.exception("Failed to analyze USN CSV %s", csv_path)

        return results

    def _row_to_event(
        self, row: dict[str, str], device_id: str, volume: str = ""
    ) -> DataEvent | None:
        """Convert one USN CSV row to a DataEvent, or None if not interesting."""
        name = row.get("Name") or row.get("FileName") or ""
        if not name:
            return None

        parent_path = row.get("ParentPath", "") or ""
        full_path = build_volume_path(parent_path, name, volume)

        reasons_raw = row.get("UpdateReasons") or row.get("UpdateReason") or ""
        reasons = decode_usn_reason_from_string(reasons_raw)

        timestamp = parse_mftecmd_timestamp(row.get("UpdateTimestamp", ""))
        if timestamp is None:
            return None  # DataEvent.timestamp is required

        event_type = _classify(reasons)
        if event_type is None:
            return None  # nothing forensically interesting

        file_size = self._safe_int(row.get("FileSize"))
        entry_id = self._safe_int(
            row.get("EntryNumber") or row.get("FileReferenceNumber")
        )
        parent_entry_id = self._safe_int(
            row.get("ParentEntryNumber") or row.get("ParentFileReferenceNumber")
        )

        return DataEvent(
            timestamp=timestamp,
            event_type=event_type,
            source_device=device_id,
            source_path=full_path,
            file_size=file_size,
            confidence=Confidence.HIGH,
            raw_source="MFTECmd $UsnJrnl",
            metadata={
                "entry_id": entry_id,
                "parent_entry_id": parent_entry_id,
                "reasons": reasons,
                "file_attributes": row.get("FileAttributes"),
            },
        )

    @staticmethod
    def _safe_int(value: str | None) -> int | None:
        """Parse an optional integer, returning None on failure."""
        try:
            return int(value)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return None
