"""
Chain of custody logging.

Records every tool action during an investigation (acquisition, processing,
analysis, export) with timestamps, tool versions, target, and result, plus
investigator identity, and exports the log as JSON.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from helios.models import CustodyEntry

logger = logging.getLogger(__name__)

HELIOS_VERSION = "0.1.0"


class ChainOfCustodyLog:
    """
    Logs every tool action with timestamp, action type, target, result, tool
    name/version, and investigator identity.

    Entries are model-native :class:`CustodyEntry` objects so they can be
    attached directly to an :class:`Investigation` for reporting.
    """

    def __init__(self, case_id: str, investigator: str) -> None:
        self.case_id = case_id
        self.investigator = investigator
        self.entries: list[CustodyEntry] = []

    def log(
        self,
        action: str,
        target: str,
        result: str,
        tool_name: str = "Helios",
        tool_version: str = HELIOS_VERSION,
        details: dict[str, Any] | None = None,
    ) -> CustodyEntry:
        """Record one tool action in the chain of custody."""
        entry = CustodyEntry(
            action=action,
            timestamp=datetime.now(),
            target=target,
            result=result,
            tool_name=tool_name,
            tool_version=tool_version,
            details=details or {},
        )
        self.entries.append(entry)
        logger.info("Custody[%s] %s | tool=%s %s | %s", self.case_id, action, tool_name, tool_version, result)
        return entry

    def to_dict(self) -> dict[str, Any]:
        """Serialize the custody log to a JSON-friendly dict."""
        return {
            "case_id": self.case_id,
            "investigator": self.investigator,
            "entry_count": len(self.entries),
            "entries": [
                {
                    "action": e.action,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "target": e.target,
                    "result": e.result,
                    "tool_name": e.tool_name,
                    "tool_version": e.tool_version,
                    "details": e.details,
                }
                for e in self.entries
            ],
        }

    def to_json(self, output_path: Path) -> Path:
        """Export the custody log as a JSON file."""
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=4)
        logger.info("Chain of custody exported to %s", output_path)
        return output_path
