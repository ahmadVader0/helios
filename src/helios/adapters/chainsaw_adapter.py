"""
Chainsaw EVTX Hunting Adapter.
"""

import json
import logging
from pathlib import Path
from typing import Any

from helios.adapters.base import ForensicToolAdapter, ToolRunResult, resolve_tool_binary
from helios.models import Alert, Confidence, Severity

logger = logging.getLogger(__name__)


class ChainsawAdapter(ForensicToolAdapter):
    """
    Adapter for running Chainsaw EVTX hunts using Sigma rules.
    """

    def tool_name(self) -> str:
        """Return the name of the tool."""
        return "Chainsaw Adapter"

    def get_executable(self) -> str:
        """Resolve chainsaw executable path."""
        resolved = resolve_tool_binary("chainsaw", self.tool_path)
        return str(resolved) if resolved else "chainsaw"

    def is_available(self) -> bool:
        """Check if chainsaw binary is available."""
        return resolve_tool_binary("chainsaw", self.tool_path) is not None

    def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
        """Run chainsaw with arguments."""
        cmd = [self.get_executable()] + args
        return self.run_subprocess(cmd, timeout=timeout)

    def parse_output(self, raw_output: str) -> list[Any]:
        """Parse raw JSON output from Chainsaw."""
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.warning("Chainsaw JSON parsing failed: %s. Output snippet: %s", e, raw_output[:200])
            return []

    def _resolve_mapping_file(self, explicit_mapping: Path | None = None) -> Path | None:
        """Resolve Chainsaw mapping file."""
        if explicit_mapping and explicit_mapping.exists():
            return explicit_mapping

        try:
            from helios.config import get_bundle_root

            bundle_root = get_bundle_root()
            candidates = [
                bundle_root / "tools" / "mappings" / "sigma-event-logs-all.yml",
                bundle_root / "mappings" / "sigma-event-logs-all.yml",
                Path.cwd() / "tools" / "mappings" / "sigma-event-logs-all.yml",
                Path.cwd() / "mappings" / "sigma-event-logs-all.yml",
                Path(__file__).resolve().parent.parent.parent.parent / "tools" / "mappings" / "sigma-event-logs-all.yml",
                Path(__file__).resolve().parent.parent.parent.parent / "mappings" / "sigma-event-logs-all.yml",
            ]
            # ONLY files qualify — returning a directory here makes chainsaw
            # exit non-zero and every Sigma alert for the EVTX is silently lost.
            for cand in candidates:
                if cand.is_file():
                    return cand
        except Exception as e:
            logger.debug("Error resolving chainsaw mapping file: %s", e)
        return None

    def run_sigma_hunt(
        self,
        evtx_dir: Path,
        sigma_rules_dir: Path,
        output_json: Path,
        mapping_file: Path | None = None,
    ) -> list[Alert]:
        """
        Execute `chainsaw hunt <evtx_dir> -s <sigma_rules_dir> --mapping <mapping> --json` and parse results.
        Supports both directories and single .evtx files as input.
        """
        if not self.is_available():
            logger.warning("Chainsaw binary not found.")
            return []

        if not evtx_dir.exists():
            logger.warning(f"EVTX path not found: {evtx_dir}")
            return []
        if not (evtx_dir.is_dir() or evtx_dir.is_file()):
            logger.warning(f"EVTX path is not a directory or file: {evtx_dir}")
            return []

        if not sigma_rules_dir.exists() or not sigma_rules_dir.is_dir():
            logger.warning(f"Sigma rules directory not found: {sigma_rules_dir}")
            return []

        mapping = self._resolve_mapping_file(mapping_file)
        args = ["hunt", str(evtx_dir), "-s", str(sigma_rules_dir)]
        if mapping:
            args.extend(["--mapping", str(mapping)])
        args.extend(["--json", "--no-banner"])

        result = self.run(args, timeout=600)

        # Only trust the hunt output when chainsaw actually succeeded or produced valid JSON.
        output_json.parent.mkdir(parents=True, exist_ok=True)
        with open(output_json, "w", encoding="utf-8") as f:
            f.write(result.stdout or "")

        # Try parsing structured findings from output file or stdout
        alerts = self._parse_findings(output_json)
        if not alerts and result.stdout:
            alerts = self._parse_findings_from_text(result.stdout)

        if not alerts and result.returncode != 0:
            err_msg = (result.stderr or result.stdout or "").strip()
            # Clean any leftover banner/newlines
            first_err = [ln for ln in err_msg.splitlines() if ln.strip() and not ln.strip().startswith("█")][:3]
            logger.debug(
                "Chainsaw hunt returned rc=%d for %s: %s",
                result.returncode, evtx_dir, " ".join(first_err) or "non-zero returncode",
            )
            return []

        return alerts

    @staticmethod
    def _extract_json_data(raw: str) -> Any:
        """Extract JSON structure from mixed text/JSON output."""
        raw = raw.strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            pass
        start_arr = raw.find("[")
        end_arr = raw.rfind("]")
        if start_arr != -1 and end_arr != -1 and end_arr > start_arr:
            try:
                return json.loads(raw[start_arr : end_arr + 1])
            except json.JSONDecodeError:
                pass
        start_obj = raw.find("{")
        end_obj = raw.rfind("}")
        if start_obj != -1 and end_obj != -1 and end_obj > start_obj:
            try:
                return json.loads(raw[start_obj : end_obj + 1])
            except json.JSONDecodeError:
                pass
        return None

    def _parse_findings_from_text(self, text: str) -> list[Alert]:
        """Parse Alerts from raw string output containing JSON."""
        data = self._extract_json_data(text)
        if not data:
            return []
        return self._build_alerts_from_data(data)

    def _parse_findings(self, json_file: Path) -> list[Alert]:
        """Parse Chainsaw detection findings into Alert objects with mapped severities."""
        if not json_file.exists():
            return []

        try:
            with open(json_file, "r", encoding="utf-8") as f:
                content = f.read()
            data = self._extract_json_data(content)
            if not data:
                return []
            return self._build_alerts_from_data(data)
        except Exception as e:
            logger.debug(f"Error parsing Chainsaw JSON output from {json_file}: {e}")
            return []

    def _build_alerts_from_data(self, data: Any) -> list[Alert]:
        """Convert extracted JSON detection data into Alert instances."""
        alerts: list[Alert] = []
        items = self._flatten_detections(data)

        for item in items:
            title = item.get("name") or item.get("title") or "Chainsaw Sigma Match"
            level = str(item.get("level", "medium")).lower()
            document = item.get("document", item.get("Document", ""))

            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            severity = severity_map.get(level, Severity.MEDIUM)

            alerts.append(
                Alert(
                    title=title,
                    category="Event Log Anomaly",
                    description=item.get("description", "Matched Sigma detection rule in Windows Event Logs"),
                    severity=severity,
                    confidence=Confidence.HIGH,
                    evidence=[str(document)] if document else [],
                )
            )
        return alerts

    @staticmethod
    def _flatten_detections(data: Any) -> list[dict[str, Any]]:
        """Flatten Chainsaw JSON into a flat list of detection dicts, handling nested structures."""
        items: list[dict[str, Any]] = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    if "detections" in item and isinstance(item["detections"], list):
                        items.extend(d for d in item["detections"] if isinstance(d, dict))
                    else:
                        items.append(item)
        elif isinstance(data, dict):
            detections = data.get("detections")
            if isinstance(detections, list):
                for d in detections:
                    if isinstance(d, dict):
                        items.append(d)
            elif isinstance(detections, dict):
                for d in detections.values():
                    if isinstance(d, dict):
                        items.append(d)
                    elif isinstance(d, list):
                        items.extend(x for x in d if isinstance(x, dict))
            else:
                items.append(data)
        return items
