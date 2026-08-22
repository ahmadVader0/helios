"""
HTML Table Builder for Helios Reports.
"""

from datetime import datetime as _dt
from typing import Any


class HTMLTableBuilder:
    """Builds HTML tables for various data models."""

    @staticmethod
    def _escape(text: Any) -> str:
        """Escape basic HTML characters."""
        if text is None:
            return ""
        text = str(text)
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

    @staticmethod
    def _fmt_ts(value: Any) -> str:
        """Render timestamps consistently (second precision, no microseconds)."""
        if isinstance(value, _dt):
            if getattr(value, "year", 0) >= 9000:
                return ""
            return value.strftime("%Y-%m-%d %H:%M:%S")
        text = str(value or "")
        return text[:19].replace("T", " ") if len(text) > 19 else text

    @classmethod
    def build_alerts_table(cls, alerts: list[Any], table_id: str = 'alertsTable') -> str:
        """
        Render the alerts table colored by severity, with detection-rule
        provenance when a rule id is attached to the alert.

        Args:
            alerts: List of Alert instances.
            table_id: The ID to assign to the HTML table.

        Returns:
            HTML string of the table.
        """
        any_rule = any(getattr(a, "rule_id", "") for a in alerts)

        html = [
            '<div class="table-responsive">',
            f'<table id="{table_id}" class="report-table">',
            '<thead>',
            '<tr>',
            '<th>Severity</th>',
            '<th>Timestamp</th>',
            '<th>Title</th>',
            '<th>Description</th>',
            '<th>Artifact Path</th>',
        ]
        if any_rule:
            html.append('<th>Detection Rule</th>')
        html.extend(['</tr>', '</thead>', '<tbody>'])

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

        def severity_of(alert: Any) -> str:
            sev = getattr(alert, "severity", "info")
            if sev is not None and hasattr(sev, "value"):
                return str(sev.value).lower()
            return str(sev or "info").lower()

        def first_path(alert: Any) -> str:
            """Extract the first path-like string from the alert evidence list."""
            evidence = getattr(alert, "evidence", None) or []
            for item in evidence:
                if isinstance(item, str) and ("\\" in item or "/" in item):
                    return item
            if isinstance(evidence, str) and evidence:
                return evidence
            return ""

        for alert in sorted(alerts, key=lambda a: severity_order.get(severity_of(a), 9)):
            severity = severity_of(alert)
            ts = cls._escape(cls._fmt_ts(getattr(alert, "timestamp", "")))
            title = cls._escape(getattr(alert, "title", ""))
            desc = cls._escape(getattr(alert, "description", ""))
            path = cls._escape(first_path(alert))

            html.append('<tr>')
            html.append(f'<td><span class="sev-badge sev-{severity}">{severity.upper()}</span></td>')
            html.append(f'<td>{ts}</td>')
            html.append(f'<td><strong>{title}</strong></td>')
            html.append(f'<td>{desc}</td>')
            html.append(f'<td><small><code>{path or "—"}</code></small></td>')
            if any_rule:
                rule_id = cls._escape(getattr(alert, "rule_id", ""))
                rule_name = cls._escape(getattr(alert, "rule_name", ""))
                cell = f'{rule_id}<br><small style="color:#6b7280;">{rule_name}</small>' if rule_id else '—'
                html.append(f'<td>{cell}</td>')
            html.append('</tr>')

        html.append('</tbody>')
        html.append('</table>')
        html.append('</div>')

        return "\n".join(html)
