"""
HTML Table Builder for Helios Reports.
"""

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

    @classmethod
    def build_events_table(cls, events: list[Any], table_id: str = 'eventsTable') -> str:
        """
        Render a sortable HTML table for events.

        Args:
            events: List of DataEvent instances.
            table_id: The ID to assign to the HTML table.

        Returns:
            HTML string of the table.
        """
        html = [
            '<div class="table-responsive">',
            f'<input type="text" id="{table_id}_search" class="form-control mb-3" placeholder="Search events..." onkeyup="filterTable(\'{table_id}\')">',
            f'<table id="{table_id}" class="table table-striped table-hover sortable">',
            '<thead>',
            '<tr>',
            f'<th onclick="sortTable(\'{table_id}\', 0)">Timestamp &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 1)">Event Type &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 2)">Source &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 3)">Description &#x21D5;</th>',
            '</tr>',
            '</thead>',
            '<tbody>'
        ]

        for event in events:
            ts = cls._escape(getattr(event, "timestamp", ""))
            ev_type = cls._escape(getattr(event, "event_type", getattr(event, "action", "")))
            source = cls._escape(getattr(event, "source_device", ""))
            desc = cls._escape(getattr(event, "metadata", {}).get("description", "") if isinstance(getattr(event, "metadata", None), dict) else "")

            html.append('<tr>')
            html.append(f'<td>{ts}</td>')
            html.append(f'<td><span class="badge bg-secondary">{ev_type}</span></td>')
            html.append(f'<td>{source}</td>')
            html.append(f'<td>{desc}</td>')
            html.append('</tr>')

        html.append('</tbody>')
        html.append('</table>')
        html.append('</div>')

        return "\n".join(html)

    @classmethod
    def build_alerts_table(cls, alerts: list[Any], table_id: str = 'alertsTable') -> str:
        """
        Render a sortable alerts table colored by severity.

        Args:
            alerts: List of Alert instances.
            table_id: The ID to assign to the HTML table.

        Returns:
            HTML string of the table.
        """
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
            '</tr>',
            '</thead>',
            '<tbody>'
        ]

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
            ts = cls._escape(getattr(alert, "timestamp", ""))
            title = cls._escape(getattr(alert, "title", ""))
            desc = cls._escape(getattr(alert, "description", ""))
            path = cls._escape(first_path(alert))

            html.append('<tr>')
            html.append(f'<td><span class="sev-badge sev-{severity}">{severity.upper()}</span></td>')
            html.append(f'<td>{ts}</td>')
            html.append(f'<td><strong>{title}</strong></td>')
            html.append(f'<td>{desc}</td>')
            html.append(f'<td><small><code>{path or "—"}</code></small></td>')
            html.append('</tr>')

        html.append('</tbody>')
        html.append('</table>')
        html.append('</div>')

        return "\n".join(html)

    @classmethod
    def build_files_table(cls, records: list[Any], table_id: str = 'filesTable') -> str:
        """
        Render a file records table.

        Args:
            records: List of FileRecord instances.
            table_id: The ID to assign to the HTML table.

        Returns:
            HTML string of the table.
        """
        html = [
            '<div class="table-responsive">',
            f'<input type="text" id="{table_id}_search" class="form-control mb-3" placeholder="Search files..." onkeyup="filterTable(\'{table_id}\')">',
            f'<table id="{table_id}" class="table table-striped table-hover sortable">',
            '<thead>',
            '<tr>',
            f'<th onclick="sortTable(\'{table_id}\', 0)">File Name &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 1)">Path &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 2)">Size &#x21D5;</th>',
            f'<th onclick="sortTable(\'{table_id}\', 3)">Status &#x21D5;</th>',
            '</tr>',
            '</thead>',
            '<tbody>'
        ]

        for record in records:
            name = cls._escape(getattr(record, "file_name", ""))
            path = cls._escape(getattr(record, "file_path", ""))
            size = getattr(record, "size", 0)
            is_deleted = getattr(record, "is_deleted", False)
            is_recovered = getattr(record, "is_recovered", False)

            status_badges = []
            if is_deleted:
                status_badges.append('<span class="badge bg-danger">Deleted</span>')
            if is_recovered:
                status_badges.append('<span class="badge bg-success">Recovered</span>')
            if not is_deleted and not is_recovered:
                status_badges.append('<span class="badge bg-primary">Existing</span>')
            
            status_html = " ".join(status_badges)

            html.append('<tr>')
            html.append(f'<td>{name}</td>')
            html.append(f'<td><small><code>{path}</code></small></td>')
            html.append(f'<td>{size} bytes</td>')
            html.append(f'<td>{status_html}</td>')
            html.append('</tr>')

        html.append('</tbody>')
        html.append('</table>')
        html.append('</div>')

        return "\n".join(html)
