"""
ApexCharts Configuration Generator for Helios Reports.
"""

from collections import defaultdict
from datetime import datetime
from typing import Any


class ApexChartBuilder:
    """Builds ApexCharts JSON configurations for various data visualizations."""

    @staticmethod
    def build_timeline_chart(events: list[Any]) -> dict[str, Any]:
        """
        Build a zoomable interactive timeline chart configuration.

        Args:
            events: List of DataEvent instances.

        Returns:
            Dictionary representing the ApexCharts configuration.
        """
        date_counts: dict[str, int] = defaultdict(int)
        for event in events:
            ts = getattr(event, "timestamp", None)
            if ts:
                if isinstance(ts, str):
                    try:
                        # Handle basic ISO format parsing
                        ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                if isinstance(ts, datetime):
                    date_str = ts.strftime("%Y-%m-%d")
                    date_counts[date_str] += 1

        sorted_dates = sorted(date_counts.keys())
        data = [{"x": date, "y": count} for date, count in zip(sorted_dates, [date_counts[d] for d in sorted_dates])]

        return {
            "chart": {
                "type": "area",
                "height": 350,
                "zoom": {"enabled": True},
                "toolbar": {"show": True}
            },
            "dataLabels": {"enabled": False},
            "stroke": {"curve": "smooth"},
            "series": [{"name": "Events", "data": data}],
            "xaxis": {"type": "datetime"},
            "yaxis": {"title": {"text": "Event Count"}},
            "title": {"text": "Event Timeline", "align": "left"}
        }

    @staticmethod
    def build_heatmap_chart(heatmap_matrix: dict[str, list[int]]) -> dict[str, Any]:
        """
        Build a 24x7 activity calendar heatmap configuration.

        Args:
            heatmap_matrix: Dictionary where keys are days (e.g., 'Mon', 'Tue') and values are lists of 24 integers (hours).

        Returns:
            Dictionary representing the ApexCharts configuration.
        """
        series = []
        for day, hours in heatmap_matrix.items():
            series.append({
                "name": day,
                "data": [{"x": f"{i:02d}:00", "y": count} for i, count in enumerate(hours)]
            })

        return {
            "chart": {
                "type": "heatmap",
                "height": 350
            },
            "series": series,
            "dataLabels": {"enabled": False},
            "colors": ["#008FFB"],
            "title": {"text": "24x7 Activity Heatmap"}
        }

    @staticmethod
    def build_filetype_donut(file_records: list[Any]) -> dict[str, Any]:
        """
        Build a donut chart config for file extension distribution.

        Args:
            file_records: List of FileRecord instances.

        Returns:
            Dictionary representing the ApexCharts configuration.
        """
        ext_counts: dict[str, int] = defaultdict(int)
        for record in file_records:
            ext = getattr(record, "extension", "unknown").lower()
            if not ext:
                ext = "none"
            ext_counts[ext] += 1
        
        labels = list(ext_counts.keys())
        series = list(ext_counts.values())

        return {
            "chart": {
                "type": "donut",
                "height": 350
            },
            "series": series,
            "labels": labels,
            "title": {"text": "File Types Distribution"}
        }

    @staticmethod
    def build_deletion_bar_chart(events: list[Any]) -> dict[str, Any]:
        """
        Build a bar chart of deletions per day.

        Args:
            events: List of DataEvent instances.

        Returns:
            Dictionary representing the ApexCharts configuration.
        """
        deletion_counts: dict[str, int] = defaultdict(int)
        for event in events:
            etype = getattr(event, "event_type", None)
            etype_val = etype.value if etype is not None and hasattr(etype, "value") else str(etype or "")
            if etype_val == "FILE_DELETE":
                ts = getattr(event, "timestamp", None)
                if ts:
                    if isinstance(ts, str):
                        try:
                            ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                        except ValueError:
                            continue
                    if isinstance(ts, datetime):
                        date_str = ts.strftime("%Y-%m-%d")
                        deletion_counts[date_str] += 1

        sorted_dates = sorted(deletion_counts.keys())
        data = [{"x": date, "y": count} for date, count in zip(sorted_dates, [deletion_counts[d] for d in sorted_dates])]

        return {
            "chart": {
                "type": "bar",
                "height": 350
            },
            "series": [{"name": "Deletions", "data": data}],
            "xaxis": {"type": "datetime"},
            "title": {"text": "Deletions Per Day"}
        }

    @staticmethod
    def build_data_flow_chart(correlations: list[Any], devices: list[Any] | None = None) -> dict[str, Any]:
        """
        Build a data flow chart aggregated per device pair.

        Correlations may be dictionaries (JSON round-trip) or MovementChain
        objects. Source/target device IDs are mapped to display names.
        Deletions are shown as flows to "Deleted / Recycle Bin".

        Args:
            correlations: List of correlation objects/dicts.
            devices: Optional list of Device models for ID -> name mapping.

        Returns:
            Dictionary representing the ApexCharts configuration.
        """
        names: dict[str, str] = {}
        for dev in devices or []:
            dev_id = getattr(dev, "device_id", None)
            if dev_id:
                names[dev_id] = getattr(dev, "device_name", "") or dev_id

        def chain_get(chain: Any, key: str) -> Any:
            if isinstance(chain, dict):
                return chain.get(key, "")
            return getattr(chain, key, "")

        flows: dict[tuple[str, str], int] = defaultdict(int)
        for corr in correlations:
            source = chain_get(corr, "source_device") or "Unknown"
            targets = chain_get(corr, "target_devices") or []
            if not targets:
                continue
            target = targets[0] if isinstance(targets, (list, tuple)) else targets
            if not target:
                continue

            src_name = names.get(source, source)
            # Map RecycleBin/deletion targets to a readable label
            if str(target) in ("RecycleBin/External", "RecycleBin", "Deleted"):
                dst_name = "Deleted / Recycle Bin"
            else:
                dst_name = str(names.get(target, target) or target)

            if src_name == dst_name:
                continue
            flows[(str(src_name), str(dst_name))] += 1

        data = [
            {"x": f"{source} -> {target}", "y": count}
            for (source, target), count in sorted(flows.items(), key=lambda kv: -kv[1])
        ]

        return {
            "chart": {
                "type": "bar",
                "height": 350
            },
            "plotOptions": {
                "bar": {
                    "horizontal": True
                }
            },
            "series": [{"name": "File Transfers", "data": data}],
            "title": {"text": "Data Flow Between Devices"}
        }
