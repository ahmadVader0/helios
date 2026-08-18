from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from helios.models import (
    Alert,
    Confidence,
    DataEvent,
    Device,
    DeviceType,
    DriveType,
    EventType,
    FileRecord,
    Investigation,
    Severity,
)

logger = logging.getLogger(__name__)

def _safe_ts(ts: datetime | None) -> datetime:
    """Normalize a timestamp to naive UTC for safe comparison."""
    if ts is None:
        return datetime.max
    if ts.tzinfo is not None:
        return ts.replace(tzinfo=None)
    return ts


@dataclass
class MovementChain:
    """
    Represents a chain of data movement across different devices, tracking
    a specific file by its hash as it moves from one device to another.
    """
    chain_id: str
    file_name: str
    sha256_hash: str
    # hops: List of (timestamp, source_device_id, target_device_id, action)
    hops: list[tuple[datetime, str, str, str]]
    source_device: str
    target_devices: list[str]
    exfiltrated: bool
    confidence: Confidence


class CrossDeviceCorrelator:
    """
    Engine to correlate events and file movements across multiple devices,
    building movement chains and detecting exfiltration.
    """

    def __init__(self, investigation: Investigation):
        """
        Initialize the CrossDeviceCorrelator with an investigation context.

        Args:
            investigation: The Investigation instance containing devices,
                           events, and file records.
        """
        self.investigation = investigation
        self.movement_chains: list[MovementChain] = []
        self.inferred_events: list[DataEvent] = []
        self.alerts: list[Alert] = []

    def correlate(self) -> list[dict[str, Any]]:
        """
        Run the complete correlation pipeline.

        Returns:
            A list of serialized correlation results including chains,
            detected USB transfers, exfiltration alerts, and the movement graph.
        """
        logger.info("Starting cross-device correlation pipeline.")
        
        chains = self.match_files_by_hash()
        self.movement_chains.extend(chains)
        
        usb_transfers = self.detect_usb_transfers()
        self.inferred_events.extend(usb_transfers)
        
        exfiltration_alerts = self.detect_exfiltration_patterns()
        self.alerts.extend(exfiltration_alerts)
        
        movement_graph = self.build_data_movement_graph()

        logger.info("Cross-device correlation pipeline completed.")
        
        return [
            {
                "type": "movement_chains",
                "count": len(chains),
                "data": chains
            },
            {
                "type": "inferred_usb_transfers",
                "count": len(usb_transfers),
                "data": usb_transfers
            },
            {
                "type": "exfiltration_alerts",
                "count": len(exfiltration_alerts),
                "data": exfiltration_alerts
            },
            {
                "type": "movement_graph",
                "data": movement_graph
            }
        ]

    def match_files_by_hash(self) -> list[MovementChain]:
        """
        Match FileRecords across Devices by SHA-256 (or MD5). If a file exists on PC 
        and USB, or was deleted on PC but exists on USB, create a MovementChain.

        Returns:
            A list of detected MovementChain objects.
        """
        logger.debug("Matching files by hash across devices...")
        chains = []
        
        # Group file records by hash
        hash_map: dict[str, list[tuple[Device, FileRecord]]] = {}
        device_map = {d.device_id: d for d in self.investigation.devices}
        
        for record in self.investigation.file_records:
            file_hash = record.sha256_hash or record.md5_hash
            if file_hash:
                dev = device_map.get(record.source_device, Device(device_type=DeviceType.PC, device_name="Unknown", device_id=record.source_device))
                if file_hash not in hash_map:
                    hash_map[file_hash] = []
                hash_map[file_hash].append((dev, record))
                    
        EMPTY_HASHES = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "d41d8cd98f00b204e9800998ecf8427e",
            "",
            "N/A",
        }

        # Analyze hashes that appear on multiple devices or different drives
        for file_hash, records in hash_map.items():
            if not file_hash or file_hash in EMPTY_HASHES:
                continue

            devices_involved = set(d.device_id for d, _ in records)
            drives_involved = set(Path(r.file_path).drive.upper() for _, r in records if r.file_path and Path(r.file_path).drive)
            has_deleted = any(r.is_deleted for _, r in records)

            if len(devices_involved) > 1 or len(drives_involved) > 1 or has_deleted:
                # Sort records by creation time to determine source/target
                sorted_records = sorted(
                    records, 
                    key=lambda x: _safe_ts(x[1].created)
                )
                
                source_device_id = sorted_records[0][0].device_id
                target_device_ids: set[str] = set()
                file_name = sorted_records[0][1].file_name or "unknown"
                
                hops: list[tuple[datetime, str, str, str]] = []
                for i in range(1, len(sorted_records)):
                    prev_dev, prev_rec = sorted_records[i-1]
                    curr_dev, curr_rec = sorted_records[i]

                    rec_ts = curr_rec.created or curr_rec.modified or curr_rec.accessed
                    if rec_ts is None:
                        continue
                    timestamp = _safe_ts(rec_ts)
                    if timestamp.year >= 9000:
                        continue

                    prev_drive = Path(prev_rec.file_path).drive.upper() if prev_rec.file_path else ""
                    curr_drive = Path(curr_rec.file_path).drive.upper() if curr_rec.file_path else ""

                    if curr_dev.device_id != prev_dev.device_id:
                        target_id = curr_dev.device_id
                        target_device_ids.add(target_id)
                        action = "copied" if not prev_rec.is_deleted else "moved"
                        hops.append((timestamp, prev_dev.device_id, target_id, action))
                    elif curr_drive and prev_drive and curr_drive != prev_drive:
                        target_id = curr_drive
                        target_device_ids.add(target_id)
                        action = "copied" if not prev_rec.is_deleted else "moved"
                        hops.append((timestamp, prev_drive or prev_dev.device_id, target_id, action))
                    elif curr_rec.is_deleted or "$recycle.bin" in curr_rec.file_path.lower():
                        target_id = "RecycleBin"
                        target_device_ids.add(target_id)
                        action = "deleted"
                        hops.append((timestamp, prev_dev.device_id, target_id, action))

                if not hops:
                    if len(devices_involved) > 1:
                        for dev_id in devices_involved:
                            if dev_id != source_device_id:
                                target_device_ids.add(dev_id)
                    elif len(drives_involved) > 1:
                        src_drv = Path(sorted_records[0][1].file_path).drive.upper() if sorted_records[0][1].file_path else ""
                        for drv_id in drives_involved:
                            if drv_id != src_drv:
                                target_device_ids.add(drv_id)

                if target_device_ids or hops:
                    is_exfiltrated = any(
                        getattr(d.device_type, "value", str(d.device_type)) in ("USB", "ANDROID")
                        for d, _ in records
                        if d.device_id != source_device_id
                    )
                    
                    chain = MovementChain(
                        chain_id=str(uuid.uuid4()),
                        file_name=file_name,
                        sha256_hash=file_hash,
                        hops=hops,
                        source_device=source_device_id,
                        target_devices=list(target_device_ids),
                        exfiltrated=is_exfiltrated,
                        confidence=Confidence.HIGH
                    )
                    chains.append(chain)

        # Single-volume event-based chain building (LNK / USB session / Deletions)
        for event in self.investigation.events:
            etype = getattr(event, "event_type", None)
            etype_val = etype.value if etype is not None and hasattr(etype, "value") else str(etype or "")
            sp = getattr(event, "source_path", "")
            dp = getattr(event, "destination_path", "")

            if etype_val == "FILE_DELETE":
                fname = Path(sp).name if sp else "Unknown"
                chain = MovementChain(
                    chain_id=str(uuid.uuid4()),
                    file_name=fname,
                    sha256_hash=getattr(event, "file_hash", "") or "N/A",
                    hops=[(_safe_ts(event.timestamp), event.source_device or "Host PC", "RecycleBin", etype_val)],
                    source_device=event.source_device or "Host PC",
                    target_devices=["RecycleBin"],
                    exfiltrated=False,
                    confidence=Confidence.MEDIUM,
                )
                chains.append(chain)
            elif etype_val in ("FILE_COPY", "FILE_MOVE") and (dp or sp):
                meta = getattr(event, "metadata", {}) or {}
                dst_dev = meta.get("target_device")
                src_dev = event.source_device or "Host PC"
                if not dst_dev:
                    sp_drive = Path(sp).drive if sp else ""
                    dp_drive = Path(dp).drive if dp else ""
                    if dp_drive and sp_drive and dp_drive.lower() != sp_drive.lower():
                        dst_dev = dp_drive
                    elif "usb" in str(event.raw_source).lower() or "usb" in str(meta.get("description", "")).lower():
                        dst_dev = "USB Storage"

                if not dst_dev:
                    dst_dev = "External / Removable"

                fname = Path(sp or dp).name if (sp or dp) else "Unknown"
                chain = MovementChain(
                    chain_id=str(uuid.uuid4()),
                    file_name=fname,
                    sha256_hash=getattr(event, "file_hash", "") or "N/A",
                    hops=[(_safe_ts(event.timestamp), src_dev, dst_dev, etype_val)],
                    source_device=src_dev,
                    target_devices=[dst_dev],
                    exfiltrated="removable" in str(dp).lower() or "usb" in str(dst_dev).lower(),
                    confidence=Confidence.MEDIUM,
                )
                chains.append(chain)

        return chains

    def detect_usb_transfers(self) -> list[DataEvent]:
        """
        Cross-reference USB connection timestamps with USN Journal / File creation
        events on USB drives. Infers FILE_COPY or FILE_MOVE events.

        Returns:
            A list of inferred DataEvent objects representing transfers.
        """
        logger.debug("Detecting USB transfers via connection timestamps and file events...")
        inferred_events = []
        
        # 1. Identify Host vs USB/Removable Devices
        host_dev_id = "Host PC"
        usb_device_ids: set[str] = set()
        removable_roots: set[str] = set()

        for d in self.investigation.devices:
            dtype = getattr(d.device_type, "value", str(d.device_type))
            if dtype in ("PC", "LAPTOP", "SERVER"):
                host_dev_id = d.device_id
            elif dtype in ("USB", "ANDROID"):
                usb_device_ids.add(d.device_id)
                if d.mount_point:
                    removable_roots.add(str(d.mount_point).lower())

        # Also check drives scanned for removable / USB flags
        for drv in getattr(self.investigation, "drives_scanned", []):
            if getattr(drv, "is_removable", False) or getattr(drv, "drive_type", None) == DriveType.USB:
                dl = str(getattr(drv, "drive_letter", "")).lower()
                if dl:
                    removable_roots.add(dl)

        # 2. Extract USB connection windows
        usb_sessions: list[dict[str, Any]] = []
        disconnects_by_device: dict[str, list[datetime]] = {}
        for d_event in self.investigation.events:
            if getattr(d_event, "event_type", None) != getattr(EventType, "USB_DISCONNECT", "USB_DISCONNECT"):
                continue
            dev = getattr(d_event, "source_device", None) or "unknown_usb"
            ts = getattr(d_event, "timestamp", None)
            if ts is not None:
                disconnects_by_device.setdefault(dev, []).append(ts)

        for event in self.investigation.events:
            if getattr(event, "event_type", None) == getattr(EventType, "USB_CONNECT", "USB_CONNECT"):
                dev = getattr(event, "source_device", None) or "unknown_usb"
                connect_time = getattr(event, "timestamp", None)
                if connect_time is None:
                    continue
                connect_time = _safe_ts(connect_time)
                disconnect_time = next(
                    (ts for ts in disconnects_by_device.get(dev, []) if _safe_ts(ts) > connect_time),
                    None,
                )
                # Bound open-ended sessions without a disconnect event to 4 hours maximum
                session_end = _safe_ts(disconnect_time) if disconnect_time else connect_time + timedelta(hours=4)
                usb_sessions.append({
                    "device_id": dev,
                    "connect_time": connect_time,
                    "disconnect_time": session_end,
                    "has_real_disconnect": disconnect_time is not None,
                })

        # 3. Check file events falling within these verified windows
        for session in usb_sessions:
            usb_dev = session["device_id"]
            for event in self.investigation.events:
                if event.event_type != EventType.FILE_CREATE:
                    continue

                event_path_lower = str(event.source_path).lower()
                
                # A file creation is a target USB transfer if:
                # 1. The event device is a known USB device, or
                # 2. The event path starts with a removable drive mount/letter, or
                # 3. The event metadata indicates removable media.
                # Host system drive (e.g. C:) file creations are NOT USB destinations.
                is_on_removable = any(
                    event_path_lower.startswith(root) for root in removable_roots if root
                )
                is_target_usb = (
                    (event.source_device in usb_device_ids and event.source_device != host_dev_id)
                    or is_on_removable
                    or bool(event.metadata.get("removable_media_flag"))
                )

                if not is_target_usb:
                    continue

                event_time = _safe_ts(event.timestamp) if event.timestamp else None
                if event_time is None or event_time.year >= 9000:
                    continue

                session_start = session["connect_time"]
                session_end = session["disconnect_time"]
                inside_window = session_start <= event_time <= session_end

                if inside_window:
                    metadata = event.metadata or {}
                    transfer_event = DataEvent(
                        event_id=str(uuid.uuid4()),
                        timestamp=event_time,
                        event_type=EventType.FILE_COPY,
                        source_device=host_dev_id,
                        source_path=event.source_path,
                        destination_path=event.source_path,
                        raw_source="Correlator",
                        confidence=Confidence.HIGH if session["has_real_disconnect"] else Confidence.MEDIUM,
                        metadata={
                            "original_event_id": event.event_id,
                            "target_device": usb_dev if usb_dev != "unknown_usb" else "Removable USB",
                            "file_name": metadata.get("file_name", Path(event.source_path).name),
                            "description": f"File transferred to USB storage during active connection session.",
                        }
                    )
                    inferred_events.append(transfer_event)

        return inferred_events

    def detect_exfiltration_patterns(self) -> list[Alert]:
        """
        Flag files deleted from a PC endpoint within 10 minutes of being copied
        to removable USB media or uploaded to cloud storage.

        Returns:
            A list of generated Alert objects with Severity.CRITICAL.
        """
        logger.debug("Detecting exfiltration patterns (copy then delete)...")
        alerts = []
        
        # We need a list of transfer events and a list of deletion events
        transfers = [e for e in self.investigation.events + self.inferred_events 
                     if e.event_type in (EventType.FILE_COPY, EventType.FILE_MOVE)]
                     
        deletions = [e for e in self.investigation.events 
                     if e.event_type == EventType.FILE_DELETE]
        
        # Index deletions by file name for O(1) lookup instead of an O(T×D)
        # nested scan.
        deletions_by_name: dict[str, list[DataEvent]] = {}
        for delim in deletions:
            meta = delim.metadata or {}
            del_file = meta.get("file_name") or Path(delim.source_path).name
            if del_file:
                deletions_by_name.setdefault(del_file, []).append(delim)
        
        for trans in transfers:
            meta = trans.metadata or {}
            trans_file = meta.get("file_name") or Path(trans.source_path).name
            trans_time = _safe_ts(trans.timestamp) if trans.timestamp else None
            if trans_time is None or trans_time.year >= 9000:
                continue  # no real timestamp — skip
            
            if not trans_file:
                continue
            
            for delim in deletions_by_name.get(trans_file, []):
                del_time = _safe_ts(delim.timestamp) if delim.timestamp else None
                if del_time is None or del_time.year >= 9000:
                    continue  # no real timestamp — skip
                time_diff = del_time - trans_time
                # If deleted within 10 minutes (600 seconds) after transfer
                if timedelta(seconds=0) <= time_diff <= timedelta(minutes=10):
                        alert = Alert(
                            alert_id=str(uuid.uuid4()),
                            severity=Severity.CRITICAL,
                            category="Exfiltration",
                            title="Suspected Exfiltration and Cleanup",
                            description=f"File '{trans_file}' was transferred and then deleted within {time_diff.total_seconds()}s.",
                            evidence=[trans.event_id, delim.event_id],
                            device=trans.source_device,
                            timestamp=del_time,
                            confidence=Confidence.HIGH
                        )
                        alerts.append(alert)
                        
        return alerts

    def build_data_movement_graph(self) -> dict[str, Any]:
        """
        Build a node/edge graph representation of file transfers between devices.
        Useful for visualization (PC -> USB -> Mobile).

        Returns:
            A dictionary containing 'nodes' and 'edges'.
        """
        logger.debug("Building data movement graph...")
        nodes: dict[str, dict[str, Any]] = {}
        edges: list[dict[str, Any]] = []
        
        # Populate nodes from investigation devices
        for device in self.investigation.devices:
            dev_id = getattr(device, "device_id", "unknown")
            dev_type = getattr(device.device_type, "value", str(device.device_type)) if getattr(device, "device_type", None) else "Endpoint"
            nodes[dev_id] = {
                "id": dev_id,
                "label": getattr(device, "device_name", dev_id),
                "type": dev_type
            }
            
        # Populate edges from movement chains
        edge_map: dict[str, dict[str, Any]] = {}
        for chain in self.movement_chains:
            for hop in chain.hops:
                timestamp, source, target, action = hop
                
                # Ensure nodes exist
                if source not in nodes:
                    nodes[source] = {"id": source, "label": source, "type": "Unknown"}
                if target not in nodes:
                    nodes[target] = {"id": target, "label": target, "type": "Unknown"}
                    
                edge_id = f"{source}->{target}_{chain.sha256_hash}"
                
                # Check if edge already exists, update weight if so
                existing_edge = edge_map.get(edge_id)
                if existing_edge:
                    existing_edge["weight"] += 1
                    existing_edge["files"].append(chain.file_name)
                    existing_edge["timestamps"].append(timestamp.isoformat())
                else:
                    edge = {
                        "id": edge_id,
                        "source": source,
                        "target": target,
                        "action": action,
                        "weight": 1,
                        "files": [chain.file_name],
                        "timestamps": [timestamp.isoformat()]
                    }
                    edge_map[edge_id] = edge
                    edges.append(edge)
                    
        return {
            "nodes": list(nodes.values()),
            "edges": edges
        }
