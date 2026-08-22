from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _ensure_utc(dt: datetime | None) -> datetime | None:
    """Ensure a datetime object is UTC-aware."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class EventType(Enum):
    FILE_CREATE = "FILE_CREATE"
    FILE_DELETE = "FILE_DELETE"
    FILE_MOVE = "FILE_MOVE"
    FILE_RENAME = "FILE_RENAME"
    FILE_MODIFY = "FILE_MODIFY"
    FILE_COPY = "FILE_COPY"
    USB_CONNECT = "USB_CONNECT"
    USB_DISCONNECT = "USB_DISCONNECT"
    APP_EXECUTE = "APP_EXECUTE"
    FILE_ACCESS = "FILE_ACCESS"
    DEVICE_CONNECT = "DEVICE_CONNECT"


class DeviceType(Enum):
    PC = "PC"
    LAPTOP = "LAPTOP"
    USB = "USB"
    ANDROID = "ANDROID"


class DriveType(Enum):
    SSD = "SSD"
    HDD = "HDD"
    USB = "USB"
    NETWORK = "NETWORK"
    UNKNOWN = "UNKNOWN"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Confidence(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RecoveryStatus(Enum):
    RECOVERABLE = "RECOVERABLE"
    PARTIAL = "PARTIAL"
    NOT_RECOVERABLE = "NOT_RECOVERABLE"
    NOT_DELETED = "NOT_DELETED"


def _generate_uuid() -> str:
    """Generate a UUID string."""
    return str(uuid.uuid4())


def _now() -> datetime:
    """Return the current UTC datetime."""
    return datetime.now(tz=timezone.utc)


@dataclass
class DataEvent:
    """A single forensic event."""
    timestamp: datetime
    event_type: EventType
    source_device: str
    source_path: str
    event_id: str = field(default_factory=_generate_uuid)
    destination_path: str | None = None
    file_hash: str | None = None
    file_size: int | None = None
    user_account: str | None = None
    confidence: Confidence = Confidence.MEDIUM
    raw_source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Ensure timestamp is UTC-aware."""
        if self.timestamp is not None and self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)

    def __repr__(self) -> str:
        """Return a concise string representation."""
        return f"DataEvent(event_type={self.event_type.name}, source_path='{self.source_path}')"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_type": self.event_type.value,
            "source_device": self.source_device,
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "user_account": self.user_account,
            "confidence": self.confidence.value,
            "raw_source": self.raw_source,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DataEvent:
        """Deserialize from a dict."""
        d = data.copy()
        if "timestamp" in d and isinstance(d["timestamp"], str):
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        if "event_type" in d and isinstance(d["event_type"], str):
            d["event_type"] = EventType(d["event_type"])
        if "confidence" in d and isinstance(d["confidence"], str):
            d["confidence"] = Confidence(d["confidence"])
        return cls(**d)


@dataclass
class Device:
    """A physical/logical device."""
    device_type: DeviceType
    device_name: str
    device_id: str = field(default_factory=_generate_uuid)
    serial_number: str = ""
    drive_letter: str = ""
    mount_point: str = ""
    filesystem_type: str = ""
    capacity: int = 0
    model: str = ""
    os_version: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "device_id": self.device_id,
            "device_type": self.device_type.value,
            "device_name": self.device_name,
            "serial_number": self.serial_number,
            "drive_letter": self.drive_letter,
            "mount_point": self.mount_point,
            "filesystem_type": self.filesystem_type,
            "capacity": self.capacity,
            "model": self.model,
            "os_version": self.os_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Device:
        """Deserialize from a dict."""
        d = data.copy()
        if "device_type" in d and isinstance(d["device_type"], str):
            d["device_type"] = DeviceType(d["device_type"])
        return cls(**d)


@dataclass
class DriveInfo:
    """A drive/partition."""
    drive_letter: str
    label: str = ""
    filesystem: str = ""
    total_size: int = 0
    free_space: int = 0
    drive_type: DriveType = DriveType.UNKNOWN
    is_removable: bool = False
    device_serial: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "drive_letter": self.drive_letter,
            "label": self.label,
            "filesystem": self.filesystem,
            "total_size": self.total_size,
            "free_space": self.free_space,
            "drive_type": self.drive_type.value,
            "is_removable": self.is_removable,
            "device_serial": self.device_serial,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DriveInfo:
        """Deserialize from a dict."""
        d = data.copy()
        if "drive_type" in d and isinstance(d["drive_type"], str):
            d["drive_type"] = DriveType(d["drive_type"])
        return cls(**d)


@dataclass
class FileRecord:
    """A file found during analysis."""
    file_path: str
    file_name: str
    extension: str = ""
    actual_type: str = ""
    size: int = 0
    sha256_hash: str = ""
    md5_hash: str = ""
    created: datetime | None = None
    modified: datetime | None = None
    accessed: datetime | None = None
    entry_modified: datetime | None = None
    is_deleted: bool = False
    is_hidden: bool = False
    is_system: bool = False
    is_encrypted: bool = False
    mft_entry_number: int | None = None
    parent_path: str = ""
    source_device: str = ""
    recovery_status: RecoveryStatus = RecoveryStatus.NOT_DELETED
    tags: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Ensure file timestamps are UTC-aware."""
        self.created = _ensure_utc(self.created)
        self.modified = _ensure_utc(self.modified)
        self.accessed = _ensure_utc(self.accessed)
        self.entry_modified = _ensure_utc(self.entry_modified)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "file_path": self.file_path,
            "file_name": self.file_name,
            "extension": self.extension,
            "actual_type": self.actual_type,
            "size": self.size,
            "sha256_hash": self.sha256_hash,
            "md5_hash": self.md5_hash,
            "created": self.created.isoformat() if self.created else None,
            "modified": self.modified.isoformat() if self.modified else None,
            "accessed": self.accessed.isoformat() if self.accessed else None,
            "entry_modified": self.entry_modified.isoformat() if self.entry_modified else None,
            "is_deleted": self.is_deleted,
            "is_hidden": self.is_hidden,
            "is_system": self.is_system,
            "is_encrypted": self.is_encrypted,
            "mft_entry_number": self.mft_entry_number,
            "parent_path": self.parent_path,
            "source_device": self.source_device,
            "recovery_status": self.recovery_status.value,
            "tags": self.tags,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Deserialize from a dict."""
        d = data.copy()
        for date_field in ("created", "modified", "accessed", "entry_modified"):
            if date_field in d and isinstance(d[date_field], str):
                d[date_field] = datetime.fromisoformat(d[date_field])
        if "recovery_status" in d and isinstance(d["recovery_status"], str):
            d["recovery_status"] = RecoveryStatus(d["recovery_status"])
        return cls(**d)


@dataclass
class Alert:
    """A suspicious finding."""
    severity: Severity
    category: str
    title: str
    alert_id: str = field(default_factory=_generate_uuid)
    description: str = ""
    evidence: list[str] = field(default_factory=list)
    device: str = ""
    timestamp: datetime | None = None
    confidence: Confidence = Confidence.MEDIUM
    rule_id: str = ""
    rule_name: str = ""

    def __post_init__(self) -> None:
        """Ensure alert timestamp is UTC-aware."""
        self.timestamp = _ensure_utc(self.timestamp)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "alert_id": self.alert_id,
            "severity": self.severity.value,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "device": self.device,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "confidence": self.confidence.value,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Deserialize from a dict."""
        d = data.copy()
        if "severity" in d and isinstance(d["severity"], str):
            d["severity"] = Severity(d["severity"])
        if "confidence" in d and isinstance(d["confidence"], str):
            d["confidence"] = Confidence(d["confidence"])
        if "timestamp" in d and isinstance(d["timestamp"], str):
            d["timestamp"] = datetime.fromisoformat(d["timestamp"])
        return cls(**d)


@dataclass
class Snapshot:
    """Point-in-time filesystem state."""
    name: str
    snapshot_id: str = field(default_factory=_generate_uuid)
    created_at: datetime = field(default_factory=_now)
    drive: str = ""
    path: str = ""
    file_count: int = 0
    total_size: int = 0
    file_hashes: dict[str, str] = field(default_factory=dict)


@dataclass
class ScanOptions:
    """User's scan configuration."""
    drives: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    date_from: datetime | None = None
    date_to: datetime | None = None
    file_types: list[str] = field(default_factory=list)
    keywords: list[str] = field(default_factory=list)
    excluded_paths: list[str] = field(default_factory=list)
    max_depth: int | None = None
    skip_media: bool = False
    profile_name: str = "full"
    modules_enabled: list[str] = field(default_factory=list)
    working_hours: tuple[str, str, list[str]] | None = None


@dataclass
class CustodyEntry:
    """Chain of custody log entry."""
    action: str
    timestamp: datetime = field(default_factory=_now)
    target: str = ""
    result: str = ""
    tool_name: str = ""
    tool_version: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class Investigation:
    """Complete forensic case."""
    case_name: str
    case_id: str = field(default_factory=_generate_uuid)
    investigator: str = ""
    created_at: datetime = field(default_factory=_now)
    completed_at: datetime | None = None
    devices: list[Device] = field(default_factory=list)
    drives_scanned: list[DriveInfo] = field(default_factory=list)
    scan_options: ScanOptions | None = None
    events: list[DataEvent] = field(default_factory=list)
    file_records: list[FileRecord] = field(default_factory=list)
    alerts: list[Alert] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    snapshots: list[Snapshot] = field(default_factory=list)
    evidence_hash: str = ""
    chain_of_custody: list[CustodyEntry] = field(default_factory=list)
    module_results: list[dict[str, Any]] = field(default_factory=list)
    profile_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "case_id": self.case_id,
            "case_name": self.case_name,
            "investigator": self.investigator,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "devices": [d.to_dict() for d in self.devices],
            "drives_scanned": [d.to_dict() for d in self.drives_scanned],
            "events": [e.to_dict() for e in self.events],
            "file_records": [f.to_dict() for f in self.file_records],
            "alerts": [a.to_dict() for a in self.alerts],
            "correlations": self.correlations,
            "evidence_hash": self.evidence_hash,
            "module_results": self.module_results,
            "profile_name": self.profile_name,
            "chain_of_custody": [
                {
                    "action": e.action,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "target": e.target,
                    "result": e.result,
                    "tool_name": e.tool_name,
                    "tool_version": e.tool_version,
                    "details": e.details,
                }
                for e in self.chain_of_custody
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Investigation:
        """Deserialize from a dict."""
        d = data.copy()
        if "created_at" in d and isinstance(d["created_at"], str):
            d["created_at"] = datetime.fromisoformat(d["created_at"])
        if "completed_at" in d and isinstance(d["completed_at"], str):
            d["completed_at"] = datetime.fromisoformat(d["completed_at"])
        if "devices" in d:
            d["devices"] = [Device.from_dict(dev) for dev in d["devices"]]
        if "drives_scanned" in d:
            d["drives_scanned"] = [DriveInfo.from_dict(drv) for drv in d["drives_scanned"]]
        if "events" in d:
            d["events"] = [DataEvent.from_dict(evt) for evt in d["events"]]
        if "file_records" in d:
            d["file_records"] = [FileRecord.from_dict(fr) for fr in d["file_records"]]
        if "alerts" in d:
            d["alerts"] = [Alert.from_dict(a) for a in d["alerts"]]
        if "chain_of_custody" in d:
            d["chain_of_custody"] = [
                CustodyEntry(
                    action=e.get("action", ""),
                    timestamp=datetime.fromisoformat(e["timestamp"]) if e.get("timestamp") else _now(),
                    target=e.get("target", ""),
                    result=e.get("result", ""),
                    tool_name=e.get("tool_name", ""),
                    tool_version=e.get("tool_version", ""),
                    details=e.get("details", {}),
                )
                for e in d["chain_of_custody"]
            ]
        return cls(**d)
