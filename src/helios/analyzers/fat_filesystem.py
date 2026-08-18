"""
FAT32 and exFAT filesystem analyzer for Helios.

This module provides an analyzer that walks the file system of FAT formatted volumes,
collecting file metadata and generating forensic timeline events.
"""

import os
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path

from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.core.hasher import hash_file
from helios.models import Alert, Confidence, DataEvent, Device, EventType, FileRecord


class FATFileSystemAnalyzer(AnalyzerBase):
    """
    Analyzer for FAT32 and exFAT volumes.

    Walks the entire volume, hashing files and generating forensic timeline events
    for file creation, modification, and access.
    """

    MAX_HASH_SIZE = 500 * 1024 * 1024  # 500 MB

    def name(self) -> str:
        """Get the human-readable name of the analyzer."""
        return "FAT/exFAT Filesystem Analyzer"

    def can_run(self) -> bool:
        """
        Determine whether this analyzer can run.
        Always runs for USB devices as a generic fallback.
        """
        return True

    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Walk the specified device mount point and collect FileRecords.

        Args:
            device (Device): The target device to scan.

        Returns:
            list[RawArtifact]: Raw artifacts containing FileRecords.
        """
        artifacts: list[RawArtifact] = []
        if not device.mount_point or not os.path.isdir(device.mount_point):
            return artifacts

        for root, _, files in os.walk(device.mount_point):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                try:
                    stat_res = os.stat(file_path)
                except OSError:
                    continue

                size = stat_res.st_size
                file_hash = ""
                if size <= self.MAX_HASH_SIZE:
                    file_hash = hash_file(Path(file_path))
                
                # Determine extension
                _, ext = os.path.splitext(file_name)
                ext = ext.lstrip(".").lower()

                # Parse timestamps to UTC
                mtime = datetime.fromtimestamp(stat_res.st_mtime, tz=timezone.utc)
                atime = datetime.fromtimestamp(stat_res.st_atime, tz=timezone.utc)
                
                # Handle creation time
                st_birthtime = getattr(stat_res, "st_birthtime", None)
                if st_birthtime is not None:
                    ctime = datetime.fromtimestamp(st_birthtime, tz=timezone.utc)
                else:
                    # Fallback for Linux where st_ctime is metadata change time
                    ctime = datetime.fromtimestamp(min(stat_res.st_ctime, stat_res.st_mtime), tz=timezone.utc)

                record = FileRecord(
                    file_path=file_path,
                    file_name=file_name,
                    extension=ext,
                    size=size,
                    sha256_hash=file_hash,
                    created=ctime,
                    modified=mtime,
                    accessed=atime,
                )

                artifact = RawArtifact(
                    artifact_id=str(uuid.uuid4()),
                    artifact_type="fat_file_record",
                    source_path=Path(file_path),
                    device_id=device.device_id,
                    collected_at=datetime.now(tz=timezone.utc),
                    raw_data=record,
                    metadata={"size": size, "hash": file_hash}
                )
                artifacts.append(artifact)

        return artifacts

    def analyze(self, artifacts: list[RawArtifact]) -> Sequence[DataEvent | Alert]:
        """
        Convert collected RawArtifacts into DataEvents.

        Args:
            artifacts (list[RawArtifact]): The collected artifacts wrapping FileRecords.

        Returns:
            Sequence[DataEvent | Alert]: The generated forensic events.
        """
        events: list[DataEvent | Alert] = []

        for artifact in artifacts:
            if not isinstance(artifact.raw_data, FileRecord):
                continue

            record = artifact.raw_data

            metadata = {
                "file_name": record.file_name,
                "file_path": record.file_path,
                "extension": record.extension,
                "size": record.size,
                "sha256_hash": record.sha256_hash,
            }

            # FILE_CREATE Event
            if record.created:
                events.append(
                    DataEvent(
                        timestamp=record.created,
                        event_type=EventType.FILE_CREATE,
                        source_device=artifact.device_id,
                        source_path=record.file_path,
                        file_hash=record.sha256_hash,
                        file_size=record.size,
                        confidence=Confidence.HIGH,
                        raw_source="FAT Filesystem Walk",
                        metadata=metadata.copy(),
                    )
                )

            # FILE_MODIFY Event
            if record.modified:
                events.append(
                    DataEvent(
                        timestamp=record.modified,
                        event_type=EventType.FILE_MODIFY,
                        source_device=artifact.device_id,
                        source_path=record.file_path,
                        file_hash=record.sha256_hash,
                        file_size=record.size,
                        confidence=Confidence.HIGH,
                        raw_source="FAT Filesystem Walk",
                        metadata=metadata.copy(),
                    )
                )

        return events
