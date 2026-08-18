"""
Filesystem Snapshot & Diff Engine.

Provides functionality to capture filesystem snapshots, hash files, and compare
snapshots to produce detailed differences (added, deleted, modified, renamed).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from helios.models import FileRecord

logger = logging.getLogger(__name__)


@dataclass
class Snapshot:
    """Represents a point-in-time filesystem snapshot."""
    name: str
    base_path: str
    timestamp: datetime
    files: dict[str, FileRecord] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialize snapshot to dictionary."""
        return {
            "name": self.name,
            "base_path": self.base_path,
            "timestamp": self.timestamp.isoformat(),
            "files": {path: record.to_dict() for path, record in self.files.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Snapshot":
        """Deserialize snapshot from dictionary."""
        return cls(
            name=data["name"],
            base_path=data["base_path"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            files={path: FileRecord.from_dict(rec) for path, rec in data.get("files", {}).items()},
        )


@dataclass
class SnapshotDiff:
    """Result of comparing two snapshots."""
    added_files: list[FileRecord] = field(default_factory=list)
    deleted_files: list[FileRecord] = field(default_factory=list)
    modified_files: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)
    renamed_files: list[tuple[FileRecord, FileRecord]] = field(default_factory=list)


class SnapshotEngine:
    """Engine for creating and comparing filesystem snapshots."""

    def __init__(self, chunk_size: int = 8192) -> None:
        """Initialize the SnapshotEngine.

        Args:
            chunk_size: Size of chunks for reading files during hashing.
        """
        self.chunk_size = chunk_size

    def _hash_file(self, file_path: Path) -> str:
        """Compute SHA-256 hash of a file.

        Args:
            file_path: Path to the file.

        Returns:
            Hex digest of the file's SHA-256 hash.
        """
        sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(self.chunk_size):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.warning("Failed to hash file %s: %s", file_path, e)
            return ""

    def take_snapshot(self, drive_or_path: Path, name: str) -> Snapshot:
        """Take a snapshot of the given path, hashing all files.

        Args:
            drive_or_path: Target directory to snapshot.
            name: Name of the snapshot.

        Returns:
            A populated Snapshot instance.
        """
        if not drive_or_path.exists() or not drive_or_path.is_dir():
            raise ValueError(f"Path does not exist or is not a directory: {drive_or_path}")

        snapshot = Snapshot(
            name=name,
            base_path=str(drive_or_path.resolve()),
            timestamp=datetime.now(tz=timezone.utc)
        )

        for filepath in drive_or_path.rglob("*"):
            if filepath.is_file():
                try:
                    stat = filepath.stat()
                    file_hash = self._hash_file(filepath)
                    record = FileRecord(
                        file_path=str(filepath),
                        file_name=filepath.name,
                        extension=filepath.suffix.lower(),
                        size=stat.st_size,
                        sha256_hash=file_hash,
                        created=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc),
                        modified=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                        accessed=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc),
                        parent_path=str(filepath.parent)
                    )
                    snapshot.files[str(filepath)] = record
                except Exception as e:
                    logger.warning("Could not process file %s: %s", filepath, e)

        return snapshot

    def save_snapshot(self, snapshot: Snapshot, output_file: Path) -> None:
        """Save a snapshot to a JSON file.

        Args:
            snapshot: Snapshot to save.
            output_file: Target JSON file path.
        """
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(snapshot.to_dict(), f, indent=2)

    def load_snapshot(self, snapshot_file: Path) -> Snapshot:
        """Load a snapshot from a JSON file.

        Args:
            snapshot_file: Path to the JSON snapshot file.

        Returns:
            The loaded Snapshot instance.
        """
        if not snapshot_file.exists():
            raise FileNotFoundError(f"Snapshot file not found: {snapshot_file}")
        
        with open(snapshot_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        return Snapshot.from_dict(data)

    def compare_snapshots(self, snap_a: Snapshot, snap_b: Snapshot) -> SnapshotDiff:
        """Compare two snapshots and return their differences.

        Args:
            snap_a: The older snapshot.
            snap_b: The newer snapshot.

        Returns:
            A SnapshotDiff containing added, deleted, modified, and renamed files.
        """
        diff = SnapshotDiff()
        
        a_paths = set(snap_a.files.keys())
        b_paths = set(snap_b.files.keys())
        
        a_hashes = {v.sha256_hash: k for k, v in snap_a.files.items() if v.sha256_hash}
        
        # Files in B but not A (added or renamed)
        added_paths = b_paths - a_paths
        # Files in A but not B (deleted or renamed)
        deleted_paths = a_paths - b_paths
        # Files in both (could be modified)
        common_paths = a_paths & b_paths
        
        # Check common paths for modifications
        for path in common_paths:
            file_a = snap_a.files[path]
            file_b = snap_b.files[path]
            if file_a.sha256_hash != file_b.sha256_hash:
                diff.modified_files.append((file_a, file_b))

        # Check added/deleted paths for renames (same hash, different path)
        matched_added = set()
        matched_deleted = set()
        
        for added_path in added_paths:
            file_b = snap_b.files[added_path]
            if file_b.sha256_hash and file_b.sha256_hash in a_hashes:
                original_path = a_hashes[file_b.sha256_hash]
                if original_path in deleted_paths:
                    file_a = snap_a.files[original_path]
                    diff.renamed_files.append((file_a, file_b))
                    matched_added.add(added_path)
                    matched_deleted.add(original_path)

        # Remaining un-matched added paths are genuine additions
        for p in (added_paths - matched_added):
            diff.added_files.append(snap_b.files[p])

        # Remaining un-matched deleted paths are genuine deletions
        for p in (deleted_paths - matched_deleted):
            diff.deleted_files.append(snap_a.files[p])

        return diff
