"""
Magic Bytes File Extension Mismatch Verifier.

Reads file headers (magic bytes) to verify if the content matches the reported
file extension, flagging files attempting to disguise their true format.
"""

import logging
from pathlib import Path
from typing import Any

from helios.adapters.exiftool_adapter import ExifToolAdapter
from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import Alert, Confidence, ScanOptions, Severity

logger = logging.getLogger(__name__)

# Common magic bytes signatures (first few bytes of a file)
MAGIC_SIGNATURES: dict[bytes, str] = {
    b"MZ": ".exe",
    b"\x7fELF": ".elf",
    b"%PDF": ".pdf",
    b"\x89PNG\r\n\x1a\n": ".png",
    b"\xff\xd8\xff": ".jpg",
    b"\x47\x49\x46\x38": ".gif",
    b"PK\x03\x04": ".zip",
    b"Rar!\x1a\x07\x00": ".rar",
    b"Rar!\x1a\x07\x01\x00": ".rar",
    b"\x1f\x8b": ".gz",
    b"\x42\x5a\x68": ".bz2",
    b"\x7f\x5a\x4c\x53\x70": ".tar",
}

# Extensions that are safe to skip in the double/mismatch check because the
# format is a zip/ole container regardless of the extension used.
ZIP_BASED_EXTENSIONS: set[str] = {".docx", ".xlsx", ".pptx", ".jar", ".apk", ".zip", ".odt", ".ods", ".odp", ".epub"}

# Files larger than this are skipped by the exiftool deep-verification pass.
EXIFTOOL_MAX_SIZE_BYTES = 25 * 1024 * 1024


class FileTypeVerifierAnalyzer(AnalyzerBase):
    """Analyzer to detect file extension spoofing via magic byte verification."""

    def __init__(
        self,
        config: dict | None = None,
        scan_options: ScanOptions | None = None,
        exiftool_adapter: ExifToolAdapter | None = None,
    ) -> None:
        super().__init__(config=config or {}, scan_options=scan_options or ScanOptions())
        self.exiftool = exiftool_adapter or ExifToolAdapter(config=self.config)

    def name(self) -> str:
        return "Magic Bytes File Extension Mismatch Verifier"

    def can_run(self) -> bool:
        return True

    def collect(self, device: Any) -> list[RawArtifact]:
        return []

    def analyze(self, artifacts: list[RawArtifact]) -> list[Any]:
        """Analyze artifacts to verify file types."""
        alerts: list[Any] = []

        # Records whose magic bytes matched a known signature are resolved
        # immediately; everything else is queued for one batched exiftool
        # pass below (never one subprocess per file).
        pending: list[tuple[Any, str]] = []

        for artifact in artifacts:
            raw = artifact.raw_data
            if isinstance(raw, dict):
                record = raw.get("file_record")
            elif raw is not None:
                record = raw
            else:
                record = artifact.metadata.get("file_record") if isinstance(artifact.metadata, dict) else None
            if not record or not getattr(record, "file_path", None):
                continue

            try:
                with open(record.file_path, "rb") as f:
                    header = f.read(16)
            except (PermissionError, FileNotFoundError, OSError) as e:
                logger.debug("Cannot read file header for %s: %s", record.file_path, e)
                continue

            actual_ext = None
            for signature, ext in MAGIC_SIGNATURES.items():
                if header.startswith(signature):
                    actual_ext = ext
                    break

            reported_ext = record.extension.lower() if record.extension else ""

            if actual_ext:
                # Special cases
                if actual_ext == ".zip" and reported_ext in ZIP_BASED_EXTENSIONS:
                    continue  # These are ZIP-based formats, so it's normal
                if actual_ext == ".jpg" and reported_ext in [".jpeg"]:
                    continue

                if actual_ext != reported_ext and reported_ext != "":
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Obfuscation",
                        title="File Extension Mismatch",
                        description=f"File extension spoofing detected: {record.file_name} claims to be {reported_ext} but is {actual_ext}.",
                        evidence=[record.file_path],
                        device=record.source_device,
                        confidence=Confidence.HIGH
                    ))
            else:
                # No magic signature matched: defer to the batched exiftool
                # deep-verification pass (size-bounded).
                try:
                    if getattr(record, "size", 0) <= EXIFTOOL_MAX_SIZE_BYTES:
                        if reported_ext:
                            pending.append((record, reported_ext))
                except (TypeError, ValueError):
                    pass

        if pending:
            self._verify_batch_with_exiftool(alerts, pending)

        return alerts

    def _verify_batch_with_exiftool(self, alerts: list[Any], pending: list[tuple[Any, str]]) -> None:
        """Deep-verify unresolved file types in one batched exiftool pass."""
        try:
            batch = self.exiftool.get_file_types([Path(r.file_path) for r, _ in pending])
        except (AttributeError, TypeError):
            logger.warning("Batched exiftool verification unavailable; falling back to per-file.")
            for record, reported_ext in pending:
                self._verify_with_exiftool(alerts, record, reported_ext)
            return
        except Exception as e:
            logger.warning("Batched exiftool verification failed: %s", e)
            return

        for record, reported_ext in pending:
            true_ext, metadata = batch.get(str(Path(record.file_path)), (None, {}))
            if not true_ext:
                continue

            # Normalize common aliases so we do not flag legitimately named files.
            normalized_reported = reported_ext.lstrip(".")
            alias_pairs = {("jpg", "jpeg"), ("jpeg", "jpg"), ("htm", "html"), ("html", "htm")}
            if normalized_reported == true_ext or (normalized_reported, true_ext) in alias_pairs:
                continue

            evidence: list[Any] = [record.file_path]
            if metadata:
                evidence.append(repr(metadata))
            alerts.append(Alert(
                severity=Severity.HIGH,
                category="Obfuscation",
                title="File Extension Mismatch",
                description=(
                    f"File extension spoofing detected: {record.file_name} claims to be "
                    f".{normalized_reported} but exiftool identifies it as .{true_ext}."
                ),
                evidence=evidence,
                device=record.source_device,
                confidence=Confidence.HIGH
            ))

    def _verify_with_exiftool(self, alerts: list[Any], record: Any, reported_ext: str) -> None:
        """Deep-verify an unresolved file type using exiftool."""
        try:
            if getattr(record, "size", 0) > EXIFTOOL_MAX_SIZE_BYTES:
                return
        except (TypeError, ValueError):
            return

        if not reported_ext:
            return

        true_ext, metadata = self.exiftool.get_file_type(record.file_path)
        if not true_ext:
            return

        # Normalize common aliases so we do not flag legitimately named files.
        normalized_reported = reported_ext.lstrip(".")
        alias_pairs = {("jpg", "jpeg"), ("jpeg", "jpg"), ("htm", "html"), ("html", "htm")}
        if normalized_reported == true_ext or (normalized_reported, true_ext) in alias_pairs:
            return

        evidence: list[Any] = [record.file_path]
        if metadata:
            evidence.append(repr(metadata))
        alerts.append(Alert(
            severity=Severity.HIGH,
            category="Obfuscation",
            title="File Extension Mismatch",
            description=(
                f"File extension spoofing detected: {record.file_name} claims to be "
                f".{normalized_reported} but exiftool identifies it as .{true_ext}."
            ),
            evidence=evidence,
            device=record.source_device,
            confidence=Confidence.HIGH
        ))
