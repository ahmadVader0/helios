"""
Suspicious Activity & Heuristics Rule Engine.

Detects suspicious patterns such as executables on USBs, double extensions,
hidden files in unusual locations, crypto containers, large archives in temp,
password-protected archives, autorun files, mass deletions and after-hours
USB activity. All rules defined in ``config/suspicious_rules.yaml`` are
enforced here (file-based rules in ``analyze()``, event-based rules in
``analyze_events()``). Rule RULE-009 (extension mismatch) is enforced by
``FileTypeVerifierAnalyzer``.
"""

import logging
import re
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from helios.analyzers.base import AnalyzerBase, RawArtifact
from helios.models import Alert, Confidence, DataEvent, EventType, Severity

logger = logging.getLogger(__name__)

# Executable / script extensions commonly abused by malware, backdoors and
# droppers. Used for "dangerous file" checks on removable media and in
# user-content folders where they have no legitimate business.
EXECUTABLE_EXTENSIONS: set[str] = {
    ".exe", ".scr", ".pif", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".hta", ".ps1", ".psm1", ".psd1",
    ".jar", ".msi", ".cpl", ".iso", ".lnk", ".msc", ".reg", ".docm",
    ".xlsm", ".pptm",
}

# Folder fragments (lower-cased) that are user-content / temp areas where an
# executable or script is unusual and worth flagging.
UNUSUAL_EXEC_LOCATIONS: tuple[str, ...] = (
    "download", "document", "desktop", "temp", "tmp", "appdata\\local\\temp",
    "inbox", "attachment", "recycle", "public\\documents",
)

# Scripts that carry a strong malware-persistence fingerprint in their first
# bytes (e.g. a VBS/JS/BAT/PS1 that is actually a compiled PE, or a script
# that immediately invokes hidden execution).
SCRIPT_EXTENSIONS: set[str] = {".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".bat", ".cmd", ".hta", ".ps1", ".psm1", ".psd1"}

# System directories where scripts are expected; a script file anywhere else
# (user profile root, scan root, USB drive, random folder) is worth flagging.
SYSTEM_DIR_FRAGMENTS: tuple[str, ...] = (
    "\\windows\\", "/windows/", "\\system32", "/system32", "\\syswow64",
    "/syswow64", "\\program files", "/program files", "\\programdata",
    "/programdata", "/usr/", "/bin/", "/sbin/", "/lib/", "/etc/", "/var/", "/opt/",
)

TEMP_DIR_FRAGMENTS: tuple[str, ...] = ("temp", "tmp")

ARCHIVE_EXTENSIONS: set[str] = {".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz"}

# Maps YAML rule names to internal analyzer keys. Rule RULE-009
# (extension_mismatch) is consumed here but enforced by the file-type
# verifier module; it is included so the toggle remains loadable.
RULE_NAME_MAP: dict[str, str] = {
    "executables_on_usb": "usb_executables",
    "double_extensions": "double_extensions",
    "hidden_in_unusual_locations": "hidden_unusual",
    "encrypted_containers": "crypto_containers",
    "large_archives_in_temp": "large_archives",
    "mass_deletion": "mass_deletion",
    "after_hours_usb": "after_hours_usb",
    "password_protected_archives": "password_archives",
    "extension_mismatch": "extension_mismatch",
    "executables_in_content_dirs": "executables_in_content_dirs",
    "script_binary_disguise": "script_binary_disguise",
    "scripts_outside_system_dirs": "scripts_outside_system_dirs",
    "autorun_files": "autorun_files",
}


def _rule_enabled(rules: dict[str, Any], key: str, default: bool = True) -> bool:
    """Read an enabled flag that may be a bare bool or a config dict."""
    value = rules.get(key, default)
    if isinstance(value, dict):
        return bool(value.get("enabled", default))
    return bool(value)


class SuspiciousDetectorAnalyzer(AnalyzerBase):
    """Analyzer for detecting suspicious files and activity heuristics."""

    def __init__(self, config: dict | None = None, scan_options: Any = None, rules_path: str = "config/suspicious_rules.yaml") -> None:
        """Initialize the SuspiciousDetectorAnalyzer.

        Args:
            config: Optional configuration dict.
            scan_options: Optional scan options.
            rules_path: Path to the YAML rules file.
        """
        super().__init__(config=config or {}, scan_options=scan_options)
        self.rules_path = Path(rules_path)
        self.rules: dict[str, Any] = self._load_rules()

    def name(self) -> str:
        """Return analyzer name."""
        return "Suspicious Activity & Heuristics Analyzer"

    def can_run(self) -> bool:
        """Check if analyzer can run."""
        return True

    def collect(self, device: Any) -> list[RawArtifact]:
        """Collect artifacts."""
        return []

    def _load_rules(self) -> dict[str, Any]:
        """Load suspicious activity rules from YAML config."""
        from helios.config import get_bundle_root

        project_root = get_bundle_root()
        rules_path = Path(self.rules_path)
        if not rules_path.is_absolute():
            # Resolve relative paths against the project root (e.g. config/...)
            rules_path = (project_root / rules_path).resolve()
        else:
            rules_path = rules_path.resolve()

        # Block traversal sequences that escape the project directory
        try:
            rules_path.relative_to(project_root)
        except ValueError:
            logger.warning("Rules path %s resolves outside project root; using defaults.", rules_path)
            rules_path = project_root / "config" / "suspicious_rules.yaml"

        if not rules_path.exists():
            logger.warning("Rules file %s not found. Using defaults.", rules_path)
            return {
                "double_extensions": True,
                "usb_executables": True,
                "hidden_unusual": True,
                "crypto_containers": [".hc", ".tc", ".vc"]
            }

        try:
            with open(rules_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            # Real rules files wrap entries under a top-level "rules" key
            return self._normalize_rules(data.get("rules", data) if isinstance(data, dict) else {})
        except Exception as e:
            logger.error("Failed to load rules: %s", e)
            return {}

    @staticmethod
    def _normalize_rules(rules: dict[str, Any]) -> dict[str, Any]:
        """Map every YAML rule to the analyzer's internal rule keys.

        Rules carrying parameters keep their parameters as a nested dict so
        the analyzer can honor thresholds, extensions and directories.
        """
        normalized: dict[str, Any] = {}
        for rule_name, body in rules.items():
            internal = RULE_NAME_MAP.get(rule_name)
            if internal is None or not isinstance(body, dict):
                continue

            if internal == "crypto_containers":
                # Preserve the extension/header list the analyzer checks
                if not body.get("enabled", True):
                    normalized[internal] = []
                    continue
                ext_map = {
                    "VeraCrypt": ".hc", "TrueCrypt": ".tc", "BitLocker": ".bt"
                }
                exts = [ext_map.get(s.get("name", "")) for s in body.get("signatures", []) if s.get("name") in ext_map]
                normalized[internal] = exts or [".hc", ".tc", ".vc"]
                continue

            if internal in ("large_archives", "mass_deletion", "password_archives", "autorun_files"):
                # Parameterized rules keep their full body so thresholds,
                # extensions and directories are honored.
                normalized[internal] = dict(body)
                continue

            normalized[internal] = body.get("enabled", True)
        return normalized

    def analyze(
        self,
        artifacts: list[RawArtifact],
        device_types: dict[str, Any] | None = None,
    ) -> list[Alert]:
        """Analyze artifacts against suspicious rules.

        Args:
            artifacts: List of RawArtifact objects (wrapping FileRecords).
            device_types: Optional mapping of source_device -> DeviceType so
                files can be attributed to removable media correctly.

        Returns:
            List of generated Alerts.
        """
        alerts: list[Alert] = []
        device_types = device_types or {}

        for artifact in artifacts:
            record = artifact.raw_data
            if isinstance(record, dict):
                record = record.get("file_record")
            if not record or not hasattr(record, "file_path"):
                continue

            file_path = str(record.file_path).lower()
            file_name = str(record.file_name).lower()
            ext = str(record.extension).lower()
            src_dev = str(record.source_device or "").lower()
            is_usb = (
                "usb" in src_dev or "removable" in src_dev
                or str(device_types.get(record.source_device, "")).upper() in ("USB", "ANDROID")
            )

            # RULE-001 — Executables / scripts on USB (any dangerous extension)
            if _rule_enabled(self.rules, "usb_executables"):
                if is_usb and ext in EXECUTABLE_EXTENSIONS:
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Suspicious File",
                        title="Executable or Script on USB Drive",
                        description=f"Dangerous executable/script file found on USB device: {file_name} ({ext})",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.HIGH
                    ))

            # RULE-002 — Double extensions (e.g. document.pdf.exe, invoice.xlsx.js)
            if _rule_enabled(self.rules, "double_extensions"):
                if re.search(r'\.[a-z0-9]{1,5}\.(exe|bat|cmd|com|pif|scr|vbs|vbe|js|jse|wsf|wsh|hta|ps1|psm1|jar|msi|cpl|lnk|iso|reg|docm|xlsm|pptm)$', file_name):
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Obfuscation",
                        title="Double Extension Detected",
                        description=f"File appears to use a double extension to hide its type: {file_name}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.HIGH
                    ))

            # RULE-011 — Dangerous executable/script in a user-content folder
            #     (Downloads, Documents, Desktop, Temp, email attachments...)
            path_parts = [p for p in re.split(r"[\\/]", file_path) if p]
            in_content_dir = any(
                frag in comp
                for comp in path_parts
                for frag in UNUSUAL_EXEC_LOCATIONS
            )
            in_system_dir = any(
                frag in file_path
                for frag in SYSTEM_DIR_FRAGMENTS
            )
            if _rule_enabled(self.rules, "executables_in_content_dirs"):
                if ext in EXECUTABLE_EXTENSIONS and in_content_dir:
                    alerts.append(Alert(
                        severity=Severity.MEDIUM,
                        category="Suspicious File",
                        title="Executable or Script in User-Content Folder",
                        description=f"Dangerous file type ({ext}) located in a user-content folder: {file_path}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.MEDIUM
                    ))

            # RULE-012 — Script file that is actually a compiled PE (MZ header)
            #     or ELF binary — a classic malware smuggling trick.
            if _rule_enabled(self.rules, "script_binary_disguise"):
                if ext in SCRIPT_EXTENSIONS:
                    try:
                        with open(record.file_path, "rb") as f:
                            header = f.read(4)
                        if header.startswith(b"MZ") or header.startswith(b"\x7fELF"):
                            alerts.append(Alert(
                                severity=Severity.HIGH,
                                category="Obfuscation",
                                title="Script Extension Masks a Compiled Binary",
                                description=f"File {file_name} claims to be a {ext} script but starts with a "
                                            f"compiled binary header ({(header[:2] or header[:4]).hex()}).",
                                evidence=[str(record.file_path)],
                                device=record.source_device,
                                confidence=Confidence.HIGH
                            ))
                    except (OSError, PermissionError):
                        pass

            # RULE-013 — Script file located outside system directories.
            #     User-content folders are already covered by RULE-011, so
            #     those paths are skipped here to avoid duplicate alerts.
            if _rule_enabled(self.rules, "scripts_outside_system_dirs"):
                if ext in SCRIPT_EXTENSIONS and not in_system_dir and not in_content_dir:
                    alerts.append(Alert(
                        severity=Severity.MEDIUM,
                        category="Suspicious File",
                        title="Script File Outside System Directories",
                        description=f"Script file ({ext}) located outside system directories: {file_path}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.MEDIUM
                    ))

            # RULE-003 — Hidden files in non-standard locations
            if _rule_enabled(self.rules, "hidden_unusual"):
                excluded_dirs = self.rules.get("hidden_unusual", True)
                excluded_fragments = (
                    [d.lower() for d in excluded_dirs.get("exclude_directories", [])]
                    if isinstance(excluded_dirs, dict) else []
                )
                is_hidden = bool(getattr(record, "is_hidden", False)) or file_name.startswith(".")
                in_excluded = any(frag in file_path for frag in excluded_fragments)
                if is_hidden and not in_excluded:
                    alerts.append(Alert(
                        severity=Severity.MEDIUM,
                        category="Suspicious File",
                        title="Hidden File in Non-Standard Location",
                        description=f"Hidden file discovered outside standard system directories: {file_path}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.MEDIUM
                    ))

            # RULE-005 — Large archive files in temporary directories
            large_archives = self.rules.get("large_archives", {})
            if _rule_enabled(self.rules, "large_archives", default=False):
                archive_exts = [str(e).lower() for e in large_archives.get("archive_extensions", [])]
                target_dirs = [str(d).lower() for d in large_archives.get("target_directories", [])]
                max_size = int(large_archives.get("max_size_mb", 100)) * 1024 * 1024
                size = int(getattr(record, "size", 0) or 0)
                in_temp = any(frag in file_path for frag in target_dirs) or any(
                    frag in file_path for frag in TEMP_DIR_FRAGMENTS
                )
                if in_temp and ext in archive_exts and size >= max_size:
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Suspicious File",
                        title="Large Archive in Temporary Directory",
                        description=f"Archive of {size / (1024 * 1024):.1f} MB stored in a temporary directory: {file_path}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.MEDIUM
                    ))

            # RULE-008 — Password-protected archives (zip flag / RAR header flag)
            if _rule_enabled(self.rules, "password_archives", default=False):
                archive_exts = [str(e).lower() for e in self.rules.get("password_archives", {}).get("archive_extensions", [])]
                if ext in archive_exts and _archive_is_encrypted(record.file_path, ext):
                    alerts.append(Alert(
                        severity=Severity.MEDIUM,
                        category="Encryption",
                        title="Password-Protected Archive",
                        description=f"Archive is password-protected or encrypted: {file_name}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.MEDIUM
                    ))

            # RULE-010 — Autorun files on removable media
            if _rule_enabled(self.rules, "autorun_files", default=False):
                autorun_name = str(self.rules.get("autorun_files", {}).get("filename", "autorun.inf")).lower()
                if is_usb and file_name == autorun_name:
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Suspicious File",
                        title="Autorun Configuration File on USB",
                        description=f"autorun.inf found on removable media, often used for persistence or lateral movement: {file_path}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.HIGH
                    ))

            # RULE-004 — Crypto Containers
            if _rule_enabled(self.rules, "crypto_containers", default=True):
                crypto_cfg = self.rules.get("crypto_containers", [".hc", ".tc", ".vc"])
                if isinstance(crypto_cfg, dict):
                    crypto_exts = [str(e).lower() for e in crypto_cfg.get("extensions", [".hc", ".tc", ".vc"])]
                elif isinstance(crypto_cfg, list):
                    crypto_exts = [str(e).lower() for e in crypto_cfg]
                else:
                    crypto_exts = [".hc", ".tc", ".vc"]

                if ext in crypto_exts or "veracrypt" in file_name or "truecrypt" in file_name:
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Encryption",
                        title="Encrypted Container Detected",
                        description=f"Potential TrueCrypt/VeraCrypt container found: {file_name}",
                        evidence=[str(record.file_path)],
                        device=record.source_device,
                        confidence=Confidence.HIGH
                    ))

        return alerts

    def analyze_events(
        self,
        events: list[DataEvent],
        working_hours: dict[str, Any] | None = None,
    ) -> list[Alert]:
        """Run event-timeline based suspicious rules.

        Implements:
        - RULE-006 mass deletion: N+ deletions within a time window.
        - RULE-007 after-hours USB connection.
        """
        alerts: list[Alert] = []

        def _to_utc(dt: datetime | None) -> datetime:
            if dt is None:
                return datetime.min.replace(tzinfo=timezone.utc)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)

        # RULE-006 — Mass deletion burst
        mass = self.rules.get("mass_deletion", {})
        if _rule_enabled(self.rules, "mass_deletion", default=False):
            threshold = int(mass.get("threshold_count", 20))
            window_minutes = int(mass.get("time_window_minutes", 5))
            window = timedelta(minutes=window_minutes)

            _SYS_DEL_TOKENS = (
                "system volume information", "$recycle.bin", "$extend", "fve2.{", "fve.{"
            )
            deletions = sorted(
                (
                    e for e in events
                    if getattr(e, "event_type", None) == EventType.FILE_DELETE
                    and getattr(e, "timestamp", None) is not None
                    and not any(tok in str(getattr(e, "source_path", "")).lower() for tok in _SYS_DEL_TOKENS)
                ),
                key=lambda e: _to_utc(e.timestamp),
            )
            if deletions:
                best_start = _to_utc(deletions[0].timestamp)
                best_count = 0
                left = 0
                for right in range(len(deletions)):
                    right_ts = _to_utc(deletions[right].timestamp)
                    while _to_utc(deletions[left].timestamp) + window < right_ts:
                        left += 1
                    count = right - left + 1
                    if count > best_count:
                        best_count = count
                        best_start = _to_utc(deletions[left].timestamp)
                if best_count >= threshold:
                    burst_paths = [
                        str(e.source_path) for e in deletions
                        if best_start <= _to_utc(e.timestamp) <= best_start + window
                    ][:10]
                    alerts.append(Alert(
                        severity=Severity.HIGH,
                        category="Mass Deletion",
                        title="Mass File Deletion Detected",
                        description=f"{best_count} files deleted within {window_minutes} minutes — "
                                     f"possible evidence wiping.",
                        evidence=burst_paths,
                        device="",
                        timestamp=best_start,
                        confidence=Confidence.HIGH,
                    ))

        # RULE-007 — After-hours USB connections
        if _rule_enabled(self.rules, "after_hours_usb", default=False):
            wh = working_hours or {}
            start_str = str(wh.get("start", "09:00"))
            end_str = str(wh.get("end", "17:00"))

            def _hour_min(value: str) -> tuple[int, int]:
                try:
                    parts = value.split(":")
                    return int(parts[0]), int(parts[1])
                except (ValueError, IndexError):
                    return 9, 0

            start_h, start_m = _hour_min(start_str)
            end_h, end_m = _hour_min(end_str)

            for evt in events:
                if getattr(evt, "event_type", None) != EventType.USB_CONNECT:
                    continue
                ts = getattr(evt, "timestamp", None)
                if ts is None:
                    continue
                local_ts = ts.astimezone() if ts.tzinfo else ts
                outside = (local_ts.hour, local_ts.minute) < (start_h, start_m) or (local_ts.hour, local_ts.minute) >= (end_h, end_m)
                if outside:
                    alerts.append(Alert(
                        severity=Severity.MEDIUM,
                        category="After-Hours Activity",
                        title="USB Connection Outside Working Hours",
                        description=f"USB device connected at {ts.strftime('%Y-%m-%d %H:%M')} "
                                    f"(working hours {start_str}-{end_str}).",
                        evidence=[getattr(evt, "source_path", "") or ""],
                        device=getattr(evt, "source_device", ""),
                        timestamp=ts,
                        confidence=Confidence.MEDIUM,
                    ))

        return alerts


def _archive_is_encrypted(file_path: str, ext: str) -> bool:
    """Determine whether an archive is password-protected.

    ZIP: a member whose decompression raises an encrypted error.
    RAR: the HEAD_FLAGS encryption bit (0x0004) in the main header.
    7z:  no reliable header-level flag; not claimed.
    """
    try:
        if ext == ".zip":
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    try:
                        zf.open(info).read(1)
                    except RuntimeError as exc:
                        if "encrypted" in str(exc).lower():
                            return True
                    except Exception:
                        continue
            return False
        if ext == ".rar":
            with open(file_path, "rb") as f:
                header = f.read(12)
            if header[:6] in (b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"):
                flags = int.from_bytes(header[9:11], "little")
                return bool(flags & 0x0004)
            return False
    except OSError:
        pass
    return False
