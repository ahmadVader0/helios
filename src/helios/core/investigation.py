"""
Investigation profile management.

Loads investigation profiles from ``config/investigation_profiles.yaml``,
maps profile module keys to concrete Helios analyzer/engine modules, and
decides which modules are enabled for a given profile.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_PROFILE = "full"

# Maps profile module keys (as defined in config/investigation_profiles.yaml)
# to concrete Helios import paths that implement the corresponding analysis.
PROFILE_MODULE_MAP: dict[str, list[str]] = {
    "usb_transfers": ["helios.analyzers.usb_history"],
    "file_deletions": ["helios.analyzers.recycle_bin"],
    "recent_file_access": ["helios.analyzers.lnk_jumplists"],
    "event_logs": ["helios.analyzers.event_logs"],
    "program_execution": ["helios.analyzers.prefetch"],
    "shellbags": ["helios.analyzers.shellbags"],
    "deleted_file_recovery": ["helios.adapters.sleuthkit_adapter"],
    "suspicious_files": ["helios.analyzers.suspicious_detector", "helios.analyzers.file_type_verifier", "helios.adapters.exiftool_adapter"],
    "cross_device_matching": ["helios.core.correlator"],
    "mft_analysis": ["helios.analyzers.mft_analyzer"],
    "usn_journal": ["helios.analyzers.usn_journal"],
}


@dataclass
class InvestigationProfile:
    """A named investigation profile with enabled/disabled module keys."""

    name: str
    description: str = ""
    enabled: set[str] = field(default_factory=set)
    disabled: set[str] = field(default_factory=set)

    def is_module_enabled(self, module_key: str) -> bool:
        """Whether a profile module key is enabled under this profile."""
        if module_key in self.disabled:
            return False
        if self.enabled and module_key in self.enabled:
            return True
        if self.enabled:
            return False
        return True

    def enabled_modules(self) -> list[str]:
        """Resolve profile module keys to concrete Helios import paths."""
        keys = self.enabled if self.enabled else set(PROFILE_MODULE_MAP) - self.disabled
        modules: list[str] = []
        for key in keys:
            modules.extend(PROFILE_MODULE_MAP.get(key, []))
        return sorted(set(modules))


class ProfileManager:
    """
    Loads and queries investigation profiles.

    Accepts the raw ``profiles`` YAML structure or a config dict that wraps it
    under a top-level ``profiles`` key (as produced by HeliosConfig).
    """

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self._profiles: dict[str, InvestigationProfile] = {}
        config = config or {}
        raw = config.get("profiles", config) if isinstance(config, dict) else {}
        if isinstance(raw, dict):
            for name, body in raw.items():
                if not isinstance(body, dict):
                    continue
                modules = body.get("modules", {}) if isinstance(body.get("modules"), dict) else {}
                self._profiles[name] = InvestigationProfile(
                    name=str(name),
                    description=str(body.get("description", "")),
                    enabled=set(modules.get("enabled", []) or []),
                    disabled=set(modules.get("disabled", []) or []),
                )

    def get_profile(self, name: str = DEFAULT_PROFILE) -> InvestigationProfile:
        """Fetch a profile, failing closed for unknown profile names.

        An unknown profile name disables every module instead of silently
        running everything (fail-open would be dangerous in a forensic tool).
        """
        profile = self._profiles.get(name)
        if profile is not None:
            return profile
        logger.warning(
            "Unknown investigation profile '%s' — all modules disabled. "
            "Known profiles: %s",
            name, ", ".join(sorted(self._profiles)) or "(none loaded)",
        )
        return InvestigationProfile(name=name, enabled=set(), disabled=set(PROFILE_MODULE_MAP))

    def is_module_enabled(self, profile_name: str, module_key: str) -> bool:
        """Whether a module key runs under the named profile."""
        return self.get_profile(profile_name).is_module_enabled(module_key)

    def enabled_modules(self, profile_name: str) -> list[str]:
        """Concrete Helios import paths enabled for the named profile."""
        return self.get_profile(profile_name).enabled_modules()
