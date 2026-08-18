import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# External forensic binaries the Helios pipeline actually invokes, with the
# feature that uses each one. Keys are resolved via resolve_tool_binary()
# (bundle-aware) and shown in the Settings & Tools diagnostics screen.
# Tools that are not listed here are not part of the pipeline and are not
# shown in the UI.
TOOLS_IN_USE: tuple[str, ...] = (
    "fls", "fsstat",          # SleuthKit — deleted-file recovery
    "LECmd", "JLECmd",        # LNK & JumpList access history
    "PECmd",                  # Prefetch execution history
    "RBCmd",                  # Recycle Bin $I parsing
    "SBECmd",                 # ShellBags folder history
    "MFTECmd",                # MFT & USN Journal parse
    "chainsaw",               # Sigma rule hunts over Windows event logs
    "exiftool",               # deep file-type verification
    "adb",                    # Android device detection
)

TOOL_LABELS: dict[str, str] = {
    "fls": "SleuthKit fls (deleted-file listing)",
    "fsstat": "SleuthKit fsstat (volume info)",
    "LECmd": "LECmd (LNK parse)",
    "JLECmd": "JLECmd (JumpList parse)",
    "PECmd": "PECmd (Prefetch parse)",
    "RBCmd": "RBCmd (Recycle Bin parse)",
    "SBECmd": "SBECmd (ShellBags parse)",
    "MFTECmd": "MFTECmd (MFT & USN Journal parse)",
    "chainsaw": "Chainsaw (Sigma EVTX hunts)",
    "exiftool": "ExifTool (file-type verification)",
    "adb": "ADB (Android device detection)",
}


@dataclass
class HeliosConfig:
    """Holds configuration for the Helios forensic tool."""
    tool_paths: dict[str, str | None] = field(default_factory=dict)
    working_hours: dict[str, str | list[str]] = field(default_factory=dict)
    hashing: dict[str, str | bool | int] = field(default_factory=dict)
    scanning: dict[str, str | bool | int] = field(default_factory=dict)
    report: dict[str, str] = field(default_factory=dict)
    evidence: dict[str, bool] = field(default_factory=dict)
    investigation_profiles: dict[str, dict] = field(default_factory=dict)
    suspicious_rules: list[dict] = field(default_factory=list)
    device_profiles: dict[str, dict] = field(default_factory=dict)


def get_bundle_root() -> Path:
    """Returns the directory containing bundled resources (config, tools, templates).

    Under a PyInstaller-frozen executable this is ``sys._MEIPASS``, where
    ``config/``, ``tools/`` and the ``helios`` package are extracted.
    In source checkouts this is the project root (parent of ``src/``).
    """
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parent.parent.parent


def load_config(config_dir: Path | None = None) -> HeliosConfig:
    """
    Loads all configuration files and resolves external tool paths.
    
    Args:
        config_dir: Optional path to the configuration directory.
        
    Returns:
        A populated HeliosConfig object.
    """
    if config_dir is None:
        config_dir = get_bundle_root() / "config"
        if getattr(sys, "frozen", False):
            # Frozen builds: prefer a user-supplied config/ beside the executable
            exe_config = Path(sys.argv[0]).resolve().parent / "config"
            if exe_config.exists():
                config_dir = exe_config

    # Default configuration
    config = HeliosConfig(
        working_hours={
            "start": "09:00",
            "end": "17:00",
            "days": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"]
        },
        hashing={
            "algorithm": "sha256",
            "hash_large_files": False,
            "large_file_threshold_mb": 500
        },
        scanning={
            "max_depth": 100,
            "skip_media": True,
            "skip_system_dirs": True
        },
        report={
            "theme": "dark",
            "company_name": "Default Corp",
            "logo_path": "",
            "output_format": "html"
        },
        evidence={
            "create_package": True,
            "include_raw_artifacts": False
        }
    )

    def _load_yaml(filename: str) -> dict | list | None:
        path = config_dir / filename
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f)
            except Exception:
                return None
        return None

    # Load main config (config.yaml or the bundled default_config.yaml)
    main_config = _load_yaml("config.yaml")
    if main_config is None:
        main_config = _load_yaml("default_config.yaml")
    if isinstance(main_config, dict):
        if "tool_paths" in main_config and isinstance(main_config["tool_paths"], dict):
            config.tool_paths.update(main_config["tool_paths"])
        if "working_hours" in main_config:
            config.working_hours.update(main_config["working_hours"])
        if "hashing" in main_config:
            config.hashing.update(main_config["hashing"])
        if "scanning" in main_config:
            config.scanning.update(main_config["scanning"])
        if "report" in main_config:
            config.report.update(main_config["report"])
        if "evidence" in main_config:
            config.evidence.update(main_config["evidence"])

    # Load profiles and rules
    profiles = _load_yaml("investigation_profiles.yaml")
    if isinstance(profiles, dict):
        # The YAML file wraps profiles under a top-level "profiles" key
        config.investigation_profiles = profiles.get("profiles", profiles)

    rules = _load_yaml("suspicious_rules.yaml")
    if isinstance(rules, dict):
        config.suspicious_rules = rules.get("rules", rules)
    elif isinstance(rules, list):
        config.suspicious_rules = rules

    devices = _load_yaml("device_profiles.yaml")
    if isinstance(devices, dict):
        config.device_profiles = devices

    # Resolve tool paths for every external binary the pipeline actually uses.
    # Resolution is bundle-aware (checks the bundled tools/ directory, the
    # PyInstaller bundle, the exe directory and PATH in that order) so a
    # bundled binary shows as DETECTED even when it is not on PATH.
    from helios.adapters.base import resolve_tool_binary

    for tool in TOOLS_IN_USE:
        explicit = config.tool_paths.get(tool)
        resolved = resolve_tool_binary(tool, explicit_path=explicit)
        config.tool_paths[tool] = str(resolved) if resolved else None

    return config
