"""
Base components for forensic analyzers.

This module defines the foundational classes used by all specialized analyzers
within Helios, ensuring consistency in how artifacts are collected and processed.
"""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Forward declarations for core models
try:
    from helios.models import Alert, DataEvent, Device, ScanOptions
except ImportError:
    Alert = Any  # type: ignore[misc,assignment]
    DataEvent = Any  # type: ignore[misc,assignment]
    Device = Any  # type: ignore[misc,assignment]
    ScanOptions = Any  # type: ignore[misc,assignment]


@dataclass
class RawArtifact:
    """
    Represents a raw piece of forensic data collected from a system.

    Attributes:
        artifact_id (str): A unique identifier for the artifact.
        artifact_type (str): The category or type of the artifact (e.g., 'registry', 'mft').
        source_path (Path): The original file path or location where the artifact was found.
        device_id (str): Identifier for the device from which the artifact was collected.
        collected_at (datetime): The timestamp when the artifact was gathered.
        raw_data (Any, optional): The actual raw data content, if stored in memory. Defaults to None.
        metadata (Dict[str, Any]): Additional contextual information about the artifact.
    """
    artifact_id: str
    artifact_type: str
    source_path: Path
    device_id: str
    collected_at: datetime
    raw_data: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AnalyzerBase(ABC):
    """
    Abstract Base Class for all forensic analyzers in Helios.

    Analyzers are responsible for discovering, collecting, and processing
    specific types of forensic artifacts.
    """

    def __init__(self, config: dict | None = None, scan_options: ScanOptions | None = None):
        """
        Initialize the analyzer.

        Args:
            config (Optional[dict], optional): The general configuration dictionary. Defaults to None.
            scan_options (Optional[ScanOptions], optional): The scan options. Defaults to None.
        """
        self.config = config or {}
        self.scan_options = scan_options or ScanOptions()

    @abstractmethod
    def name(self) -> str:
        """
        Get the human-readable name of the analyzer.

        Returns:
            str: The analyzer name.
        """

    @abstractmethod
    def can_run(self) -> bool:
        """
        Determine whether this analyzer can run in the current environment.

        This might involve checking the OS platform, privileges, or availability
        of specific tools and libraries.

        Returns:
            bool: True if the analyzer can execute, False otherwise.
        """

    @abstractmethod
    def collect(self, device: Device) -> list[RawArtifact]:
        """
        Collect artifacts from the specified device.

        Args:
            device (Device): The target device to scan.

        Returns:
            List[RawArtifact]: A list of raw artifacts collected.
        """

    @abstractmethod
    def analyze(self, artifacts: list[RawArtifact]) -> Sequence[DataEvent | Alert]:
        """
        Analyze a list of raw artifacts and produce standardized data events
        and/or alerts.

        Args:
            artifacts (List[RawArtifact]): The raw artifacts to process.

        Returns:
            Sequence[DataEvent | Alert]: The interpreted and normalized data
                events and alerts.
        """
