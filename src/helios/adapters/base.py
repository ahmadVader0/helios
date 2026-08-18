"""
Base components for forensic tool adapters.

This module defines the abstract base class and result classes for interacting
with external forensic utilities and parsing their outputs.
"""

import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Assuming DataEvent is defined in helios.models.
# Fallback to Any if not present to ensure the module loads.
try:
    from helios.models import DataEvent
except ImportError:
    DataEvent = Any  # type: ignore[misc,assignment]

logger = logging.getLogger(__name__)

# Matches ISO-8601 timestamps like "2023-01-05 14:32:01" or "2023-01-05T14:32:01.123Z"
TIMESTAMP_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)


def extract_timestamp(line: str) -> datetime | None:
    """
    Extract the first ISO-8601 timestamp found in a raw output line.

    Used by generic raw-output parsers so events are only produced when a
    real timestamp exists in the output; fabricated timestamps are never used.

    Args:
        line: A single line of tool output.

    Returns:
        Optional[datetime]: The parsed timestamp, or None if none found.
    """
    match = TIMESTAMP_RE.search(line)
    if not match:
        return None
    ts_str = match.group(1)
    try:
        parsed = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


_PE_MACHINE_TYPES: dict[int, str] = {
    0x014C: "x86",
    0x8664: "x64",
    0xAA64: "ARM64",
    0xA641: "ARM64EC",
    0x01C4: "ARMv7",
}


def _read_bytes(path: Path, size: int) -> bytes | None:
    """Read the first ``size`` bytes of a file, or None on failure."""
    try:
        with open(path, "rb") as f:
            return f.read(size)
    except OSError:
        return None


def _pe_machine(path: Path) -> int | None:
    """
    Return the COFF machine type of a Windows PE file, or None if invalid.

    A structurally valid PE starts with the MZ DOS stub, carries a sane
    e_lfanew pointer, and has the ``PE\\0\\0`` signature followed by a known
    machine type. Corrupt or truncated files fail one of these checks.
    """
    data = _read_bytes(path, 4096)
    if data is None or not data.startswith(b"MZ"):
        return None
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        return None
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None
    return int.from_bytes(data[e_lfanew + 4 : e_lfanew + 6], "little")


def _host_pe_machine(on_windows: bool) -> int | None:
    """Return the PE machine type this host can run natively, or None."""
    if not on_windows:
        return None
    host = platform.machine().lower()
    if host in ("amd64", "x86_64"):
        return 0x8664
    if host in ("arm64", "aarch64"):
        return 0xAA64
    if host in ("x86", "i386", "i686"):
        return 0x014C
    return None


def _is_platform_compatible(path: Path, on_windows: bool) -> bool:
    """
    Check that a candidate binary can actually be executed on this platform.

    The tools directory ships both Linux (ELF) and Windows (PE) variants of
    the same utility. Executing the wrong format fails with ``WinError 193``
    on Windows (or ``Exec format error`` on POSIX), and a corrupt PE raises
    ``WinError 216``, so candidates are structurally validated up front.

    Args:
        path: Candidate executable path.
        on_windows: True when resolving for Windows (``os.name == "nt"``).

    Returns:
        bool: True if the binary format matches the target platform.
    """
    if on_windows:
        machine = _pe_machine(path)
        if machine is None:
            return False
        if machine not in _PE_MACHINE_TYPES:
            return False
        host_machine = _host_pe_machine(on_windows=True)
        if host_machine is None:
            return True
        # x64 hosts run 32-bit x86 binaries via WOW64
        if host_machine == 0x8664 and machine in (0x8664, 0x014C):
            return True
        return machine == host_machine
    data = _read_bytes(path, 4)
    if data is None:
        return False
    return data.startswith(b"\x7fELF") or data.startswith(b"#!")


def _name_candidates(binary_name: str, on_windows: bool) -> list[str]:
    """
    Build the ordered list of candidate file names for a tool binary.

    The bundled ``tools/`` directory contains both Linux and Windows builds
    of the same utility (``LECmd`` and ``LECmd.exe``). The native variant is
    tried first so the correct executable is selected on each platform.

    Args:
        binary_name: Base binary name, with or without ``.exe``.
        on_windows: True when resolving for Windows (``os.name == "nt"``).

    Returns:
        list[str]: Candidate names in preferred order, deduplicated.
    """
    base = binary_name[:-4] if binary_name.lower().endswith(".exe") else binary_name
    if on_windows:
        names = [f"{base}.exe", base]
    else:
        names = [base, f"{base}.exe"]
    return list(dict.fromkeys(names))


def resolve_tool_binary(binary_name: str, explicit_path: str | None = None) -> Path | None:
    """
    Resolve the absolute path to a forensic tool executable.

    Searches in order:
    1. Explicit path if provided.
    2. PyInstaller bundle directory (sys._MEIPASS / "tools" / binary_name).
    3. Executable adjacent tools folder (Path(sys.executable).parent / "tools" / binary_name).
    4. Project working directory (Path.cwd() / "tools" / binary_name).
    5. System PATH via shutil.which.

    Args:
        binary_name: Base binary name (e.g. 'exiftool', 'adb', 'chainsaw').
        explicit_path: Optional explicit file path.

    Returns:
        Optional[Path]: Resolved path if executable exists, None otherwise.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.exists() and p.is_file() and _is_platform_compatible(p, on_windows=os.name == "nt"):
            return p.resolve()

    # Prefer the native binary variant for the current platform so a bundled
    # tools/ directory (containing both Linux and Windows builds) resolves
    # to the correct executable.
    names = _name_candidates(binary_name, on_windows=os.name == "nt")

    search_dirs = []

    # 1. PyInstaller _MEIPASS bundle location
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        search_dirs.append(Path(sys._MEIPASS) / "tools")
        search_dirs.append(Path(sys._MEIPASS))

    # 2. Executable parent directory
    if getattr(sys, "executable", None):
        search_dirs.append(Path(sys.executable).parent / "tools")
        search_dirs.append(Path(sys.executable).parent)

    # 3. Current Working Directory
    search_dirs.append(Path.cwd() / "tools")
    search_dirs.append(Path.cwd())

    for d in search_dirs:
        for name in names:
            candidate = d / name
            if candidate.exists() and candidate.is_file():
                # On POSIX, require the file to be executable
                if os.name != "nt" and not os.access(candidate, os.X_OK):
                    logger.debug("Found %s but it is not executable", candidate)
                    continue
                # Reject binaries built for the other platform
                if not _is_platform_compatible(candidate, on_windows=os.name == "nt"):
                    logger.debug("Found %s but it is not a %s binary", candidate, "Windows" if os.name == "nt" else "Linux")
                    continue
                return candidate.resolve()

    # 4. System PATH lookup
    for name in names:
        found = shutil.which(name)
        if found and _is_platform_compatible(Path(found), on_windows=os.name == "nt"):
            return Path(found).resolve()

    return None


@dataclass
class ToolRunResult:
    """
    Represents the result of executing an external tool.

    Attributes:
        returncode (int): The exit code of the executed command.
        stdout (str): Standard output from the command.
        stderr (str): Standard error from the command.
        execution_time (float): The total time taken to execute the command in seconds.
        command (List[str]): The exact command list that was executed.
    """
    returncode: int
    stdout: str
    stderr: str
    execution_time: float
    command: list[str]

    def is_success(self) -> bool:
        """
        Check if the tool execution was successful.

        Returns:
            bool: True if returncode is 0, False otherwise.
        """
        return self.returncode == 0


class ForensicToolAdapter(ABC):
    """
    Abstract Base Class for integrating external forensic tools.
    """

    def __init__(self, config: dict | None = None, tool_path: str | None = None):
        """
        Initialize the ForensicToolAdapter.

        Args:
            config (Optional[dict], optional): Configuration dictionary for the adapter. Defaults to None.
            tool_path (Optional[str], optional): Explicit path to the tool executable. Defaults to None.
        """
        self.config = config or {}
        self.tool_path = tool_path

    @abstractmethod
    def tool_name(self) -> str:
        """
        Get the name of the forensic tool.

        Returns:
            str: The name of the tool.
        """

    @abstractmethod
    def is_available(self) -> bool:
        """
        Check if the tool is installed and accessible.

        Returns:
            bool: True if the tool is available to be run, False otherwise.
        """

    @abstractmethod
    def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
        """
        Run the tool with specific arguments.

        Args:
            args (List[str]): The arguments to pass to the tool (excluding the tool binary itself).
            timeout (int, optional): The maximum execution time in seconds. Defaults to 300.

        Returns:
            ToolRunResult: The result of the execution.
        """

    @abstractmethod
    def parse_output(self, raw_output: str) -> list[DataEvent]:
        """
        Parse the raw output of the tool into structured DataEvent objects.

        Args:
            raw_output (str): The raw standard output from the tool.

        Returns:
            List[DataEvent]: A list of structured data events.
        """

    def run_subprocess(self, cmd: list[str], timeout: int = 300, env: dict[str, str] | None = None) -> ToolRunResult:
        """
        Safely execute a subprocess command.

        This helper method invokes subprocess.run with proper safeguards:
        never using shell=True, capturing stdout and stderr, enforcing timeouts,
        and measuring execution duration.

        Args:
            cmd (List[str]): The full command list to execute (including the binary).
            timeout (int, optional): The maximum execution time in seconds. Defaults to 300.
            env (Optional[Dict[str, str]]): Optional environment variables to pass
                to the subprocess (e.g. LD_LIBRARY_PATH for bundled binaries).

        Returns:
            ToolRunResult: The detailed outcome of the execution.
        """
        start_time = time.perf_counter()
        stdout = ""
        stderr = ""
        returncode = -1

        logger.debug(f"Executing command: {cmd}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,  # Explicitly disallow shell execution
                env=env,
            )
            stdout = result.stdout
            stderr = result.stderr
            returncode = result.returncode
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out after {timeout} seconds: {cmd}")
            stdout = e.stdout.decode('utf-8') if isinstance(e.stdout, bytes) else (e.stdout or "")
            stderr = e.stderr.decode('utf-8') if isinstance(e.stderr, bytes) else (e.stderr or "")
            returncode = -1  # Indicate failure
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error executing command {cmd}: {e}")
            stderr = str(e)
            returncode = -1
        except Exception as e:
            logger.exception("Unexpected error executing command %s", cmd)
            stderr = str(e)
            returncode = -1
        finally:
            end_time = time.perf_counter()
            execution_time = end_time - start_time

        return ToolRunResult(
            returncode=returncode,
            stdout=stdout,
            stderr=stderr,
            execution_time=execution_time,
            command=cmd
        )
