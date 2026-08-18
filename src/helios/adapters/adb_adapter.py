"""
ADB (Android Debug Bridge) adapter.

Wraps the bundled/installed ``adb`` binary for Android device collection.
All calls are list-argv subprocess invocations with timeouts — never a shell
string. The binary is resolved bundle-aware (``tools/adb.exe`` inside the
PyInstaller bundle or the repo tree) so Windows builds work without adb on
PATH.
"""

from __future__ import annotations

import logging
import shlex
import time

from helios.adapters.base import ForensicToolAdapter, ToolRunResult, resolve_tool_binary

logger = logging.getLogger(__name__)


class AdbAdapter(ForensicToolAdapter):
    """Adapter around the Android Debug Bridge CLI."""

    def __init__(self, config: dict | None = None, tool_path: str | None = None) -> None:
        super().__init__(config=config, tool_path=tool_path)
        self._binary: str | None = None
        if tool_path:
            self._binary = tool_path
        else:
            resolved = resolve_tool_binary("adb")
            if resolved is not None:
                self._binary = str(resolved)

    def tool_name(self) -> str:
        """Get the name of the forensic tool."""
        return "ADB (Android Debug Bridge)"

    def is_available(self) -> bool:
        """Whether an adb binary could be resolved."""
        return self._binary is not None

    def run(self, args: list[str], timeout: int = 60) -> ToolRunResult:
        """Run adb with the given arguments (excluding the binary itself)."""
        if self._binary is None:
            return ToolRunResult(-1, "", "adb binary not available", 0.0, ["adb"] + args)
        import subprocess

        command = [self._binary, *args]
        started = time.monotonic()
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            return ToolRunResult(
                returncode=proc.returncode,
                stdout=proc.stdout or "",
                stderr=proc.stderr or "",
                execution_time=time.monotonic() - started,
                command=command,
            )
        except FileNotFoundError:
            logger.error("adb binary not found at %s", self._binary)
            return ToolRunResult(-1, "", f"adb binary not found: {self._binary}", 0.0, command)
        except subprocess.TimeoutExpired:
            logger.error("adb command timed out after %ds: %s", timeout, command)
            return ToolRunResult(-1, "", f"timed out after {timeout}s", 0.0, command)
        except OSError as exc:
            logger.error("adb command failed: %s", exc)
            return ToolRunResult(-1, "", str(exc), 0.0, command)

    def devices(self) -> list[dict[str, str]]:
        """List attached devices: [{serial, state, model}]."""
        result = self.run(["devices", "-l"])
        found: list[dict[str, str]] = []
        if result.returncode != 0:
            return found
        for line in result.stdout.strip().splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            entry: dict[str, str] = {"serial": parts[0], "state": parts[1]}
            for p in parts[2:]:
                if p.startswith("model:"):
                    entry["model"] = p.split(":", 1)[1].replace("_", " ")
            found.append(entry)
        return found

    def shell(self, serial: str, command: str, timeout: int = 120) -> str:
        """Run a single remote shell command and return its stdout."""
        result = self.run(["-s", serial, "shell", command], timeout=timeout)
        return result.stdout

    def list_recursive(self, serial: str, root: str = "/sdcard", timeout: int = 180) -> str:
        """Return raw ``ls -laR`` output for the given storage root."""
        return self.shell(
            serial, f"ls -laR {shlex.quote(root)}", timeout=timeout
        )

    def sha256_of(self, serial: str, path: str, timeout: int = 30) -> str:
        """Return the on-device SHA-256 digest of a file, or '' on failure."""
        digest = self.shell(
            serial, f"sha256sum {shlex.quote(path)}", timeout=timeout
        ).strip()
        hex_part = digest.split(maxsplit=1)[0] if digest else ""
        return hex_part if len(hex_part) == 64 else ""
