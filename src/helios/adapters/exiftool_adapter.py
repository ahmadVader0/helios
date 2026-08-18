import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from helios.adapters.base import ForensicToolAdapter, ToolRunResult, resolve_tool_binary


class ExifToolAdapter(ForensicToolAdapter):
    """ExifTool Adapter for extracting photo and document metadata."""

    def tool_name(self) -> str:
        return "ExifTool Adapter"

    def get_executable(self) -> str:
        """Resolve exiftool executable path."""
        resolved = resolve_tool_binary("exiftool", self.tool_path)
        return str(resolved) if resolved else "exiftool"

    def is_available(self) -> bool:
        """Check if exiftool binary is available."""
        return resolve_tool_binary("exiftool", self.tool_path) is not None

    def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
        """Run exiftool with arguments."""
        cmd = [self.get_executable()] + args
        return self.run_subprocess(cmd, timeout=timeout)

    def parse_output(self, raw_output: str) -> list[Any]:
        """Parse raw JSON output."""
        try:
            return json.loads(raw_output)
        except json.JSONDecodeError as e:
            logger.warning(f"ExifTool JSON parsing failed: {e}. Output snippet: {raw_output[:100]}")
            return []

    def get_file_type(self, file_path: Path | str) -> tuple[str | None, dict[str, Any]]:
        """
        Query exiftool for the true file type of a file.

        Returns a tuple of (normalized FileTypeExtension, metadata dict), or
        (None, {}) when the tool is unavailable or the file cannot be read.
        """
        path = Path(file_path)
        if not self.is_available() or not path.exists():
            return None, {}

        res = self.run(["-json", "-FileTypeExtension", "-FileType", str(path)])
        if not res.is_success() or not res.stdout.strip():
            return None, {}

        data = self.parse_output(res.stdout)
        if not data or not isinstance(data, list) or not isinstance(data[0], dict):
            return None, {}

        raw = data[0]
        ext = raw.get("FileTypeExtension")
        metadata = {
            k: v for k, v in raw.items()
            if k not in ("SourceFile", "FileTypeExtension", "FileType") and v
        }
        normalized = str(ext).lower().lstrip(".") if ext else None
        return normalized, metadata

    def get_file_types(self, file_paths: list[Path]) -> dict[str, tuple[str | None, dict[str, Any]]]:
        """
        Query exiftool for the true file type of many files in a single
        process invocation (batched). Without batching, spawning one process
        per file made live scans crawl (thousands of spawns on real drives).

        Args:
            file_paths: List of paths to query.

        Returns:
            A dict mapping each str(path) to (FileTypeExtension, metadata),
            or (None, {}) for files exiftool could not process.
        """
        results: dict[str, tuple[str | None, dict[str, Any]]] = {
            str(p): (None, {}) for p in file_paths
        }
        existing = [p for p in file_paths if p.exists()]
        if not existing or not self.is_available():
            return results

        path_map: dict[str, str] = {}
        for p in file_paths:
            try:
                path_map[str(p.resolve())] = str(p)
            except Exception:
                path_map[str(p)] = str(p)

        # Keep each command line comfortably below Windows' 32K limit:
        # 300 paths per batch is safe even with long UNC/WSL paths.
        batch_size = 300
        for i in range(0, len(existing), batch_size):
            batch = existing[i:i + batch_size]
            res = self.run(
                ["-json", "-FileTypeExtension", "-FileType", "-n", "-q",
                 "-charset", "json=UTF8", "-charset", "filename=UTF8"]
                + [str(p) for p in batch]
            )
            if not res.is_success() or not res.stdout.strip():
                continue
            data = self.parse_output(res.stdout)
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                src = entry.get("SourceFile")
                ext = entry.get("FileTypeExtension")
                if src is None or ext is None:
                    continue
                metadata = {
                    k: v for k, v in entry.items()
                    if k not in ("SourceFile", "FileTypeExtension", "FileType") and v
                }
                type_tuple: tuple[str | None, dict[str, Any]] = (
                    str(ext).lower().lstrip(".") or None,
                    metadata,
                )
                try:
                    resolved_src = str(Path(src).resolve())
                except Exception:
                    resolved_src = str(src)

                original_key = path_map.get(resolved_src, str(src))
                results[original_key] = type_tuple
                results[str(src)] = type_tuple
                results[resolved_src] = type_tuple
        return results
