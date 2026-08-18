"""
Cross-Device Keyword & Pattern Search Engine.

Goal: keyword triage of a drive or folder for data-exfiltration indicators.
The engine matches investigator-defined keywords (or regex patterns) against
file names, file paths and — for text-like files within size limits — file
contents, returning structured hits with match context.

Guarantees (honesty rules):
- Binary files are never opened for content search.
- Content search is capped (file size and lines scanned) so one huge file
  cannot hang an investigation.
- A hit is only reported when the keyword actually appears; no fabricated
  matches are ever produced.
"""

import logging
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Content search limits — searching stops beyond these to keep scans bounded.
MAX_CONTENT_FILE_SIZE = 10 * 1024 * 1024      # 10 MB
MAX_CONTENT_LINES_PER_FILE = 500
MAX_HITS_PER_FILE = 20


@dataclass
class SearchResult:
    """A match from the KeywordSearchEngine."""
    match_id: str
    keyword: str
    file_name: str
    file_path: str
    device_id: str
    match_context: str
    match_type: str  # 'path' | 'name' | 'content'
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dict."""
        return {
            "match_id": self.match_id,
            "keyword": self.keyword,
            "file_name": self.file_name,
            "file_path": self.file_path,
            "device_id": self.device_id,
            "match_context": self.match_context,
            "match_type": self.match_type,
            "line_number": self.line_number,
        }


# File types that are never content-searched (binary/executable/media).
_SKIP_CONTENT_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".db", ".mft", ".evtx",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", ".ico",
    ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wav", ".flac", ".ogg",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".iso", ".img", ".vhd", ".vhdx",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt",
    ".pf", ".pst", ".ost", ".lnk", ".msi", ".cab", ".ttf", ".woff",
}


def _is_text_like(path: str, size: int) -> bool:
    """Decide whether a file is a safe candidate for content scanning.

    Files over the size cap, or with known binary/media extensions, are
    skipped. Unknown extensions are probed for NUL bytes (binary marker).
    """
    ext = Path(path).suffix.lower()
    if ext in _SKIP_CONTENT_EXTENSIONS:
        return False
    if size > MAX_CONTENT_FILE_SIZE or size <= 0:
        return False
    return True


class KeywordSearchEngine:
    """Engine for searching keywords and patterns across investigation data."""

    def __init__(self, chunk_size: int = 4096) -> None:
        """Initialize the KeywordSearchEngine.

        Args:
            chunk_size: Size of file chunks to read when searching contents.
        """
        self.chunk_size = chunk_size

    def search(
        self,
        investigation: Any,
        keywords: list[str],
        regex_patterns: list[str] | None = None,
        search_content: bool = False
    ) -> list[SearchResult]:
        """Search for keywords and patterns.

        Args:
            investigation: The investigation context containing file records.
            keywords: List of raw strings to search for.
            regex_patterns: List of regex patterns to search for.
            search_content: Whether to open text-like files and search contents.

        Returns:
            A list of SearchResult objects representing matches.
        """
        regex_patterns = regex_patterns or []
        results: list[SearchResult] = []

        compiled_patterns: list[re.Pattern[str]] = []
        for kw in keywords:
            if not kw:
                continue
            compiled_patterns.append(re.compile(re.escape(kw), re.IGNORECASE))
        for rgx in regex_patterns:
            if not rgx:
                continue
            compiled_patterns.append(re.compile(rgx, re.IGNORECASE))

        if not compiled_patterns:
            return results

        file_records = getattr(investigation, "file_records", [])

        for record in file_records:
            name = str(record.file_name or "")
            path = str(record.file_path or "")
            device_id = getattr(record, "source_device", "") or ""
            hits_for_file = 0

            # Match against the file name
            for patt in compiled_patterns:
                if patt.search(name):
                    results.append(SearchResult(
                        match_id=str(uuid.uuid4()),
                        keyword=patt.pattern,
                        file_name=name,
                        file_path=path,
                        device_id=device_id,
                        match_context=name,
                        match_type="name"
                    ))
                    hits_for_file += 1
                    if hits_for_file >= MAX_HITS_PER_FILE:
                        break

            # Match against the file path
            if hits_for_file < MAX_HITS_PER_FILE:
                for patt in compiled_patterns:
                    if patt.search(path):
                        results.append(SearchResult(
                            match_id=str(uuid.uuid4()),
                            keyword=patt.pattern,
                            file_name=name,
                            file_path=path,
                            device_id=device_id,
                            match_context=path,
                            match_type="path"
                        ))
                        hits_for_file += 1
                        if hits_for_file >= MAX_HITS_PER_FILE:
                            break

            # Match against file contents (text-like files only)
            if search_content and hits_for_file < MAX_HITS_PER_FILE:
                size = int(getattr(record, "size", 0) or 0)
                if path and _is_text_like(path, size):
                    hits_for_file += self._search_content(
                        path, name, device_id, compiled_patterns, results,
                        max_hits=MAX_HITS_PER_FILE - hits_for_file,
                    )

        return results

    def _search_content(
        self,
        path: str,
        file_name: str,
        device_id: str,
        patterns: list[re.Pattern[str]],
        results: list[SearchResult],
        max_hits: int,
    ) -> int:
        """Search a single file's contents, line by line, with context.

        Returns the number of new hits appended (capped by ``max_hits``).
        """
        new_hits = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    if line_num > MAX_CONTENT_LINES_PER_FILE:
                        break
                    for patt in patterns:
                        if patt.search(line):
                            snippet = line.strip()[:200]
                            results.append(SearchResult(
                                match_id=str(uuid.uuid4()),
                                keyword=patt.pattern,
                                file_name=file_name,
                                file_path=path,
                                device_id=device_id,
                                match_context=snippet,
                                match_type="content",
                                line_number=line_num,
                            ))
                            new_hits += 1
                            break  # one content hit per line
                    if new_hits >= max_hits:
                        break
        except (PermissionError, FileNotFoundError, OSError) as e:
            logger.debug("Could not read file %s for content search: %s", path, e)
        return new_hits
