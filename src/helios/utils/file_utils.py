import hashlib
from pathlib import Path


def hash_file(path: Path, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
    """Hashes a single file using the specified algorithm."""
    try:
        hasher = hashlib.new(algorithm)
        with open(path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)
        return hasher.hexdigest()
    except ValueError as exc:
        raise ValueError(f"Unknown hash algorithm: {algorithm}") from exc
    except OSError:
        return ""


def format_size(size_bytes: int) -> str:
    """Formats a byte count into a human-readable string."""
    if size_bytes < 0:
        return "0 B"

    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    size = float(size_bytes)
    unit_index = 0

    while size >= 1024.0 and unit_index < len(units) - 1:
        size /= 1024.0
        unit_index += 1

    # Format with up to 2 decimal places if needed
    if unit_index == 0:
        return f"{int(size)} {units[unit_index]}"
    return f"{size:.2f} {units[unit_index]}"
