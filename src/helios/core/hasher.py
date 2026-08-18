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
    except OSError:
        return ""
