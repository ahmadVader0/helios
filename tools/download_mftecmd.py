"""
Helper script to download and extract Eric Zimmerman's MFTECmd into the tools/ directory.

Usage:
    python tools/download_mftecmd.py
"""

from __future__ import annotations

import io
import logging
import sys
import urllib.request
import zipfile
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("download_mftecmd")

URLS = [
    "https://download.ericzimmerman.ch/net6/MFTECmd.zip",
    "https://download.ericzimmerman.ch/MFTECmd.zip",
    "https://f001.backblazeb2.com/file/EricZimmermanTools/net6/MFTECmd.zip",
]


def download_and_extract_mftecmd(target_dir: Path | None = None) -> bool:
    """Download MFTECmd.zip from Eric Zimmerman's servers and extract into target_dir."""
    if target_dir is None:
        target_dir = Path(__file__).resolve().parent

    target_dir.mkdir(parents=True, exist_ok=True)
    exe_target = target_dir / "MFTECmd.exe"

    if exe_target.exists() and exe_target.stat().st_size > 0:
        logger.info("MFTECmd.exe already exists in %s (%d bytes).", target_dir, exe_target.stat().st_size)
        return True

    logger.info("Attempting to download MFTECmd into %s...", target_dir)
    headers = {"User-Agent": "Helios-Forensic-Suite/1.0"}

    for url in URLS:
        try:
            logger.info("Trying %s...", url)
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()
                logger.info("Downloaded %d bytes. Extracting...", len(data))
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    z.extractall(target_dir)
                if exe_target.exists():
                    logger.info("Successfully installed MFTECmd.exe to %s", exe_target)
                    return True
        except Exception as exc:
            logger.warning("Failed to download from %s: %s", url, exc)

    logger.error(
        "Could not download MFTECmd automatically. Please download MFTECmd.zip manually from "
        "https://download.ericzimmerman.ch/net6/MFTECmd.zip and extract MFTECmd.exe into %s",
        target_dir,
    )
    return False


if __name__ == "__main__":
    success = download_and_extract_mftecmd()
    sys.exit(0 if success else 1)
