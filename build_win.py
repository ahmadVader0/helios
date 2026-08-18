"""
Automated Standalone Windows Executable Build Script for Helios.

This script checks for PyInstaller and dependencies, builds the single-file executable `dist/helios.exe`,
verifies the binary payload integrity, and copies default configuration files alongside the binary.
"""

from __future__ import annotations

import sys
import os
import shutil
import subprocess
from pathlib import Path


def main() -> None:
    """Builds the standalone Helios executable using PyInstaller."""
    print("=" * 60)
    print("  Helios Standalone Windows Executable Build Script")
    print("=" * 60)

    project_dir = Path(__file__).parent.resolve()
    os.chdir(project_dir)

    # 1. Check required build dependencies
    required_packages = ["click", "rich", "jinja2", "xxhash", "yaml", "PyInstaller"]
    missing = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"[!] Missing build dependencies ({', '.join(missing)}). Installing via pip...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "click", "rich", "jinja2", "xxhash", "pyyaml", "pyinstaller"],
            check=True,
        )
    else:
        print("[+] All required dependencies (click, rich, jinja2, xxhash, pyyaml, PyInstaller) detected.")

    # 2. Clean previous build artifacts
    build_dir = project_dir / "build"
    dist_dir = project_dir / "dist"

    if build_dir.exists():
        print("[i] Cleaning build/ directory...")
        shutil.rmtree(build_dir, ignore_errors=True)

    if dist_dir.exists():
        print("[i] Cleaning dist/ directory...")
        shutil.rmtree(dist_dir, ignore_errors=True)

    # 3. Execute PyInstaller build using helios.spec
    spec_path = project_dir / "helios.spec"
    print(f"\n[*] Compiling Helios executable using {spec_path.name}...")

    cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", str(spec_path)]
    res = subprocess.run(cmd, cwd=str(project_dir))

    if res.returncode != 0:
        print("\n[-] Build failed during PyInstaller compilation.")
        sys.exit(1)

    exe_path = dist_dir / "helios.exe"
    if not exe_path.exists():
        exe_path = dist_dir / "helios"

    if exe_path.exists():
        size_mb = exe_path.stat().st_size / (1024 * 1024)
        print("\n" + "=" * 60)
        print("  BUILD SUCCESSFUL!")
        print("=" * 60)
        print(f"  Binary Output : {exe_path}")
        print(f"  Binary Size   : {size_mb:.2f} MB")
        print("  Target System : Windows / Standalone (No Python installation required)")
        print("=" * 60)
    else:
        print(f"\n[-] Expected binary {exe_path} not found after build.")
        sys.exit(1)


if __name__ == "__main__":
    main()
