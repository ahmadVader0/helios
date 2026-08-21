"""Helios device & drive detector — auto-detect drives, partitions, and devices."""

from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path

from helios.models import Device, DeviceType, DriveInfo, DriveType

_last_adb_status: str = ""


def _get_disk_usage(mount: str) -> tuple[int, int]:
    """Return (total_bytes, free_bytes) for a mount point."""
    try:
        stat = os.statvfs(mount)
        total = stat.f_frsize * stat.f_blocks
        free = stat.f_frsize * stat.f_bavail
        return total, free
    except (OSError, AttributeError):
        return 0, 0


def _detect_drives_proc_mounts() -> list[DriveInfo]:
    """Fallback drive detection by parsing /proc/mounts (POSIX)."""
    found: list[DriveInfo] = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1].startswith("/"):
                    _dev, mount, fstype = parts[0], parts[1], parts[2]
                    # Skip virtual filesystems
                    if fstype in ("proc", "sysfs", "devtmpfs", "tmpfs",
                                  "devpts", "securityfs", "cgroup", "cgroup2",
                                  "pstore", "debugfs", "hugetlbfs", "mqueue",
                                  "configfs", "fusectl", "binfmt_misc",
                                  "autofs", "tracefs", "fuse.portal",
                                  "overlay", "rootfs", "swap"):
                        continue
                    # Skip WSL internal plumbing mounts (/mnt/wsl, /mnt/wslg)
                    if (mount.startswith("/mnt/wsl") or mount == "/init"
                            or mount.startswith("/usr/lib/wsl")):
                        continue
                    total, free = _get_disk_usage(mount)
                    found.append(DriveInfo(
                        drive_letter=mount,
                        label="",
                        filesystem=fstype,
                        total_size=total,
                        free_space=free,
                        drive_type=DriveType.UNKNOWN,
                        is_removable=False,
                    ))
    except OSError:
        pass
    return found


def detect_drives() -> list[DriveInfo]:
    """Detect all mounted drives and partitions on the current system.

    On Linux: uses ``lsblk --json`` and ``os.statvfs`` for size data.
    On Windows: uses ``wmic logicaldisk`` CSV output.
    """
    drives: list[DriveInfo] = []
    os_name = platform.system()

    if os_name == "Linux":
        try:
            result = subprocess.run(
                ["lsblk", "--json", "--output",
                 "NAME,FSTYPE,SIZE,MOUNTPOINT,RM,TYPE,LABEL,SERIAL"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
            )
            data = json.loads(result.stdout)

            def _process_block(block: dict, parent_serial: str = "") -> None:
                # Newer lsblk versions emit "mountpoints" (list) instead of the
                # singular "mountpoint" field; handle both.
                mount = block.get("mountpoint")
                if not mount and isinstance(block.get("mountpoints"), list):
                    mount = block["mountpoints"][0] if block["mountpoints"] else None
                blk_type = block.get("type", "")

                if (mount and blk_type in ("part", "disk", "lvm", "crypt")
                        and mount != "[SWAP]"
                        and not mount.startswith("/mnt/wsl")
                        and not mount.startswith("/usr/lib/wsl")):
                    is_removable = block.get("rm") in (True, "1", 1)
                    drive_type = DriveType.USB if is_removable else DriveType.HDD
                    total, free = _get_disk_usage(mount)

                    drives.append(DriveInfo(
                        drive_letter=mount,
                        label=block.get("label") or "",
                        filesystem=block.get("fstype") or "",
                        total_size=total,
                        free_space=free,
                        drive_type=drive_type,
                        is_removable=is_removable,
                        device_serial=block.get("serial") or parent_serial or "",
                    ))

                for child in block.get("children", []):
                    _process_block(child, parent_serial=block.get("serial") or parent_serial)

            for blk in data.get("blockdevices", []):
                _process_block(blk)

        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
            pass  # fall through to /proc/mounts below

        # Always merge /proc/mounts into the lsblk results: lsblk cannot see
        # WSL drvfs/9p mounts (/mnt/c, /mnt/d, ...) or network mounts, yet
        # those are exactly the Windows volumes a WSL forensic scan targets.
        lsblk_mounts = {d.drive_letter for d in drives}
        for d in _detect_drives_proc_mounts():
            if d.drive_letter not in lsblk_mounts:
                drives.append(d)

    elif os_name == "Windows":
        # 1. Primary: Native Windows Kernel32 API via ctypes (works on 100% of Windows versions)
        try:
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for letter_code in range(26):
                if bitmask & (1 << letter_code):
                    drive_letter = f"{chr(65 + letter_code)}:"
                    drive_root = f"{drive_letter}\\"

                    dtype_code = ctypes.windll.kernel32.GetDriveTypeW(drive_root)
                    if dtype_code not in (2, 3, 4):  # 2=Removable, 3=Fixed, 4=Remote
                        continue

                    is_removable = (dtype_code == 2)
                    d_type = DriveType.USB if is_removable else (DriveType.NETWORK if dtype_code == 4 else DriveType.HDD)

                    free_user = ctypes.c_ulonglong(0)
                    total = ctypes.c_ulonglong(0)
                    free_total = ctypes.c_ulonglong(0)
                    ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                        drive_root,
                        ctypes.byref(free_user),
                        ctypes.byref(total),
                        ctypes.byref(free_total)
                    )

                    vol_name = ctypes.create_unicode_buffer(261)
                    fs_name = ctypes.create_unicode_buffer(261)
                    vol_serial = ctypes.c_ulong(0)
                    ctypes.windll.kernel32.GetVolumeInformationW(
                        drive_root,
                        vol_name,
                        261,
                        ctypes.byref(vol_serial),
                        None,
                        None,
                        fs_name,
                        261
                    )
                    serial_hex = f"{vol_serial.value:08X}" if vol_serial.value else ""

                    drives.append(DriveInfo(
                        drive_letter=drive_letter,
                        label=vol_name.value or "",
                        filesystem=fs_name.value or "NTFS",
                        total_size=total.value,
                        free_space=free_total.value or free_user.value,
                        drive_type=d_type,
                        is_removable=is_removable,
                        device_serial=serial_hex,
                    ))
        except Exception:
            pass

        # 2. Fallback: PowerShell Get-Volume if ctypes returns empty
        if not drives:
            try:
                ps_cmd = "Get-Volume | Select-Object DriveLetter,FileSystemLabel,FileSystem,SizeRemaining,Size,DriveType | ConvertTo-Json"
                res = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, encoding="utf-8", errors="replace", check=True)
                vols = json.loads(res.stdout)
                if isinstance(vols, dict):
                    vols = [vols]
                for v in vols:
                    dl = v.get("DriveLetter")
                    if dl:
                        dtype_code = str(v.get("DriveType", "3"))
                        is_removable = dtype_code == "2"
                        drives.append(DriveInfo(
                            drive_letter=f"{dl}:",
                            label=v.get("FileSystemLabel") or "",
                            filesystem=v.get("FileSystem") or "NTFS",
                            total_size=v.get("Size") or 0,
                            free_space=v.get("SizeRemaining") or 0,
                            drive_type=DriveType.USB if is_removable else DriveType.HDD,
                            is_removable=is_removable,
                        ))
            except Exception:
                pass

        # 3. Fallback: WMIC logicaldisk
        if not drives:
            try:
                result = subprocess.run(
                    ["wmic", "logicaldisk", "get",
                     "DeviceID,DriveType,FileSystem,FreeSpace,Size,VolumeName",
                     "/format:csv"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", check=True,
                )
                for line in result.stdout.strip().splitlines():
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 7 and parts[1] and parts[1] != "DeviceID":
                        dev_id = parts[1]
                        d_type_code = parts[2]
                        fs = parts[3]
                        free_str = parts[4]
                        size_str = parts[5]
                        vol = parts[6] if len(parts) > 6 else ""

                        type_map = {"2": DriveType.USB, "3": DriveType.HDD,
                                    "4": DriveType.NETWORK, "5": DriveType.UNKNOWN}
                        d_type = type_map.get(d_type_code, DriveType.UNKNOWN)
                        is_removable = d_type_code == "2"

                        drives.append(DriveInfo(
                            drive_letter=dev_id,
                            label=vol,
                            filesystem=fs,
                            total_size=int(size_str) if size_str.isdigit() else 0,
                            free_space=int(free_str) if free_str.isdigit() else 0,
                            drive_type=d_type,
                            is_removable=is_removable,
                        ))
            except (subprocess.SubprocessError, FileNotFoundError):
                pass

    return drives


def detect_android_devices() -> list[Device]:
    """Detect Android devices connected via ADB USB debugging.

    Uses the bundle-aware ``resolve_tool_binary`` (never a bare PATH call) so
    the packaged exe and repo tree both find adb. Devices are reported with
    their real ADB state: authorized devices become ``Device`` entries while
    unauthorized/offline states are surfaced through ``last_adb_status`` so
    the caller can show the user what is wrong instead of silently returning
    an empty list.
    """
    global _last_adb_status
    devices: list[Device] = []
    _last_adb_status = ""

    from helios.adapters.base import resolve_tool_binary

    adb_path = resolve_tool_binary("adb")
    if adb_path is None:
        _last_adb_status = (
            "adb binary not found — install it (sudo apt install adb) or make "
            "sure tools/adb is available for this platform"
        )
        return devices

    try:
        result = subprocess.run(
            [str(adb_path), "devices", "-l"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", check=True, timeout=10,
        )
        lines = [ln.strip() for ln in result.stdout.strip().splitlines()[1:] if ln.strip()]
        if not lines:
            _last_adb_status = (
                "No Android devices listed by adb — check USB debugging is "
                "enabled and the device is attached via usbipd (WSL) / USB passthrough"
            )
            return devices
        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            if state != "device":
                _last_adb_status = (
                    f"Android device {serial} connected but state is '{state}' "
                    "(accept the USB-debugging prompt / unlock the phone)"
                )
                continue

            model = "Unknown"
            for p in parts[2:]:
                if p.startswith("model:"):
                    model = p.split(":", 1)[1].replace("_", " ")

            # Query Android version
            os_version = "Android"
            try:
                prop = subprocess.run(
                    [str(adb_path), "-s", serial, "shell", "getprop",
                     "ro.build.version.release"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", check=True, timeout=5,
                )
                os_version = f"Android {prop.stdout.strip()}"
            except (subprocess.SubprocessError, subprocess.TimeoutExpired):
                pass

            devices.append(Device(
                device_type=DeviceType.ANDROID,
                device_name=model,
                serial_number=serial,
                model=model,
                os_version=os_version,
            ))
    except FileNotFoundError:
        _last_adb_status = f"adb not found at {adb_path}"
    except (subprocess.SubprocessError, subprocess.TimeoutExpired) as exc:
        _last_adb_status = f"adb query failed: {exc}"

    return devices


def last_adb_status() -> str:
    """Human-readable status of the last Android detection run."""
    return _last_adb_status


def _os_description() -> str:
    """Human-readable OS description.

    Windows 11 reports kernel version 10.0 (same as Windows 10) so
    ``platform.release()`` alone returns "10" there. The build number is the
    reliable discriminator: build >= 22000 is Windows 11.
    """
    system = platform.system()
    if system == "Windows":
        try:
            build = sys.getwindowsversion().build
            if build >= 22000:
                return f"Windows 11 (build {build})"
            return f"Windows 10 (build {build})"
        except (AttributeError, OSError):
            return "Windows"
    return f"{system} {platform.release()}"


def get_local_device() -> Device:
    """Return a Device representing the current PC/laptop."""
    hostname = socket.gethostname()
    os_info = _os_description()
    machine = platform.machine()

    # Heuristic: if laptop-related keywords in hostname or has battery
    device_type = DeviceType.PC
    if "laptop" in hostname.lower() or "notebook" in hostname.lower():
        device_type = DeviceType.LAPTOP
    else:
        # Check for battery on Linux (implies laptop)
        bat_path = Path("/sys/class/power_supply/BAT0")
        if bat_path.exists():
            device_type = DeviceType.LAPTOP

    return Device(
        device_type=device_type,
        device_name=hostname,
        serial_number=hostname,
        model=machine,
        os_version=os_info,
    )


def detect_all_devices() -> tuple[list[DriveInfo], list[Device]]:
    """Detect all drives and Android devices."""
    drives = detect_drives()
    android_devices = detect_android_devices()
    return drives, android_devices
