from helios.adapters.exiftool_adapter import ExifToolAdapter
from helios.adapters.ez_tools_adapter import EZToolsAdapter
from helios.adapters.sleuthkit_adapter import SleuthKitAdapter


def test_adapter_instantiation():
    ez = EZToolsAdapter()
    tsk = SleuthKitAdapter()
    exif = ExifToolAdapter()

    assert ez.tool_name() == "Eric Zimmerman Tools Adapter"
    assert tsk.tool_name() == "SleuthKit"
    assert exif.tool_name() == "ExifTool Adapter"


def test_ez_tools_returns_empty_on_nonzero_exit(tmp_path, monkeypatch):
    """A failing tool run must NOT ingest stale CSV output — fail closed."""
    from types import SimpleNamespace

    ez = EZToolsAdapter()

    monkeypatch.setattr(
        ez,
        "run_subprocess",
        lambda args, timeout: SimpleNamespace(returncode=2, stderr="tool failed"),
    )
    result = ez._run_cmd_and_parse_csv(["LECmd.exe"], tmp_path, "LECmd")
    assert result == []


def test_sleuthkit_fls_parsing():
    raw_fls = "r/r * 1234: /home/user/deleted_file.txt\nd/d 5678: /home/user/folder\n"
    tsk = SleuthKitAdapter()
    records, _ = tsk.parse_fls_output(raw_fls, device_id="TEST-DEV")
    
    assert len(records) == 2
    assert records[0].is_deleted is True
    assert records[0].file_name == "deleted_file.txt"
    assert records[1].is_deleted is False  # d/d is directory, not deleted!


def test_sleuthkit_fls_recursive_parsing():
    raw_fls = (
        "+ r/r * 1234: Users/Ahmad/Desktop/deleted_sub.txt\n"
        "++ r/r * 5678-144-1(realloc): Users/Ahmad/Downloads/file2.docx\n"
        "+ + d/d * 9012: Users/Ahmad/Documents\n"
    )
    tsk = SleuthKitAdapter()
    records, _ = tsk.parse_fls_output(raw_fls, device_id="TEST-DEV", deleted_only=True)
    
    assert len(records) == 3
    assert all(r.is_deleted for r in records)
    assert records[0].file_name == "deleted_sub.txt"
    assert records[1].file_name == "file2.docx"
    assert records[1].mft_entry_number == 5678
    assert records[2].file_name == "Documents"


def test_name_candidates_platform_preference():
    """Native binary variant must be tried first on each platform."""
    from helios.adapters.base import _name_candidates

    assert _name_candidates("LECmd", on_windows=True) == ["LECmd.exe", "LECmd"]
    assert _name_candidates("LECmd", on_windows=False) == ["LECmd", "LECmd.exe"]
    assert _name_candidates("MFTECmd.exe", on_windows=True) == ["MFTECmd.exe", "MFTECmd"]
    assert _name_candidates("MFTECmd.exe", on_windows=False) == ["MFTECmd", "MFTECmd.exe"]


def test_platform_compatibility_magic_bytes(tmp_path):
    """ELF binaries must be rejected on Windows, PE binaries on POSIX."""
    from helios.adapters.base import _is_platform_compatible

    elf = tmp_path / "LECmd"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    pe = tmp_path / "LECmd.exe"
    _write_pe(pe, machine=0x8664)

    assert _is_platform_compatible(elf, on_windows=True) is False
    assert _is_platform_compatible(pe, on_windows=True) is True
    assert _is_platform_compatible(elf, on_windows=False) is True
    assert _is_platform_compatible(pe, on_windows=False) is False


def test_resolve_prefers_native_binary(tmp_path, monkeypatch):
    """Resolution from a mixed tools/ dir must return the native variant."""
    from helios.adapters import base as adapter_base

    tools = tmp_path / "tools"
    tools.mkdir()
    elf = tools / "LECmd"
    elf.write_bytes(b"\x7fELF" + b"\x00" * 32)
    elf.chmod(0o755)
    pe = tools / "LECmd.exe"
    pe.write_bytes(b"MZ\x90\x00" + b"\x00" * 32)
    pe.chmod(0o755)

    monkeypatch.chdir(tmp_path)
    result = adapter_base.resolve_tool_binary("LECmd", explicit_path=None)
    assert result is not None
    assert result == elf.resolve()  # POSIX resolution must pick the ELF, not the PE
    assert result.name == "LECmd"


def _write_pe(path, machine=0x8664):
    """Write a minimal structurally-valid PE with the given COFF machine type."""
    e_lfanew = 0x80
    buf = bytearray(0x80 + 24)
    buf[0:2] = b"MZ"
    buf[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"
    buf[e_lfanew + 4 : e_lfanew + 6] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(buf))


def test_platform_compat_rejects_corrupt_pe(tmp_path):
    """A corrupt .exe (MZ magic but no valid PE structure) must be rejected."""
    from helios.adapters import base as adapter_base

    corrupt = tmp_path / "LECmd.exe"
    corrupt.write_bytes(b"MZ\x90\x00" + b"\x11" * 512)
    assert adapter_base._pe_machine(corrupt) is None
    assert not adapter_base._is_platform_compatible(corrupt, on_windows=True)


def test_platform_compat_accepts_valid_pe(tmp_path):
    """A structurally valid x64 PE must be accepted on Windows."""
    from helios.adapters import base as adapter_base

    valid = tmp_path / "LECmd.exe"
    _write_pe(valid, machine=0x8664)
    assert adapter_base._pe_machine(valid) == 0x8664
    assert adapter_base._is_platform_compatible(valid, on_windows=True)


def test_platform_compat_accepts_x86_pe_on_x64_host(tmp_path):
    """32-bit x86 binaries run on x64 Windows via WOW64 and must be accepted."""
    from helios.adapters import base as adapter_base

    x86 = tmp_path / "fls.exe"
    _write_pe(x86, machine=0x014C)
    assert adapter_base._is_platform_compatible(x86, on_windows=True)


def test_platform_compat_rejects_wrong_arch_pe(tmp_path):
    """A PE built for an incompatible architecture must be rejected."""
    from helios.adapters import base as adapter_base

    arm = tmp_path / "tool.exe"
    _write_pe(arm, machine=0xAA64)
    assert not adapter_base._is_platform_compatible(arm, on_windows=True)


def test_sleuthkit_fls_strips_metadata_suffixes():
    """TSK suffix markers like ($FILE_NAME) and (deleted) must be stripped from file names."""
    raw_fls = (
        "r/r * 1234-128-3: Users/Ahmad/Desktop/SecretPlan.pdf ($FILE_NAME) (deleted)\n"
        "r/r * 5678: Users/Ahmad/Documents/Quarterly.xlsx ($DATA) (deleted-realloc)\n"
    )
    tsk = SleuthKitAdapter()
    records, _ = tsk.parse_fls_output(raw_fls, device_id="TEST-DEV", deleted_only=True)

    assert len(records) == 2
    assert records[0].file_name == "SecretPlan.pdf"
    assert "($FILE_NAME)" not in records[0].file_path
    assert records[1].file_name == "Quarterly.xlsx"
    assert "($DATA)" not in records[1].file_path


def test_sleuthkit_fls_identifies_and_flags_system_metadata():
    """BitLocker keys (FVE2) and NTFS meta files ($MFT, $LogFile) must be flagged as is_system."""
    raw_fls = (
        "r/r * 10-128-1: System Volume Information/FVE2.{93de4bce-e958-48b6-9fac-602d0294e5ef}.1 ($FILE_NAME) (deleted)\n"
        "r/r * 0-128-6: $MFT\n"
        "r/r * 9999: ImportantDocument.docx (deleted)\n"
    )
    tsk = SleuthKitAdapter()
    records, _ = tsk.parse_fls_output(raw_fls, device_id="TEST-DEV", deleted_only=True)

    assert len(records) == 3
    assert records[0].is_system is True
    assert records[0].file_name == "FVE2.{93de4bce-e958-48b6-9fac-602d0294e5ef}.1"
    assert records[1].is_system is True
    assert records[1].file_name == "$MFT"
    assert records[2].is_system is False
    assert records[2].file_name == "ImportantDocument.docx"


def test_sleuthkit_fls_deduplicates_filename_streams():
    """Duplicate inode entries from $FILE_NAME stream and $DATA stream must be deduped."""
    raw_bodyfile = (
        "0|D:/Secret.pdf ($FILE_NAME) (deleted)|1234-48-2|r/rrwxrwxrwx|0|0|1024|1723900000|1723900000|1723900000|1723900000\n"
        "0|D:/Secret.pdf (deleted)|1234-128-3|r/rrwxrwxrwx|0|0|1024|1723900000|1723900000|1723900000|1723900000\n"
    )
    tsk = SleuthKitAdapter()
    records, _ = tsk.parse_fls_output(raw_bodyfile, device_id="TEST-DEV", deleted_only=True)

    assert len(records) == 1
    assert records[0].file_name == "Secret.pdf"
    assert records[0].file_path == "D:/Secret.pdf"

