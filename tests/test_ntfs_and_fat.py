"""
Unit tests for NTFS utilities, MFTECmd adapter, MFT analyzer, USN Journal analyzer,
and FAT filesystem analyzer.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone
from pathlib import Path

from helios.adapters.mftecmd_adapter import MFTECmdAdapter
from helios.analyzers.base import RawArtifact
from helios.analyzers.fat_filesystem import FATFileSystemAnalyzer
from helios.analyzers.mft_analyzer import MFTAnalyzer
from helios.analyzers.usn_journal import USNJournalAnalyzer
from helios.models import Alert, DataEvent, Device, DeviceType, EventType
from helios.utils.ntfs import (
    decode_mft_flags,
    decode_usn_reason,
    decode_usn_reason_from_string,
    detect_timestomping,
    filetime_to_datetime,
    has_alternate_data_stream,
    parse_mftecmd_timestamp,
)


def test_mftecmd_adapter_initialization():
    adapter = MFTECmdAdapter(config={}, tool_path="")
    assert adapter.tool_name() == "MFTECmd"
    # is_available returns a bool depending on environment without crashing
    assert isinstance(adapter.is_available(), bool)


def test_filetime_to_datetime():
    # None or 0 returns None
    assert filetime_to_datetime(None) is None
    assert filetime_to_datetime(0) is None

    # Known FILETIME value: 133500000000000000 -> 2024-01-18 10:40:00 UTC
    # 116444736000000000 is Unix epoch (1970-01-01)
    unix_epoch_ft = 116444736000000000
    dt = filetime_to_datetime(unix_epoch_ft)
    assert dt == datetime(1970, 1, 1, tzinfo=timezone.utc)

    # 1 second after epoch
    dt_1s = filetime_to_datetime(unix_epoch_ft + 10_000_000)
    assert dt_1s == datetime(1970, 1, 1, 0, 0, 1, tzinfo=timezone.utc)


def test_parse_mftecmd_timestamp():
    # Empty or whitespace
    assert parse_mftecmd_timestamp(None) is None
    assert parse_mftecmd_timestamp("") is None
    assert parse_mftecmd_timestamp("   ") is None
    assert parse_mftecmd_timestamp("invalid-date") is None

    # Standard format with 7-digit fractional seconds
    ts_str = "2024-05-01 13:45:02.1234567"
    dt = parse_mftecmd_timestamp(ts_str)
    assert dt is not None
    assert dt.year == 2024
    assert dt.month == 5
    assert dt.day == 1
    assert dt.hour == 13
    assert dt.minute == 45
    assert dt.second == 2
    assert dt.microsecond == 123456
    assert dt.tzinfo == timezone.utc

    # Standard format without fractions
    ts_no_frac = "2024-05-01 13:45:02"
    dt2 = parse_mftecmd_timestamp(ts_no_frac)
    assert dt2 == datetime(2024, 5, 1, 13, 45, 2, tzinfo=timezone.utc)


def test_decode_usn_reason_and_flags():
    # Bitmask decoding
    reasons = decode_usn_reason(0x00000100 | 0x80000000)  # FileCreate | Close
    assert "FileCreate" in reasons
    assert "Close" in reasons

    assert decode_usn_reason(None) == []
    assert decode_usn_reason(0) == []

    # String decoding
    parsed = decode_usn_reason_from_string("FileCreate | DataExtend, Close")
    assert "FileCreate" in parsed
    assert "DataExtend" in parsed
    assert "Close" in parsed
    assert decode_usn_reason_from_string("") == []


def test_decode_mft_flags_and_ads():
    assert decode_mft_flags(None) == {"in_use": False, "is_directory": False}
    assert decode_mft_flags(0x0001) == {"in_use": True, "is_directory": False}
    assert decode_mft_flags(0x0002) == {"in_use": False, "is_directory": True}
    assert decode_mft_flags(0x0003) == {"in_use": True, "is_directory": True}

    # Alternate Data Stream detection
    assert has_alternate_data_stream(None) is False
    assert has_alternate_data_stream("file.txt") is False
    assert has_alternate_data_stream("C:\\Windows\\file.txt") is False  # drive letter colon
    assert has_alternate_data_stream("payload.exe:hidden_stream") is True


def test_detect_timestomping():
    si_created = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    si_modified = datetime(2024, 1, 1, 12, 30, 0, tzinfo=timezone.utc)
    fn_created = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    fn_modified = datetime(2024, 1, 1, 12, 30, 0, tzinfo=timezone.utc)

    # Normal timestamps: no timestomping
    assert detect_timestomping(si_created, si_modified, fn_created, fn_modified) is False

    # Copy pattern (FN created later than SI created) is NOT timestomping —
    # this fires on most real volumes and drowned reports in false positives.
    copied_si_created = datetime(2023, 12, 20, 12, 0, 0, tzinfo=timezone.utc)
    assert detect_timestomping(copied_si_created, si_modified, fn_created, fn_modified) is False

    # Timestomping: SI created forged NEWER than FN creation — the kernel can
    # never produce an SI timestamp after its own FN record.
    forged_si_created = datetime(2024, 1, 5, 12, 0, 0, tzinfo=timezone.utc)
    assert detect_timestomping(forged_si_created, si_modified, fn_created, fn_modified) is True

    # Timestomping: whole-second zeroing on SI while FN keeps precision
    zeroed_si = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    precise_fn = datetime(2024, 1, 1, 12, 0, 7, 123456, tzinfo=timezone.utc)
    assert detect_timestomping(zeroed_si, si_modified, precise_fn, fn_modified) is True

    # SI modified earlier than SI created alone is a normal copy artifact — not flagged
    impossible_modified = datetime(2024, 1, 1, 11, 0, 0, tzinfo=timezone.utc)
    assert detect_timestomping(si_created, impossible_modified, fn_created, fn_modified) is False


def test_mft_analyzer_with_csv(tmp_path: Path):
    csv_file = tmp_path / "mft_test.csv"
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "EntryNumber", "ParentEntryNumber", "FileName", "ParentPath",
            "FileSize", "InUse", "IsDirectory", "HasAds",
            "Created0x10", "Created0x30", "LastModified0x10", "LastModified0x30",
        ])
        # Row 1: Normal created file
        writer.writerow([
            "100", "5", "normal.docx", "Users\\Admin\\Documents",
            "1024", "True", "False", "False",
            "2024-05-01 10:00:00.0000000", "2024-05-01 10:00:00.0000000",
            "2024-05-01 10:05:00.0000000", "2024-05-01 10:05:00.0000000",
        ])
        # Row 2: Deleted file with ADS and Timestomping
        # (SI created forged NEWER than FN created — kernel-impossible)
        writer.writerow([
            "101", "5", "stealth.exe:stream", "Users\\Admin\\Downloads",
            "2048", "False", "False", "True",
            "2024-05-01 12:00:00.0000000", "2024-05-01 10:00:00.0000000",
            "2024-05-01 12:00:00.0000000", "2024-05-01 12:00:00.0000000",
        ])

    analyzer = MFTAnalyzer()
    artifact = RawArtifact(
        artifact_id="mft-test",
        artifact_type="mft",
        source_path=csv_file,
        device_id="DEV-USB",
        collected_at=datetime.now(timezone.utc),
        raw_data=csv_file,
    )

    results = analyzer.analyze([artifact])
    events = [r for r in results if isinstance(r, DataEvent)]
    alerts = [r for r in results if isinstance(r, Alert)]

    assert len(events) == 1
    assert events[0].event_type == EventType.FILE_DELETE
    assert events[0].source_path == "Users\\Admin\\Downloads\\stealth.exe:stream"
    assert events[0].source_device == "DEV-USB"

    # Row 2 should trigger both Timestomping and ADS alerts
    assert len(alerts) >= 2
    categories = [a.category for a in alerts]
    assert "Timestomping" in categories
    assert "Alternate Data Stream" in categories


def test_usn_journal_analyzer_with_csv(tmp_path: Path):
    csv_file = tmp_path / "usn_test.csv"
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "EntryNumber", "ParentEntryNumber", "Name", "ParentPath",
            "FileSize", "UpdateTimestamp", "UpdateReasons", "FileAttributes",
        ])
        writer.writerow([
            "200", "10", "confidential.pdf", "Projects\\TopSecret",
            "50000", "2024-06-10 14:20:00.1234567", "FileCreate, Close", "Archive",
        ])
        writer.writerow([
            "201", "10", "cleanup.bat", "Projects\\TopSecret",
            "500", "2024-06-10 14:25:00.1234567", "FileDelete, Close", "Archive",
        ])

    analyzer = USNJournalAnalyzer()
    artifact = RawArtifact(
        artifact_id="usn-test",
        artifact_type="usn",
        source_path=csv_file,
        device_id="DEV-PC",
        collected_at=datetime.now(timezone.utc),
        raw_data=csv_file,
    )

    results = analyzer.analyze([artifact])
    events = [r for r in results if isinstance(r, DataEvent)]
    assert len(events) == 2
    assert events[0].event_type == EventType.FILE_CREATE
    assert events[0].source_path == "Projects\\TopSecret\\confidential.pdf"
    assert events[0].timestamp == datetime(2024, 6, 10, 14, 20, 0, 123456, tzinfo=timezone.utc)

    assert events[1].event_type == EventType.FILE_DELETE
    assert events[1].source_path == "Projects\\TopSecret\\cleanup.bat"


def test_fat_filesystem_analyzer(tmp_path: Path):
    # Setup a dummy directory representing a FAT USB mount point
    usb_dir = tmp_path / "usb_mount"
    usb_dir.mkdir()
    doc = usb_dir / "report.txt"
    doc.write_text("Helios Forensic Test Content", encoding="utf-8")

    device = Device(
        device_type=DeviceType.USB,
        device_name="Test USB",
        serial_number="USB999",
        mount_point=str(usb_dir),
    )

    analyzer = FATFileSystemAnalyzer()
    assert analyzer.can_run() is True
    artifacts = analyzer.collect(device)
    assert len(artifacts) == 1

    events = analyzer.analyze(artifacts)
    # Should produce FILE_CREATE and FILE_MODIFY events
    event_types = {e.event_type for e in events if isinstance(e, DataEvent)}
    assert EventType.FILE_CREATE in event_types
    assert EventType.FILE_MODIFY in event_types
