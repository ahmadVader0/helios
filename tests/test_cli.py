from click.testing import CliRunner

from helios.cli import main
from helios.display import print_drives_table
from helios.models import DriveInfo, DriveType


def test_cli_demo_command():
    runner = CliRunner()
    result = runner.invoke(main, ["demo"])
    assert result.exit_code == 0
    assert "Data Movement Forensics" in result.output
    assert "███" in result.output
    assert "Detected Drives" in result.output


def test_cli_drives_command():
    runner = CliRunner()
    result = runner.invoke(main, ["drives"])
    assert result.exit_code == 0
    assert "Mounted Drives" in result.output


def test_cli_devices_command():
    runner = CliRunner()
    result = runner.invoke(main, ["devices"])
    assert result.exit_code == 0
    assert "Connected Devices" in result.output


def test_cli_keyword_search_command(tmp_path):
    runner = CliRunner()
    hit = tmp_path / "passwords.txt"
    hit.write_text("exfiltration report\n", encoding="utf-8")

    out_dir = tmp_path / "out"
    result = runner.invoke(
        main,
        ["keyword-search", "-k", "exfiltration", "-p", str(tmp_path), "-o", str(out_dir)],
    )
    assert result.exit_code == 0
    assert "Total matches: 1" in result.output
    assert list(out_dir.glob("*.html")), "keyword report must be written"
    assert list(out_dir.glob("*.json")), "matches JSON must be written"


def test_cli_keyword_search_requires_existing_dir(tmp_path):
    runner = CliRunner()
    result = runner.invoke(
        main, ["keyword-search", "-k", "x", "-p", str(tmp_path / "missing")]
    )
    assert result.exit_code != 0
    assert "not a directory" in result.output


def test_display_drives_table():
    d1 = DriveInfo(drive_letter="/mnt/usb", label="USB", filesystem="vfat", total_size=1000, free_space=500, drive_type=DriveType.USB, is_removable=True)
    # Should run without throwing exception
    print_drives_table([d1])
