import logging
from pathlib import Path
from typing import Any

from helios.adapters.base import ForensicToolAdapter, ToolRunResult, resolve_tool_binary

logger = logging.getLogger(__name__)

class MFTECmdAdapter(ForensicToolAdapter):
    """
    Adapter for Eric Zimmerman's MFTECmd.exe to parse $MFT and $UsnJrnl.
    """
    def __init__(self, config: dict | None = None, tool_path: str = "") -> None:
        super().__init__(config, tool_path)
        resolved = resolve_tool_binary(self.tool_name(), self.tool_path)
        self.executable: str | None = str(resolved) if resolved else None

    def tool_name(self) -> str:
        return "MFTECmd"

    def is_available(self) -> bool:
        return self.executable is not None

    def run(self, args: list[str], timeout: int = 300) -> ToolRunResult:
        if not self.executable:
            raise RuntimeError(f"{self.tool_name()} is not available.")
        cmd = [self.executable] + args
        return self.run_subprocess(cmd, timeout=timeout)

    def parse_output(self, raw_output: str) -> list[Any]:
        # MFTECmd writes CSV, so parsing stdout isn't used to return DataEvents
        return []

    def parse_mft(self, mft_file: Path, output_dir: Path, out_name: str = "mft_dump") -> Path:
        """
        Parse an $MFT file using MFTECmd.exe.
        
        Args:
            mft_file: Path to the $MFT file.
            output_dir: Directory to store the resulting CSV.
            out_name: Base name for the output CSV file.
            
        Returns:
            Path to the generated CSV file.
        """
        if not self.is_available() or self.executable is None:
            raise RuntimeError(f"{self.tool_name()} is not available.")
            
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd: list[str] = [
            self.executable,
            "-f", str(mft_file),
            "--csv", str(output_dir),
            "--csvf", f"{out_name}.csv"
        ]
        
        result: ToolRunResult = self.run_subprocess(cmd)
        if result.returncode != 0:
            logger.error(f"MFTECmd parse_mft failed: {result.stderr}")
            raise RuntimeError(f"MFTECmd parse_mft failed with return code {result.returncode}")
            
        expected_out: Path = output_dir / f"{out_name}.csv"
        if not expected_out.exists():
            raise FileNotFoundError(f"MFTECmd parse_mft did not produce the expected output file: {expected_out}")
            
        return expected_out

    def parse_usn_journal(
        self, 
        volume_or_journal: Path, 
        output_dir: Path, 
        out_name: str = "usn_dump", 
        mft_file: Path | None = None
    ) -> Path:
        """
        Parse a $UsnJrnl:$J file using MFTECmd.exe.
        
        Args:
            volume_or_journal: Path to the $UsnJrnl file or volume path.
            output_dir: Directory to store the resulting CSV.
            out_name: Base name for the output CSV file.
            mft_file: Optional $MFT file for context.
            
        Returns:
            Path to the generated CSV file.
        """
        if not self.is_available() or self.executable is None:
            raise RuntimeError(f"{self.tool_name()} is not available.")
            
        output_dir.mkdir(parents=True, exist_ok=True)
        cmd: list[str] = [
            self.executable,
            "-f", str(volume_or_journal),
            "--csv", str(output_dir),
            "--csvf", f"{out_name}.csv"
        ]
        
        if mft_file is not None:
            cmd.extend(["-m", str(mft_file)])
            
        result: ToolRunResult = self.run_subprocess(cmd)
        if result.returncode != 0:
            logger.error(f"MFTECmd parse_usn_journal failed: {result.stderr}")
            raise RuntimeError(f"MFTECmd parse_usn_journal failed with return code {result.returncode}")
            
        expected_out: Path = output_dir / f"{out_name}.csv"
        if not expected_out.exists():
            raise FileNotFoundError(f"MFTECmd parse_usn_journal did not produce expected file: {expected_out}")
            
        return expected_out
