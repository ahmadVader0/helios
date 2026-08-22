# TOOLS_REFERENCE.md

> References only the external utilities currently bundled and wired into the
> Helios pipeline. `MFTECmd.exe` is bundled in `tools/` and drives the MFT
> Analyzer and USN Journal Analyzer modules (see `MFTECmdAdapter`,
> `mft_analyzer.py`, `usn_journal.py`). Windows Event Logs (.evtx) are parsed
> directly with the bundled-in `python-evtx` library, with Chainsaw/Sigma
> hunting layered on top.

## MFTECmd
- **License:** MIT (Eric Zimmerman Tools)
- **URL:** https://ericzimmerman.github.io/
- **What it does:** Parses NTFS `$MFT` and `$UsnJrnl:$J` into CSV.
- **How we use it:** `MFTECmdAdapter` invokes the bundled binary;
  `MFTAnalyzer` and `USNJournalAnalyzer` parse its CSV output into
  DataEvents (created/modified timestamps, copy indicators, USN reasons).
- **Data produced:** Full MFT record timeline ($SI/$FN), USN journal change
  journal rows (rename, overwrite, delete, data-extension reasons).
- **Installation:** Bundled Windows binary (`tools/MFTECmd.exe`).
- **Sample command:** `MFTECmd.exe -f "E:\$MFT" --csv .\output`
- **Limitations:** NTFS volumes only; requires read access to `$MFT` /
  `$UsnJrnl` on the evidence volume.


## The Sleuth Kit (fls, fsstat)
- **License:** CPL/GPL
- **URL:** https://www.sleuthkit.org/
- **What it does:** Filesystem analysis and deleted-file listing.
- **How we use it:** `SleuthKitAdapter` runs `fls` on a raw volume or disk
  image to list deleted entries and `fsstat` for filesystem metadata.
- **Data produced:** Directory listings, MAC times, inode allocations.
- **Installation:** Bundled Windows binaries + DLL set; Linux binaries in
  `tools/` with shared libs in `tools/linux64/lib/`.
- **Sample command:** `fls -r -m / /dev/sda1`
- **Limitations:** Raw-disk access requires an elevated/admin terminal.
  Parsing bodyfile output can be memory intensive for large drives.

## JLECmd & LECmd
- **License:** MIT (Eric Zimmerman Tools)
- **URL:** https://ericzimmerman.github.io/
- **What it does:** Parses Jump Lists (JLECmd) and LNK files (LECmd).
- **How we use it:** `LnkJumpListAnalyzer` runs the tools against
  `AutomaticDestinations` and `.lnk` files.
- **Data produced:** File access history, volume serial numbers, MAC addresses.
- **Installation:** Bundled Windows binaries (`tools/`).
- **Sample command:** `LECmd.exe -d C:\Users\user\Recent --csv .\output`
- **Limitations:** Windows-specific artifacts.

## SBECmd, RBCmd & PECmd
- **License:** MIT (Eric Zimmerman Tools)
- **URL:** https://ericzimmerman.github.io/
- **What it does:** Parsers for ShellBags (SBECmd), Recycle Bin (RBCmd) and
  Prefetch (PECmd).
- **How we use it:** Extracts folder access, deleted files and execution
  history via `EZToolsAdapter` (batched, 120s timeout, fail-closed CSV parse).
- **Data produced:** Timestamps of folder browsing, deleted file original
  paths, application execution times.
- **Installation:** Bundled Windows binaries (`tools/`).
- **Sample command:** `PECmd.exe -d C:\Windows\Prefetch --csv .\output`
- **Limitations:** Dependent on Windows OS settings.

## ADB (Android Debug Bridge)
- **License:** Apache 2.0
- **URL:** https://developer.android.com/studio/command-line/adb
- **What it does:** Interfaces with Android devices.
- **How we use it:** Collects accessible application data, photos, and system
  config from devices with USB debugging enabled.
- **Data produced:** Logical file extractions of accessible storage.
- **Installation:** Bundled `adb.exe` + AdbWin DLLs.
- **Sample command:** `adb pull /sdcard/DCIM ./output`
- **Limitations:** Cannot access `/data/data` without root.

## ExifTool
- **License:** GPL/Artistic
- **URL:** https://exiftool.org/
- **What it does:** Reads metadata in files.
- **How we use it:** `FileTypeVerifierAnalyzer` runs batched deep
  verification of unresolved files to catch extension spoofing.
- **Data produced:** JSON/CSV of rich metadata and MIME types.
- **Installation:** Bundled Windows build + Linux perl distribution.
- **Sample command:** `exiftool -j ./images > metadata.json`
- **Limitations:** Slow on massive numbers of files if not batched.

## Chainsaw
- **License:** GPLv3
- **URL:** https://github.com/WithSecureLabs/chainsaw
- **What it does:** Rapidly searches and hunts through Windows Event Logs.
- **How we use it:** `EventLogsAnalyzer` applies bundled Sigma rules against
  collected EVTX files.
- **Data produced:** Suspicious event detections (JSON, reparsed into `Alert`s).
- **Installation:** Bundled `chainsaw.exe` + `sigma_rules/`.
- **Sample command:** `chainsaw hunt -r rules/ evtx_folder/ --json`
- **Limitations:** Relies on robust Sigma rule sets for accurate detections.

## python-evtx (library)
- **License:** LGPL-3.0
- **URL:** https://github.com/williballenthin/python-evtx
- **What it does:** Pure Python parser for Windows Event Log (.evtx) files.
- **How we use it:** `EventLogsAnalyzer` reads collected Security/System/
  Software/Partition-Diagnostic EVTX files directly via `Evtx.Evtx`
  (`_parse_evtx`), extracting record timestamps, EventIDs and payload data;
  on live systems, `wevtutil epl` exports are parsed the same way.
  Chainsaw/Sigma hunts run on top of these records for detections.
- **Data produced:** Per-record XML (SystemTime, EventID, event data)
  reparsed into Helios DataEvents.
- **Installation:** `pip install python-evtx`
- **Sample command:** Used as a Python library, not a CLI tool.
- **Limitations:** No recovery of heavily corrupted chunks; large EVTX
  files parse slower than native tooling.

## python-registry (library)
- **License:** Apache 2.0
- **URL:** https://github.com/williballenthin/python-registry
- **What it does:** Pure Python library to read Windows Registry files.
- **How we use it:** `UsbHistoryAnalyzer` extracts USB connection history from
  SYSTEM (USBSTOR) and SOFTWARE (MountPoints2) hives.
- **Data produced:** Registry key values and LastWrite times.
- **Installation:** `pip install python-registry`
- **Sample command:** Used as a Python library, not a CLI tool.
- **Limitations:** Cannot process active hives on a live system without
  VSS/extraction.
