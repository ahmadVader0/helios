# TOOLS_REFERENCE.md

> References only the external utilities currently bundled and wired into the
> Helios pipeline. Deleted/unused tools (MFTECmd, icat, mmls, EvtxECmd,
> ALEAPP, PhotoRec, Bulk Extractor, Plaso) were removed from the bundle — see
> `AUDIT_REPORT.md`.

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
