===============================================================================
               HELIOS EXTERNAL FORENSIC TOOLS DIRECTORY
===============================================================================

Pre-compiled standalone Windows CLI executables (.exe) plus native Linux
builds live here. When building Helios via `pyinstaller helios.spec`,
PyInstaller packages this whole directory into the single `helios.exe` binary.
The runtime resolver (`helios.adapters.base.resolve_tool_binary`) picks the
native variant for the current platform automatically.

Supported External Forensic Utilities (wired into the live scan pipeline):
-------------------------------------------------------------------------------
1. Eric Zimmerman Tools (LNK / JumpList / Prefetch / Recycle Bin /
   ShellBags parsing)
     LECmd.exe, JLECmd.exe, SBECmd.exe, PECmd.exe, RBCmd.exe
     -> auto-invoked by LnkJumpListAnalyzer, PrefetchAnalyzer,
        ShellBagsAnalyzer, RecycleBinAnalyzer (via EZToolsAdapter)
2. SleuthKit CLI Suite (deleted-file recovery & disk-image enumeration)
     fls.exe, fsstat.exe   (Windows)
     fls, fsstat            (Linux, with linux64/lib)
     -> auto-invoked by the deleted-file recovery scan step
3. ExifTool (true file-type verification against extension spoofing)
     exiftool.exe + exiftool_files/ (Windows runtime)
     exiftool + lib/                (Linux perl distribution)
     -> auto-invoked by FileTypeVerifierAnalyzer
4. Android Debug Bridge (Android device collection)
     adb.exe, AdbWinApi.dll, AdbWinUsbApi.dll
     -> auto-invoked by the Android device collection step
5. Chainsaw EVTX Hunter (Sigma hunting on Windows event logs)
     chainsaw.exe + sigma_rules/ (bundled curated Sigma rules)
     -> auto-invoked by EventLogsAnalyzer

Bundled Windows build versions (verified x86/x64 PEs):
-------------------------------------------------------------------------------
- LECmd, JLECmd, PECmd, SBECmd, RBCmd (Eric Zimmerman Tools,
  download.ericzimmermanstools.com)
- chainsaw (WithSecureLabs/chainsaw)
- exiftool 64-bit with bundled Perl (exiftool.org)
- adb platform-tools (dl.google.com/android/repository)
- SleuthKit win32 (sleuthkit/sleuthkit, runs via WOW64) + TSK DLL set

Bundled Linux builds:
-------------------------------------------------------------------------------
- SleuthKit Ubuntu binaries (fls/fsstat) + shared libs in linux64/lib/
  (libtsk, libewf, libafflib, libvhdi, libvmdk, libbfio)
- exiftool perl distribution (exiftool script + lib/ pure-perl modules)

Note:
-------------------------------------------------------------------------------
If an external tool is NOT available for the current platform, Helios
degrades gracefully: analyzers return empty results instead of crashing,
and the report records the module as "failed"/"skipped" honestly.
===============================================================================
