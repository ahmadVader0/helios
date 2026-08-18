# Helios Forensic Platform — Audit Report

**Date:** 2026-07-30  
**Target Codebase:** `src/helios/`  
**Auditor Agent:** `code-auditor`  
**Execution Policy:** Read-only analysis across 8 audit passes.

---

## Audit Update (2026-08-02) — Closure & Verification

All CRITICAL / HIGH findings from the 8-pass audit below are **resolved and verified**:

- **CRITICAL adapter instantiation failures** (EZTools, MFTECmd, SleuthKit) — abstract methods implemented, `super().__init__()` calls added; `tests/test_adapters.py` (38 lines) covers instantiation and parsing.
- **CRITICAL dataclass schema mismatches** (MFT/FLS/USN parsing, correlator, keyword_search, timeline, drive_selector, duplicate_finder, lnk_jumplists, prefetch, shellbags, usn_journal, event_logs) — aligned to `helios.models`; `tests/test_analyzers.py` (66 lines), `tests/test_devices.py` (47 lines), `tests/test_core.py` (76 lines) added.
- **HIGH duplicate magic-byte signature** (`PK\x03\x04` shadowing) — duplicate dict key removed (`file_utils.py`, `file_type_verifier.py`).
- **`resolve_tool_binary` X_OK check** — added for POSIX; `_MEIPASS/tools` lookup added for frozen builds.
- **Static analysis** — `mypy src/helios` reports **0 errors across 62 files**; `pytest` **18 passed**; `ruff` clean of F-class (bug) findings.

### New Findings — Frozen (PyInstaller) Build Audit, fixed 2026-08-02

| Severity | File:Line | Description & Impact | Resolution |
| :--- | :--- | :--- | :--- |
| CRITICAL | `adapters/base.py` `resolve_tool_binary` | The bundled `tools/` dir ships both Linux (ELF) and Windows (PE) builds of each utility. On Windows, `names` was ordered `[LECmd, LECmd.exe]`, so the Linux ELF was found first and executed — `[WinError 193] %1 is not a valid Win32 application` for every LNK/JumpList parse during live scans. | Added `_name_candidates()` (native `.exe` variant first on Windows, extension-less first on POSIX) and `_is_platform_compatible()` (rejects ELF on Windows, MZ/PE on POSIX via magic bytes) in `adapters/base.py`; both applied in `resolve_tool_binary` for explicit paths, dir search, and PATH lookup. 3 new unit tests. |
| CRITICAL | `config.py:22` `get_project_root()` | Under PyInstaller onefile, `Path(__file__).resolve()` resolves inside `_MEIPASS`; `parent.parent.parent` pointed at `%TEMP%`, so `config/` (profiles, rules, defaults) was never found in the frozen exe — everything silently fell back to code defaults. | Added `get_bundle_root()` returning `sys._MEIPASS` when frozen; `load_config()` prefers a user `config/` beside the executable, then the bundled `_MEIPASS/config`. |
| CRITICAL | `suspicious_detector.py:50` | `Path(__file__).resolve().parents[3]` broke under frozen exe, so `suspicious_rules.yaml` could not load (defaults used, guard rejected valid paths). | Now uses shared `helios.config.get_bundle_root()`. |
| OK | `demo.py`, `report_generator.py` | Templates/static/demo-data resolution is `__file__`-relative, matching spec datas destinations (`helios/reporting/templates`, `helios/reporting/static`, `helios/demo_data`) — frozen-safe. | Verified via real onefile build: `demo`, `devices`, `drives`, `menu` all run from the packaged binary. |
| HIGH | `tools/*.exe` (all 16 bundled Windows builds) | Every bundled `.exe` was a corrupt stub: `MZ` magic followed by random bytes (entropy 7.95, no valid PE structure). Windows refused to run them — `[WinError 216] This version of %1 is not compatible...` for every LECmd/JLECmd call during live scans on the Windows side. | Downloaded and verified all 16 real Windows builds (LECmd 1.5.0.1, JLECmd 1.5.0.1, MFTECmd 1.2.0.1, PECmd 1.5.0.1, SBECmd 1.5.0.1, RBCmd 1.6.0, chainsaw 2.16.2, exiftool 13.59 + `exiftool_files/` runtime, adb platform-tools, SleuthKit 4.15.0, bulk_extractor 2.0.0, ALEAPP 3.6.0); see `tools/README.txt`. |
| MEDIUM | `adapters/base.py` `_is_platform_compatible` | Magic-byte check only rejected ELF-on-Windows / MZ-on-POSIX, so a structurally corrupt PE (MZ + garbage) still passed and crashed with WinError 216. | Added `_pe_machine()` (validates MZ stub, sane `e_lfanew`, `PE\0\0` signature, known COFF machine type) and `_host_pe_machine()` (rejects wrong-arch PEs; allows x86 via WOW64 on x64 hosts). 4 new unit tests. |
| HIGH | `tools/*` (all Linux-side builds) | Every Linux ELF in `tools/` was a corrupt stub: fake `ELF` magic followed by random bytes (`unknown arch 0xffff...`, entropy ~8), so every adapter on the Linux build died with `[Errno 8] Exec format error`. The Windows `.exe` builds had been fixed earlier, but the Linux side was never exercised. | Replaced with real Linux builds where they exist: exiftool 13.59 perl distribution (`exiftool` + `lib/`), SleuthKit 4.12.1 Ubuntu binaries (`fls`, `icat`, `mmls`, `fsstat` + shared libs under `linux64/lib/`); removed fake ELF stubs for Windows-only tools (EZ suite, adb, chainsaw, ALEAPP, bulk_extractor) so the resolver degrades to built-in parsers instead of crashing. `SleuthKitAdapter` now sets `LD_LIBRARY_PATH` via `run_subprocess(..., env=...)`. |
| MEDIUM | `helios.spec` `datas` | `('tools/*', 'tools')` glob did not recurse, so bundled subdirectories (`exiftool_files/`, `lib/`, `linux64/`, `sigma_rules/`) were omitted from the frozen build. | Changed to recursive glob `('tools/**', 'tools')`. |
| HIGH | Analyzer ↔ tool wiring gap | Adapters for Chainsaw, ExifTool, PECmd, RBCmd, SBECmd and SleuthKit existed but were never invoked; the live scan never ran EventLogs/Prefetch/ShellBags/FileTypeVerifier analyzers, and ShellBags' built-in parser was a stub returning `[]` — bundled tools did nothing outside manual use. | Wired every tool into the automatic pipeline: Chainsaw Sigma hunts in `EventLogsAnalyzer` (+ 8 curated rules under `tools/sigma_rules/`), ExifTool type verification in `FileTypeVerifierAnalyzer`, PECmd/RBCmd/SBECmd enrichment in Prefetch/RecycleBin/ShellBags analyzers, SleuthKit deleted-file recovery step in `menu.py`; added the analyzer steps to the live scan and the `deleted_file_recovery` module to the `full` profile. 12 new unit tests (`tests/test_tool_wiring.py`). |

### Frozen Build Verification (2026-08-02)

- PyInstaller 6.21.0 build from `helios.spec` succeeds; all `datas` patterns match real files.
- Packaged onefile binary executes `demo` end-to-end: 18 events, 5 alerts (3 CRITICAL), 9 files, HTML report (72 KB, timeline.js + ApexCharts embedded), exports ZIP (5 entries, integrity OK), custody log.
- `devices`, `drives`, `menu` verified on the packaged binary; simulated `_MEIPASS` extraction confirmed profiles (`exfiltration`, `employee_exit`, `incident_response`, `full`) and 10 suspicious rules load correctly.

---


## Executive Summary
This report aggregates findings from systematic audits across all modules in `src/helios/`.

---

## Module Audit: `src/helios/adapters/`

| Severity | Pass | Module / File:Line | Description & Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| CRITICAL | Pass 1: Correctness | [ez_tools_adapter.py:L15-L73](file:///home/ahmad/Forensics/helios/src/helios/adapters/ez_tools_adapter.py#L15-L73) | `EZToolsAdapter` inherits from `ForensicToolAdapter` but fails to implement abstract methods `run()` and `parse_output()`. Calling `EZToolsAdapter()` raises `TypeError` and prevents instantiation. | Implement `run()` and `parse_output()` methods, or change inheritance to avoid ABC instantiation failure. |
| CRITICAL | Pass 1: Correctness | [mftecmd_adapter.py:L15-L55](file:///home/ahmad/Forensics/helios/src/helios/adapters/mftecmd_adapter.py#L15-L55) | `MFTECmdAdapter` inherits from `ForensicToolAdapter` but fails to implement abstract methods `run()` and `parse_output()`, causing `TypeError` on instantiation. Also `__init__` does not invoke `super().__init__()`. | Implement abstract methods and call `super().__init__(config, tool_path)` in `__init__`. |
| CRITICAL | Pass 1: Correctness | [sleuthkit_adapter.py:L14-L64](file:///home/ahmad/Forensics/helios/src/helios/adapters/sleuthkit_adapter.py#L14-L64) | `SleuthKitAdapter` inherits from `ForensicToolAdapter` but fails to implement abstract methods `run()` and `parse_output()`, causing `TypeError` on instantiation. `__init__` also omits `super().__init__()`. | Implement abstract methods `run()` and `parse_output()` and invoke `super().__init__()`. |
| CRITICAL | Pass 1: Correctness | [mftecmd_adapter.py:L197-L215](file:///home/ahmad/Forensics/helios/src/helios/adapters/mftecmd_adapter.py#L197-L215) | `parse_mft_csv` instantiates `FileRecord` with invalid keyword arguments (`entry_number`, `sequence_number`, `directory`, `file_size`, `created_0x10`, etc.) that do not exist on `FileRecord` dataclass in `helios/models.py`, causing immediate `TypeError` at runtime. | Map CSV attributes to valid `FileRecord` dataclass fields (`mft_entry_number`, `parent_path`, `size`, `created`, etc.). |
| CRITICAL | Pass 1: Correctness | [mftecmd_adapter.py:L254-L264](file:///home/ahmad/Forensics/helios/src/helios/adapters/mftecmd_adapter.py#L254-L264) | `parse_usn_csv` instantiates `DataEvent` with invalid keyword arguments (`file_name`, `file_path`, `attributes`, `usn`, `entry_number`, `raw_reason`) while omitting required positional fields (`source_device`, `source_path`), raising `TypeError`. | Map USN Journal attributes to standard `DataEvent` fields (`source_path`, `raw_source`, `metadata`). |
| CRITICAL | Pass 1: Correctness | [sleuthkit_adapter.py:L133-L140](file:///home/ahmad/Forensics/helios/src/helios/adapters/sleuthkit_adapter.py#L133-L140) | `parse_fls_output` instantiates `FileRecord` with invalid keyword arguments `entry_number` and `directory`, raising `TypeError` at runtime. | Change parameter names to match `FileRecord` schema (`mft_entry_number` or metadata dictionary). |
| HIGH | Pass 1: Correctness | [sleuthkit_adapter.py:L131](file:///home/ahmad/Forensics/helios/src/helios/adapters/sleuthkit_adapter.py#L131) | `parse_fls_output` sets `is_deleted = bool(deleted_marker == '*' or entry_type == 'd/d')`. In SleuthKit `fls`, `d/d` denotes a directory inode (not deleted). This misclassifies every single directory as a deleted file. | Fix deleted classification logic to check only for `*` marker in `fls` output lines. |
| HIGH | Pass 1: Correctness | [bulk_extractor_adapter.py:L56](file:///home/ahmad/Forensics/helios/src/helios/adapters/bulk_extractor_adapter.py#L56) | `carve_artifacts` executes `output_dir.mkdir(parents=True, exist_ok=True)` prior to running `bulk_extractor`. `bulk_extractor` aborts execution if the target output directory already exists. | Remove pre-creation of output directory or pass `-f` overwrite flag to `bulk_extractor`. |
| HIGH | Pass 3: Chain-of-Custody & Data Integrity | [aleapp_adapter.py:L60](file:///home/ahmad/Forensics/helios/src/helios/adapters/aleapp_adapter.py#L60) | `parse_tsv_findings` sets `timestamp=datetime.now()` for all extracted `DataEvent` records instead of parsing actual timestamps from TSV files, destroying forensic timeline integrity. | Parse timestamp columns from ALEAPP TSV output and assign accurate event timestamps. |
| HIGH | Pass 2: Edge Cases | [exiftool_adapter.py:L69](file:///home/ahmad/Forensics/helios/src/helios/adapters/exiftool_adapter.py#L69) | `extract_batch` passes `existing_paths` list directly as command line arguments. Processing large file sets (thousands of files) exceeds OS argument limits (`ARG_MAX`), triggering `OSError: [Errno 7] Argument list too long`. | Use ExifTool `-@` argfile feature or chunk input file lists into batches. |
| HIGH | Pass 1: Correctness | [chainsaw_adapter.py:L82-L105](file:///home/ahmad/Forensics/helios/src/helios/adapters/chainsaw_adapter.py#L82-L105) | `_parse_findings` assumes `chainsaw hunt --json` output is a flat JSON array of rule objects. Chainsaw outputs nested objects (`detections` list / `kind.Sigma`), causing parsing to fail or return fallback alerts. | Update JSON parser to handle modern Chainsaw JSON structure (`data.get("detections")` and nested Sigma rule fields). |
| HIGH | Pass 1: Correctness | [mftecmd_adapter.py:L191-L196](file:///home/ahmad/Forensics/helios/src/helios/adapters/mftecmd_adapter.py#L191-L196) | Timestomping check in `parse_mft_csv` calculates `diff = (created_0x30 - created_0x10).total_seconds()` and checks `diff > 10`. This misses future timestomping (`diff < 0`) and generates false positives on normal Windows file copies. | Compare both direction deltas (`abs(diff) > threshold`) and cross-reference `$STANDARD_INFORMATION` entry modification timestamps. |
| MEDIUM | Pass 2: Edge Cases | [adb_adapter.py:L45-L66](file:///home/ahmad/Forensics/helios/src/helios/adapters/adb_adapter.py#L45-L66) | `list_devices` assumes `lines[1:]` skips a single header. If ADB daemon startup messages precede output, header status lines are parsed as fake device objects (`serial="List"`, `state="of"`). | Filter out lines starting with `*` or lines matching `"List of devices attached"` before parsing device entries. |
| MEDIUM | Pass 2: Edge Cases | [chainsaw_adapter.py:L54](file:///home/ahmad/Forensics/helios/src/helios/adapters/chainsaw_adapter.py#L54) | `run_sigma_hunt` returns `[]` if `not evtx_dir.is_dir()`. Chainsaw supports analyzing single `.evtx` files, but `is_dir()` rejects valid single-file targets. | Check `evtx_dir.is_file()` or `evtx_dir.exists()` to support single `.evtx` file inputs. |
| MEDIUM | Pass 2: Edge Cases | [aleapp_adapter.py:L42](file:///home/ahmad/Forensics/helios/src/helios/adapters/aleapp_adapter.py#L42) | `run_aleapp` hardcodes `-t folder` when invoking ALEAPP. If input path is a `.zip` or `.tar` archive file, ALEAPP fails to process the input. | Inspect input path extension and set `-t zip`, `-t tar`, or `-t folder` dynamically. |
| MEDIUM | Pass 2: Edge Cases | [ez_tools_adapter.py:L140](file:///home/ahmad/Forensics/helios/src/helios/adapters/ez_tools_adapter.py#L140) | `_parse_csv` performs `{k.strip(): v.strip() for k, v in row.items() if k}`. If CSV has missing trailing values (`v is None`), `v.strip()` raises `AttributeError` and discards the whole file. | Add `v and v.strip()` null check before calling `.strip()`. |
| MEDIUM | Pass 3: Chain-of-Custody & Data Integrity | [adb_adapter.py:L86](file:///home/ahmad/Forensics/helios/src/helios/adapters/adb_adapter.py#L86) | `pull_path` returns `res.is_success()` based solely on exit code. ADB often returns exit code 0 even when file transfer fails due to permission errors. | Validate downloaded file existence, non-zero size, or parse ADB stderr for `"0 files pulled"`. |
| MEDIUM | Pass 4: Error Handling | [aleapp_adapter.py:L68-L69](file:///home/ahmad/Forensics/helios/src/helios/adapters/aleapp_adapter.py#L68-L69) | `parse_tsv_findings` uses empty `except Exception: continue`, silently swallowing I/O errors and parsing exceptions without logging. | Log exceptions with `logger.warning` or `logger.error` before continuing. |
| MEDIUM | Pass 4: Error Handling | [chainsaw_adapter.py:L43](file:///home/ahmad/Forensics/helios/src/helios/adapters/chainsaw_adapter.py#L43) | `parse_output` silently catches `json.JSONDecodeError` and returns `[]` without logging warning or reporting corrupt tool output. | Add error log with raw output snippet when JSON decoding fails. |
| MEDIUM | Pass 4: Error Handling | [exiftool_adapter.py:L33](file:///home/ahmad/Forensics/helios/src/helios/adapters/exiftool_adapter.py#L33) | `parse_output` silently swallows `json.JSONDecodeError` and returns `[]` without logging. | Log JSON decode failure details. |
| MEDIUM | Pass 5: Security | [adb_adapter.py:L74](file:///home/ahmad/Forensics/helios/src/helios/adapters/adb_adapter.py#L74) | `run_adb_shell` appends raw `command` string to `["shell", command]`. Unsanitized user inputs passed to `run_adb_shell` present shell command injection risks on the Android target device. | Sanitize or validate command inputs before passing to `adb shell`. |
| MEDIUM | Pass 6: Concurrency & State | [mftecmd_adapter.py:L78,L118](file:///home/ahmad/Forensics/helios/src/helios/adapters/mftecmd_adapter.py#L78) | `run_mft_parsing` and `run_usn_parsing` bypass `self.get_executable()` and invoke `self.mftecmd_path` directly. On non-Windows platforms, this fails to resolve binary path. | Call `self.get_executable()` to obtain resolved binary path. |
| MEDIUM | Pass 6: Concurrency & State | [sleuthkit_adapter.py:L81,L157,L186,L226](file:///home/ahmad/Forensics/helios/src/helios/adapters/sleuthkit_adapter.py#L81) | SleuthKit execution methods (`run_fls`, `run_icat`, `run_mmls`, `run_fsstat`) use `self.fls_path`, `self.icat_path`, etc., bypassing `resolve_tool_binary`. | Update all tool execution helper methods to use `resolve_tool_binary` helper methods. |
| LOW | Pass 2: Edge Cases | [base.py:L47-L84](file:///home/ahmad/Forensics/helios/src/helios/adapters/base.py#L47-L84) | `resolve_tool_binary` checks `candidate.exists() and candidate.is_file()` without checking `os.access(candidate, os.X_OK)`. Non-executable matching files cause execution failure. | Include `os.access(candidate, os.X_OK)` check when resolving executable binaries on POSIX systems. |
| LOW | Pass 3: Chain-of-Custody & Data Integrity | [exiftool_adapter.py:L51-L58,L80-L89](file:///home/ahmad/Forensics/helios/src/helios/adapters/exiftool_adapter.py#L51-L58) | `extract_metadata` and `extract_batch` return raw unparsed date strings (`CreateDate`, `ModifyDate`) without timezone offset standardization. | Parse and convert ExifTool date strings into standardized ISO-8601 UTC datetimes. |
| LOW | Pass 7: Test Coverage | `src/helios/adapters/` | Module `src/helios/adapters/` has zero unit test coverage or mock fixtures in `tests/`. Critical class instantiation failures and dataclass schema mismatches remained undetected. | Add comprehensive test suite in `tests/adapters/` covering tool resolution, output parsing, schema conversion, and CLI execution mocks. |

---

## Module Audit: `src/helios/analyzers/`

| Severity | Pass | Module / File:Line | Description & Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| CRITICAL | Pass 1: Correctness | [event_logs.py:L13-L58](file:///home/ahmad/Forensics/helios/src/helios/analyzers/event_logs.py#L13-L58) | `event_logs.py` redefines local stub classes (`AnalyzerBase`, `Device`, `RawArtifact`, `DataEvent`, `Alert`) instead of importing `helios.models`. `EventLogsAnalyzer` fails `isinstance` checks, expects `device.root_path` on `Device`, and returns invalid stub objects. `_mock_parse_evtx` returns `[]`, leaving EVTX files unparsed. | Replace local stub classes with imports from `helios.models` and `helios.analyzers.base`, map real `Device` fields, and implement actual EVTX record parsing. |
| CRITICAL | Pass 1: Correctness | [usn_journal.py:L122-L169](file:///home/ahmad/Forensics/helios/src/helios/analyzers/usn_journal.py#L122-L169) | `UsnJournalAnalyzer._detect_cut_vs_copy` raises `NameError: name 'datetime' is not defined` (L122), `AttributeError` on non-existent `DataEvent` fields `file_name`/`file_path` (L128-131, 155, 167), `AttributeError` on non-existent `EventType.FILE_RENAME_OLD` (L149), and `TypeError` when instantiating `DataEvent` (L151, 163). | Import `datetime`, fix `DataEvent` field queries to use `source_path` and `metadata`, reference valid `EventType` enums, and pass correct positional parameters. |
| CRITICAL | Pass 1: Correctness | [duplicate_finder.py:L95-L138](file:///home/ahmad/Forensics/helios/src/helios/analyzers/duplicate_finder.py#L95-L138) | `DuplicateFinderAnalyzer` accesses non-existent `FileRecord` fields `name`, `device_id`, `path` via `getattr`, returning `'Unknown'` for all records. Instantiating `DataEvent` with string timestamp `"1970-01-01T00:00:00"`, invalid string `event_type`, and invalid keyword arguments raises `TypeError`. | Align field queries with `FileRecord` dataclass (`file_name`, `source_device`, `file_path`), and pass valid `datetime`, `EventType`, and `DataEvent` fields. |
| CRITICAL | Pass 1: Correctness | [lnk_jumplists.py:L55-L236](file:///home/ahmad/Forensics/helios/src/helios/analyzers/lnk_jumplists.py#L55-L236) | `LnkJumpListAnalyzer` defines `name` as `@property` (L55) breaking ABC contract. References non-existent `EventType.FILE_ACCESS` (L194, 232) raising `AttributeError`. Instantiates `DataEvent` with invalid parameters `source` and `description` while omitting required fields `source_device` and `source_path` (L193, 231). | Change `name` to a standard method, map `FILE_ACCESS` to valid `EventType` enum member, and pass required `DataEvent` parameters. |
| CRITICAL | Pass 1: Correctness | [prefetch.py:L55-L164](file:///home/ahmad/Forensics/helios/src/helios/analyzers/prefetch.py#L55-L164) | `PrefetchAnalyzer` instantiates `RawArtifact` with missing required positional arguments (`artifact_id`, `device_id`, `collected_at`) (L55). Instantiates `DataEvent` with string timestamp and invalid fields (L88-101). Instantiates `Alert` with invalid parameter `source_event=event` (L152, 164), raising `TypeError`. | Supply required `RawArtifact` positional parameters, pass `datetime` objects and `EventType` enum to `DataEvent`, and fix `Alert` parameters. |
| CRITICAL | Pass 1: Correctness | [shellbags.py:L58-L114](file:///home/ahmad/Forensics/helios/src/helios/analyzers/shellbags.py#L58-L114) | `ShellBagsAnalyzer` instantiates `RawArtifact` without required positional fields (`artifact_id`, `device_id`, `collected_at`) (L58, 63). Instantiates `DataEvent` with string timestamp and invalid enum `"FOLDER_ACCESS"` (L93). Instantiates `Alert` with invalid `source_event=event` (L108). | Provide all required `RawArtifact` parameters, pass valid `datetime` and `EventType` to `DataEvent`, and remove invalid `Alert` fields. |
| HIGH | Pass 1: Correctness | [after_hours.py:L29-L57](file:///home/ahmad/Forensics/helios/src/helios/analyzers/after_hours.py#L29-L57) | `AfterHoursAnalyzer.__init__` calls `super().__init__()` with 0 arguments instead of required `config` and `scan_options` (L29). `analyze()` accesses non-existent `artifact.data` (L57) raising `AttributeError`. | Update `__init__` to accept and pass `config` and `scan_options` to `super().__init__()`. Access `artifact.raw_data` or `artifact.metadata` instead of `artifact.data`. |
| HIGH | Pass 1: Correctness | [data_volume.py:L28-L47](file:///home/ahmad/Forensics/helios/src/helios/analyzers/data_volume.py#L28-L47) | `DataVolumeAnalyzer.__init__` calls `super().__init__()` with 0 arguments (L28), failing `AnalyzerBase.__init__`. Line 47 accesses `artifact.data` which raises `AttributeError: 'RawArtifact' object has no attribute 'data'`. | Pass `config` and `scan_options` to `super().__init__()` in `__init__`. Access `artifact.raw_data` or `artifact.metadata` instead of `artifact.data`. |
| HIGH | Pass 1: Correctness | [file_type_verifier.py:L18-L45](file:///home/ahmad/Forensics/helios/src/helios/analyzers/file_type_verifier.py#L18-L45) | `MAGIC_SIGNATURES` defines `b"PK\x03\x04": ".zip"` at L23 and `b"\x50\x4B\x03\x04": ".docx"` at L26. Byte-identical keys cause `.docx` to overwrite `.zip`, misidentifying every `.zip` file as `.docx` and raising false positive alerts. Also L45 accesses non-existent `artifact.data`. | Disambiguate ZIP container signatures, check inner file paths for Office Open XML files, and fix `artifact.data` access. |
| HIGH | Pass 1: Correctness | [android_parser.py:L37](file:///home/ahmad/Forensics/helios/src/helios/analyzers/android_parser.py#L37) | `collect()` accesses `device.metadata.get("serial")`, but `Device` dataclass in `helios.models` has no `metadata` field, raising `AttributeError: 'Device' object has no attribute 'metadata'` during Android collection. | Access `device.serial_number` field directly from `Device` model. |
| HIGH | Pass 3: Chain-of-Custody & Data Integrity | [cloud_sync.py:L181-L224](file:///home/ahmad/Forensics/helios/src/helios/analyzers/cloud_sync.py#L181-L224) | `CloudSyncAnalyzer` sets `timestamp=datetime.now()` for all extracted OneDrive, Google Drive, and Dropbox sync events instead of parsing actual sync timestamps from SQLite tables, destroying forensic timeline accuracy. | Extract actual `mtime`/`sync_time` timestamp fields from cloud sync SQLite tables and convert to standardized UTC datetimes. |
| HIGH | Pass 1: Correctness | [mft_analyzer.py:L288-L301](file:///home/ahmad/Forensics/helios/src/helios/analyzers/mft_analyzer.py#L288-L301) | `MftAnalyzer._parse_mft` calls mock methods `_mock_extract_si_times` and `_mock_extract_fn_times` returning synthetic `now - timedelta(days=2)` timestamps, bypassing binary MFT `$SI` and `$FN` attribute parsing. | Implement binary attribute parsing for 0x10 ($SI) and 0x30 ($FN) attributes or integrate `MFTECmdAdapter` output. |
| HIGH | Pass 1: Correctness | [usb_history.py:L202-L235](file:///home/ahmad/Forensics/helios/src/helios/analyzers/usb_history.py#L202-L235) | `UsbHistoryAnalyzer._parse_system_registry` returns hardcoded dummy Kingston DataTraveler events with `datetime.now()` timestamps instead of parsing binary SYSTEM registry hives, bypassing real USB evidence. | Use a registry parser (`python-registry` or `yarp`) to parse `USBSTOR` and `MountedDevices` keys from SYSTEM hives. |
| MEDIUM | Pass 2: Edge Cases | [browser_history.py:L34-L53](file:///home/ahmad/Forensics/helios/src/helios/analyzers/browser_history.py#L34-L53) | `_get_target_paths` checks Windows environment variables and Wine paths (`~/.wine/...`), ignoring native Linux Chrome (`~/.config/google-chrome/`) and Firefox (`~/.mozilla/firefox/`) profile directories. | Include standard Linux browser profile locations (`~/.config/google-chrome/`, `~/.mozilla/firefox/`) in target path resolution. |
| MEDIUM | Pass 3: Chain-of-Custody & Data Integrity | [browser_history.py:L145](file:///home/ahmad/Forensics/helios/src/helios/analyzers/browser_history.py#L145) | `_chrome_time_to_datetime` converts WebKit timestamp via `datetime.fromtimestamp(unix_time)` without specifying UTC timezone (`tz=timezone.utc`), introducing local UTC offset shifts. | Use `datetime.fromtimestamp(unix_time, tz=timezone.utc)` to standardize UTC timestamps. |
| MEDIUM | Pass 4: Error Handling | [usn_journal.py:L63-L101](file:///home/ahmad/Forensics/helios/src/helios/analyzers/usn_journal.py#L63-L101) | `collect()` passes invalid arguments (`name="$J"`, `data_stream=...`) to `RawArtifact`, and `analyze()` accesses `artifact.name` at L101. Exception handler logging `artifact.name` raises `AttributeError` inside `except`, masking root errors. | Use standard `RawArtifact` attributes (`artifact_id`, `source_path`, `metadata`) and log `artifact.source_path` in exception handlers. |
| MEDIUM | Pass 5: Security | [suspicious_detector.py:L24-L32](file:///home/ahmad/Forensics/helios/src/helios/analyzers/suspicious_detector.py#L24-L32) | `SuspiciousDetectorAnalyzer` accepts an unsanitized `rules_path` string without resolving path traversal sequences (`../`), allowing arbitrary file read attempts if passed unsafe config paths. | Validate and resolve `rules_path` against allowed configuration directories using `Path.resolve()`. |
| MEDIUM | Pass 6: Concurrency & State | [browser_history.py:L121](file:///home/ahmad/Forensics/helios/src/helios/analyzers/browser_history.py#L121) | `sqlite3.connect(..., uri=True)` opens live browser databases directly. Active process file locks on `History` or `places.sqlite` raise `sqlite3.OperationalError: database is locked`. | Copy SQLite database and WAL files to a temporary working directory before executing read queries. |
| LOW | Pass 2: Edge Cases | [recycle_bin.py:L194-L196](file:///home/ahmad/Forensics/helios/src/helios/analyzers/recycle_bin.py#L194-L196) | `_parse_i_file` parses `path_len = struct.unpack("<i", data[24:28])[0]` without validating bounds or positive length, risking `IndexError` on corrupted `$I` artifacts. | Validate `path_len > 0` and ensure `28 + (path_len * 2) <= len(data)` before unpacking bytes. |
| LOW | Pass 7: Test Coverage | `src/helios/analyzers/` | `src/helios/analyzers/` has zero unit test coverage in `tests/`. Instantiation failures, `AttributeError` bugs, missing imports, and dataclass schema mismatches went completely undetected. | Add a comprehensive test suite in `tests/test_analyzers.py` covering artifact collection, model serialization, database parsing, and schema validation. |
| LOW | Pass 8: Static Analysis Validation | `src/helios/analyzers/` | Static analysis via `mypy` reported 87 type errors and schema mismatches across 13 files in `src/helios/analyzers/` (missing constructor arguments, invalid enum types, incompatible return types). | Resolve type annotations, fix return type declarations (`List[DataEvent]` vs `List[Alert]`), and enforce `mypy --strict` compliance. |

---

## Module Audit: `src/helios/models.py` & `src/helios/core/`

| Severity | Pass | Module / File:Line | Description & Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| CRITICAL | Pass 1: Correctness | [correlator.py:L118-L161](file:///home/ahmad/Forensics/helios/src/helios/core/correlator.py#L118-L161) | `CrossDeviceCorrelator.match_files_by_hash` attempted to iterate over `device.file_records`, raising `AttributeError` on `Device` instances. Creation date queries used `x[1].creation_time` and deletion checks used `prev_rec.deleted`, raising `AttributeError` on `FileRecord`. | Iterate over `self.investigation.file_records`, lookup devices by `record.source_device`, and query `record.created` and `record.is_deleted`. |
| CRITICAL | Pass 1: Correctness | [correlator.py:L212-L224](file:///home/ahmad/Forensics/helios/src/helios/core/correlator.py#L212-L224) | `detect_usb_transfers` instantiated `DataEvent` with non-existent kwargs (`device_id`, `description`, `attributes`) and `event_id` override, raising `TypeError` at runtime. | Map attributes to standard `DataEvent` fields (`source_device`, `source_path`, `raw_source`, `metadata`). |
| CRITICAL | Pass 1: Correctness | [correlator.py:L265-L273](file:///home/ahmad/Forensics/helios/src/helios/core/correlator.py#L265-L273) | `detect_exfiltration_patterns` instantiated `Alert` with non-existent kwarg `related_events`, raising `TypeError`. | Map related event IDs to `evidence=[trans.event_id, delim.event_id]` attribute. |
| HIGH | Pass 1: Correctness | [correlator.py:L303](file:///home/ahmad/Forensics/helios/src/helios/core/correlator.py#L303) | `build_data_movement_graph` queried `device.name`, raising `AttributeError: 'Device' object has no attribute 'name'`. | Access `device.device_name` field directly from `Device` model. |
| HIGH | Pass 1: Correctness | [keyword_search.py:L75](file:///home/ahmad/Forensics/helios/src/helios/core/keyword_search.py#L75) | `KeywordSearchEngine.search` queried `investigation.files`, returning `[]` and failing search for all records. | Query `investigation.file_records` attribute on `Investigation` model. |
| MEDIUM | Pass 1: Correctness | [timeline.py:L91](file:///home/ahmad/Forensics/helios/src/helios/core/timeline.py#L91) | `TimelineBuilder.build_timeline` queried `event.device_id`, returning `None` and breaking device ID filtering. | Query `event.source_device` attribute on `DataEvent` model. |
| LOW | Pass 7: Test Coverage | `src/helios/core/` | `src/helios/core/` had zero unit test coverage. | Added comprehensive unit tests in [`tests/test_core.py`](file:///home/ahmad/Forensics/helios/tests/test_core.py) covering correlation, timeline sorting, and annotation storage. |

---

## Module Audit: `src/helios/devices/` & `src/helios/evidence/`

| Severity | Pass | Module / File:Line | Description & Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| CRITICAL | Pass 1: Correctness | [drive_selector.py:L18-L80](file:///home/ahmad/Forensics/helios/src/helios/devices/drive_selector.py#L18-L80) | `drive_selector.py` queried non-existent `DriveInfo` attributes (`mountpoint`, `size`, `fstype`, `DriveType.REMOVABLE`), causing immediate `AttributeError` during drive filtering. | Map queries to valid `DriveInfo` attributes (`drive_letter`, `total_size`, `filesystem`, `is_removable`, `DriveType.USB`). |
| LOW | Pass 7: Test Coverage | `src/helios/devices/`, `src/helios/evidence/` | Zero test coverage for drive selection, device detection, and evidence packaging. | Added unit tests in [`tests/test_devices.py`](file:///home/ahmad/Forensics/helios/tests/test_devices.py) covering local device detection, drive filtering, and evidence ZIP packaging. |

---

## Module Audit: `src/helios/cli.py`, `display.py`, & `menu.py`

| Severity | Pass | Module / File:Line | Description & Impact | Recommendation |
| :--- | :--- | :--- | :--- | :--- |
| MEDIUM | Pass 1: Correctness | [menu.py:L388](file:///home/ahmad/Forensics/helios/src/helios/menu.py#L388) | `ScanOptions` constructed during investigation menu wizard was unused prior to confirmation screen. | Pass `scan_options` to `print_scan_summary` to render scan scope to investigator. |
| LOW | Pass 7: Test Coverage | `src/helios/cli.py` | CLI commands (`demo`, `drives`, `devices`) had no test suite. | Added test suite in [`tests/test_cli.py`](file:///home/ahmad/Forensics/helios/tests/test_cli.py) covering `click` entry points and Rich table rendering. |

---

## Cleanup Log (2026-08-02) — Dead Code Pruning & Lean-Build Audit

Phase 2 cleanup removing code unrelated to the file-movement forensics mission (USB history, LNK/JumpLists, USN journal, Recycle Bin, Prefetch, ShellBags, exiftool verification, SleuthKit recovery, Android, suspicious detection, correlator, snapshots, keyword search, reporting, evidence).

### Deleted Modules (zero references in `src/helios/` non-test code)

| Module | Rationale |
| :--- | :--- |
| `core/alerting.py` | No consumers; alerts built inline by analyzers. |
| `utils/ntfs.py`, `utils/time_utils.py` | Unused helpers. |
| `devices/drive_selector.py` | Superseded by `menu.py` drive filtering. |
| `adapters/aleapp_adapter.py`, `adapters/bulk_extractor_adapter.py` | Tools out of scope (vetoed additions). |
| `analyzers/cloud_sync.py`, `email_artifacts.py`, `data_volume.py`, `after_hours.py`, `browser_history.py`, `duplicate_finder.py`, `mft_analyzer.py` | Out-of-mission analyzers. |
| `core/timeline.py` | Timeline building moved into `menu.py`/`correlator.py`. |

### Pruned Methods & Fields

- `exiftool_adapter.py` — removed `extract_metadata`, `extract_batch`, `_normalize_timestamp` (and unused `datetime` import); `get_file_type` retained (used by `file_type_verifier`).
- `mftecmd_adapter.py` — removed `run_mft_parsing`, `parse_mft_csv` (MFT flow superseded by SleuthKit `fls`); USN parsing retained.
- `adb_adapter.py` — removed `list_devices`, `get_device_props` (and unused `re` import); `run_adb_shell`/`pull_path` retained.
- `sleuthkit_adapter.py` — removed `icat`/`mmls` paths, getters, `run_icat`, `run_mmls`; `fls`/`fsstat` retained.
- `lnk_jumplists.py` — removed unused `DriveType` members and dead `LnkMetadata` dataclass.
- `android_collector.py` — removed `collect_app_usage`, `extract_public_media`.
- `core/hasher.py` — reduced to `hash_file` only (removed dual-hash, directory hash, xxhash quick-hash, compare sets; dropped `xxhash` dependency).
- `core/investigation.py` — removed unused `available` property.
- `utils/registry.py` — removed unused `enum_values`.
- `utils/file_utils.py` — removed `is_extension_mismatch` (superseded by `file_type_verifier`).
- `devices/detector.py` — removed unused `_parse_size_string`.
- `reporting/report_generator.py` — removed unused `prefer` parameter from `_pick_match`.
- `analyzers/shellbags.py` — removed stub `_parse_shellbags` (always returned `[]`; SBECmd is authoritative).
- `config.py` — removed dead `get_project_root` alias; `get_bundle_root()` retained.
- `pyproject.toml` — removed stale `mft_analyzer` from mypy overrides.
- `models.py` — `DriveType.SSD` retained after verification (used by demo `investigation.json`).

### Test Suite Updates

- `tests/test_adapters.py` — dropped ALEAPP/bulk_extractor tests.
- `tests/test_analyzers.py` — dropped after_hours/browser_history/data_volume/duplicate_finder tests.
- `tests/test_core.py` — dropped timeline builder test (module deleted).
- `tests/test_devices.py` — dropped drive_selector tests.
- `tests/test_tool_wiring.py` — dropped `_parse_shellbags` monkeypatch.

### Verification

- `pytest`: **44 passed**
- `mypy src/helios`: **0 errors across 48 source files**
- `ruff check --select F`: **clean**
- `vulture --min-confidence 100`: **clean** (0 findings)

## Fix Log (2026-08-02) — Profile Accuracy, Data Movement Graph, Suspicious-File Coverage

### 1. Investigation profiles now match what actually runs

**Root cause:** `config/investigation_profiles.yaml` referenced modules that were deleted in the cleanup (`cloud_sync`, `timeline_generation`, `duplicate_finder`, `mft_analyzer`, `aleapp_parser`) and used keys that did not match the `menu.py` module gates. Gated modules then silently failed via `except: pass` with zero trace in the report — the report could never show what really ran.

**Fix:**
- `config/investigation_profiles.yaml` rewritten — 4 profiles (`exfiltration`, `employee_exit`, `incident_response`, `full`) built exclusively from real gates: `usb_transfers, file_deletions, recent_file_access, event_logs, program_execution, shellbags, deleted_file_recovery, suspicious_files, cross_device_matching`.
- `src/helios/core/investigation.py` `PROFILE_MODULE_MAP` rewritten to reference only existing modules (9 keys).
- Wizard profile table text in `menu.py` updated to the real focus areas.
- **New:** `Investigation.module_results: list[dict]` + `Investigation.profile_name: str` with full `to_dict`/`from_dict` serialization.
- **New:** `menu.py` `_run_module()` closure records a real per-module outcome — `ran` / `disabled` / `failed` — with real event/alert deltas and the actual exception detail (previously swallowed by `except: pass`). All 8 raw `if module_enabled(...): try/except pass` blocks replaced; module logic extracted into `_usb_history_module`, `_recycle_bin_module`, `_lnk_jumplist_module`, `_event_logs_module`, `_prefetch_module`, `_shellbags_module`, `_sleuthkit_module`, `_suspicious_module`, `_correlator_module`.
- **New report card:** "Investigation Profile & Module Execution" renders profile name plus a Module / Status / Events / Alerts / Detail table with Ran / Failed / Disabled badges (added `.badge-danger` CSS). A custody log entry now shows the profile name and real module execution results instead of a fabricated "USBSTOR Registry & SetupAPI Log Parsing" entry.
- Demo reports correctly show the honest empty state ("No module execution log recorded") since demo data predates the field — no fake data injected.

### 2. Data movement graph was always empty on live scans

**Root cause:** every scanned `FileRecord` was assigned `source_device = local_device.device_id`, so the cross-device hash matcher could never find two records with equal hashes on different devices — the movement chart always rendered empty. (Demo mode worked because `demo_data/sample_investigation/investigation.json` contains real per-device correlations.)

**Fix:**
- `menu.py` now maps each scanned drive to a real `Device` object (`drive_devices`); removable/USB drives become `DeviceType.USB` devices with their real label, serial, and filesystem. `device_list = [local_device] + USB devices` is passed to the Investigation and the correlator, and `FileRecord.source_device` is set per-drive.
- **Bug fixed in `core/correlator.py`:** the exfiltration flag compared a `DeviceType` enum against plain strings, which never matched — `exfiltrated` was always `False`. Now compares `device_type.value`, so a copy found on a USB/Android device is correctly flagged.
- **Bug fixed in `analyzers/file_type_verifier.py`:** the analyzer silently skipped `FileRecord` objects passed directly as `raw_data` (it only read records wrapped in a dict), so live-scan extension-mismatch alerts never fired. Now accepts both forms.

### 3. Suspicious-file detection expanded to real malware-vector files

**Root cause:** only double-extension files were flagged; `.vbs`, `.bat`, `.exe` and other script/executable malware vectors in normal locations produced nothing.

**Fix (`analyzers/suspicious_detector.py`):**
- `EXECUTABLE_EXTENSIONS` expanded to 24 malware-vector extensions (`exe scr pif com bat cmd vbs vbe js jse wsf wsh hta ps1 psm1 psd1 jar msi cpl iso lnk msc reg docm xlsm pptm`).
- New checks (each gated in `config/suspicious_rules.yaml` — RULE-011 `executables_in_content_dirs`, RULE-012 `script_binary_disguise`):
  1. Any executable/script on a USB drive → HIGH (was limited to 5 extensions).
  2. Executable/script in user-content folders (Downloads, Documents, Desktop, Temp, attachments, Recycle Bin) → MEDIUM. Matching is per path component, not a raw substring, so a folder literally named `tmp`/`temp` is flagged but random path substrings are not.
  3. Script-extension file (`.vbs .js .bat .ps1 ...`) whose first bytes are a real PE/ELF header (`MZ` / `\x7fELF`) → HIGH "Script Extension Masks a Compiled Binary".
- Double-extension regex expanded to 22 hidden extensions.
- `file_type_verifier.py`: magic signatures added (GIF, GZ, BZ2, TAR, PK ZIP variants); `ZIP_BASED_EXTENSIONS` (docx/xlsx/pptx/jar/apk/zip/odt/ods/odp/epub) recognized as legitimately ZIP-based.

### New tests (all real files, no fixtures fabricated)

- `test_suspicious_detector_flags_vbs_in_user_content` — real file with actual `MZ` header bytes → HIGH masquerade alert.
- `test_suspicious_detector_flags_double_extension_script` — `.jpg.bat` double extension.
- `test_suspicious_detector_ignores_benign_script` — `.cmd` in a benign folder → no alert.
- `test_correlator_flags_exfiltration_to_usb` — same-hash file on PC + USB → one movement chain, `exfiltrated=True`.
- `test_file_type_verifier` raw-data handling covered by the existing mismatch test plus the direct-`FileRecord` path fix.

### Verification

- `pytest`: **48 passed** (was 44)
- `mypy src/helios`: **0 errors across 48 source files**
- `ruff check --select F`: **clean**
- Live-style report render verified: Module Execution card shows profile + Ran/Failed/Disabled badges; movement chart shows real correlations (demo: `DESKTOP-F0R3N51C -> Kingston DataTraveler`) and honest empty states otherwise.
- `dist/helios.exe` rebuilt from fresh PyInstaller run; demo run OK (18 events, 5 alerts, 9 files).

## Fix Log (2026-08-02) — Windows Live-Scan Runtime Errors (user-reported)

### 1. Missing SleuthKit DLLs → `libvhdi.dll` popup + 4-minute report hang

**Symptom:** Running a full scan on Windows raised a modal error popup about `libvhdi.dll`, `fsstat.exe` failed with exit code `3221225781` (0xC0000135, STATUS_DLL_NOT_FOUND), and the report-generation progress bar sat "counting" for minutes.

**Root cause:** `tools/` contained the SleuthKit Windows executables (`fls.exe`, `fsstat.exe`, `icat.exe`, `mmls.exe`) but **none of the Windows DLLs** they link against (`libtsk.dll`, `libvhdi.dll`, `libewf.dll`, etc.). The Windows loader showed a blocking modal dialog, which stalled `subprocess.run` — and `run_fsstat` had **no timeout**, so the scan hung until the popup was manually dismissed.

**Fix:**
- Bundled the official SleuthKit 4.15.0 win32 DLL set (57 DLLs incl. `libvhdi.dll`, `libtsk.dll`, API-set forwards) into `tools/` next to the exes; the PyInstaller spec already bundles `tools/**` recursively.
- `sleuthkit_adapter.py`: new `_suppress_windows_error_dialogs()` calls `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX)` before spawning tools so a missing/older DLL surfaces as a clean failure instead of a blocking popup.
- `run_fsstat` now goes through the timeout-safe `run_subprocess` (120s) instead of a bare `subprocess.run`; no subprocess can hang the pipeline indefinitely.

### 2. USB history module crashed on registry hives

**Symptom:** `Module usb_transfers failed: [WinError 5] Access is denied: 'C:\\Windows\\System32\\config\\SYSTEM'`.

**Root cause:** `UsbHistoryAnalyzer.collect()` called `Path.exists()` on `C:\Windows\System32\config\SYSTEM` (and SOFTWARE), which raises `PermissionError` instead of returning False when the process lacks admin rights — both in the main loop and in the scan-options path.

**Fix:** Both `exists()`/`is_file()` calls are wrapped; inaccessible paths are logged as warnings and skipped, so the module records a clean "ran" with zero artifacts instead of failing the whole module.

### 3. Repeated "No CSV files found ... prefix LECmd" noise

**Symptom:** A dozen identical warnings for LECmd/JLECmd/RBCmd — one per per-file subprocess run.

**Fix:** `ez_tools_adapter.py` dedupes the warning per `prefix|dir` (subsequent occurrences log at debug), and every EZ-tool subprocess now enforces a 120s timeout (`TimeoutExpired` caught).

### New test

- `test_usb_history_collect_skips_inaccessible_paths` — monkeypatches `Path.exists`/`is_file` to raise `PermissionError`; asserts `collect()` returns `[]` without crashing.

### Verification

- `pytest`: **49 passed**
- `mypy src/helios`: clean (48 files); `ruff check --select F`: clean
- `dist/helios.exe` rebuilt (72MB, includes 57 TSK DLLs); demo run OK (18 events, 5 alerts)
- `helios-v0.1.0-final.zip` rebuilt: 1095 files, 95 DLLs, 0 caches, 0 deleted-module refs

## Fix Log (2026-08-02) — Live-Scan Performance: ExifTool Batching & Correlator Complexity

**Symptom:** On a live Windows scan, the "Correlate events, detect anomalies & build report" stage ran 1:42+ without finishing.

**Root causes found by profiling with synthetic 20k-event / 10k-file data:**

1. **Per-file exiftool subprocess spawn (dominant).** `FileTypeVerifierAnalyzer` invoked `exiftool.exe` as a **separate subprocess for every file** whose magic bytes did not match a known signature (txt, dll, data files — the majority on a real drive). On a 2000-file drive walk that is up to 2000 process spawns, each ~0.5–1s on WSL-mounted paths → minutes. 
   **Fix:** `ExifToolAdapter.get_file_types()` batches up to 300 paths per single exiftool invocation (JSON output, UTF-8 forced via `-charset json=UTF8`), and the verifier queues all unresolved records for one batched pass. Worst case on a 2000-file walk: ~7 spawns instead of 2000. A fallback to the per-file path exists if an adapter lacks batching. New test `test_file_type_verifier_uses_single_batched_exiftool_call` asserts exactly one batched call for 5 files.

2. **Quadratic loops in `CrossDeviceCorrelator`.** Three methods scaled O(N²) with event counts:
   - `detect_usb_transfers` scanned all events for a disconnect per USB_CONNECT → now indexed disconnects by device (O(N)).
   - `detect_exfiltration_patterns` nested transfers × deletions → now an O(1) name index of deletions (O(T+D)).
   - `build_data_movement_graph` did a linear `next()` scan over edges per hop → now a dict lookup (O(E)).
   Profiled after fix: full correlator on 20k events + 10k file records = **0.3s** (was unbounded/minutes). Report generation on same data: **0.19s**.

### Verification

- `pytest`: **50 passed** (new batching test)
- `mypy src/helios`: clean (48 files); `ruff check --select F`: clean
- Batched adapter verified against the real bundled exiftool (txt→txt, MZ→exe)
- `dist/helios.exe` rebuilt; demo run OK (18 events, 5 alerts)
- `helios-v0.1.0-final.zip` rebuilt: 1095 files, 0 caches, 0 deleted-module refs

## Fix Log (2026-08-02) — Profile-Specific Reports, Clickable Findings, Option-Driven Utilities

### 1. Each scan profile now renders its own report

**Problem:** All 4 scan types (exfiltration, employee_exit, incident_response, full) produced identical reports.

**Fix:** `_profile_sections()` in `report_generator.py` derives which sections to render from the REAL module execution log (`module_results` keys + status):
- `transfers` (Data Flow chart + File Transfers table + File Transfers metric) — only when `cross_device_matching` or `usb_transfers` actually ran.
- `deletions` (Deleted Files table + Deletions-by-Day chart + Deleted Files metric) — only when `file_deletions` or `deleted_file_recovery` ran.
- `data_movement` tab — shown when either of the above is true; otherwise the tab is removed entirely.
- Reports without a module log (demo/legacy/quick scans) fall back to showing everything.
- The template gates the tab bar, panels, metric cards, summary charts, and the chart-init JS array accordingly.

Example outcomes verified: exfiltration shows transfers + deletions; incident_response hides the transfers metric, Data Flow chart, and transfers table (deletions only).

### 2. Key-finding stat cards are now clickable buttons

**Problem:** Stat cards (Files Indexed, Forensic Events, Alerts Raised, Deleted Files, File Transfers) were static numbers with no way to jump to the data.

**Fix:** Every metric card is an `<a class="metric">` button with a "View … →" affordance. Clicking switches to the relevant tab and smooth-scrolls to the exact section:
- Files Indexed → new **Files Indexed** table (first 1,000 records with full path, type, size, device, modified time; note when truncated; full inventory in CSV).
- Forensic Events → Timeline tab.
- Alerts Raised → Alerts tab.
- Deleted Files → Data Movement → Deleted Files.
- File Transfers → Data Movement → File Transfers.
JS: `goToMetric()` activates the target panel and scrolls to the section anchor; hover/focus styling added.

### 3. Key findings and alerts show the artifact path

**Problem:** "key finding should have path of that artifact".

**Fix:** 
- Key Findings list now renders the alert's evidence path (`Artifact: <code>path</code>`), falling back to raw evidence (e.g. event IDs) only when the evidence contains no path.
- Alerts table gained an "Artifact Path" column (`table_builder.py::build_alerts_table`), extracting the first path-like evidence item.

### 4. Option-driven utility UIs

**Quick USB Scan** — options now: [1] Complete scan (registry history + mounted drives, recommended), [2] Registry history only, [3] Mounted drives only, [B] back.

**Snapshot Manager** — create: pick a drive from a numbered list (or "enter path manually" as the last option) instead of typing a path; snapshot label defaults to an auto timestamp. Compare: snapshots listed with creation date, selection via numbered menu (rejects invalid indexes instead of crashing).

**Keyword Search** — two-step option menus: keyword preset ([1] credentials, [2] financial, [3] confidential, [4] personal identifiers, [5] custom entry), then search location from detected drives (or manual path). No free-text path required for the common case.

### Verification

- `pytest`: **52 passed** (new `test_profile_sections_from_module_log`, `test_alerts_table_includes_artifact_path`)
- `mypy src/helios`: clean (48 files); `ruff check --select F`: clean
- Rendered HTML verified per profile: gating flags correct for exfiltration / incident_response / legacy-demo
- `dist/helios.exe` rebuilt; demo run OK (18 events, 5 alerts)
- `helios-v0.1.0-final.zip` rebuilt: 1097 files, 0 caches, 0 deleted-module refs

---

## Fix Log (2026-08-02) — Distinct Per-Profile Reports, Stale Copy, .bat Detection, Report Data Fixes

### 1. Distinct report template per scan profile

**Problem:** all 4 scan types rendered the same report, and the module-execution gating was not visibly distinguishable.

**Fix:** report generation is now profile-aware:
- `_base.html.j2` + `_macros.html.j2`: shared layout, CSS, tab/chart JS, and reusable cards (metric card, key findings, devices, module execution, alerts, evidence, events table).
- One template per profile: `full_report.html.j2`, `exfiltration_report.html.j2` (movement-focused, Events tab), `employee_exit_report.html.j2` (adds "Recently Accessed Files (LNK/JumpLists)" table), `incident_response_report.html.j2` (no Data Movement tab; Deleted Files on Summary).
- `report_generator.py::_resolve_template(profile_name)` picks the template; `generate_html_report()` defaults to the profile template instead of a hardcoded one.
- Report filename now includes the profile: `helios_report_{CASE}_{profile}.html`.
- Removed the unused legacy `summary_report.html.j2`.

### 2. Removed stale "Retro" copy

- `menu.py` scan-complete message said "✓ Retro Interactive HTML Report generated" — now "✓ HTML Report generated at:".

### 3. Report data fixes

- **Deleted Files metric vs table mismatch:** the metric counted `file_records | selectattr('is_deleted')` (always 0 on live scans) while the table showed real deletion chains. Both now count the same `deletions` list (`build_movement_rows` output).
- **Files Indexed table removed:** the report no longer lists up to 1,000 files (inventory listing is not the report's purpose); the "Files Indexed" metric scrolls to the scanned-devices card. Full inventory stays in the exported CSV.
- **Forensic Events metric now lands on real data:** Timeline/Events tabs include an "Event Log" table (timestamp, type, source, path, confidence, newest first, capped at 500 with CSV note) built by `_build_event_rows()`.
- **Shift+Delete visibility:** honest "Limitation note" card in every Deleted Files section — Shift+Delete bypasses the Recycle Bin ($I never created) and is invisible to Recycle Bin parsing; only raw-disk scanning (SleuthKit fls, admin) or the NTFS USN journal can see it. Same note printed in the wizard after a scan.

### 4. .bat (and scripts in general) now flagged as warnings

**Problem:** a `.bat` created outside the known content folders (Downloads/Documents/Desktop/Temp...) was not flagged.

**Fix:** new rule **RULE-013 `scripts_outside_system_dirs`** in `suspicious_detector.py`: any script extension (.bat/.cmd/.vbs/.ps1/...) outside system directories (Windows, System32, Program Files, ProgramData, /usr, /bin, ...) and outside content dirs (already covered by RULE-011) → MEDIUM "Script File Outside System Directories". Added to `config/suspicious_rules.yaml`.

### 5. Filesystem walk cap is now visible

- Wizard logs a warning when the 2,000-file-per-drive inventory cap is hit, so silently-unindexed files are surfaced.

### Verification

- `pytest`: **56 passed** (new `test_profile_template_resolution`, `test_build_event_rows_sorted_and_capped`, `test_profile_report_renders_distinct_content`; updated benign-script test to use `C:\Windows\System32\cleanup.cmd`; new `.bat`-outside-system-dirs test)
- `mypy src/helios`: clean (48 files); `ruff check --select F`: clean
- Rendered HTML verified per profile: 4 distinct reports; IR has no Data Movement tab; event tables populated; Shift+Delete note present
- `dist/helios.exe` rebuilt (74 MB); demo run OK (18 events, 5 alerts, 9 files)
- `helios-v0.1.0-final.zip` rebuilt: 1106 files, caches excluded

---

## Fix Log (2026-08-02) — Repository Cleanup, README & AGENT Guide

### Changes
- **Removed stale docs:** `ARCHITECTURE.md`, `DESIGN.md`, `TASKS.md`, `CHANGELOG.md`, `CONTRIBUTING.md`, `SECURITY.md` (pre-refactor specs / boilerplate no longer matching the codebase).
- **Rewrote `README.md`:** current features, profile table, quick start (.bat scripts + pip), project layout, dev gates.
- **Rewrote `AGENTS.md`:** single source of truth for future AI agents — verified current state (56 tests, mypy 48 files, ruff clean), architecture essentials, hard guardrails, verification gates, testing conventions, task→file map, known limitations.
- **Removed runtime/generated dirs:** `build/`, `demo_output/`, `reports/`, `snapshots/`, and tool caches (`.mypy_cache`, `.pytest_cache`, `.ruff_cache`, `__pycache__`).
- **`.gitignore`:** added `reports/`, `snapshots/`, `demo_output/`, `.mypy_cache/`, `.ruff_cache/`.
- **Kept intact (explicit):** `run_helios.bat`, `build_exe.bat`, `test_exe.bat`, `dist/helios.exe`, `tools/` binaries, `.agents/` configs.
- **Rebuilt** `helios-v0.1.0-final.zip`: 1091 files, 6 md files, caches excluded.

### Verification
- `pytest`: **56 passed**; `mypy src/helios`: clean (48 files); `ruff --select F`: clean.

---

## Fix Log (2026-08-02) — Full Codebase Sweep: Dead Code, Settings Screen, Keyword Search, CLI Pipeline

### Changes
- **Deleted dead modules:** `analyzers/android_parser.py`, `analyzers/usn_journal.py`, `adapters/adb_adapter.py`, `adapters/mftecmd_adapter.py`, `devices/android_collector.py`, `utils/registry.py`, `core/annotations.py`, `evidence/packager.py` (no imports anywhere; the exe imports would fail at runtime).
- **Trimmed tool bundle:** removed unused `MFTECmd.exe`, `icat(.exe)`, `mmls(.exe)`; updated `tools/README.txt` + `TOOLS_REFERENCE.md`; mypy override for the deleted `helios.utils.registry` removed.
- **Settings screen fixed:** `config.py` now resolves only tools actually used (`TOOLS_IN_USE`/`TOOL_LABELS`: fls, fsstat, LECmd, JLECmd, PECmd, RBCmd, SBECmd, chainsaw, exiftool, adb) via the bundle-aware `resolve_tool_binary`; `menu_settings` shows ACTIVE/NOT FOUND per tool role instead of a hardcoded list that always said NOT FOUND.
- **Keyword search now has a defined goal:** `core/keyword_search.py` rewritten as exfiltration-keyword triage (name/path always; content only for text-like files ≤10 MB, ≤500 lines, ≤20 hits/file; binary/media/archive extensions excluded). New `templates/keyword_search_report.html.j2`, `ReportGenerator.generate_keyword_report()`, `helios keyword-search` CLI command, and menu keyword flow now writes the HTML report + JSON hit export.
- **CLI `helios investigate` was dead code** (printed status only). Now wired to the new `src/helios/pipeline.py` `run_investigation_pipeline()` — same gated pipeline the wizard uses: drive detection, device mapping, walk (SHA-256), 10 profile-gated modules, chain of custody, profile HTML report, walk-cap warning.
- **`menu.py` cleaned:** dead module helpers moved into pipeline.py; removed duplicate Sub-Menu 3 header and unused model imports.
- **Audit fixes:**
  - `core/correlator.py`: USB sessions without a disconnect use `None` (no fabricated `datetime.now()`); `event.metadata or {}` guards.
  - `core/investigation.py` `ProfileManager`: unknown profile **fails closed** (all modules disabled, warning logged).
  - `devices/detector.py`: lsblk `mountpoints` list field handled; `/proc/mounts` fallback added.
  - `analyzers/base.py`: removed dead `is_enabled()`.
  - `analyzers/usb_history.py`: `can_run()` dead branch removed (offline runs require evidence paths); SOFTWARE hive now actually parsed — `Explorer\MountPoints2` subkeys emit MEDIUM-confidence USB_CONNECT events from real hive LastWrite times (no fabricated timestamps).
  - `analyzers/prefetch.py`: no duplicate `.exe`; case-insensitive `.pf` glob.
  - `analyzers/lnk_jumplists.py`: events carry the real source device (was hardcoded `LOCAL_DISK`); `_get_users` guarded.
  - `analyzers/shellbags.py`: correct SBECmd columns (`LastAccessed0x20`/`LastModified0x10`/`0x30`/`Created0x10`/`0x30`).
  - `analyzers/event_logs.py`: rewritten to emit real `Alert` objects (dicts rendered empty in reports); EventID mapping (4624/4625 logon, 20001/20003 USB, 1102 audit cleared, 7045 service install); python-evtx XML parsing; records without real timestamps skipped; Chainsaw sigma hunts produce keyword alerts with real artifact paths.
  - `analyzers/suspicious_detector.py`: all 13 rules implemented (RULE-001..013 incl. mass deletion + after-hours USB via `analyze_events`, encrypted zip/RAR detection, MZ/ELF script-disguise, autorun, scripts-in-content-dirs); `RULE_NAME_MAP`; path-traversal-safe `_load_rules`; parameterized rules kept as dicts (fixes `autorun_files` bool-vs-dict crash).
  - `adapters/ez_tools_adapter.py`: fail-closed CSV parse (returns `[]` on non-zero exit; uses `run_subprocess`).
  - `adapters/chainsaw_adapter.py`: output JSON always rewritten, parsed only on rc 0 (no stale findings).
- **Tests:** rewrote `test_analyzers.py`, `test_core.py`, `test_adapters.py`, `test_devices.py`, `test_tool_wiring.py` — dropped imports of deleted modules; added coverage for the new pipeline/profile fail-closed behavior, keyword engine caps, USB MountPoints2/setupapi parsing, EZTools fail-closed CSV, and the trimmed tool bundle.

### Verification
- `pytest`: **67 passed**; `mypy src/helios`: clean (41 files); `ruff check --select F src/helios tests`: clean.
- CLI smoke tests: `helios keyword-search` produces HTML report + JSON export; `helios investigate -c SmokeTest -p <evidence>` runs the full pipeline (2000 events, 205 alerts, walk-cap warning, profile HTML report).
- Docs updated: `AGENTS.md` (layout/gates/templates), `README.md` (keyword-search CLI, settings screen), `TOOLS_REFERENCE.md`, `tools/README.txt`.

---

## Fix Log (2026-08-02) — Android Device Detection + Windows 11 OS Label (user-reported)

### Changes
- **`devices/detector.py` `detect_android_devices()`:** was calling bare `adb` from PATH and silently swallowing every failure (`FileNotFoundError`, `SubprocessError`), so a phone never appeared and nothing told the user why. Now resolves adb via the bundle-aware `resolve_tool_binary` (finds `tools/adb.exe` in the exe bundle/repo) and records an honest human-readable status (`last_adb_status()`) for: adb missing, no devices listed, unauthorized/offline device states, and query failures.
- **Windows 11 shows "Windows 10":** `get_local_device()` built `os_version` from `platform.system() + platform.release()`, and Windows 11 still reports NT kernel `10` — so Windows 11 displayed as "Windows 10". Added `_os_description()` which discriminates by build number (`>= 22000` → "Windows 11 (build …)"), falling back gracefully.
- **UI surfacing:** `helios devices` CLI command and menu option 2 (Drives & Devices Inspector) now print `Android status: …` when detection isn't clean.
- **Tests:** `test_devices.py` +5 (Windows 11/10 build detection, bundle-resolver usage, unauthorized-state reporting). Total: **72 passed**.

### Verification
- `pytest`: 72 passed; `mypy`: clean (41 files); `ruff --select F`: clean.
- `dist/helios.exe` rebuilt; `devices` command reports `Android status: adb binary not found …` on this host instead of silently showing nothing.

---

## Fix Log (2026-08-18) — Full Drive Enumeration, UTC Timestamps, NTFS & FAT Forensic Engine Overhaul

### Problems Diagnosed
1. **Incomplete Scan Results:** USB scans previously only showed files from the past few weeks because `pipeline.py` had a hardcoded `MAX_FILES_PER_DRIVE = 2000` cap, stopping filesystem walks prematurely in arbitrary order. Files >10MB were skipped during hashing, breaking cross-device matching.
2. **Incorrect File Timestamps:** All timestamp conversions across the scanner used naive local time (`datetime.fromtimestamp()`). On POSIX, `st_ctime` was read as file creation time (when it is inode metadata change time). In `correlator.py`, records with missing timestamps fabricated `datetime.now()`, making old deleted files appear as recent activity today.
3. **Missing Deep Low-Level Filesystem Support:** Unlike Autopsy and specialized tools, Helios lacked support for NTFS `$MFT`, `$UsnJrnl` change journals, timestomping detection, alternate data streams (ADS), and dedicated recursive FAT filesystem walks.

### Changes Implemented
- **`pipeline.py` Overhaul:**
  - `MAX_FILES_PER_DRIVE` increased from 2,000 to **500,000** files per drive.
  - `MAX_HASH_FILE_SIZE` increased from 10 MB to **500 MB**.
  - `_run_walk` updated to emit 3 distinct `DataEvent` items per file (`FILE_CREATE`, `FILE_MODIFY`, `FILE_ACCESS`).
  - Standardized all timestamps to UTC via `datetime.fromtimestamp(..., tz=timezone.utc)`.
  - Added Linux creation time resolution using `st_birthtime` (Python 3.12+) with fallback to `min(st_ctime, st_mtime)`.
  - Wired `_mft_module` and `_usn_journal_module` into the profile-gated execution pipeline.
- **`core/correlator.py`:**
  - Removed all `datetime.now()` fallback fabrications.
  - Safely filters missing/sentinel timestamps to ensure honest timeline reconstruction.
- **`adapters/sleuthkit_adapter.py`:**
  - Standardized bodyfile Unix timestamp parsing to UTC (`tz=timezone.utc`).
- **`models.py`:**
  - Added `EventType.FILE_ACCESS` to support complete file access timeline logging.
- **`utils/ntfs.py` (New Module):**
  - Implemented `filetime_to_datetime`, `parse_mftecmd_timestamp` (with 7-digit subsecond tick handling), `decode_usn_reason`, `decode_mft_flags`, `has_alternate_data_stream`, and heuristic `detect_timestomping` comparing SI vs FN timestamps.
- **`analyzers/fat_filesystem.py` (New Module):**
  - Full recursive `os.walk` for FAT/exFAT USB drives with SHA-256 hashing up to 500MB and UTC `DataEvent` generation.
- **`adapters/mftecmd_adapter.py` (New Module):**
  - Adapter for Eric Zimmerman's MFTECmd tool to dump `$MFT` and `$UsnJrnl` to CSV.
- **`analyzers/mft_analyzer.py` & `analyzers/usn_journal.py` (New Modules):**
  - Parsers for MFT and USN Journal CSV outputs into `DataEvent` and `Alert` records with timestomping and ADS detection.
- **`config/investigation_profiles.yaml` & `core/investigation.py`:**
  - Added `mft_analysis` and `usn_journal` to profile configurations and module maps.
- **Tests (`tests/test_ntfs_and_fat.py`):**
  - Added 12 new comprehensive unit tests covering all new utilities, adapters, and analyzers. Total passing tests increased from 72 to **84**.

### Verification
- `pytest`: **84 passed** cleanly (`venv/bin/python -m pytest -v`).
- `mypy`: **Clean across 56 source files** (`venv/bin/mypy src/helios tests`).
- `ruff`: **All checks passed** (`venv/bin/ruff check --select F src/helios tests`).
- `helios demo`: Verified end-to-end demo execution generates full HTML reports, JSON/CSV exports, chain-of-custody logs, and tamper-evident ZIP archives.

---

## Fix Log (2026-08-18) — File Limits, Windows Console UTF-8 & Emoji Fix, Report Profile Isolation & Windows Tests

### Problems Addressed
1. **File Limit Increase:** Raised scan limits from 500,000 to **5,000,000** files per drive and hash limit to 500MB in `pipeline.py`, updating dynamic formatting in `menu.py`.
2. **Windows Console Emojis & '?' Symbol Glitches:** 
   - Initialized Windows console output and input code pages to UTF-8 (`SetConsoleOutputCP(65001)` + `sys.stdout.reconfigure(encoding='utf-8')`) via `init_windows_console()` in `display.py` and `menu.py`.
   - Replaced brittle status icons and symbols (`✓`, `⚠`, `✗`, `ℹ`, `⏳`, `➤`, `●`, `○`) with clean, universal bracket tags (`[+]`, `[!]`, `[-]`, `[*]`, `[>]`, `>`) that render flawlessly across standard Windows CMD, PowerShell, and compiled PyInstaller `.exe` binaries.
   - Preserved the signature Helios golden sun and block-letter ASCII banner untouched.
   - Added `@chcp 65001 >nul` to all batch scripts (`run_helios.bat`, `build_exe.bat`, `test_exe.bat`).
3. **HTML Report Strict Profile Isolation:**
   - Isolated each profile report template so it contains ONLY the sections and data promised by that scan profile:
     - `exfiltration`: Shows only USB connections, cross-device file transfers, post-transfer exfiltration deletions, and exfiltration alerts. Completely excludes raw-disk SleuthKit recovery, Prefetch execution, and Windows Event Log cards.
     - `employee_exit`: Shows USB history, LNK/JumpList recent access, ShellBags folder exploration, and unallocated/Recycle Bin deletions. Strictly excludes Prefetch and Event Log cards.
     - `incident_response`: Focuses on Executed Programs (Prefetch / service installs), Windows Event Logs & Sigma compromise hunts, ShellBags, and Shift+Deleted files. Strictly excludes USB transfer movement tables.
     - `full`: Complete multi-tab forensic dashboard with dynamic module gating.
4. **Intelligent Test Suite Expansion:**
   - Created `tests/test_profile_report_strictness.py` to assert that rendered HTML reports strictly isolate their respective profile modules without leaking disabled sections.
   - Created `tests/test_windows_forensics.py` to test Windows FILETIME epoch calculations, 7-digit MFTECmd subsecond parsing, NTFS timestomping heuristics, Alternate Data Streams (ADS), USN reason decoding, and 5,000,000 file capacity limits.
   - Total passing test suite expanded to **97 tests**.

### Verification
- `pytest`: **97 passed in 13.48s** (`venv/bin/python -m pytest -q`).
- `mypy`: **Clean across 58 source files** (`venv/bin/mypy src/helios tests`).
- `ruff`: **All checks passed** (`venv/bin/ruff check --select F src/helios tests`).
- `helios demo`: Verified end-to-end execution.
- `helios-v0.1.0-final.zip`: Distribution package rebuilt (1111 files, caches excluded).

---

## Fix Log (2026-08-18) — Live Scan Crash Fixes: UTC Datetime Normalization, Graceful Tool Fallback, Clean Logs

### Problems Diagnosed from Windows Host Live Scan
1. **Datetime Comparison Collision (`TypeError: can't compare offset-naive and offset-aware datetimes`):**
   - In `pipeline.py`, filesystem walk events produced UTC-aware datetimes (`datetime.fromtimestamp(..., tz=timezone.utc)`).
   - Artifact analyzers (`usb_history.py`, `prefetch.py`, `recycle_bin.py`, `shellbags.py`, `lnk_jumplists.py`, `event_logs.py`) parsed CSV / registry timestamps into offset-naive datetimes (`datetime.strptime()` without timezone or with `.replace(tzinfo=None)`).
   - When `suspicious_detector.py` evaluated `analyze_events()` (RULE-006 Mass Deletion), sorting and subtracting `e.timestamp - start_evt.timestamp` triggered a fatal `TypeError` that crashed the live investigation pipeline.
2. **MFTECmd Missing Tool Exception Dumps:**
   - When MFTECmd was not present in `tools/` or PATH, `pipeline.py` raised `RuntimeError`, causing `_run_module` to dump multi-line stack traces to the user console.
3. **Noisy Temporary CSV Warnings:**
   - When EZ Tools ran on empty or non-applicable directories, `ez_tools_adapter.py` emitted `WARNING` level log entries (`No CSV files found in ... matching prefix ...`) directly to stderr.
4. **Residual Emoji Glyph in Pipeline Spinner:**
   - `menu.py` line 425 contained an unescaped `⏳` glyph before `Running live forensic analysis pipeline...`.

### Changes Implemented
1. **Universal UTC Datetime Normalization:**
   - In `models.py`:
     - Added `_ensure_utc(dt: datetime | None) -> datetime | None` helper.
     - Added `__post_init__` to `DataEvent`, `FileRecord`, and `Alert` to automatically normalize naive datetimes to `timezone.utc`.
     - Standardized `_now()` to `datetime.now(tz=timezone.utc)`.
   - In `analyzers/suspicious_detector.py`:
     - Added `_to_utc(dt)` helper in `analyze_events()` ensuring safe comparison and timedelta calculations across all events.
   - In `analyzers/prefetch.py`, `usb_history.py`, `shellbags.py`, `recycle_bin.py`, `lnk_jumplists.py`, `event_logs.py`:
     - Standardized all `strptime`, `fromtimestamp`, and `datetime.now()` calls to explicitly include `tzinfo=timezone.utc` / `tz=timezone.utc`.
     - Preserved UTC time metadata when parsing EVTX records with python-evtx.
2. **Graceful MFTECmd Fallback:**
   - In `pipeline.py`:
     - In `_mft_module` and `_usn_journal_module`, replaced `raise RuntimeError(...)` with clean `logger.debug(...)` early returns when MFTECmd is unavailable.
     - In `_run_module`, changed unhandled exception logging to `logger.warning` / `logger.debug` for tracebacks to avoid console clutter.
3. **Cleaned Console Output:**
   - In `adapters/ez_tools_adapter.py`: lowered missing CSV notifications from `logger.warning` to `logger.debug`.
   - In `menu.py`: replaced `⏳` with `[*] Running live forensic analysis pipeline...`.
4. **Test Suite Expansion:**
   - Added `test_suspicious_detector_handles_mixed_naive_aware_timestamps` in `tests/test_analyzers.py` to ensure offset-naive and offset-aware datetimes never trigger errors.
   - Updated test assertions to match UTC timezone semantics across 98 passing tests.

### Verification
- `pytest`: **98 passed in 13.59s** (`venv/bin/python -m pytest -v`).
- `mypy`: **Clean across 58 source files** (`venv/bin/mypy src/helios tests`).
- `ruff`: **All checks passed** (`venv/bin/ruff check --select F src/helios tests`).
- `helios demo`: Successfully executed end-to-end (18 events, 5 alerts, 9 files indexed, valid HTML report + exports generated).

---

## Fix Log (2026-08-18) — SleuthKit Deleted File Cleanup, Live Winreg Querying, & Report Movement Segregation

### 1. SleuthKit Deleted Filename & Path Cleanup (`sleuthkit_adapter.py`)
- **Root Cause:** SleuthKit `fls` appends stream markers (`($FILE_NAME)`, `($DATA)`, `($INDEX_ALLOCATION)`) and status flags (`(deleted)`, `(deleted-realloc)`, `(realloc)`) to file paths and names. Furthermore, internal NTFS metadata files (`$MFT`, `$LogFile`, `$Volume`, `$Bitmap`, `$Boot`, `$Secure`, `$Extend`, `$UsnJrnl`) and BitLocker volume encryption keys (`System Volume Information\FVE2.{guid}.*`) were being presented as user-deleted files.
- **Fix:**
  - Implemented `_clean_fls_path_and_name()` to strip TSK metadata stream and allocation suffixes via regex.
  - Implemented `_is_system_metadata()` to classify NTFS metadata files, BitLocker keys, and System Volume Information entries as `is_system=True`.
  - Implemented stream deduplication in `parse_fls_output()` using `(inode_num, clean_path.lower())` so duplicate `$FILE_NAME` vs `$DATA` entries are merged cleanly.

### 2. Drive Path Normalization & File Delete Event Gating (`pipeline.py`)
- **Root Cause:** Slashes and drive letter concatenation resulted in malformed paths like `D:\D:\...`. System metadata files also emitted `FILE_DELETE` events which triggered false-positive mass deletion alerts.
- **Fix:**
  - Standardized drive path normalization with regex `^[a-zA-Z]:[\\/]`.
  - Gated `FILE_DELETE` `DataEvent` generation so records with `is_system=True` do not emit deletion timeline events.

### 3. Suspicious Detector Mass Deletion False-Positive Filter (`suspicious_detector.py`)
- **Fix:** Updated `RULE-006` mass deletion detector to ignore system metadata tokens (`system volume information`, `$recycle.bin`, `$extend`, `fve2.{`, `fve.}`) so BitLocker key updates during volume operations do not trigger high-severity evidence-wiping alerts.

### 4. Timestamp Integrity Preservation (`mft_analyzer.py`)
- **Fix:** Removed `datetime.now(timezone.utc)` fallback when MFT timestamps cannot be parsed from deleted file records, preserving genuine timestamp integrity.

### 5. Live Windows Registry Access & PyInstaller Hidden Imports (`usb_history.py`, `helios.spec`)
- **Root Cause:** On live Windows, `C:\Windows\System32\config\SYSTEM` and `SOFTWARE` are locked exclusively with `ERROR_SHARING_VIOLATION` by the Windows kernel (`ntoskrnl.exe`). Also, `helios.spec` lacked `Registry` and `Evtx` hidden imports and collection hooks.
- **Fix:**
  - Implemented `_parse_live_winreg()` using Python's standard library `winreg` to directly query `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` and `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` and extract 64-bit FILETIME last-write timestamps without file locking.
  - Updated `helios.spec` to use `collect_all('Registry')`, `collect_all('Evtx')`, and add `winreg`, `Registry`, `Evtx` to `hiddenimports`.
  - Installed `python-registry` and `python-evtx` in the environment.

### 6. Report Movement Segregation (`report_generator.py`)
- **Fix:** Updated `build_movement_rows()` so deleted files (`target_raw == "RecycleBin"` or `event_type == "FILE_DELETE"`) are strictly routed to the deletions context and omitted from the file transfers table. Filtered system metadata tokens from deletions and deleted files report tables.

### 7. Automated Test Suite Expansion (`tests/test_adapters.py`, `tests/test_analyzers.py`)
- Added tests for TSK suffix stripping (`test_sleuthkit_fls_strips_metadata_suffixes`).
- Added tests for system metadata detection (`test_sleuthkit_fls_identifies_and_flags_system_metadata`).
- Added tests for inode stream deduplication (`test_sleuthkit_fls_deduplicates_filename_streams`).
- Added tests for graceful offline registry parsing (`test_usb_history_graceful_on_missing_registry_package`).
- Added tests for transfer vs deletion segregation (`test_report_generator_segregates_deletions_from_transfers`).

### Final Verification Results
- **pytest**: **103 passed in 11.50s** (`venv/bin/python -m pytest -v`)
- **mypy**: **Clean across 58 source files** (`venv/bin/mypy src/helios tests`)
- **ruff**: **All checks passed** (`venv/bin/ruff check --select F src/helios tests`)
- **PyInstaller build**: Standalone executable `dist/helios.exe` built successfully and passed `helios demo` smoke test.

---

## Fix Log 8 (2026-08-18) — Cross-Device Hop Correction, Multi-Drive Recycle Bin & Deleted Files Engine

### 1. Fixed "File Transfers Source and Destination are Same" Bug (`correlator.py`, `report_generator.py`, `chart_builder.py`)
- **Root Cause**: `match_files_by_hash()` previously grouped files across different paths on the *same* machine (such as identical 0-byte files with hash `e3b0c44...`) and created phantom `MovementChain` instances where `source_device = "DeathStar"` and `target_devices = ["D:"]`. When rendered in the report, this showed as transfers from DeathStar to D:.
- **Fix**:
  - Excluded empty file hashes (`EMPTY_SHA256 = "e3b0c442..."`, `EMPTY_MD5 = "d41d8cd9..."`, `""`, `"N/A"`) from cross-file movement matching.
  - Required distinct devices (`len(devices_involved) > 1`) or explicit deletion flags for `MovementChain` generation.
  - In single-volume event chains, resolved destination device from `event.metadata["target_device"]` or cross-drive path detection, preventing self-loop hops (`PC -> PC`).
  - In `detect_usb_transfers()`, properly set `source_device` to the host PC and destination USB device in metadata.
  - In `build_movement_rows()`, normalized drive letters and suppressed same-device hops.
  - In `build_data_flow_chart()`, replaced unicode arrows `→` with ASCII `->` and suppressed self-flow edges.

### 2. Multi-Drive $Recycle.Bin Discovery (`recycle_bin.py`)
- **Root Cause**: `RecycleBinAnalyzer.collect()` was hardcoded to only check `C:\$Recycle.Bin`, completely ignoring `$Recycle.Bin` on secondary partitions (D:, E:, etc.).
- **Fix**: Updated `collect()` to check all connected drives (`device.drive_letter`, `device.mount_point`, `scan_options.drives`, and candidate letters `D:\` through `Z:\`).

### 3. Deleted Files Filtering & Template Enrichment (`report_generator.py`, `full_report.html.j2`)
- **Fix**: Removed `$recycle.bin` from `_SYS_NOISE_TOKENS` so user files deleted into the Recycle Bin are no longer suppressed. Enriched the Deleted Files table to display full file paths, sizes, and timestamps.

### 4. Emoji & Unicode Consolidation for Windows Console Portability (`menu.py`, `cli.py`, `build_win.py`)
- Replaced all emojis and non-ASCII bullets (`•`, `—`, `✓`, `⏳`, `✗`) with clean ASCII tags (`[1]`, `[+]`, `[*]`, `[-]`, `--`) across interactive menus, wizards, and build scripts.

- **Distribution archive**: `/home/ahmad/Forensics/helios-v0.1.0-final.zip` rebuilt cleanly.


