# Helios — Extreme Deep Code Analysis & Bug Report

**Repository:** `github.com/ahmadVader0/helios` (branch `main`, analyzed 2026-08-19)
**Scope:** Full static analysis of every module, dynamic reproductions of the critical bugs, test-suite execution (pytest), linting (ruff), and cross-verification of third-party tool behavior (Eric Zimmerman Tools, SleuthKit, chainsaw, wevtutil) against official sources.
**Test suite result:** 102 passed, **1 failed** (`tests/test_tool_wiring.py::test_bundled_tools_layout` — the repo contradicts its own test, see §6.3).

---

## 1. Executive Summary — Why Helios "Produces No Results Like Autopsy", Even As Admin

Your observation is correct, and it is **not** a permissions problem. Running as administrator does not help because the failures are in Helios's own code. The forensic evidence chain is broken at **seven independent points**, each of which alone is enough to zero out entire modules. They are all *silent* failures — Helios catches the exceptions, logs at `debug` level, and reports success with an empty timeline.

### The kill chain (each verified, most reproduced dynamically)

| # | Bug | Effect |
|---|-----|--------|
| 1 | **EZ Tools CSV filename glob never matches real output** (`ez_tools_adapter.py:148`) | LNK, JumpLists, PECmd enrichment, RBCmd enrichment, ShellBags → **all return zero rows** |
| 2 | **CSV column-name mismatches** (`shellbags.py`, `lnk_jumplists.py`) | Even if #1 were fixed, ShellBags and LNK/JumpList parsers skip **every row** |
| 3 | **Built-in Prefetch parser cannot parse any real .pf file** (`prefetch.py:215`) | Program-execution history silently empty on all Windows 7/10/11 |
| 4 | **Tool resolution depends on current working directory** (`base.py:170`) | All bundled tools "not found" unless launched from repo root |
| 5 | **Live Security.evtx locked + wevtutil fallback broken** (`event_logs.py:339-356`) | Windows event-log module yields nothing on a live machine |
| 6 | **Sigma rules path wrong** (`event_logs.py:225`) | chainsaw threat-hunt *always* skipped silently |
| 7 | **`pyproject.toml` missing runtime dependencies** | `pip install -e .` yields an environment where registry-hive and EVTX parsing are silently dead |

And when Helios *does* find something, the results are "very bad" because of **false-positive floods**:

| # | Bug | Effect |
|---|-----|--------|
| 8 | **USB transfer correlator matches host events, not USB events** (`correlator.py:275+`) | Reproduced: **5,000 out of 5,000** ordinary `C:` file creations flagged "transferred to USB" with HIGH confidence |
| 9 | **Timestomping detector flags every copied file** (`ntfs.py:166`) | `si_modified < si_created → True` is the *normal* result of an NTFS copy |
| 10 | **USB connect events duplicated** (`usb_history.py`) | Same USB connection parsed twice (registry parse + live-winreg fallback both run) |
| 11 | **Event-log report section always empty** (`report_generator.py:465`) | Even successfully parsed EVTX events never appear in the HTML report |

Details, evidence, and fixes below.

---

## 2. Critical Bugs — The Evidence Pipeline Is Broken

### 2.1 ★ ROOT CAUSE #1 — EZ Tools CSV glob can never match real tool output

**File:** `src/helios/adapters/ez_tools_adapter.py:148`

```python
# EZ Tools typically generate a file like: <Prefix>_Output_<Timestamp>.csv
csv_files = list(output_csv_dir.glob(f"{expected_csv_prefix}*.csv"))
```

with prefixes `"LECmd"`, `"JLECmd"`, `"SBECmd"`, `"PECmd"`, `"RBCmd"`.

**Reality** (verified in LECmd's official `Program.cs` source):

```csharp
var outName = $"{tsNow:yyyyMMddHHmmss}_LECmd_Output.csv";
```

The timestamp comes **first**: `20260819103022_LECmd_Output.csv`. A glob of `LECmd*.csv` can **never** match. Reproduced:

```
Real LECmd output file present: ['20260819103022_LECmd_Output.csv']
Helios glob 'LECmd*.csv' matches: []  -> ingestion sees ZERO rows
```

**Impact:** Every module that relies on `EZToolsAdapter` silently produces nothing:

- **recent_file_access** (LNK files via LECmd) — zero events
- **recent_file_access** (JumpLists via JLECmd) — zero events
- **program_execution** PECmd enrichment — zero events
- **file_deletions** RBCmd enrichment — zero events
- **shellbags** (SBECmd) — zero events

Note the code comment itself states the wrong filename format (`<Prefix>_Output_<Timestamp>.csv`) — the author never tested against real tool output. The unit tests hide this: they create mock CSVs with prefix-first names, so all 102 tests pass while production gets nothing.

**Secondary bug in the same function:** when the tool exits 0 but writes no matching CSV, the code takes `max(csv_files, key=mtime)` — i.e. it would happily ingest a **stale CSV from a previous run** in the same directory as if it were fresh evidence. The stale-file guard exists only for `returncode != 0`. In a forensic tool this is an evidence-integrity hazard.

**Fix:** pass `--csvf <explicit_name>` to every EZ tool (MFTECmd adapter already does this correctly — the pattern exists in the same codebase), or glob `f"*{expected_csv_prefix}*"`. Reject CSVs older than the subprocess start time.

---

### 2.2 ★ ROOT CAUSE #2 — CSV column names don't match real tool output

Even with the glob fixed, two modules still return zero rows because they read column names that don't exist.

**ShellBags — `src/helios/analyzers/shellbags.py`** reads:
`FolderPath`, `LastAccessed0x20`, `LastModified0x10`, `Created0x10`

**Actual SBECmd columns:** `AbsolutePath`, `BagPath`, `CreatedOn`, `ModifiedOn`, `AccessedOn`, `FirstInteracted`, `LastInteracted`, `NodeSlot`, `MruPosition`, …

→ Every row fails the "missing path, skipping" check. **Zero shellbag events, always.**

**LNK/JumpLists — `src/helios/analyzers/lnk_jumplists.py`** reads:
`TargetCreationTime`, `TargetModificationTime`, `TargetAccessTime` (`SourceCreated` happens to be correct)

**Actual LECmd/JLECmd columns** (verified against multiple DFIR write-ups and the EZ Tools manual): `TargetCreated`, `TargetModified`, `TargetAccessed`.

→ Every row fails the "missing target timestamps, skipping" check. **Zero file-access events from LNK/JumpLists, always.**

There is no native fallback parser for either artifact, so these are hard zeros.

**Fix:** read the actual column names (preferably tolerant lookup over a synonym set), and add an integration test that runs the real bundled exes on a small fixture directory.

---

### 2.3 ★ ROOT CAUSE #3 — The built-in Prefetch parser parses zero real files

**File:** `src/helios/analyzers/prefetch.py:215`

```python
if len(data) < 84 or data[:4] != b"MAM\x04":
    return None
```

Two fatal misunderstandings of the format:

1. `MAM\x04` is the signature of an **XPRESS-Huffman-compressed** Prefetch (all Windows 10/11 files). The code checks the signature, then parses the **still-compressed payload** as if it were the raw v30/v31 layout — every offset read is garbage, so it returns `None` (or nonsense). It never decompresses.
2. Windows 7 uncompressed Prefetch files start with the version DWORD followed by `SCCA` — these are **rejected** by the `MAM\x04` check.

Reproduced dynamically:

```
Case 1 — real Win10/11 MAM\x04 compressed prefetch -> None (silently dropped)
Case 2 — Win7 uncompressed SCCA prefetch            -> None (silently dropped)
```

So the native parser yields **nothing on any supported Windows version**, and the module's only working path was PECmd — which is dead because of bug 2.1. Result: **no program-execution history at all**, one of the most basic things Autopsy shows out of the box.

**Bonus bug:** suspicious-tool detections (`SUSPICIOUS_TOOLS`) are stuffed into `event.metadata["alert"]` and never added to the investigation's `alerts` list — they are invisible in the report.

**Fix:** decompress `MAM\x04` payloads (LZNT1/XPRESS — `libmspress`/`pypff`-style or call PECmd), accept `SCCA` files, and emit real `Alert` objects.

---

### 2.4 ★ ROOT CAUSE #4 — Tool resolution silently fails outside the repo root

**File:** `src/helios/adapters/base.py:170` — `resolve_tool_binary()` searches, in order:

1. `sys._MEIPASS/tools` (PyInstaller bundle)
2. `Path(sys.executable).parent/tools`
3. **`Path.cwd()/tools`** ← current working directory
4. `PATH`

It **never** searches the repo's own `tools/` directory via a path anchored at the package — even though `config.py` already provides `get_bundle_root()` for exactly this (and `sleuthkit_adapter.py` uses it — the codebase is internally inconsistent). Empirically verified: when CWD ≠ repo root, resolution returns `None` for all bundled tools.

**Impact:**

- `run_helios.bat` masks this with `pushd` — launching from anywhere else (double-clicking a script, `python -m helios` from another directory, the installed console script) makes **every external tool vanish**: LECmd, JLECmd, PECmd, SBECmd, RBCmd, MFTECmd, chainsaw, exiftool, fls/fsstat, adb.
- Failures are silent (`logger.debug`), so the user sees a clean run with empty results.

**Fix:** resolve relative to `Path(__file__)` / `get_bundle_root()` first; log tool-missing at WARNING and surface it in the report.

---

### 2.5 ★ ROOT CAUSE #5 — Event logs: locked file + broken wevtutil fallback

**File:** `src/helios/analyzers/event_logs.py:339-356`

On a live system, `C:\Windows\System32\winevt\Logs\Security.evtx` is **locked by the Event Log service** — even administrator cannot open it for reading with normal file APIs. The code's fallback:

```python
["wevtutil", "epl", str(path), tmp_path]
```

passes a **file path** where `wevtutil epl` expects a **log name** (e.g. `wevtutil epl Security C:\out.evtx`). The fallback therefore always fails too. Net effect on a live machine: **no Security/System event-log events** — no logons, no 4663 file-access auditing, nothing. (Autopsy reads these from a disk image, where there is no lock; Helios runs live, so it must use `wevtutil epl Security …`, VSS, or raw NTFS reads.)

Additional bugs in the same module:

- **Sigma path bug (line 225):** `sigma_rules_dir = get_bundle_root() / "sigma_rules"` — but the rules live in `tools/sigma_rules` (bundled as `_MEIPASS/tools/sigma_rules` per `helios.spec`). The directory never exists → **chainsaw hunting is silently skipped on every run**.
- Non-Windows: `root.rglob("*.evtx")` walks the **entire filesystem** — unbounded.
- Event IDs **4624/4625 (logon success/failure) are misclassified as `EventType.APP_EXECUTE`**, and a separate alert is raised **per 4625 event** — on a machine exposed to the internet this means thousands of "failed logon" alerts drowning the report.

---

### 2.6 ★ ROOT CAUSE #6 — `$MFT` / `$UsnJrnl` accessed as plain paths

**File:** `src/helios/pipeline.py` (`_mft_module`, `_usn_journal_module`)

```python
mft_path = Path(f"{drv.drive_letter}\\$MFT")
usn_path = Path(f"{drv.drive_letter}\\$Extend\\$UsnJrnl:$J")
```

On a live system these metafiles are **locked by NTFS**. This can work only if the bundled `MFTECmd.exe` is v6.0+ ("locked file support added") **and** the process is elevated **and** the tool actually resolves (bug 2.4). The bundled MFTECmd version is unknown, and — compounding everything — the repo's own test suite **asserts MFTECmd.exe must NOT be bundled** (see §6.3), so depending on which state of the repo you have, the MFT module either runs an old binary that fails on live systems or has no binary at all. Failures are swallowed into `module_results` and the pipeline continues.

Related: `mftecmd_adapter.py` writes every drive's dump to the **same** `--csvf` name (`mft_dump`), so scanning multiple drives **overwrites the previous drive's evidence CSV**.

---

### 2.7 ★ ROOT CAUSE #7 — `pip install -e .` produces a silently broken install

`pyproject.toml` omits `python-registry` and `python-evtx`, although the code imports `Registry` and `Evtx` at runtime (both are in `requirements.txt`). So the supported install path (`pip install -e .`) yields an environment where:

- offline registry-hive parsing (USB history, ShellBags fallback) → dead
- EVTX parsing → dead

`run_helios.bat`'s fallback `pip install` has the same omission. Imports are wrapped in try/except with `debug`-level logging, so nothing tells the user.

---

## 3. High-Severity Correctness Bugs — Why The Results You Do Get Are "Very Bad"

### 3.1 ★ USB-transfer correlator: everything matches (false-positive flood)

**File:** `src/helios/core/correlator.py:275` — `detect_usb_transfers()`

Two compounding logic errors:

1. USB sessions are keyed by the `source_device` of **USB_CONNECT events** — which the registry analyzer attributes to the **host PC's device UUID** (the artifact is parsed *on* the host; `usb_history.py:221` passes the host's `device_id`). Host file-walk `FILE_CREATE` events use that **same** host device id (`pipeline.py:527`). So `event.source_device == usb_dev` matches **host** file creations, not USB ones. Genuine file creations on a USB drive (which get fresh random Device UUIDs) **never** match.
2. Sessions without a disconnect event are **unbounded** (`session_end is None → inside_window` is just `connect_time <= event_time`), so one USB stick plugged in 2020 makes the "session" cover all subsequent history.

**Reproduced** with a synthetic investigation (1 USB connect in 2020, no disconnect, 5,000 ordinary `C:\Users\...\*.docx` creations in 2026):

```
USB sessions: 1 (opened 2020-01-01, never closed)
Ordinary C:-drive file creates: 5000
Flagged as 'transferred to USB' with confidence HIGH: 5000
Sample: 'File transferred to USB HOST-UUID-1234 during active connection session.'
```

Every file ever created on the PC is reported as exfiltrated to USB with **HIGH confidence**. This alone makes the report worse than useless — it inverts the signal.

Related correlator flaws:

- `match_files_by_hash()` can only match when the identical file is present on both devices **at scan time** — deleted files recovered via `fls` have no hash, so the advertised "deleted on PC but exists on USB" detection cannot fire for the exact scenario it advertises.
- One `MovementChain` is created **per FILE_DELETE event**, so a bulk delete floods the chain list with one-entry "chains".

### 3.2 ★ Timestomping detector flags normal file copies

**File:** `src/helios/utils/ntfs.py:166`

```python
if si_modified and si_created and si_modified < si_created:
    return True
```

`$SI modified < $SI created` is the **normal** result of copying a file on NTFS (copy preserves the source's mtime; the destination gets a fresh creation time). Every copied file — i.e. most of what an exfiltration investigation looks at — is flagged as timestomped. The second check (`fn_created - si_created > 60s`) is the legitimate indicator; the first must go (or be gated behind FN-attribute confirmation).

### 3.3 ★ Event-log section of the report is always empty

**File:** `src/helios/reporting/report_generator.py:465`

```python
_EVTX_SOURCES = ("python-evtx", "Chainsaw", "Event Logs", "Security.evtx", "System.evtx")
event_log_rows = [r for r in all_event_rows if r["raw_source"] in _EVTX_SOURCES or r["type"] == "EVENT_LOG"]
```

But the event-log analyzer emits `raw_source="EVTX"` (`event_logs.py:127-189`) and **no** event ever has type `EVENT_LOG` (4624/4625→`APP_EXECUTE`, 6416→`USB_CONNECT`, 4663→`FILE_DELETE`). Reproduced: 3 real EVTX events → **0 rows** in the report's event-log section. So even where collection works, the report hides it.

### 3.4 Duplicate USB connection events

**File:** `src/helios/analyzers/usb_history.py`

The analyze path parses the collected registry artifact, and when the locked `SYSTEM` hive parse fails (always, on a live system), `_parse_live_winreg()` runs as a "fallback" — but the live parse was **also** already collected/run, so the same USBSTOR entries are emitted twice as duplicate `USB_CONNECT` events. (Also: `ContainerID` is treated as a **subkey** — `winreg.OpenKey(inst_k, "ContainerID")` — when it is actually a **value**; `InstallTime` actually lives under the `Properties` subkey. This whole branch is dead code that always falls back to the key's LastWriteTime, which is *not* the first-connect time.)

### 3.5 Buried alerts

`prefetch.py` (suspicious tools) and `shellbags.py` (disconnected-USB folders) write detections into `event.metadata["alert"]` instead of creating `Alert` objects — they never reach the alerts list, the alerts table, or the risk score.

---

## 4. Medium-Severity Bugs

| # | File:Line | Bug |
|---|-----------|-----|
| 4.1 | `menu.py:254` | `os.getlogin()` is evaluated **eagerly** as a default argument → `OSError: No such device or address` crash when run without a controlling terminal (SSH, service, scheduled task, some RDP sessions) |
| 4.2 | `menu.py:866` | `if matches or True:` — dead condition; the branch always executes |
| 4.3 | `cli.py:176` | `selected_drive_letters=drive_list if drive_list and not all_devices else None` — combining `--all-devices` with `--drives` **silently discards** the user's drive selection |
| 4.4 | `recycle_bin.py:127,198` | `device_id` set to the **drive letter string** (`"C:"`) instead of the Device UUID → recycle-bin events can't correlate with anything; attribution mismatch |
| 4.5 | `config.py` | The YAML `tool_paths:` section is parsed but **never merged** — user-configured tool locations are silently ignored |
| 4.6 | `file_type_verifier.py` | tar magic constant `b"\x7f\x5a\x4c\x53\x70"` is wrong (real tar magic is `ustar` at offset 257); `MZ` → always reported as `.exe` (false-positives on .dll/.scr/.com); **re-reads every walked file** → the whole drive is read twice |
| 4.7 | `suspicious_detector.py` | RULE-004 crypto-container check is **not gated** by `_rule_enabled` (fires even when disabled, including a naive `"veracrypt" in name` string match); BitLocker mapped to a bogus `.bt` extension |
| 4.8 | `usb_history.py` | `setupapi.dev.log` timestamps are **local time** but parsed as UTC (timezone-skewed timeline); hardcodes `C:\Windows` paths (breaks on non-C: system roots); contains mock `/tmp` paths in production code |
| 4.9 | `devices/detector.py` | `free_space=free_user` (quota-limited value) instead of `free_total`; USB-attached HDDs report `DRIVE_FIXED` → misclassified as local drives; `device_serial` never populated on Windows |
| 4.10 | `sleuthkit_adapter.py` | `run_fls(timeout=600)` — fls on a large multi-TB drive takes far longer → killed mid-scan, partial results presented as complete |
| 4.11 | `pipeline.py` | fls/sleuthkit module exceptions swallowed into `module_results`; reports default to `Path.cwd()/reports` (CWD-dependent, like the tools); `MAX_FILES_PER_DRIVE` documented as 2,000 (README), 500,000 (docstring), implemented as 5,000,000 |
| 4.12 | `exiftool_adapter.py` | batch results keyed by `str(Path(...))`; path-separator/relative-absolute mismatch on Windows lookups can silently drop matches |
| 4.13 | `hasher.py` | 8 KB read chunks (needlessly slow for full-drive hashing); returns `""` silently on read errors — downstream code can't distinguish "unhashable" from "not hashed" |
| 4.14 | `snapshot.py:170` | rename detection indexes `a_hashes` by hash → **duplicate-content files overwrite each other**, renames involving duplicates are mis-paired |

---

## 5. Design & Scalability Gaps vs. Autopsy

These are why, even with every bug fixed, Helios won't feel like Autopsy:

1. **Everything lives in memory as Python lists.** `pipeline._run_walk` builds `file_records` + up to 2 events per file for up to **5,000,000 files per drive**, then `report_generator.all_event_rows` materializes a second full uncapped copy for templating. A real drive means tens of millions of objects — expect multi-GB RAM and hours of runtime. Autopsy uses an embedded database (SQLite/PostgreSQL) with indexed queries; Helios has no persistence layer at all.
2. **Full-drive re-reads.** The walk hashes every file ≤ 500 MB; `file_type_verifier` then opens and re-reads every file again; snapshot/diff hashes again. Several full passes over the disk per run.
3. **No carving / no unallocated-space analysis.** Deleted-file "recovery" is `fls` deleted-entry listing (metadata only) — no content recovery, no file carving, no unallocated blocks. Autopsy's headline features simply don't exist here.
4. **No keyword-search cap in CLI mode** (`cli.py` keyword search walks without the 2,000-file menu cap) — unbounded runtime.
5. **Live-system blind spots without VSS.** Locked hives (SYSTEM, NTUSER.DAT, UsrClass.dat of the active user) and locked event logs all fail on the live machine; there is no Volume Shadow Copy fallback anywhere. Autopsy sidesteps this by analyzing images.
6. **Single 600 s timeout** for `fls` regardless of drive size (4.10).
7. **Timezone hygiene:** FILETIME, setupapi local time, and `st_*` times are mixed; only some paths normalize to UTC.

---

## 6. Packaging, Tests & Repo Hygiene

1. **`pyproject.toml` vs `requirements.txt` skew** (§2.7): also `pandas`, `networkx`, `python-magic`, `inquirerpy` are declared in requirements but barely/never used — bloat on one side, missing critical deps on the other.
2. **`helios.spec` references `src/helios/demo_data/**`**, which does not exist in the repo — PyInstaller builds break or silently omit data. Sigma rules are bundled under `tools/` but looked up at bundle root (§2.5).
3. **Failing test:** `tests/test_tool_wiring.py::test_bundled_tools_layout` asserts bundled MFTECmd.exe **must be absent** ("Deleted tool bundles must stay deleted") — yet the repo bundles it. The repo contradicts its own test; CI cannot be green.
4. **The test suite teaches the bugs to pass:** mock EZ CSVs use prefix-first filenames and the wrong column names, so 102 tests pass while production integrations are broken. **Add integration tests that execute the real bundled binaries on tiny fixtures** — that one test would have caught bugs 2.1–2.3.
5. Ruff (F-rules) is clean; `mypy` coverage is cosmetic next to the above.

---

## 7. Prioritized Fix List

**P0 — makes results appear at all:**
1. Fix EZ CSV discovery: pass `--csvf` everywhere, or glob `*{Tool}*`; reject stale CSVs (`ez_tools_adapter.py:148`).
2. Fix SBECmd/LECmd/JLECmd column names; use tolerant multi-name column lookup (`shellbags.py`, `lnk_jumplists.py`).
3. Fix Prefetch: XPRESS-decompress `MAM\x04`, accept `SCCA` (`prefetch.py:215`).
4. Anchor tool resolution at the package, not CWD; WARN loudly when a tool is missing (`base.py:170`).
5. wevtutil fallback: pass log **name** not file path; add VSS/raw-read fallback for locked logs (`event_logs.py:347`).
6. Sigma rules path → `get_bundle_root() / "tools" / "sigma_rules"` (`event_logs.py:225`).
7. Add `python-registry`, `python-evtx` to `pyproject.toml` (and the .bat).

**P1 — makes results trustworthy:**
8. Rewrite `detect_usb_transfers()`: sessions keyed by real USB device id (from USBSTOR serial → correlatable identifier), bounded by disconnect with a sane max window, match only events whose device is the USB device, downgrade inference to MEDIUM/LOW (`correlator.py:275`).
9. Remove `si_modified < si_created` timestomp heuristic; require SI/FN divergence (`ntfs.py:166`).
10. Emit real `Alert` objects from prefetch/shellbags instead of metadata stuffing.
11. Fix `_EVTX_SOURCES` to include `"EVTX"` or tag rows by module (`report_generator.py:465`).
12. De-duplicate USB parsing paths; fix ContainerID/Properties registry reads; convert setupapi times to UTC (`usb_history.py`).

**P2 — quality:**
13. `menu.py` getlogin/try-except; remove `or True`; fix `--all-devices` + `--drives` interaction.
14. Per-drive MFTECmd output names; VSS fallback for $MFT/$UsnJrnl; verify bundled MFTECmd ≥ 6.0.
15. Honor `tool_paths:` config; fix tar magic & MZ mapping; stop re-reading files; cap CLI keyword search.
16. Recycle-bin `device_id` → real device UUID; per-4625 alert aggregation; drive-type detection via `DeviceIoControl`/`GetVolumeInformation` + bus type.
17. Move to SQLite-backed event store; stream template rows; single-pass collection.

---

## 8. Appendix — Verification Performed

- **Dynamic repro 1 (correlator flood):** synthetic investigation → 5,000/5,000 host file-creates flagged as USB exfiltration, HIGH confidence. *(§3.1)*
- **Dynamic repro 2 (prefetch):** `MAM\x04` and `SCCA` fixtures → both return `None`. *(§2.3)*
- **Dynamic repro 3 (report):** real `raw_source="EVTX"` events → 0 rows through the report filter. *(§3.3)*
- **Dynamic repro 4 (EZ glob):** real filename `20260819103022_LECmd_Output.csv` vs glob `LECmd*.csv` → no match. *(§2.1)*
- **Tool-output verification:** LECmd output naming from official `Program.cs` source; LECmd/JLECmd/SBECmd column names cross-checked against the EZ Tools manual and multiple DFIR write-ups; MFTECmd v6.0 locked-file support confirmed from release notes.
- **Test run:** `pytest` → 102 passed, 1 failed (stale MFTECmd bundle assertion). `ruff` F-rules clean.

*Bottom line: Helios's architecture (profiles → adapters → analyzers → correlator → Jinja reports) is reasonable, but the integration layer with its external tools was clearly never run end-to-end against real tool output on a live Windows machine. Admin rights can't fix filename globs, column names, or a compressed binary format — which is why you see empty and noisy results where Autopsy, reading the same artifacts from an image with mature parsers, delivers.*
