# AGENTS.md — AI Agent Engineering Guide for Helios

> **Read this before modifying anything.** This file is the single source of truth for how Helios works today, what the guardrails are, and how to prove your work. It is updated as the codebase evolves — keep it current.

---

## 1. What Helios Is

Helios is a Python 3.11+ **local CLI** forensic suite that answers *"Where did the data go?"* across **live** devices (PC, Laptop, USB drives, Android via ADB). It walks mounted filesystems, parses Windows artifacts, correlates events by SHA-256 hash, detects exfiltration/deletion patterns, and renders self-contained HTML reports with chain-of-custody evidence.

- Read-only against evidence. Never modifies source devices.
- No web server. No async. No disk imaging. No dark-hacker report themes.
- Reports are static HTML + JSON/CSV exports + a tamper-evident ZIP.

## 2. Current State (verified 2026-08-18)

- **Tests:** 97 passing (`venv/bin/python -m pytest -q`)
- **Type check:** mypy clean across 58 files (`venv/bin/mypy src/helios tests`)
- **Lint:** ruff clean (`venv/bin/ruff check --select F src/helios tests`)
- **Windows exe:** buildable from `helios.spec` -> `dist/helios.exe` (PyInstaller)
- **Distro zip:** `/home/ahmad/Forensics/helios-v0.1.0-final.zip` (1111 files, caches excluded)
- **Report templates:** 4 profile-specific templates + keyword-search report + shared base/macros
- **Suspicious rules:** 13 rules in `config/suspicious_rules.yaml` (RULE-001 ... RULE-013)

## 3. Repository Layout

```
config/                    investigation_profiles.yaml, suspicious_rules.yaml, device_profiles.yaml
src/helios/
  cli.py                   click entrypoints: menu, drives, devices, investigate, demo, keyword-search
  menu.py                  interactive wizard, utility menus (settings, keyword search, exports)
  pipeline.py              run_investigation_pipeline(): single gated execution path
  models.py                DataEvent, FileRecord, Investigation, Alert, Device, DriveInfo,
                           enums (EventType, DeviceType, Severity, Confidence...)
  analyzers/               artifact parsers → DataEvent + Alert
    usb_history.py         registry USBSTOR (SYSTEM) + MountPoints2 (SOFTWARE) + setupapi.dev.log
    recycle_bin.py         RBCmd $I parsing
    lnk_jumplists.py       LECmd/JLECmd access events
    prefetch.py            PECmd + builtin fallback
    event_logs.py          EVTX (python-evtx) + Chainsaw/Sigma → real Alert objects
    shellbags.py           SBECmd
    suspicious_detector.py heuristic rules RULE-001..013 (YAML-driven)
    file_type_verifier.py  magic-byte + batched ExifTool checks
  adapters/                external-tool wrappers (subprocess, list args, never shell=True)
    ez_tools_adapter.py    LECmd/PECmd/RBCmd/SBECmd/JLECmd wrapper (batched, 120s timeout, fail-closed)
    sleuthkit_adapter.py   fls/fsstat + bundled win32 DLLs + SetErrorMode suppression
    chainsaw_adapter.py    Sigma hunts (output JSON always rewritten, parsed only on rc 0)
    exiftool_adapter.py    batched deep verification
  core/                    correlator.py, hasher.py, investigation.py (ProfileManager, fail-closed),
                           snapshot.py, keyword_search.py
  devices/                 detector.py (drive detection, lsblk + /proc/mounts fallback)
  evidence/                chain_of_custody.py (ChainOfCustodyLog)
  reporting/               report_generator.py (incl. generate_keyword_report), chart_builder.py,
                           table_builder.py, templates/{_base,_macros,full,exfiltration,
                           employee_exit,incident_response}_report.html.j2,
                           keyword_search_report.html.j2
  demo.py                  demo investigation + run_demo_pipeline
tools/                     bundled binaries: EZ tools (LECmd/JLECmd/PECmd/RBCmd/SBECmd), adb,
                           chainsaw + sigma_rules, exiftool, fls/fsstat + TSK DLLs, linux64 libs
tests/                     65 tests, fixture-driven, no live external tools
AUDIT_REPORT.md            append-only work log + fix history (read before starting!)
TOOLS_REFERENCE.md         external tools and licensing
```

## 4. Architecture Essentials

### 4.1 Pipeline & profile gating (pipeline.py + menu.py)
- `run_investigation_pipeline()` (pipeline.py) is the **single execution path**: drive detection, device mapping, live walk (SHA-256 hashes), 10 gated modules, chain of custody, profile HTML report. Both the wizard (`menu_new_investigation`) and `helios investigate` call it.
- `ProfileManager` (core/investigation.py) + `config/investigation_profiles.yaml` decide module gates. Unknown profile names **fail closed** (all modules disabled).
- Every module runs through `_run_module(key, label, events, alerts, fn)` which appends to `investigation.module_results` with status `ran | failed | disabled` and honest event/alert counts. **The report shows this log; never fake it.**
- Drive mapping: `drive_devices` maps drive letters to `Device` objects so removable media files are attributed to a USB device (required for cross-device correlation).
- Keyword search: `core/keyword_search.py` triages a drive/folder for exfiltration keywords (name/path always, text-like content ≤10 MB / ≤500 lines / ≤20 hits per file). Results render through `generate_keyword_report` + JSON export (`helios keyword-search` CLI command, menu option 5).

### 4.2 Report generation (reporting/)
- `ReportGenerator.generate_html_report()` picks the template via `_resolve_template(profile_name)` — each profile gets a genuinely different report.
- `_profile_sections(module_results, profile_name)` gates tabs/panels/metrics from the **real** module log.
- `build_movement_rows()` builds transfers vs deletions rows from correlations + events.
- `_build_event_rows()` renders the event-log table (newest first, capped 500).
- Templates: `_base.html.j2` (layout/CSS/JS) + `_macros.html.j2` (cards/tables) imported `with context`; profile templates extend base and define their own tabs/panels/chart list.
- Key Findings show artifact paths; alerts table has an "Artifact Path" column.
- Deleted Files sections carry an honest **Shift+Delete limitation note** (no `$I` entry is ever created; only raw-disk `fls` can see it).

### 4.3 Correlation (core/correlator.py)
- O(N) implementations: `disconnects_by_device`, `deletions_by_name`, `edge_map` dicts.
- `detect_usb_transfers`, `detect_exfiltration_patterns`, `match_files_by_hash`, `build_data_movement_graph`.

### 4.4 External tool safety (adapters/)
- All subprocess calls: list args, `shell=False`, timeouts (120s), never interpolate shell strings.
- `sleuthkit_adapter` bundles 57 official TSK win32 DLLs in `tools/`; on Windows it suppresses error dialogs (`SetErrorMode 0x8001`) — removing/renaming a bundled DLL breaks the exe with 0xC0000135.
- Analyzers must return `[]` gracefully when tools are missing (no popups, no hangs).

## 5. Hard Guardrails

1. **Never fabricate data.** No invented events, alerts, hashes, timestamps, or recovery claims. If a module can't run (no admin, missing tool), record `failed` with the real error and let the report show it.
2. **Report design rule:** clean corporate dashboard. White backgrounds, soft blue accents, sans-serif. **Never dark hacker themes** (see `_base.html.j2` CSS).
3. **No async.** Synchronous only.
4. **No web server.** Static HTML only. No Flask/Django/FastAPI.
5. **Typing:** strict type hints on every function.
6. **CLI:** `click`; UI: `rich` only.
7. **External tools:** never reimplement forensic parsing when a bundled tool exists (LECmd, fls, PECmd...). Use the adapter pattern.
8. **Universal event type:** every artifact maps to `DataEvent` for timeline correlation.
9. **Hash-based correlation:** cross-device tracking uses SHA-256.
10. **Keep the exe buildable** — `helios.spec` must list every new runtime file (templates, tools, YAML). If you add a template, add it to the spec's `datas`.
11. **Don't delete `.bat` files** (`run_helios.bat`, `build_exe.bat`, `test_exe.bat`) — they are the Windows user entrypoints.
12. **Log your work:** append a dated "Fix Log" section to `AUDIT_REPORT.md` after any completed change set.

## 6. Verification Gates (run all three before finishing)

```bash
venv/bin/python -m pytest -q          # must pass (currently 65)
venv/bin/mypy src/helios              # must be clean
venv/bin/ruff check --select F src/helios tests   # must be clean
```

After code changes that affect the packaged app:

```bash
venv/bin/pyinstaller --clean --noconfirm helios.spec   # -> dist/helios.exe
./dist/helios.exe demo                                  # smoke test
```

Zip rebuild (if distributing):

```bash
zip -r /home/ahmad/Forensics/helios-v0.1.0-final.zip . \
  -x "*.git*" "*__pycache__*" "*.pyc" "build/*" "*.egg-info*" \
  "*/.cache/*" ".pytest_cache/*" ".ruff_cache/*" ".mypy_cache/*" \
  "venv/*" ".venv/*"
```

## 7. Testing Conventions

- pytest, fixture-driven. **Never run live external binaries in tests** — mock via `monkeypatch` or fixture files.
- New analyzer/adapter → unit tests required (see `tests/test_analyzers.py`, `tests/test_tool_wiring.py`).
- Report changes → add render tests in `tests/test_core.py` (e.g. `test_profile_report_renders_distinct_content`) or extend `tests/test_demo_e2e.py`.
- Keep the demo self-sufficient: `helios demo` must produce a valid report + exports + ZIP.

## 8. Common Tasks → Where to Look

| Task | File(s) |
| --- | --- |
| Add/modify a suspicious rule | `suspicious_detector.py` + `config/suspicious_rules.yaml` + tests |
| Change report layout | `reporting/templates/*.j2`, `report_generator.py` context |
| Add a new analyzer | new file in `analyzers/` (extends `AnalyzerBase`), wire in `menu.py` + profile yaml + tests |
| Fix wizard flow / pipeline | `menu.py`, `pipeline.py` |
| Fix correlation | `core/correlator.py` |
| Packaging/exe issues | `helios.spec`, `tools/` bundle, `adapters/sleuthkit_adapter.py` |
| Chain of custody | `evidence/chain_of_custody.py` |

## 9. Known Limitations (do not "fix" by inventing data)

- **Shift+Delete** bypasses Recycle Bin → invisible to `$I` parsing; only raw-disk `fls` (admin) can see it.
- **Live walk caps at 500,000 files/drive** — wizard warns when the cap is hit.
- **Raw-disk recovery** needs an elevated/admin terminal; without it the SleuthKit module fails cleanly.
- **MFT/USN modules** require MFTECmd (Windows .NET tool); they fail gracefully when unavailable.
- Deleted files can only be *listed* if a recoverable artifact exists — no fabricated recovery claims.
