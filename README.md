# Helios — Data Movement Forensics

**Answers the question: "Where did the data go?"**

Helios is a Python CLI forensic suite that tracks file movement, deletion, and transfer across **live** devices (PC, Laptop, USB drives, Android via USB debugging). It reconstructs data lifecycles, detects exfiltration, and packages everything into clean, court-friendly HTML reports with a full chain of custody.

> **Note:** Helios does NOT clone disk images. It works directly on live, mounted devices and is read-only against evidence sources.

---

## Quick Start

### Option A — Windows one-click

| Script | Purpose |
| --- | --- |
| `run_helios.bat` | Install dependencies (if needed) and launch the interactive menu |
| `build_exe.bat` | Build a standalone `dist\helios.exe` via PyInstaller |
| `test_exe.bat` | Smoke-test the built exe with demo data |

### Option B — Python / pip

```bash
# from repo root
python -m venv venv
venv\Scripts\activate            # Windows
venv/bin/activate                # Linux/macOS
pip install -r requirements.txt  # or: pip install -e .

helios --help                    # click CLI entrypoint
helios menu                      # interactive wizard
helios demo                      # run the demo investigation -> reports/
helios investigate -c "Case-001" --drives C: --interactive
helios keyword-search -k "password" -p C:\case\evidence -o ./reports
```

---

## Investigation Profiles

Helios ships four scan profiles. Each profile gates which analysis modules actually run, and **each produces its own focused HTML report template**:

| # | Profile | Focus | Report template |
| --- | --- | --- | --- |
| 1 | `exfiltration` | USB transfers, deletions, LNK/JumpLists, cross-device hash matching, suspicious files, deleted-file recovery | `exfiltration_report.html.j2` |
| 2 | `employee_exit` | USB activity, recent file access (LNK), deletions, ShellBags, suspicious files | `employee_exit_report.html.j2` |
| 3 | `incident_response` | Prefetch execution, event logs, ShellBags, suspicious files, deletions (no USB/cross-device) | `incident_response_report.html.j2` |
| 4 | `full` | Every module enabled | `full_report.html.j2` |

Profiles are defined in `config/investigation_profiles.yaml`. The report's "Module Execution" card shows exactly which modules ran, were skipped, or failed — nothing is fabricated.

---

## Core Features

- **Live filesystem walk** with real SHA-256 hashing (2,000 files/drive cap, warned when hit)
- **USB history** from Windows registry (`USBSTOR` / `MountPoints2`)
- **Recycle Bin parsing** (RBCmd) for deletions; `$I`-based
- **LNK / JumpList access** (LECmd / JLECmd)
- **Prefetch execution** (PECmd) with built-in fallback
- **Windows Event Logs** (EVTX + Sigma rules)
- **ShellBags** folder history (SBECmd)
- **SleuthKit deleted-file recovery** (`fls`/`fsstat`, raw disk, requires admin)
- **Suspicious file heuristics** — 13 rules (see `config/suspicious_rules.yaml`)
- **File-type verification** via magic bytes + batched ExifTool
- **Cross-device correlation** — hash-based movement chains, exfiltration pattern detection
- **Snapshot manager** — hash state at two points in time, diff for added/modified/deleted
- **Keyword search** — exfiltration keyword triage (name/path + text content, size/line/hit caps), presets (credentials, financial, confidential, PII) + custom; produces its own HTML report + JSON hit export
- **Evidence packaging** — JSON + CSV exports, tamper-evident ZIP with SHA-256 integrity
- **Settings screen** — shows the exact status of every tool Helios uses (ACTIVE / NOT FOUND)

---

## Outputs

Reports are written to `./reports` by default:

- `helios_report_{CASE}_{PROFILE}.html` — profile-specific self-contained HTML report
- Exports: `investigation.json`, `events.csv`, `alerts.csv`, `files.csv`, `correlations.csv`
- `chain_of_custody.json` — every tool action, timestamped

Each report includes: metric cards (clickable, jump to sections), charts, key findings with artifact paths, deleted-files with an honest **Shift+Delete limitation note**, a real event log table, alerts with artifact-path column, scanned devices, module execution log, and chain of custody.

---

## Project Layout

```
config/                        YAML: profiles, suspicious rules, device profiles
src/helios/
  cli.py                       click entrypoints (menu / investigate / demo / keyword-search)
  menu.py                      interactive wizard + utility menus (snapshot, keyword, USB quick scan)
  models.py                    DataEvent, Investigation, FileRecord, Alert, Device, enums...
  analyzers/                   per-artifact analyzers (lnk, prefetch, event_logs, recycle_bin,
                               shellbags, usb_history, suspicious_detector, file_type_verifier)
  adapters/                    wrappers for external tools (ez_tools, sleuthkit, chainsaw, exiftool)
  core/                        correlator, hasher, investigation profiles, keyword search
  devices/                     drive detection, mount mapping
  evidence/                    chain-of-custody log
  reporting/                   report_generator, chart_builder, table_builder, templates/
  demo.py                      demo investigation + pipeline
  pipeline.py                   run_investigation_pipeline(): single gated execution path
tests/                         72 pytest tests
tools/                         bundled forensic binaries (EZ tools, adb, chainsaw, exiftool, fls/fsstat + DLLs)
```

---

## Development

```bash
venv/bin/python -m pytest -q                       # 72 tests
venv/bin/mypy src/helios                           # strict type checks
venv/bin/ruff check --select F src/helios tests    # lint (F rules)
```

Rebuild the exe:

```bash
venv/bin/pyinstaller --clean --noconfirm helios.spec   # -> dist/helios.exe
```

---

## For AI Agents

If you are an AI agent working on this repository, read **`AGENTS.md`** first — it contains the full engineering context, hard guardrails, and verification gates.

---

## License

MIT — see [LICENSE](LICENSE). External forensic tools in `tools/` are bundled binaries of their respective open-source projects (see `TOOLS_REFERENCE.md`).
