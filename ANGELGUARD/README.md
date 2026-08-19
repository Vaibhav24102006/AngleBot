# ANGELGUARD

A Windows desktop security decision-support tool. It watches a Downloads
folder for new executables, statically analyzes each one (no execution,
ever), checks it against threat-intelligence services when configured,
optionally asks an LLM to explain the result in plain language, and warns
the user — with the same numbers and reasons everywhere: the popup, the
detail view, the history list, and the database.

ANGELGUARD **explains and warns**. It does not delete, quarantine, or
execute anything it analyzes.

## Architecture

```
File Monitor (monitor/monitor_service.py)
    |  detects, deduplicates, waits out locked/incomplete files
    v
Analysis Pipeline (pipeline/analysis_pipeline.py)
    |
    +-- Static Analysis        (analysis/static_analyzer.py)
    +-- Risk Engine             (decision/risk_evaluator.py)
    +-- Threat Intelligence     (threat_intel/threat_intel_client.py)   [optional]
    +-- Intelligence Aggregator (intelligence/intelligence_aggregator.py)
    +-- AI Explanation          (ai/ai_explainer.py)                    [optional]
    v
Canonical final_event
    +-- Persistence   (event_logging/admin_event_logger.py -> data/angelguard_events.db)
    +-- Warning UI    (ui/employee_guidance.py)
    +-- History / Details UI (ui/app_window.py, ui/history_panel.py, ui/analysis_details.py)
```

Every consumer of an analysis result — the warning popup, the details
view, the history list, and the database — reads the exact same
`final_event` object. Nothing computes its own risk. Threat intelligence
or AI being unavailable is always shown as **unknown**, never as "safe."

Two SQLite databases exist, deliberately separate: `data/angelguard_events.db`
(the MVP's own analysis history, described above) and `data/guardian_logs.db`
(a separate, **not currently wired into the MVP**, Phase 7 subsystem — process/
network monitoring and system snapshots, launched only via the standalone
`ui/main_window.py` entry point, never from `app/main.py`). See
`DECISIONS.md` (Step 5 audit) for the full reasoning.

The complete history of every architectural decision, why it was made, and
what it deliberately defers is in **`DECISIONS.md`**. Known limitations,
the measured performance baseline, and the full adversarial-testing
failure-mode matrix are in **`RELIABILITY.md`**.

## Requirements

- Windows (PyQt5 GUI, `pefile` PE parsing, and the monitored path all
  assume Windows)
- Python 3.12 (developed and tested against 3.12.7)

## Installation

```powershell
cd ANGELGUARD
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
```

Optionally, copy `.env.example` to `.env` and fill in any of the three
API keys (`MB_API_KEY`, `VT_API_KEY`, `OPENAI_API_KEY`). **All three are
optional** — ANGELGUARD degrades gracefully with none of them configured
(threat intelligence and AI explanation both report as unavailable rather
than failing or fabricating a result).

## Running

```powershell
python app/main.py              # full GUI: main window + warning popups
python app/main.py --headless   # console output + warning popups only, no main window
```

Either way, ANGELGUARD watches `~\Downloads` for new `.exe` files. Press
Ctrl+C to stop.

`ui/main_window.py` is a **separate**, not-yet-wired-into-the-MVP entry
point for Phase 7 (process/network monitoring, system snapshots) — it is
not part of the analysis pipeline above and is not launched by
`app/main.py`.

## Testing

```powershell
cd ANGELGUARD
pytest
```

No test requires network access, a real API key, or the real
`~\Downloads` folder or `data/angelguard_events.db` — every test uses a
temporary database and/or `tmp_path` fixtures. As of the last full run:
**188 passed, 0 failed, 0 skipped** (see `RELIABILITY.md` for the full
validation history).

## Project layout

| Path | Role |
|---|---|
| `app/main.py` | The one user-facing entry point |
| `monitor/` | Filesystem watching, dedup, retry |
| `analysis/` | Static PE analysis (hashing, imports, entropy, strings) |
| `decision/` | Deterministic risk scoring |
| `threat_intel/` | VirusTotal / MalwareBazaar lookups |
| `intelligence/` | Merges static + risk + threat-intel into one payload |
| `ai/` | Optional LLM-generated plain-language explanation |
| `pipeline/` | The single orchestrator tying all of the above together |
| `event_logging/` | Canonical persistence (`AdminEventLogger`) |
| `ui/` | Warning popup, analysis details, history, main window |
| `config/` | `.env`-backed settings (API keys, size limits) |
| `tests/` | Full automated test suite (pytest) |
| `behavior/`, `network/`, `correlation/`, `dynamic/`, `ml/` | Phase 7 / future work — present in the repo, not part of the MVP pipeline |

## Known limitations

See `RELIABILITY.md` for the complete failure-mode matrix. Notable ones:

- Files larger than `MAX_ANALYSIS_FILE_SIZE_BYTES` (default 50MB) are not
  fully analyzed — reported as `skipped:oversized`, never as safe.
- A file that's readable but still being actively written (no exclusive
  lock held by the writer) can be analyzed mid-write, which is always
  *safe* (never crashes, never claims clean) but can be *inaccurate* for
  a large, slow download.
- MalwareBazaar and VirusTotal failures are indistinguishable from a
  genuine "not found" on that specific provider when the other provider's
  call succeeds (both still correctly degrade to "unknown" if both fail).
- History refresh in the GUI is polling-based (~3s), not push-based.
