# ANGELGUARD — Step 7 Reliability & Adversarial Validation

Produced during Step 7 ("try to break ANGELGUARD without executing malicious
files, and make sure it fails safely, predictably, and observably"). This
document is the failure-mode matrix, the P0–P3 findings, the measured
performance baseline, and the manual destructive-input simulation results.
Judgment calls and the resulting code changes are logged, as usual, in
`DECISIONS.md` (Step 7 section) — this file is the reference table and
evidence, not the decision log.

No malware was used or executed anywhere in this validation. All adversarial
inputs are synthetic (hand-built PE fixtures, empty files, malformed data) or
deterministic mocks of external services.

## 1. Failure-mode matrix

Legend: **Behavior** = what actually happens (verified by a test or the
manual demonstration in §4, not assumed). **Sev** = P0/P1/P2/P3 per the
task's own classification. **Status** = Fixed / Tested-already-correct /
Documented-only.

### File monitoring (`monitor/monitor_service.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| File created | Detected, analyzed once | — | Tested (`test_monitor_service.py`) |
| File modified (same content) | Deduped against the created event | — | Tested |
| File moved into place (`.crdownload` → `.exe`) | Deduped alongside created/modified | — | Tested |
| Duplicate events for one physical write | Collapsed to exactly one analysis | — | Tested |
| **Same path, genuinely new content later** | **Was: silently never re-analyzed for the process lifetime.** Now: re-analyzed (content signature = `(size, mtime)`, not path alone) | **P1** | **Fixed** — `monitor_service.py`, `test_monitor_service.py` |
| File deleted before it becomes accessible | Silently skipped, no crash, no dedup-cache poisoning | — | Tested |
| File renamed during analysis | `on_moved` re-fires `_process_event` on the new path; treated as a fresh detection | — | Tested (via burst-dedup test) |
| File locked / still being written | Retried up to 10× at 0.5s intervals after an initial 1s settle delay; gives up gracefully if never released | — | Tested |
| Non-PE / non-`.exe` file | Ignored entirely, no analysis attempted | — | Tested |
| Extremely large file | Was: no bound — see Static Analysis row below (same root cause) | P1 | Fixed (pipeline-level size check) |
| Directory event | Ignored | — | Tested |

### Static analysis (`analysis/static_analyzer.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Empty file | `pefile.PEFormatError` caught → `error="Not a valid PE file"`, `file_size=0` — risk evaluator scores 70/HIGH_RISK | — | Tested-already-correct; live-demonstrated §4 |
| Truncated / malformed PE | `pefile.PEFormatError` caught gracefully, no crash | — | Tested-already-correct (Step 2); live-demonstrated §4 |
| Invalid header | Same as above | — | Tested-already-correct |
| Unusual section count (0, 1, many) | No special-casing needed — iterates `pe.sections`, empty is fine | — | Tested-already-correct |
| High entropy | Flagged correctly (>7.5 threshold); `section.get_entropy()` preferred over the module's own slower `calculate_entropy()` when available | — | Tested-already-correct |
| Huge string count | Extraction is O(n) pure-Python byte iteration — see perf note below | P2 | Documented, not fixed |
| Unicode / long / spaced filename | No crash; filename round-trips correctly through the whole pipeline and UI | — | Tested (`test_pipeline_adversarial_inputs.py`) |
| Path > 260 chars | No crash (verified via the `\\?\` extended-length form; a plain-`os.mkdir` limitation in test fixture setup is a Windows OS quirk, not an ANGELGUARD bug) | — | Tested |
| Permission failure reading the file | Caught by the pipeline's outer `except Exception` around `analyze_file()`, or by `static_analyzer`'s own `PermissionError` handler | — | Tested-already-correct (Step 4) |
| **File > ~a few tens of MB** | **Was: reads the whole file into memory; entropy calc is O(256×n) per section via repeated `bytes.count()`. Measured ~0.42s/MB, memory delta ≈ file size 1:1. A 200MB+ legitimate installer would block the single watchdog dispatch thread for well over a minute.** | **P1** | **Fixed** — pipeline-level `MAX_ANALYSIS_FILE_SIZE_BYTES` (default 50MB) skips full analysis with a controlled `"skipped:oversized"` result instead. The analyzer itself is untouched — see DECISIONS.md Step 7 for why a pipeline-level guard was chosen over optimizing the analyzer. |

### Risk engine (`decision/risk_evaluator.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Missing fields (empty dict) | `.get(key, default)` throughout — degrades to a low, explainable score, no crash | — | Tested (`test_pipeline_adversarial_inputs.py`) |
| Empty lists / zero values | Handled, no crash | — | Tested |
| Extreme values (very large / negative) | No crash; score explicitly capped at 100 | — | Tested |
| Contradictory indicators (invalid-PE flag + otherwise-clean signals) | Produces a stable, explainable combined score — not "either/or" logic that could hide one signal | — | Tested |
| **Wrong-typed values** (e.g. a string where an int is expected) | Raises `TypeError` — `evaluate_risk()` itself is not type-defensive | **P2** | **Documented, not fixed** — `static_analyzer.py` is its only real producer and is well-typed by construction; the pipeline's own `except Exception` around risk evaluation already catches this one layer up (verified: `analysis_status` becomes `"error:risk_evaluation"`, not a crash) |
| Analyzer failure (any of the above) | Caught by `AnalysisPipeline`'s per-stage `except Exception`, never propagates | — | Tested-already-correct (Step 4) |

### Threat intelligence (`threat_intel/threat_intel_client.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Success | Correctly parsed and mapped | — | Tested (`test_threat_intel_chaos.py`, new) |
| Timeout | Returns `{"status": "unknown"}`, never raises | — | Tested |
| Connection failure | Same | — | Tested |
| HTTP error (4xx/5xx incl. rate-limit-style) | Same | — | Tested |
| Malformed JSON | Same (`ValueError` caught) | — | Tested |
| Missing expected fields in an otherwise-`ok` response | Falls back to `"Unknown"` family, no fabricated data | — | Tested |
| API key absent | VT: skips the call entirely, returns unknown, no network attempt. MB: still calls (see below) | — | Tested |
| **Partial provider response** (one of MB/VT fails, the other succeeds) | Combined result surfaces the working side correctly; **the failed side is indistinguishable from a genuine negative** (e.g. MB timing out looks identical to "MB genuinely found no match") | **P2** | **Documented, not fixed** — pre-existing ambiguity, not a Step 7 regression; fixing it would mean changing `get_reputation()`'s return shape, out of this step's scope |
| `check_malwarebazaar()` calls live even with no `MB_API_KEY` set | Confirmed still true (returns a real 401 in the manual demo, §4) | P2 | Documented (already noted in DECISIONS.md Step 4 D19) — unchanged |
| **No automated test coverage existed for this module at all before this step** | `tests/test_threat_intel.py` was a manual CLI script with zero `test_`-prefixed functions — pytest silently collected nothing from it, and it would make a real network call if run directly | **P1** | **Fixed** — renamed to `tests/manual_threat_intel_check.py` (matching the D9 convention already established for `analysis/manual_*_check.py`), replaced with 20 deterministic mocked tests |

### AI explanation (`ai/ai_explainer.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Success | Parsed and normalized correctly | — | Tested (`test_ai_explainer_chaos.py`, new) |
| API unavailable (no key / package missing) | Fallback response, never `None` for a SUSPICIOUS/HIGH_RISK file | — | Tested-already-correct; now also mocked-deterministic |
| Timeout | Fallback response, no raise | — | Tested |
| Malformed / non-JSON response | Fallback response, no raise | — | Tested |
| Empty / `None` response content | Fallback response, no raise | — | Tested |
| Unexpected SDK exception | Fallback response, no raise | — | Tested |
| Response missing some (not all) JSON keys | Normalized with safe per-key defaults, not a crash | — | Tested |
| **Existing test could make a real network call on a machine with a real API key configured** | `test_ai_explainer.py::test_explainer_runs_on_suspicious_files` branches its assertions on `self.explainer.client` — harmless in this environment (no key set) but not deterministic in general | **P2** | **Documented, not fixed** — not touched, to avoid weakening an existing passing test outside this step's stated file list; the new `test_ai_explainer_chaos.py` provides the deterministic coverage instead |

### Persistence (`event_logging/admin_event_logger.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Database file missing | Created automatically (`_ensure_db_exists`) | — | Tested-already-correct (Step 5B) |
| Database directory missing | Created automatically (`os.makedirs(..., exist_ok=True)`) | — | Tested (`test_persistence_failure_modes.py`, new) |
| **Database file exists but is not a valid SQLite file** | Construction does not crash; `log_event()` returns `False` observably, never fabricates success | — | **Tested** (new — not previously verified against a real malformed file, only mocked) |
| **Real lock contention** (another connection holding `BEGIN EXCLUSIVE`) | With `busy_timeout=3000` (Step 6, D31): waits up to 3s, then fails observably (`False`) if still locked; succeeds if the lock releases within the window | — | **Tested against a real second SQLite connection**, not a mock |
| Disk/write failure | Caught by the existing `except sqlite3.Error`, returns `False` | — | Tested-already-correct (Step 4 D20) |
| Duplicate `event_id` | Idempotent upsert (last write wins), not a duplicate row | — | Tested-already-correct (Step 5B) |
| Invalid/incomplete payload | `.get()` throughout with sane defaults; missing `event_id` inserts as `NULL` (never collides with another `NULL`) | — | Tested-already-correct (Step 5B) |
| Interrupted write (process killed mid-`INSERT`) | Not independently tested — SQLite's own atomic-commit guarantee is relied upon rather than re-verified here | P3 | Documented, not tested (would require killing the process mid-syscall, disproportionate for this step) |

### UI (`ui/employee_guidance.py`, `ui/history_panel.py`, `ui/analysis_details.py`, `ui/app_window.py`)

| Input / scenario | Behavior | Sev | Status |
|---|---|---|---|
| Analysis completes while no dialog is open | `GuidanceController.trigger()` constructs and shows a new dialog on demand — nothing to be "closed" prematurely | — | Tested-already-correct (Step 6) |
| Repeated / multiple rapid alerts | Each gets its own `EmployeeGuidance` instance, tracked in `active_dialogs` to prevent GC; verified live with 5 rapid alerts in §4, no crash | — | Live-demonstrated §4 |
| Long / Unicode filename | Displayed correctly, no truncation crash | — | Tested |
| Missing explanation (AI unavailable) | "AI explanation unavailable." shown; deterministic `risk.reasons` still listed (Step 6 fix, D29) | — | Tested |
| Missing reputation (TI unknown) | "UNKNOWN — ... does NOT mean the file is safe" shown, never "clean" | — | Tested |
| Missing static-analysis fields | `AnalysisDetailsDialog` shows "Not available" per section rather than crashing on a missing key | — | Tested (via the `{}` static_analysis case in `_controlled_event`-derived events) |
| History with zero events | `list_events()` returns `[]`, table renders with 0 rows, no crash | — | Tested (implicit — every fresh-db test starts from zero rows before adding any) |
| History with many events | 20-file burst → 20 correctly distinct rows | — | Tested (`test_stress_rapid_events.py`) |
| Selected event disappearing (e.g. deleted between list and select) | Not applicable in the current architecture — events aren't deleted from the DB anywhere in the codebase; `get_event()` on a nonexistent id returns `None` cleanly (`HistoryPanel._open_selected` guards on this) | — | Tested (`test_get_event_returns_none_for_unknown_id`, Step 5B) |
| History database unavailable at GUI construction time | `AdminEventLogger.__init__` already handles a malformed/inaccessible db without raising (see Persistence row); `HistoryPanel.refresh()` would then just get an empty/error-tolerant result from `list_events()` — not independently re-tested here since it inherits the same guarantee | P3 | Documented (relies on the Persistence-row behavior above) |

## 2. File-system race conditions (§3 of the task)

Three race scenarios were specifically requested and are now covered by
`tests/test_monitor_service.py`:

- **File appears → analysis begins → file disappears**: handled at two
  independent layers — the monitor's own accessibility retry loop
  (`FileNotFoundError` → silent return, no cache poisoning) and the
  pipeline's `os.path.isfile()` check plus `static_analyzer`'s own
  `FileNotFoundError` handler if the file vanishes even later, mid-read.
- **File appears → still being written → analysis starts too early**: the
  1s settle delay + up to 5s of `PermissionError` retry already existed
  (Step 1); this step didn't need to change that logic, only proved it
  behaves as documented (`TestLockedFileRetry`). **Known residual limit**:
  a file that's readable-but-still-growing (no exclusive lock held by the
  writer) can be read mid-write, producing a "truncated/invalid PE" result
  that's *safe* (never crashes, never claims clean) but potentially
  *inaccurate* for a slow large download. Classified **P2** (accuracy risk,
  not a reliability/crash risk) — documented, not fixed, since fixing it
  would mean guessing at "is this file still growing," which is inherently
  heuristic and out of this step's scope.
- **created → modified → moved for the same file**: fixed to dedupe
  correctly (§1 P1 fix) while still allowing a genuinely new file at the
  same path to be analyzed.

## 3. Performance baseline (measured, not estimated)

All numbers measured directly on this development machine (`perf_counter`,
averaged over 20 runs per fixture except where noted); see
`tests/test_performance_baseline.py` for the permanent regression guards
(loose bounds — hundreds of ms, not tight micro-benchmarks) and
`tests/test_large_file_handling.py` for the size-limit policy tests.

| Fixture | Static analysis | Full pipeline (no TI/AI/persistence) |
|---|---|---|
| Valid, minimal PE (1KB) | ~1.0ms | ~1.0ms |
| Suspicious-imports PE (1.5KB) | ~1.5ms | ~1.5ms |
| High-entropy-section PE (5KB) | ~2.7ms | ~2.9ms |

| Stage | Measured |
|---|---|
| Persistence (`log_event`, temp db, fresh connection per call) | ~3.9ms/write, averaged over 50 writes |
| Large file, 5MB (low-entropy padding) | 1.77s |
| Large file, 25MB | 10.09s |
| Large file, 75MB | 31.56s |
| Memory delta vs. file size | ≈1:1 (e.g. 75MB file → ~75MB RSS growth during analysis) |

**Conclusion**: for the vast majority of real files (installers, droppers,
tools — typically well under a few MB), the pipeline's own overhead is
negligible (single-digit milliseconds). The dominant real-world latency
contributors are the deliberate 1s monitor settle delay and real network
round-trips to VirusTotal/MalwareBazaar/OpenAI when API keys are
configured — neither touched by this step. The one genuine scaling risk
(large files) is now bounded by the size-limit policy (§1 P1 fix) rather
than by the analyzer's own (unoptimized, and deliberately left
unoptimized per the task's own instruction) throughput.

## 4. Manual destructive-input simulation (real app, real process, no malware)

Ran `app/main.py` for real (properly backgrounded, not a foreground blocking
call) against the live `~/Downloads` folder, in sequence:

1. **Valid benign PE** → detected, analyzed (0 imports, 1 section, 1
   string), scored 0/SAFE, persisted. No guidance popup (correct — SAFE
   doesn't warrant one).
2. **Malformed/truncated PE** → `pefile.PEFormatError` caught
   (`'File Header missing'`), scored 40/SUSPICIOUS ("Invalid PE format"),
   persisted, **guidance popup actually rendered** ("Security warning shown
   to user").
3. **Empty file renamed `.exe`** → `'The file is empty'` caught, scored
   70/HIGH_RISK ("Invalid PE format" + "Empty file"), persisted, popup
   rendered.
4. **Five files dropped rapidly** (mixed suspicious-import and clean
   fixtures) → all five detected and analyzed exactly once each, in order,
   with the created+modified duplicate-event bursts correctly collapsed
   (visible in the raw log as a second "New executable detected" line with
   no further output — the Step 7 dedup fix (§1) working live, not just in
   the test suite).
5. **File deleted mid-settle-window** (deleted 0.3s after creation, well
   inside the 1s settle delay) → silently and safely skipped, **no crash**,
   no spurious database row, the monitor continued processing subsequent
   files normally afterward.
6. **External APIs unavailable** (no API keys configured in this
   environment — the realistic default state, not a simulated toggle):
   MalwareBazaar returned a real live 401, VirusTotal was skipped for
   missing key, AI explanation unavailable — all three degraded gracefully
   across every one of the above six files with zero crashes.
7. **Restart**: process force-stopped, then a fresh `app/main.py` process
   started against the same real database. No schema-corruption on
   restart (confirmed by direct schema inspection afterward and by the
   fact that all 8 new events plus the 3 pre-existing ones from the Step 6
   demo were correctly present).
8. **History opened** (constructed `AngelGuardWindow`/`HistoryPanel`
   programmatically against the live db — 11 total rows, 8 from this
   session's step7_* files).
9. **Original events inspected**: retrieved one event by `event_id`,
   rendered it through the real `AnalysisDetailsDialog` — correct
   filename, risk score, and reasons, no crash.

Database check after the run: exactly 8 rows matching the 8 files actually
analyzable in this session (5 base scenarios − 0, since all 3 initial +
5 rapid = 8; the deleted-mid-analysis file correctly produced **zero**
rows). No duplicates, no losses. Test artifacts removed from the real
`~/Downloads` folder afterward; the demonstration rows were left in the
real `data/angelguard_events.db`, consistent with the D18/D32 precedent.

## 5. Logging / observability

Every pipeline stage already prints/logs enough to answer, after the fact:
**what** failed (`analysis_status` value + the specific `reasons` list),
**where** (per-stage try/except in `analysis_pipeline.py` logs which named
stage via `logger.exception`/`logger.warning`, and `static_analyzer.py`
prints its own step-by-step progress), **which file/event** (file path is
in every log line; `event_id` is in the final event and, since Step 5B, in
the persisted row), **whether persistence succeeded**
(`event["persistence_error"]`, plus `AdminEventLogger`'s own
`logger.error` on failure), and **whether the user was notified**
(`event["guidance_triggered"]`, plus the "Security warning shown to user"
/ no-such-line distinction visible in console output). No secrets are
logged anywhere in the pipeline-relevant modules (API keys are read from
env vars and never printed; grepped to confirm no `print`/`logger` call
in `threat_intel_client.py`, `ai_explainer.py`, or `config/settings.py`
includes an API key variable).

## 6. Summary — MVP readiness

Steps 1–7 are complete. **188 tests passing, 0 failed, 0 skipped**
(up from 112 going into this step — 76 new tests across 8 new test files,
covering monitor races/dedup, large-file policy, adversarial inputs,
threat-intel chaos, AI chaos, security invariants, restart/recovery,
rapid-event stress, and a performance baseline). Two genuine P1 defects
were found and fixed (path-only dedup cache, unbounded large-file
analysis time); one P1 test-coverage gap was found and fixed (threat
intel had zero real automated tests). All P2/P3 findings are documented
above and in `DECISIONS.md`, deliberately not fixed, per the task's own
guidance to defer non-essential hardening.
