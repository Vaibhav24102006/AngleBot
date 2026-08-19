# ANGELGUARD — Engineering Decisions Log

Running log of judgment calls made while turning the prototype into a working
MVP. Each entry: the decision, why, and what it defers.

## STEP 1 — P0 Foundation

### D1. Canonical logger (interim vs. final)

Two independent SQLite loggers exist: `logging_bak/log_service.py`
(`analysis_logs` table, used by the real `monitor/monitor_service.py` path
once its import is fixed) and `event_logging/admin_event_logger.py`
(`threat_events` table, richer schema — file hash, risk, threat intel,
AI summary, confidence — currently only exercised by its own unit test).

**Decision:** For this stage, fix `monitor_service.py`'s broken import to
point at the existing `logging_bak.log_service.log_analysis` — i.e. restore
exactly the behavior that was originally intended, with no schema or logic
change. Do not switch loggers yet.

**Why:** Switching to `AdminEventLogger` now would require constructing a
payload with `risk_assessment` / `threat_intelligence` sub-dicts that don't
exist yet at this point in the pipeline (threat intel and AI explanation
aren't wired in until Step 4). Doing that now would pull Step 4/6 work
forward and violate "no unrelated changes in this stage."

**Final decision (deferred to Step 6):** `event_logging.AdminEventLogger`
becomes the canonical logger once the full pipeline (Step 4) produces the
richer payload it expects. `logging_bak.log_service` is legacy from that
point on and will be retired in Step 6, not deleted before then. The
`guardian_logs.db` tables written by Phase 7 (`behavior_events`,
`network_events`, `correlation_events`) and by the snapshot system
(`snapshots`) are out of scope for this MVP and are left untouched.

### D2. GUI entry point (`ui/main_window.py`)

**Decision:** Apply the one-line fix (missing `QObject` import) since it's a
zero-risk correction of an outright bug, but do **not** wire
`ui/main_window.py` into the MVP pipeline. It launches Phase 7 process/network
monitoring + the manual snapshot dashboard — a different feature surface than
"warn the user about a detected executable." The MVP's warning UI is
`ui/employee_guidance.py`, connected directly by the new orchestrator in
Step 4, without going through `main_window.py`.

### D3. Dependency versions

Pinned to latest-stable-as-of-audit for each package actually imported
somewhere in the codebase (confirmed via AST scan of every `.py` file, not
by trusting the old `requirements.txt`): `watchdog==6.0.0`,
`pefile==2024.8.26`, `psutil==7.2.2`, `PyQt5==5.15.11`, `requests==2.34.2`,
`python-dotenv==1.2.3`, `openai==3.2.0`. No ML libraries added —
`ml/` is intentionally still empty; adding `scikit-learn`/`numpy` now would
be speculative per the mission's explicit "ML comes later" constraint.

A project-local virtual environment (`ANGELGUARD/.venv`, gitignored) was
created so "clean installation works from requirements.txt" is something
that has actually been verified, not assumed — the previous global Python
environment had none of the project's 7 dependencies installed except
`requests` and `python-dotenv`.

### D4. `dest_path` fallback bug in `monitor/monitor_service.py` (found during verification, not in the original audit)

Running the fixed pipeline end-to-end for the first time (copying a real
`.exe` into `~/Downloads` while `app/main.py` was live) revealed that
**no `created` or `modified` event ever reached the analyzer**, even after
the P0 import fix. Root cause: `monitor_service.py` line 28 used
`file_path = getattr(event, 'dest_path', event.src_path)`. In watchdog
6.0.0, `FileCreatedEvent`/`FileModifiedEvent` objects already carry a
`dest_path` attribute — just set to `''` — so `getattr` found the attribute
and returned `''` instead of ever falling back to `src_path`.
`''.lower().endswith('.exe')` is always `False`, so the handler silently
did nothing for the two most common event types. Only `on_moved` (a file
renamed into place) ever worked.

**Fix:** `file_path = getattr(event, 'dest_path', '') or event.src_path` —
fall back on a falsy `dest_path` value, not on attribute absence.
Verified fixed: a copied `.exe` is now detected, analyzed, scored, and
logged to `data/guardian_logs.db` within ~2 seconds (see Step 1 verification
log). This bug meant the file-monitoring pipeline had likely never worked
end-to-end for the primary "user downloads a file" scenario, in any prior
version of this project — it's not a regression from this session's changes.

### D5. `.env` handling

`.env` was git-tracked with empty placeholder values (verified — no live
secret was ever committed). It is now `git rm --cached`'d (removed from the
index; the local working file is untouched) and added to `.gitignore`.
`.env.example` is added as the onboarding template.

## STEP 2 — Core Regression Tests

### D6. Fixture strategy: hand-built minimal PE, not a real executable

`tests/fixtures/pe_builder.py` constructs valid PE32 bytes from scratch
(DOS header, COFF file header, optional header + 16 data directories,
section headers, and — when requested — a real IMAGE_IMPORT_DESCRIPTOR
table) rather than depending on a real Windows executable on disk.

**Why:** a real system `.exe` would make fixtures non-portable across
machines, isn't appropriate to commit (binary, license-encumbered), and
would make "malformed PE" / "high entropy section" fixtures impossible to
construct precisely. The builder is fully deterministic — high-entropy
bytes come from a SHA-256 counter expansion (`deterministic_random_bytes`),
not `os.urandom()` — so every fixture is byte-identical on every run and
every machine. It was verified against the project's pinned
`pefile==2024.8.26` during development (see the module's own docstring)
before being used in any assertion.

### D7. Boundary testing on a discretely-quantized scorer

`decision/risk_evaluator.py`'s score is a sum of a small fixed set of
components ({40, 30, 40 or 30, 20, 40}), so the achievable score set is
{0, 20, 30, 40, 50, 60, 70, 80, 90, 100} — not every integer. A literal
"boundary-1/boundary/boundary+1" (e.g. 19/20/21) is not producible by the
function. Tests instead use the nearest achievable neighbors on each side
of the 20 and 60 thresholds (0/20/30 and 50/60/70), which is what actually
proves the `>=` (inclusive) comparison is correct. Documented in
`tests/test_risk_evaluator.py`'s module docstring, flagged here per the
instruction to explain judgment calls rather than silently deviate.

### D8. Two bugs found while writing tests

1. **P1, fixed:** `analysis/test_static.py` (renamed to
   `analysis/manual_static_check.py`) had a docstring containing
   `C:\Users\user\Downloads\test.exe` in a non-raw string — `\U` is a
   defined Python escape prefix requiring 8 hex digits, so this was a hard
   `SyntaxError` on every attempt to run or even import the file. This
   script has apparently never been runnable. Fixed by switching the
   example path to forward slashes (`C:/Users/user/Downloads/test.exe`),
   consistent with the rest of the file's usage text.
2. **P2, documented, not fixed:** Both `analysis/manual_static_check.py`
   and `analysis/manual_feature_check.py` print Unicode symbols (`✓ ✗ ⚠`)
   directly to stdout. In a console using a non-UTF-8 codepage (observed:
   Windows `cp1252`, e.g. this project's default terminal), printing these
   raises `UnicodeEncodeError` and crashes the script. This is confined to
   two manual CLI diagnostic scripts outside the automated pipeline —
   `analysis/static_analyzer.py` and `decision/risk_evaluator.py`
   themselves use no such characters and are unaffected. Out of Step 2's
   scope (not one of the two target modules); left for a later pass.

### D9. Test runner

`pytest.ini` added at the repo root pins `testpaths = tests`, making
`pytest` (run from `ANGELGUARD/`) the single canonical command. The two
CLI diagnostic scripts under `analysis/` were renamed off the `test_*`
prefix (`manual_static_check.py`, `manual_feature_check.py`) so they're
unambiguously excluded from discovery rather than relying on them merely
having zero `test_`-prefixed functions.

## STEP 3 — Canonical Analysis Schema + Aggregator Repair

### D10. Canonical `analysis/static_analyzer.py` output shape

No new fields were invented beyond what the analyzer already knows. One
field was added — `file_path` — since the function already receives it as
an argument and omitting it from the result made the dict unable to
describe itself to a downstream consumer that only has the dict (exactly
what `intelligence_aggregator.py` needed and didn't have). Canonical shape:

```
{
  "file_path": str,               # NEW in Step 3 — the exact path passed in
  "file_size": int,
  "hash": str,                    # sha256 hex, "" only if hashing itself failed
  "total_imports": int,
  "suspicious_imports": List[str],   # "DLL:API" strings
  "num_suspicious_imports": int,
  "num_sections": int,
  "high_entropy_sections": int,   # count where per-section entropy > 7.5
  "total_strings": int,
  "sections": List[{"name": str, "entropy": float, "size": int}],
  "error": Optional[str],         # None on success; "Not a valid PE file"
                                    # for any pefile.PEFormatError (covers
                                    # non-PE, empty, and malformed/truncated
                                    # input uniformly — see Step 2 findings)
}
```

All fields are always present, even on total failure — the module
initializes the full dict up front and returns it unmodified on early
exits. There is no separate "minimal" failure shape; the docstring's old
claim of a smaller error-only dict was already inaccurate and has been
corrected to match actual behavior.

### D11. Canonical risk-result shape — additive adapter, not a rewrite

`decision/risk_evaluator.py`'s `evaluate_risk()` returns a positional tuple
`(score, classification, reasons)`, but `intelligence_aggregator.py` was
always written expecting a dict (`risk_result.get("risk_score", ...)`) —
passing the raw tuple straight in would `AttributeError` immediately, since
tuples have no `.get()`. This was a second schema mismatch beyond the one
the audit named.

**Decision:** added `evaluate_risk_as_dict(analysis_result)` as a pure,
additive wrapper — `{"risk_score": score, "classification": classification,
"reasons": reasons}` — rather than changing `evaluate_risk()`'s signature.
`evaluate_risk()` itself, its 22 regression tests, and the scoring
algorithm are completely untouched. `evaluate_risk_as_dict` is the function
real callers (the future orchestrator, Step 4) should use when feeding
`aggregate_intelligence()`.

### D12. Aggregator repair: omit unavailable data, never fabricate it

`intelligence_aggregator.py` read `analysis_result["entropy"]` and
`["packed"]` — keys `static_analyzer.analyze_file()` never produces — so
every real call silently reported entropy=0.0 and packed_flag=False
regardless of the actual file. Fixed by deriving both from data the
analyzer actually returns, using the same **omit-the-key** convention
`ai_explainer.py`'s `.get(key, 'N/A')` reads already expected:

- `packed_flag`: `high_entropy_sections > 0`, included whenever
  `high_entropy_sections` is present (which is always, for a real
  `analyze_file()` result — even 0 on total failure, matching how
  `risk_evaluator.py` already treats this field as reliable).
- `entropy`: **max** entropy across `sections` (a single small high-entropy
  stub is more security-relevant than a low average across many sections).
  Included only when `sections` is non-empty. When a PE never parsed at
  all, `sections` is `[]` — there is genuinely no entropy to report, so
  the key is omitted rather than defaulted to a value that would read as
  "verified low entropy."
- `suspicious_imports` (a count, despite the name — pre-existing, unrelated
  to this bug): still defaults to 0 via `.get()`, which is safe because
  `num_suspicious_imports` is always present in a real analyzer result.

`file_path` now resolves correctly too, once D10 added it upstream.

### D13. Existing tests updated — three were asserting the wrong contract

`tests/test_intelligence_aggregation.py`'s fixtures constructed
`analysis_result` dicts with top-level `entropy`/`packed` keys — the exact
fictional shape the bug assumed, not what `static_analyzer.analyze_file()`
ever produces. Three tests failed immediately after the aggregator fix
(`KeyError: 'entropy'`), confirming they were testing the wrong contract,
not real behavior. Rewritten to use the canonical `sections` /
`high_entropy_sections` shape; `test_aggregate_partial_analysis` now
explicitly asserts `"entropy" not in static` and `"packed_flag" not in
static` for genuinely minimal input, which is the actual point of this
step. One new test was added alongside it
(`test_aggregate_invalid_pe_analysis_omits_entropy_but_keeps_high_entropy_count`)
covering the "PE never parsed" case specifically.

`tests/test_integration.py`'s three scenario fixtures used the same
fictional shape but never actually asserted on `entropy`/`packed_flag`, so
they kept passing throughout — updated anyway for correctness, since
leaving known-wrong fixtures in place (even where currently harmless) would
misinform the next reader. `test_admin_logger.py` and `test_ai_explainer.py`
construct their mocks at the *aggregator output* level
(`static_analysis: {"entropy":…, "packed_flag":…}`), which is exactly the
key set this fix preserves — zero changes needed there.

### D14. New schema-contract tests (`tests/test_schema_contract.py`, 11 tests)

Runs the *real* `analyze_file()` → `evaluate_risk_as_dict()` →
`aggregate_intelligence()` chain against generated PE fixtures — not just
hand-shaped dicts — to prove the three modules' contracts genuinely
interoperate. Covers: complete analysis, high-entropy population, missing
optional data (no fabricated "clean" verdicts), malformed/truncated PE
input, field preservation (suspicious-import count, file size,
high-entropy count survive unchanged), risk preservation (score/
classification/reasons identical before and after aggregation), and both
threat-intel shapes (`{"status": "unknown"}` and a populated result). No
test makes a network call.

## STEP 4 — Orchestration / Wiring

### D15. New `pipeline/analysis_pipeline.py` — the one authoritative pipeline

`AnalysisPipeline.analyze_and_decide(file_path)` runs the full chain:
static analysis → risk evaluation → threat intel (optional) → aggregation
→ AI explanation (optional) → canonical final event → persistence
(optional) → guidance (optional). Every optional stage is dependency-
injected (`threat_intel_client`, `ai_explainer`, `persistence`, `guidance`
— all default to `None`, meaning "disabled, degrade gracefully"), so
`AnalysisPipeline()` with zero arguments is fully functional, network-free,
and GUI-free — this is what lets orchestration tests avoid any live
service dependency without needing to mock anything at the module-import
level.

`build_default_pipeline(guidance=None)` is the factory real callers use:
wires a real `ThreatIntelClient`, `AIExplainer`, and `AdminEventLogger`
(see D16). `guidance` is deliberately NOT auto-defaulted to a real
`GuidanceController` — see D17 for why.

`monitor/monitor_service.py`'s `DownloadMonitorHandler` no longer contains
any analysis/risk/persistence logic — it now does exactly what Step 4
asked ("monitoring detects, the pipeline analyzes"): filesystem event
filtering, dedup, locked-file retry, then one call to
`pipeline.analyze_and_decide(file_path)`.

### D16. Canonical persistence: `AdminEventLogger`, not `logging_bak`

Per the Step 1 D1 deferred decision — now resolved. `AdminEventLogger.
log_event(payload, explanation)` accepts exactly the shape
`aggregate_intelligence()` + the AI explainer already produce, with zero
adapter code needed; `logging_bak.log_service.log_analysis()` takes flat
positional args and only captures risk info, no threat intel or AI
explanation. `build_default_pipeline()` now uses `AdminEventLogger`
exclusively. `logging_bak/log_service.py` is left in place (not deleted —
Step 4 explicitly said not to), but is no longer called by any code path;
it's legacy. Verified end-to-end: a real run wrote a complete row —
timestamp, file path, hash, risk score/classification, threat-intel
fields, and the AI fallback summary — into `data/angelguard_events.db`'s
`threat_events` table (see Step 4 manual demonstration, below).

**Correction (Step 5 audit, superseded by Step 5B):** "accepts exactly the
shape ... already produce[s], with zero adapter code needed" overstated
what actually reached storage. `AdminEventLogger` accepted a richer
*input* than `log_service` did, but persisted a *narrower schema* than the
pipeline actually computed — risk reasons, the full static-analysis
detail, the full threat-intelligence dict, and two of four AI-explanation
fields were silently dropped, and the pipeline's own `event_id` was never
passed to persistence at all. See Step 5's audit and Step 5B (D21) for the
fix. Left here uncorrected-in-place, not rewritten, per this log's own
rule of keeping historical decisions intact rather than rewriting history.

### D17. Guidance wiring and why `app/main.py` polls instead of blocking on `app.exec_()`

`ui/employee_guidance.py`'s `GuidanceController` uses Qt signals to be
thread-safe: `.trigger()` can be called from the watchdog worker thread,
and Qt queues the actual dialog-showing onto whichever thread the
`GuidanceController` (and its underlying `QApplication`) was constructed
on. For that queued delivery to ever run, something has to be pumping the
Qt event loop on that thread.

**Decision:** `app/main.py` now constructs `QApplication` and
`GuidanceController` on the main thread *before* starting the watchdog
observer (required — Qt objects must be created on the thread that will
service them), and passes the constructed `guidance` into
`build_default_pipeline(guidance=guidance)`. The main loop calls
`app.processEvents()` every 100ms instead of blocking on `app.exec_()`.

**Why not `app.exec_()`:** it would block the main thread in Qt's own
loop, and `KeyboardInterrupt` (Ctrl+C) delivery into a blocking Qt loop on
Windows is a well-known rough edge (Python's signal handler only runs
between bytecode instructions, which a blocked C-level `exec_()` call
starves). Polling with `processEvents()` keeps the exact same
`while True: time.sleep(...)` / `except KeyboardInterrupt` shape Step 1
already established and tested, while still servicing Qt's queue often
enough for the guidance dialog to actually render. This is a deliberate,
scoped judgment call, not a UI redesign — `employee_guidance.py` itself is
untouched.

**Verification caveat:** this session has no way to screenshot or
otherwise visually inspect a real desktop window. The manual demonstration
confirms guidance was triggered via the pipeline's own log line
("Security warning shown to user.") and the `guidance_triggered: true`
field in the returned event — not a visual screenshot of the dialog. If a
visual check matters, it should be done interactively by a human on a real
desktop session.

### D18. Manual end-to-end demonstration (real run, real network, no malware)

Ran `app/main.py` for real, copied a real `notepad.exe` into the live
`~/Downloads` folder. Observed, in order: detection → hashing → PE parsing
→ import/entropy analysis → **two real threat-intel failures handled
live** (MalwareBazaar returned HTTP 401 with no API key configured;
VirusTotal was skipped immediately for the same reason) → risk evaluation
(score 20, SUSPICIOUS, "Suspicious import detected (3 imports)") → AI
explanation gracefully unavailable (no `OPENAI_API_KEY`) → event persisted
to `data/angelguard_events.db` (verified by direct SQL query afterward,
full row intact) → guidance triggered. No exception, no crash, at any
point — including through two genuine live external-service failures, not
simulated ones. Test artifact removed from the real Downloads folder
afterward.

### D19. Scope boundaries not implemented (deliberately)

- `missing_file` / `error:<stage>` pipeline results are **not** persisted
  to the database — only a `"completed"` analysis (even a malformed-PE one
  that completed with an "invalid PE" risk score) reaches
  `aggregate_intelligence()` and therefore `AdminEventLogger`. A truly
  missing file or a core-stage exception is returned to the caller
  (visible in console output / the returned event) but leaves no DB trail.
  Documented as a P2 gap for a future step, not fixed now — persisting a
  failure event would require deciding a schema for it, which is exactly
  the kind of speculative expansion Step 4 asked to avoid.
- `threat_intel/threat_intel_client.py`'s `check_malwarebazaar()` makes a
  live HTTP request regardless of whether `MB_API_KEY` is set (confirmed
  live during the D18 demonstration — it returned a real 401). This is
  pre-existing behavior in a module Step 4 explicitly left untouched, not
  a new pipeline defect — noted here only because the wired pipeline is
  what surfaced it for the first time.

### D20. Persistence-failure contract mismatch, found during review, fixed

Found while verifying this step in a follow-up session: `_run_persistence`
only set `persistence_error` when `self._persistence.log_event(...)`
*raised*. But the real `AdminEventLogger.log_event()` never raises — it
catches `sqlite3.Error` internally and returns `False`, only logging the
failure through its own logger. Against the real (non-test) persistence
backend, a genuine DB write failure would have silently produced
`persistence_error: None` in the returned event, contradicting DoD item
"external-service failures do not destroy local analysis" /
"persistence failure is observable."

**Fix:** `_run_persistence` now also checks the return value — an explicit
`False` is treated as failure (`persistence_error` set to a diagnostic
string), while `None`/`True`/no return value all mean success, so a
backend with no return value isn't misreported as failing. Covered by a
new test, `test_persistence_returning_false_is_also_observable`, alongside
the existing raises-based test. No other behavior changed.

## STEP 5 — Database & Event Model Audit

Code-only audit of every SQLite database/table in the project. No
migration performed in this step — see the full audit report delivered
separately for the complete inventory, MVP event trace, identity/key
relationship analysis, concurrency inspection, and target-architecture
recommendation. Summary of what it established (all verified against code,
not prior documentation):

- Exactly **2** physical `.db` files exist: `data/angelguard_events.db`
  (`threat_events`, the live MVP sink) and `data/guardian_logs.db` (shared
  by `analysis_logs` — dead code, never called — plus Phase 7's
  `behavior_events`/`network_events`/`correlation_events`/`snapshots`,
  reachable only through the separate, unwired `ui/main_window.py` entry
  point, never from `app/main.py`).
- No identity relationship exists between the MVP's `threat_events` and
  any Phase 7 table — neither side stores a key the other could join on.
- The MVP path had two P1 defects (see D16's correction, above): the
  pipeline's `event_id` was never persisted, and the stored row dropped
  most of the canonical event's content. Fixed in Step 5B (D21-D23).
- No WAL/transaction tuning anywhere in the codebase; not a real risk on
  the current MVP path (`threat_events` has exactly one writer, zero
  readers, called serially from one thread) — only a latent risk if Phase
  7's separate `main_window.py` entry point is ever run, which was
  explicitly out of scope to fix here.
- Regression tests proving the two P1 defects were committed as
  `tests/test_persistence_audit.py` at commit `66036b2`, establishing the
  pre-migration baseline before Step 5B touched anything.

**Decision:** Option C — transitional. Widen `threat_events`' schema
in-place (additive migration) rather than consolidating with
`guardian_logs.db`; leave Phase 7's tables completely untouched, since
they track a structurally different kind of event (OS-level
process/network activity, not file analysis) and aren't even wired into
the MVP yet. Forcing a shared schema now would be exactly the kind of
speculative expansion the project's guidance repeatedly warns against.

## STEP 5B — Transitional Persistence Model

### D21. `threat_events` schema: additive migration, JSON columns for nested data

`event_logging/admin_event_logger.py`'s `_migrate_schema()` runs on every
`AdminEventLogger()` construction (fresh or pre-existing database alike —
one migration code path, not two) and adds, via `ALTER TABLE ADD COLUMN`
only:

```
event_id TEXT                    -- UNIQUE-indexed (see D22)
file_size INTEGER
risk_reasons TEXT                -- JSON array
static_analysis_json TEXT        -- JSON object, the full analyzer output
threat_intelligence_json TEXT    -- JSON object, the full TI result
explanation_json TEXT            -- JSON object or NULL
recommended_action TEXT
analysis_status TEXT
```

The original 10 columns (Phase 6.5) are untouched — old rows keep their
exact original data, and the new columns are `NULL` for them (no
fabricated history). JSON text columns were chosen over normalizing
`static_analysis`/`threat_intelligence`/`explanation` into relational
columns per the task's own framing: this data is inherently nested, has
no query requirement today that would justify dozens of columns, and
`log_service.py` already established the JSON-column-for-nested-data
pattern for `reasons` before this step. `json.dumps(..., sort_keys=True)`
is used throughout for deterministic serialization.

Verified against a hand-built pre-Step-5B-schema database (bypassing
`AdminEventLogger` entirely to construct it) in
`tests/test_admin_logger.py::TestSchemaMigrationFromLegacyDatabase`: the
old row survives with its original data intact, new columns are `NULL`
for it, and a new event logged afterward gets the full schema — both rows
coexist.

### D22. `event_id` identity: UNIQUE index, idempotent upsert on duplicate

`event_id` is not declared `UNIQUE` inline (SQLite's `ALTER TABLE ADD
COLUMN` doesn't support inline `UNIQUE`/`PRIMARY KEY` constraints); a
separate `CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_events_event_id ON
threat_events(event_id)` achieves the same enforcement. A plain (non-partial)
unique index was sufficient rather than a `WHERE event_id IS NOT NULL`
partial index: SQL treats `NULL <> NULL`, so SQLite's own `UNIQUE`
semantics already let any number of historical `NULL`-`event_id` rows
coexist without conflict — verified by
`test_events_without_event_id_do_not_collide`.

**Duplicate `event_id` behavior: idempotent (last write wins), not
rejected and not silently ignored.** `log_event()` uses
`INSERT ... ON CONFLICT(event_id) DO UPDATE SET ...`. Chosen because an
analysis event is naturally re-derivable from its own `event_id` — if a
caller (a future retry path, or a test) logs the same event twice, the
second write should reflect the more recent state, not create a
phantom-duplicate row that `list_events()` would then show twice for one
underlying analysis. Verified by
`test_duplicate_event_id_is_idempotent_not_duplicated`: exactly one row
exists after two writes with the same `event_id`, and its contents match
the second (later) write.

### D23. Persistence boundary: the canonical `final_event`, not the aggregator `payload`

`AnalysisPipeline._run_persistence` now takes `final_event` — the exact
dict object `analyze_and_decide()` returns to its caller — instead of the
aggregator's intermediate `payload`. This is the one change that makes
`event_id` reach storage at all: `payload` (built by
`intelligence_aggregator.aggregate_intelligence()`) never had an
`event_id` key; only the pipeline's own `_build_final_event()` does.
`final_event["persistence_error"]` and `["guidance_triggered"]` are
assigned *after* the persistence call returns, so the object actually
persisted never contains those two pipeline-internal bookkeeping fields —
there is exactly one canonical event object, mutated in place, not two
separately constructed representations (verified by
`persistence.calls[0] is event` in
`test_full_pipeline_produces_correct_canonical_event`). Guidance wiring
(`_run_guidance`) deliberately still receives the aggregator `payload`,
unchanged — Step 5B's scope was persistence only; `ui/employee_guidance.py`
consumes the `payload`'s `risk_assessment` shape and touching that would
be an unrelated GUI change outside this step.

### D24. Retrieval API: `get_event(event_id)` / `list_events(limit=50)`

Neither existed before Step 5B — the audit found `AdminEventLogger` was a
write-only sink. Both return the same canonical shape
`_build_final_event()` produces (decoding the JSON columns back into
nested dicts/lists), so a caller can't tell whether an event came from a
live pipeline run or was reloaded from storage. `list_events()` is a flat,
unfiltered, most-recent-first query with a default `LIMIT 50` — no
filtering/paging framework, per the task's explicit "keep it minimal"
instruction; the MVP has no history UI yet to justify more.

### D25. Regression tests updated in place, not left asserting stale behavior

`tests/test_persistence_audit.py`'s two tests originally proved the two
defects this step fixes (`event_id` not persisted; most of the canonical
event dropped). Per this project's established practice for a
deliberately corrected public contract (D13), they were updated in place
to verify the fix rather than left permanently asserting the "before"
state — which is not lost, since it's preserved exactly in git commit
`66036b2`. `tests/test_admin_logger.py` and the three `log_event(...)`
call sites in `tests/test_integration.py` were likewise updated for the
new single-argument `log_event(final_event)` contract; `FakePersistence`
in `tests/test_analysis_pipeline.py` similarly changed from a
`(payload, explanation)` two-arg fake to a single-`final_event`-arg one.
None of these changes weaken what's being asserted — each new assertion
checks strictly more than what it replaced (e.g. round-trip equality
through `get_event()`, not just raw-SQL column presence).

Full suite after Step 5B: **100 passed, 0 failed, 0 skipped** (93 going
into this step + 5 new `test_admin_logger.py` cases +
2 unchanged-in-count `test_persistence_audit.py` cases, updated in place
per D25).

### D26. Left untouched (per Step 5B's explicit scope)

`guardian_logs.db` and all four Phase 7 tables, `logging_bak/log_service.py`,
WAL/concurrency tuning (the audit found no real risk on the current
single-writer MVP path — deferred until Phase 7 is actually wired into the
same persistence architecture, not before), and `ui/employee_guidance.py`
/ `ui/main_window.py`. No ML, no GUI redesign, no new threat-intel or AI
providers.

## STEP 6 — User Experience & Analysis History

### D27. UI audit and entry-point decision

Inspected all three existing UI modules before writing anything:

- `ui/main_window.py` — `launch()` constructs Phase 7 only:
  `ProcessMonitor`/`NetworkMonitor`/`BehaviorCorrelator` on their own
  `QThread`s plus `EmployeeDashboard`. Zero relation to the MVP pipeline —
  never imports `pipeline/`, `event_logging/`, or `monitor/monitor_service.py`.
  Not reachable from `app/main.py` (confirmed by import trace, matching
  D2's original decision). Reusable: the generic `_start_monitor`/
  `_stop_monitor` QThread helpers and `apply_dark_theme`, neither used
  this step since Step 6 doesn't touch Phase 7 or restyle anything.
- `ui/employee_dashboard.py` — Phase 7 snapshot baseline/compare widget
  (`create_snapshot`/`compare_snapshots`), launched only by `main_window.py`.
  Entirely disconnected from file analysis. Not reused.
- `ui/employee_guidance.py` — the one MVP-relevant, already-partially-wired
  component (D17): `GuidanceController`/`EmployeeGuidance`, thread-safe via
  a Qt queued signal, already constructed and wired by `app/main.py`. This
  is what Step 6 reuses and extends, not replaces.

**Entry-point decision:** `app/main.py` remains ANGELGUARD's one
user-facing MVP entry point (per Step 4's original requirement) — it now
shows a real main window (`ui/app_window.py`, new) by default instead of
running fully headless. `ui/main_window.py` is left completely untouched
as the separate, still-not-wired Phase 7 "Employee Mode" launcher — Step 6
explicitly excludes Phase 7, and repurposing that module or its name would
either touch Phase 7 or create a confusing name collision. A `--headless`
CLI flag on `app/main.py` preserves the exact pre-Step-6 console-only +
popup-only behavior for development/testing, per the task's explicit ask
to keep that path useful.

### D28. New UI modules: `AnalysisDetailsDialog`, `HistoryPanel`, `AngelGuardWindow`

Three new, single-purpose modules, each reusable independently:

- `ui/analysis_details.py` — `AnalysisDetailsDialog`, a read-only view of
  one canonical event (file/risk/static analysis/threat intel/explanation/
  recommendation). Reused both from the guidance popup's new "Review
  Details" button and from history row selection — one implementation,
  not two.
- `ui/history_panel.py` — `HistoryPanel`, a table backed directly by
  `AdminEventLogger.list_events()`/`get_event()`. No new database, no new
  event schema, no persistence logic duplicated here (Step 6's explicit
  requirement) — it only ever reads.
- `ui/app_window.py` — `AngelGuardWindow`, the new main window hosting a
  status header and `HistoryPanel`. Deliberately has zero coupling to the
  pipeline, the watchdog thread, or `GuidanceController` — it only
  constructs its own `AdminEventLogger` (a second instance, same default
  db path — SQLite is the shared boundary, not a shared Python object)
  and polls. This keeps the window's thread-safety story trivial: it never
  touches anything from a non-GUI thread.

**History refresh: GUI-thread polling (`QTimer`, default 3s) plus a manual
Refresh button, not a push notification from the pipeline.** Chosen over
adding a new cross-thread signal from the watchdog thread into the window,
per the task's explicit "do not add unnecessary threading complexity" —
`GuidanceController`'s existing queued-signal mechanism already handles
the one thing that genuinely needs real-time cross-thread delivery (the
warning popup); history is not time-critical, and polling needs no new
signal plumbing, no change to `AnalysisPipeline`'s public surface, and
matches "the smallest useful history experience" the task asked for.

### D29. Guidance contract changed to consume the canonical `final_event` (supersedes D23's guidance scope note)

D23 (Step 5B) deliberately left `ui/employee_guidance.py` on the
aggregator `payload` shape, scoping that step to persistence only. Step 6
explicitly requires "the warning should consume the actual canonical final
event" and "there must not be separate backend risk vs. UI risk" — so this
step supersedes that boundary, on direct instruction, not by drift.

Changed: `GuidanceSignals.trigger_alert` from `pyqtSignal(dict, dict)` to
`pyqtSignal(dict)`; `GuidanceController.trigger()`/`_show_alert()` and
`EmployeeGuidance.populate_data()` all take one `final_event` dict, reading
`risk.level`/`risk.score`/`risk.reasons`/`explanation`/`recommended_action`
instead of `risk_assessment.classification`/`risk_assessment.risk_score`.
`AnalysisPipeline._run_guidance()` now passes `final_event` (the same
object `_run_persistence()` already receives — one canonical event, not
two constructed representations, verified by identity: `guidance.calls[0]
is event` in `test_full_pipeline_produces_correct_canonical_event`).

The fallback-vs-real-AI-content distinction in `populate_data()` was kept
faithful to the original (`"unavailable"`/`"failed"` substring check on
`ai_summary`), but the fallback branch now actually lists the deterministic
`risk.reasons` — the original fallback branch showed only generic text and
silently dropped the real reasons, which directly contradicted Step 6's
"AI unavailable → still show deterministic reasons" requirement. Verified
by `test_explanation_none_shows_unavailable_message_and_real_reasons`.

A "Review Details" button was added to `EmployeeGuidance` (alongside the
existing "Acknowledge & Close"), opening `AnalysisDetailsDialog` with the
exact same event the popup is already showing — no separate fetch, no risk
of the two views disagreeing.

### D30. Real bug found via manual demonstration: `final_event["static_analysis"]` was the aggregator's reduced sub-dict, not the raw analyzer output

While manually verifying the Analysis Details view against a real pipeline
run (see D32), `AnalysisDetailsDialog` crashed: `TypeError: can only join
an iterable` on `static.get("suspicious_imports")`. Root cause:
`AnalysisPipeline._build_final_event()` was building the event's
`static_analysis` field from `payload["static_analysis"]` —
`intelligence_aggregator.aggregate_intelligence()`'s deliberately reduced
sub-dict (`suspicious_imports` as an **int count**, a single max `entropy`
float, `packed_flag`, `file_size`, `high_entropy_sections` — see D12) — not
from `analysis`, the raw `static_analyzer.analyze_file()` result the
pipeline already had in hand (`sections` list, `total_imports`,
`suspicious_imports` as a **list of strings**, `total_strings`, PE-validity
`error`). The reduced shape is exactly right for its actual consumers (risk
scoring, the AI prompt) but is missing precisely the section/import/string
detail Step 6's Analysis Details view is required to show.

**Fix:** `_build_final_event()` now takes `analysis` (the raw dict) as an
explicit parameter and uses it for the event's `static_analysis` field,
instead of reading it back out of `payload`. `payload["static_analysis"]`
itself — and everything that reads it (`aggregate_intelligence()`'s own
output, the AI explainer's prompt construction) — is completely untouched;
this only changes what the *outward-facing* final event (and therefore
what gets persisted and shown in the UI) carries. Verified by a new
assertion block in `test_full_pipeline_produces_correct_canonical_event`
(checks `sections`, `total_imports`, `total_strings` are present and
`suspicious_imports` is a list) and by the live demonstration in D32,
re-run after the fix.

This was not caught by Step 5B's own round-trip test
(`test_stored_row_now_preserves_reasons_static_analysis_and_full_explanation`)
because that test only asserts persistence is *faithful* to whatever
`final_event["static_analysis"]` already contains — it never asserted
that content matched the raw analyzer's canonical shape. Recorded here as
a process note: a real UI consumer surfaced a data-shape gap that a
persistence-focused round-trip test structurally could not.

### D31. `AdminEventLogger` gets a `busy_timeout` PRAGMA

Step 6 is the first point where a real second accessor of
`angelguard_events.db` exists concurrently with the pipeline's writer: the
GUI thread's `HistoryPanel` poll (`list_events()`/`get_event()`), whereas
the Step 5 audit found zero readers on this database at all. A
`PRAGMA busy_timeout = 3000` was added to every connection (`_connect()`
helper) so a reader/writer collision waits briefly for the lock instead of
raising `sqlite3.OperationalError` immediately. This is the single PRAGMA
the audit already anticipated would eventually be needed "if Phase 7 is
ever run" — it turned out to be needed sooner, from the MVP's own new GUI,
not from Phase 7. WAL and broader concurrency tuning remain deferred, per
the audit and per the task's explicit "do not add WAL merely because it
sounds good" — one writer plus one lightweight poller doesn't need it.

### D32. Manual end-to-end demonstration (real run, real network, no malware)

Ran `app/main.py` for real (not headless) via a properly backgrounded
process, confirmed the main window and `HistoryPanel` construct
successfully, then copied a real `notepad.exe` into the live `~/Downloads`
folder twice — once before D30's fix (which is what surfaced the bug) and
once after, to confirm the fix.

Post-fix run, observed in the live console output: detection → hashing →
PE parsing (310 imports, 8 sections, 3458 strings extracted) → 3
suspicious imports found → MalwareBazaar queried live (real 401, no API
key) → VirusTotal skipped (no API key) → risk evaluated (score 20,
SUSPICIOUS) → AI explanation gracefully unavailable (no `OPENAI_API_KEY`)
→ event persisted → **"Security warning shown to user"** (the popup
actually rendered in this session without crashing). No exception, no
crash, at any point.

Then, separately, constructed a real `AdminEventLogger` + `AngelGuardWindow`
against the live database and confirmed: `HistoryPanel.refresh()` lists the
new row; selecting it and calling `get_event()` returns the full event;
`AnalysisDetailsDialog` built from that retrieved event renders the actual
total-imports count (310), an actual suspicious import name
(`GetProcAddress`), the actual strings count (3458), the "does NOT mean the
file is safe" unknown-reputation disclaimer, and the AI-unavailable notice
— proving the full persist → list → select → retrieve → display chain
against a real (not fabricated) pipeline result. Both test artifacts
(`angelguard_step6_demo*.exe`) were removed from the real Downloads folder
afterward; the two demonstration rows were left in the real
`data/angelguard_events.db` (consistent with the D18 precedent of not
scrubbing the real database after a manual demo).

### D33. Scope boundaries not implemented (deliberately)

No ML, no Phase 7 (behavioral/network monitoring, snapshots), no
sandboxing, no new threat-intel/AI providers, no major visual redesign, no
automatic file deletion/quarantine/execution — `ui/main_window.py` and
`ui/employee_dashboard.py` are untouched. No new database or event schema
was created for history — `list_events()`/`get_event()` (Step 5B) are the
only persistence surface the new UI touches. The "Current Alert" mockup
surface from Step 6's own spec is served by the existing (now-updated)
`EmployeeGuidance` popup rather than a duplicate panel embedded in
`AngelGuardWindow` — Step 10 explicitly asked to keep scope tight, and a
second live view of "the current alert" would either duplicate the popup's
data or need its own cross-thread wiring for no functional gain over what
`HistoryPanel`'s top row already shows post-hoc.
