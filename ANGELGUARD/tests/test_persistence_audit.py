"""
Step 5 / 5B — persistence audit validation.

These tests originally PROVED two defects the Step 5 database/event-model
audit found against the real, unmodified AnalysisPipeline + AdminEventLogger
(see git commit 66036b2, "test: add persistence audit regression coverage",
for that pre-migration baseline — event_id was not persisted, and the
stored row dropped risk reasons / full static analysis / full threat
intelligence / part of the AI explanation).

Step 5B deliberately corrected AdminEventLogger's persisted schema and the
pipeline's persistence boundary to fix exactly those two defects (see
DECISIONS.md Step 5B, D21). Per this project's established practice for a
deliberately corrected public contract (see D13), these tests are updated
in place to verify the fix rather than left asserting the now-superseded
"before" behavior — which is preserved permanently in commit 66036b2, not
lost by this edit.

Uses a temp db path (tmp_path) exclusively — never the real
data/angelguard_events.db, matching the convention already established in
tests/test_admin_logger.py and tests/test_integration.py.
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline
from event_logging.admin_event_logger import AdminEventLogger
from tests.fixtures.pe_builder import make_suspicious_import_pe_bytes


class FakeThreatIntel:
    def get_reputation(self, file_hash):
        return {
            "virus_total_detections": 12, "virus_total_total_engines": 70,
            "malwarebazaar_match": True, "malware_family": "RedLine Stealer",
            "confidence": "high",
        }


class FakeAIExplainer:
    def generate_explanation(self, payload):
        return {
            "ai_summary": "fake summary",
            "threat_explanation": "fake threat explanation",
            "recommended_action": "fake recommended action",
            "confidence": "high",
        }


def _write_suspicious_exe(tmp_path):
    path = tmp_path / "susp.exe"
    path.write_bytes(make_suspicious_import_pe_bytes())
    return str(path)


def test_event_id_is_now_persisted_and_retrievable(tmp_path):
    """Was test_event_id_is_not_persisted_anywhere_in_threat_events prior to
    Step 5B (see commit 66036b2) — event_id now has a real, UNIQUE-indexed
    column, and the pipeline's own returned uuid is exactly what a caller
    can look the row back up by."""
    db_path = str(tmp_path / "audit.db")
    logger = AdminEventLogger(db_path=db_path)
    pipeline = AnalysisPipeline(
        threat_intel_client=FakeThreatIntel(),
        ai_explainer=FakeAIExplainer(),
        persistence=logger,
    )

    event = pipeline.analyze_and_decide(_write_suspicious_exe(tmp_path))
    assert event["persistence_error"] is None  # confirms the row was actually written

    conn = sqlite3.connect(db_path)
    columns = [row[1] for row in conn.execute("PRAGMA table_info(threat_events)")]
    assert "event_id" in columns

    row = conn.execute(
        "SELECT event_id FROM threat_events WHERE event_id = ?", (event["event_id"],)
    ).fetchone()
    conn.close()

    assert row is not None
    assert row[0] == event["event_id"]

    # And retrievable through the logger's own API, not just raw SQL.
    retrieved = logger.get_event(event["event_id"])
    assert retrieved is not None
    assert retrieved["event_id"] == event["event_id"]


def test_stored_row_now_preserves_reasons_static_analysis_and_full_explanation(tmp_path):
    """Was test_stored_row_loses_reasons_static_analysis_and_partial_explanation
    prior to Step 5B (see commit 66036b2) — threat_events gained JSON
    columns for exactly the data that used to be dropped, and log_event now
    receives the canonical final event (not the narrower aggregator
    payload), so all of it actually reaches storage."""
    db_path = str(tmp_path / "audit.db")
    logger = AdminEventLogger(db_path=db_path)
    pipeline = AnalysisPipeline(
        threat_intel_client=FakeThreatIntel(),
        ai_explainer=FakeAIExplainer(),
        persistence=logger,
    )

    event = pipeline.analyze_and_decide(_write_suspicious_exe(tmp_path))

    assert event["risk"]["reasons"]
    assert event["static_analysis"].get("suspicious_imports") or event["static_analysis"].get("num_suspicious_imports")
    assert event["explanation"]["threat_explanation"] == "fake threat explanation"
    assert event["explanation"]["recommended_action"] == "fake recommended action"

    retrieved = logger.get_event(event["event_id"])

    # All of it now survives the round trip through storage.
    assert retrieved["risk"]["reasons"] == event["risk"]["reasons"]
    assert retrieved["static_analysis"] == event["static_analysis"]
    assert retrieved["threat_intelligence"] == event["threat_intelligence"]
    assert retrieved["explanation"]["threat_explanation"] == "fake threat explanation"
    assert retrieved["explanation"]["recommended_action"] == "fake recommended action"
