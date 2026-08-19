"""
Step 5 — persistence audit validation.

These tests do not test new behavior; they PROVE two findings from the
Step 5 database/event-model audit against the real, unmodified
AnalysisPipeline + AdminEventLogger, so the audit's claims are verifiable
rather than asserted from reading alone:

1. The pipeline's own `event_id` (a uuid, generated in
   AnalysisPipeline.analyze_and_decide) is never passed to persistence and
   never stored anywhere in `threat_events` — there is no column for it,
   and no other stored column reproduces it. A caller holding only the
   returned event has no query path back to its own row.

2. `AdminEventLogger`'s `threat_events` schema is narrower than the
   canonical final event: risk reasons, the full static_analysis dict, the
   full threat_intelligence dict, and two of the four AI explanation
   fields (threat_explanation, recommended_action) are all computed by the
   pipeline but never persisted. The stored row cannot reconstruct the
   full analysis.

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


def test_event_id_is_not_persisted_anywhere_in_threat_events(tmp_path):
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
    assert "event_id" not in columns

    row = conn.execute("SELECT * FROM threat_events").fetchone()
    conn.close()

    # The uuid returned to the caller appears nowhere in the stored row.
    assert event["event_id"] not in row


def test_stored_row_loses_reasons_static_analysis_and_partial_explanation(tmp_path):
    db_path = str(tmp_path / "audit.db")
    logger = AdminEventLogger(db_path=db_path)
    pipeline = AnalysisPipeline(
        threat_intel_client=FakeThreatIntel(),
        ai_explainer=FakeAIExplainer(),
        persistence=logger,
    )

    event = pipeline.analyze_and_decide(_write_suspicious_exe(tmp_path))

    # The canonical event actually has this richer data available...
    assert event["risk"]["reasons"]
    assert event["static_analysis"].get("suspicious_imports") or event["static_analysis"].get("num_suspicious_imports")
    assert event["explanation"]["threat_explanation"] == "fake threat explanation"
    assert event["explanation"]["recommended_action"] == "fake recommended action"

    # ...but none of it survives into the persisted row: threat_events only
    # has columns for id/timestamp/file_path/file_hash/risk_score/
    # classification/virus_total_detections/malware_family/ai_summary/confidence.
    conn = sqlite3.connect(db_path)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(threat_events)")}
    conn.close()

    assert columns == {
        "id", "timestamp", "file_path", "file_hash", "risk_score", "classification",
        "virus_total_detections", "malware_family", "ai_summary", "confidence",
    }
    # No column exists to hold: risk reasons, static_analysis detail,
    # threat_explanation, recommended_action, or the full threat_intelligence dict.
