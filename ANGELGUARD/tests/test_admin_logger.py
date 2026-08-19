"""
tests/test_admin_logger.py

AdminEventLogger contract tests. Updated in Step 5B for the new
log_event(final_event) / get_event / list_events API — see
DECISIONS.md Step 5B for why the contract changed (log_event used to take
a (payload, ai_explanation) pair drawn from the intermediate aggregator
output and had no retrieval API at all).
"""
import unittest
import sys
import os
import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from event_logging.admin_event_logger import AdminEventLogger


_UNSET = object()  # distinguishes "not passed" (use the default) from an explicit None


def _final_event(
    event_id="evt-1", timestamp="2026-03-06T18:20:00Z",
    path="installer.exe", sha256="abc123def456", size=204800,
    risk_score=68, risk_level="SUSPICIOUS", reasons=None,
    static_analysis=None, threat_intelligence=None, explanation=_UNSET,
    recommended_action="Exercise caution.", analysis_status="completed",
):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "file": {
            "path": path,
            "filename": os.path.basename(path) if path else None,
            "size": size,
            "sha256": sha256,
        },
        "static_analysis": static_analysis if static_analysis is not None else {
            "num_suspicious_imports": 3, "high_entropy_sections": 1,
            "sections": [{"name": ".text", "entropy": 7.9, "size": 4096}],
        },
        "risk": {
            "score": risk_score, "level": risk_level,
            "reasons": reasons if reasons is not None else ["Suspicious import detected (3 imports)"],
        },
        "threat_intelligence": threat_intelligence if threat_intelligence is not None else {
            "virus_total_detections": 12, "virus_total_total_engines": 70,
            "malwarebazaar_match": False, "malware_family": "RedLine Stealer",
        },
        "explanation": explanation if explanation is not _UNSET else {
            "ai_summary": "Packed executable likely associated with trojan loaders.",
            "threat_explanation": "High entropy section detected alongside suspicious imports.",
            "recommended_action": "Do not execute; verify the source.",
            "confidence": "high",
        },
        "recommended_action": recommended_action,
        "analysis_status": analysis_status,
    }


class TestAdminLogger(unittest.TestCase):
    def setUp(self):
        # Use an isolated test database inside the tests/data directory
        test_db_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(test_db_dir, exist_ok=True)
        self.test_db_path = os.path.join(test_db_dir, 'test_events.db')

        # Fresh initialization for each suite
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

        self.logger = AdminEventLogger(db_path=self.test_db_path)

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except PermissionError:
                pass  # Depending on environment SQLite may hold lock shortly

    def test_logger_stores_full_final_event(self):
        """Simulates recording a complete suspicious incident into the database."""
        event = _final_event()

        success = self.logger.log_event(event)
        self.assertTrue(success, "AdminLogger failed to store the event.")

        conn = sqlite3.connect(self.test_db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM threat_events").fetchone()
        conn.close()

        self.assertIsNotNone(row, "No row was written to the database.")
        self.assertEqual(row["event_id"], "evt-1")
        self.assertEqual(row["timestamp"], "2026-03-06T18:20:00Z")
        self.assertEqual(row["file_path"], "installer.exe")
        self.assertEqual(row["file_hash"], "abc123def456")
        self.assertEqual(row["file_size"], 204800)
        self.assertEqual(row["risk_score"], 68)
        self.assertEqual(row["classification"], "SUSPICIOUS")
        self.assertEqual(row["virus_total_detections"], 12)
        self.assertEqual(row["malware_family"], "RedLine Stealer")
        self.assertEqual(row["ai_summary"], "Packed executable likely associated with trojan loaders.")
        self.assertEqual(row["confidence"], "high")

    def test_logger_handles_fallback_safely(self):
        """Validates that a missing AI prompt or failed intel lookup logs safely."""
        event = _final_event(
            event_id="evt-2", path="safe.exe", sha256="clean123",
            risk_score=0, risk_level="SAFE", reasons=[],
            threat_intelligence={"status": "unknown"}, explanation=None,
            recommended_action="No action needed.",
        )

        self.logger.log_event(event)

        conn = sqlite3.connect(self.test_db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM threat_events WHERE classification = 'SAFE'").fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["classification"], "SAFE")
        self.assertEqual(row["virus_total_detections"], 0)  # VT default
        self.assertEqual(row["malware_family"], "Unknown")  # Malfam default
        self.assertEqual(row["ai_summary"], "unavailable")  # AI Summary fallback
        self.assertIsNone(row["explanation_json"])  # no fabricated explanation stored

    def test_round_trip_preserves_semantic_meaning(self):
        """final_event -> log_event() -> get_event() must yield an
        equivalent event: same identity, same risk/static/TI/explanation
        content — not necessarily byte-identical JSON formatting."""
        event = _final_event()
        self.logger.log_event(event)

        retrieved = self.logger.get_event("evt-1")

        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["event_id"], event["event_id"])
        self.assertEqual(retrieved["timestamp"], event["timestamp"])
        self.assertEqual(retrieved["file"]["path"], event["file"]["path"])
        self.assertEqual(retrieved["file"]["filename"], event["file"]["filename"])
        self.assertEqual(retrieved["file"]["sha256"], event["file"]["sha256"])
        self.assertEqual(retrieved["file"]["size"], event["file"]["size"])
        self.assertEqual(retrieved["risk"]["score"], event["risk"]["score"])
        self.assertEqual(retrieved["risk"]["level"], event["risk"]["level"])
        self.assertEqual(retrieved["risk"]["reasons"], event["risk"]["reasons"])
        self.assertEqual(retrieved["static_analysis"], event["static_analysis"])
        self.assertEqual(retrieved["threat_intelligence"], event["threat_intelligence"])
        self.assertEqual(retrieved["explanation"], event["explanation"])
        self.assertEqual(retrieved["recommended_action"], event["recommended_action"])
        self.assertEqual(retrieved["analysis_status"], event["analysis_status"])

    def test_get_event_returns_none_for_unknown_id(self):
        self.assertIsNone(self.logger.get_event("does-not-exist"))

    def test_list_events_returns_most_recent_first_with_limit(self):
        for i in range(5):
            self.logger.log_event(_final_event(event_id=f"evt-{i}", path=f"file{i}.exe"))

        events = self.logger.list_events(limit=3)

        self.assertEqual(len(events), 3)
        # Most recently inserted (evt-4) first.
        self.assertEqual([e["event_id"] for e in events], ["evt-4", "evt-3", "evt-2"])

    def test_duplicate_event_id_is_idempotent_not_duplicated(self):
        """Re-logging the same event_id must update the existing row
        (last write wins), not create a second row — see DECISIONS.md
        Step 5B for why idempotent persistence was chosen."""
        first = _final_event(event_id="evt-dup", risk_score=20, risk_level="SUSPICIOUS")
        self.logger.log_event(first)

        second = _final_event(event_id="evt-dup", risk_score=90, risk_level="HIGH_RISK")
        self.logger.log_event(second)

        conn = sqlite3.connect(self.test_db_path)
        count = conn.execute(
            "SELECT COUNT(*) FROM threat_events WHERE event_id = 'evt-dup'"
        ).fetchone()[0]
        conn.close()
        self.assertEqual(count, 1, "duplicate event_id must not create a second row")

        retrieved = self.logger.get_event("evt-dup")
        self.assertEqual(retrieved["risk"]["level"], "HIGH_RISK")  # last write wins
        self.assertEqual(retrieved["risk"]["score"], 90)

    def test_events_without_event_id_do_not_collide(self):
        """A caller that never sets event_id (not the pipeline's own usage,
        but defensively supported) must not have its rows treated as
        duplicates of one another — SQL NULL is never equal to NULL."""
        self.logger.log_event(_final_event(event_id=None, path="a.exe"))
        self.logger.log_event(_final_event(event_id=None, path="b.exe"))

        conn = sqlite3.connect(self.test_db_path)
        count = conn.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)


class TestSchemaMigrationFromLegacyDatabase(unittest.TestCase):
    """Verifies an additive migration against a database created under the
    pre-Step-5B schema: old rows survive unmodified, new columns are NULL
    for them, and new events written afterward get the full schema."""

    def setUp(self):
        test_db_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(test_db_dir, exist_ok=True)
        self.test_db_path = os.path.join(test_db_dir, 'test_legacy_migration.db')
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)

        # Build a database using exactly the original (pre-Step-5B) schema,
        # bypassing AdminEventLogger entirely, then insert one legacy row.
        conn = sqlite3.connect(self.test_db_path)
        conn.execute('''
            CREATE TABLE threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                file_path TEXT,
                file_hash TEXT,
                risk_score INTEGER,
                classification TEXT,
                virus_total_detections INTEGER,
                malware_family TEXT,
                ai_summary TEXT,
                confidence TEXT
            )
        ''')
        conn.execute('''
            INSERT INTO threat_events (
                timestamp, file_path, file_hash, risk_score, classification,
                virus_total_detections, malware_family, ai_summary, confidence
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', ("2025-01-01T00:00:00Z", "legacy.exe", "legacyhash", 40,
              "SUSPICIOUS", 2, "Unknown", "legacy summary", "medium"))
        conn.commit()
        conn.close()

    def tearDown(self):
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except PermissionError:
                pass

    def test_migration_preserves_old_row_and_adds_null_columns(self):
        # Constructing AdminEventLogger against the legacy db runs the
        # additive migration.
        logger = AdminEventLogger(db_path=self.test_db_path)

        conn = sqlite3.connect(self.test_db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM threat_events WHERE file_path = 'legacy.exe'"
        ).fetchone()
        conn.close()

        self.assertIsNotNone(row, "legacy row must survive the migration")
        # Original data untouched.
        self.assertEqual(row["timestamp"], "2025-01-01T00:00:00Z")
        self.assertEqual(row["risk_score"], 40)
        self.assertEqual(row["classification"], "SUSPICIOUS")
        self.assertEqual(row["ai_summary"], "legacy summary")
        # New columns exist and are NULL — no fabricated historical data.
        self.assertIsNone(row["event_id"])
        self.assertIsNone(row["file_size"])
        self.assertIsNone(row["risk_reasons"])
        self.assertIsNone(row["static_analysis_json"])
        self.assertIsNone(row["threat_intelligence_json"])
        self.assertIsNone(row["explanation_json"])
        self.assertIsNone(row["recommended_action"])
        self.assertIsNone(row["analysis_status"])

        # get_event on the legacy row returns a well-formed (if sparse)
        # canonical-shaped dict rather than raising.
        retrieved = logger.list_events(limit=10)
        self.assertEqual(len(retrieved), 1)
        self.assertIsNone(retrieved[0]["event_id"])
        self.assertEqual(retrieved[0]["static_analysis"], {})
        self.assertEqual(retrieved[0]["risk"]["reasons"], [])

    def test_new_event_after_migration_has_full_schema(self):
        logger = AdminEventLogger(db_path=self.test_db_path)
        logger.log_event(_final_event(event_id="evt-new", path="new.exe"))

        retrieved = logger.get_event("evt-new")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["file"]["path"], "new.exe")
        self.assertEqual(retrieved["risk"]["reasons"], ["Suspicious import detected (3 imports)"])
        self.assertTrue(retrieved["static_analysis"])
        self.assertTrue(retrieved["threat_intelligence"])
        self.assertTrue(retrieved["explanation"])

        # Old and new rows coexist.
        conn = sqlite3.connect(self.test_db_path)
        count = conn.execute("SELECT COUNT(*) FROM threat_events").fetchone()[0]
        conn.close()
        self.assertEqual(count, 2)


if __name__ == '__main__':
    unittest.main()
