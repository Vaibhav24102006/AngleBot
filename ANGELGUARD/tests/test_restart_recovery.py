"""
tests/test_restart_recovery.py

Step 7 — restart/recovery testing. ANGELGUARD is a desktop application;
its database must survive a process restart with no schema corruption and
full history intact, and an already-migrated (Step 5B) database must stay
readable across restarts too. "Restart" here means constructing a fresh
AdminEventLogger against the same db_path — that's the real recovery unit,
since __init__ is exactly what runs the additive migration (see
DECISIONS.md Step 5B) on every process start.
"""
import os
import sys
import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline
from event_logging.admin_event_logger import AdminEventLogger
from tests.fixtures.pe_builder import make_suspicious_import_pe_bytes


class TestHistorySurvivesRestart:
    def test_analyze_persist_close_restart_history_still_available(self, tmp_path):
        db_path = str(tmp_path / "recovery.db")
        path = tmp_path / "susp.exe"
        path.write_bytes(make_suspicious_import_pe_bytes())

        # "Start" — first process lifetime
        logger1 = AdminEventLogger(db_path=db_path)
        pipeline = AnalysisPipeline(persistence=logger1)
        event = pipeline.analyze_and_decide(str(path))
        assert event["persistence_error"] is None
        event_id = event["event_id"]
        del logger1, pipeline  # "close" — drop all references

        # "Restart" — brand new AdminEventLogger instance, same db file
        logger2 = AdminEventLogger(db_path=db_path)
        history = logger2.list_events()
        retrieved = logger2.get_event(event_id)

        assert len(history) == 1
        assert retrieved is not None
        assert retrieved["risk"]["level"] == "SUSPICIOUS"
        assert retrieved["file"]["filename"] == "susp.exe"

    def test_multiple_restarts_accumulate_history_without_loss(self, tmp_path):
        db_path = str(tmp_path / "recovery.db")

        for i in range(3):
            logger = AdminEventLogger(db_path=db_path)  # simulates a fresh restart each time
            path = tmp_path / f"file{i}.exe"
            path.write_bytes(make_suspicious_import_pe_bytes())
            pipeline = AnalysisPipeline(persistence=logger)
            pipeline.analyze_and_decide(str(path))

        final_logger = AdminEventLogger(db_path=db_path)
        assert len(final_logger.list_events(limit=10)) == 3


class TestSchemaStabilityAcrossRestarts:
    def test_repeated_construction_against_an_existing_db_does_not_corrupt_schema(self, tmp_path):
        db_path = str(tmp_path / "stable.db")

        for _ in range(5):
            AdminEventLogger(db_path=db_path)  # migration runs every time — must be idempotent

        conn = sqlite3.connect(db_path)
        columns = [row[1] for row in conn.execute("PRAGMA table_info(threat_events)")]
        conn.close()

        expected = {
            "id", "timestamp", "file_path", "file_hash", "risk_score", "classification",
            "virus_total_detections", "malware_family", "ai_summary", "confidence",
            "event_id", "file_size", "risk_reasons", "static_analysis_json",
            "threat_intelligence_json", "explanation_json", "recommended_action", "analysis_status",
        }
        assert set(columns) == expected
        assert len(columns) == len(set(columns))  # no duplicate columns from repeated ALTER TABLE

    def test_database_remains_usable_after_many_restarts(self, tmp_path):
        db_path = str(tmp_path / "stable.db")
        for _ in range(5):
            logger = AdminEventLogger(db_path=db_path)
        # The last-constructed logger must still work normally.
        path = tmp_path / "final.exe"
        path.write_bytes(make_suspicious_import_pe_bytes())
        pipeline = AnalysisPipeline(persistence=logger)
        event = pipeline.analyze_and_decide(str(path))
        assert event["persistence_error"] is None
        assert logger.get_event(event["event_id"]) is not None


class TestOldMigratedDatabaseStaysReadable:
    def test_pre_step5b_schema_database_is_migrated_and_stays_readable_across_restarts(self, tmp_path):
        db_path = str(tmp_path / "legacy_then_restarted.db")

        # Build a database on the ORIGINAL (pre-Step-5B) schema directly,
        # bypassing AdminEventLogger, then simulate several subsequent
        # "restarts" against it.
        conn = sqlite3.connect(db_path)
        conn.execute('''
            CREATE TABLE threat_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, file_path TEXT, file_hash TEXT,
                risk_score INTEGER, classification TEXT,
                virus_total_detections INTEGER, malware_family TEXT,
                ai_summary TEXT, confidence TEXT
            )
        ''')
        conn.execute('''
            INSERT INTO threat_events (timestamp, file_path, file_hash, risk_score, classification,
                virus_total_detections, malware_family, ai_summary, confidence)
            VALUES ('2025-01-01T00:00:00Z', 'legacy.exe', 'legacyhash', 40, 'SUSPICIOUS', 2, 'Unknown', 'legacy', 'medium')
        ''')
        conn.commit()
        conn.close()

        # Restart 1: migration runs, legacy row must survive.
        logger1 = AdminEventLogger(db_path=db_path)
        assert len(logger1.list_events(limit=10)) == 1
        del logger1

        # Restart 2 and 3: still readable, still exactly one row, no
        # duplicate migration side effects.
        for _ in range(2):
            logger = AdminEventLogger(db_path=db_path)
        events = logger.list_events(limit=10)
        assert len(events) == 1
        assert events[0]["file"]["path"] == "legacy.exe"
        assert events[0]["event_id"] is None  # never fabricated for the pre-existing row
