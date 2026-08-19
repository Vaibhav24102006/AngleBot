"""
tests/test_persistence_failure_modes.py

Step 7 — persistence failure modes against the REAL AdminEventLogger (not
FakePersistence). tests/test_analysis_pipeline.py already proves the
pipeline correctly surfaces both failure contracts (raises / returns
False) using fakes; this file proves the real component's actual behavior
under genuine SQLite failure conditions: a malformed database file, real
lock contention from another connection, and a missing parent directory.
No fabricated "success" is ever allowed to be reported when persistence
actually failed.
"""
import os
import sys
import sqlite3
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from event_logging.admin_event_logger import AdminEventLogger
from pipeline.analysis_pipeline import AnalysisPipeline
from tests.fixtures.pe_builder import make_suspicious_import_pe_bytes


class TestMissingParentDirectory:
    def test_db_path_with_nonexistent_parent_directory_is_created(self, tmp_path):
        db_path = str(tmp_path / "does" / "not" / "exist" / "events.db")
        logger = AdminEventLogger(db_path=db_path)  # must not raise
        assert os.path.isdir(os.path.dirname(db_path))
        assert logger.log_event({
            "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
            "file": {"path": "x.exe", "filename": "x.exe", "size": 1, "sha256": "h"},
            "static_analysis": {}, "risk": {"score": 0, "level": "SAFE", "reasons": []},
            "threat_intelligence": {"status": "unknown"}, "explanation": None,
            "recommended_action": "None.", "analysis_status": "completed",
        }) is True


class TestMalformedDatabaseFile:
    def test_non_sqlite_file_at_db_path_does_not_crash_construction(self, tmp_path):
        db_path = str(tmp_path / "not_a_real_db.db")
        with open(db_path, "w") as f:
            f.write("this is a plain text file, not a SQLite database\n" * 10)

        logger = AdminEventLogger(db_path=db_path)  # must not raise, even though schema init will fail

        result = logger.log_event({
            "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
            "file": {"path": "x.exe", "filename": "x.exe", "size": 1, "sha256": "h"},
            "static_analysis": {}, "risk": {"score": 0, "level": "SAFE", "reasons": []},
            "threat_intelligence": {"status": "unknown"}, "explanation": None,
            "recommended_action": "None.", "analysis_status": "completed",
        })
        # Must be observably False — never fabricate success against a
        # database that cannot actually store the row.
        assert result is False

    def test_pipeline_reports_persistence_error_against_a_malformed_database(self, tmp_path):
        db_path = str(tmp_path / "not_a_real_db.db")
        with open(db_path, "w") as f:
            f.write("garbage, not a sqlite file")

        logger = AdminEventLogger(db_path=db_path)
        path = tmp_path / "susp.exe"
        path.write_bytes(make_suspicious_import_pe_bytes())
        pipeline = AnalysisPipeline(persistence=logger)

        event = pipeline.analyze_and_decide(str(path))

        assert event["analysis_status"] == "completed"  # local analysis is unaffected
        assert event["risk"]["score"] == 20  # the real result, not lost
        assert event["persistence_error"] is not None  # failure is observable, not silently "success"


class TestRealLockContention:
    def test_write_during_a_real_exclusive_lock_from_another_connection_does_not_report_false_success(self, tmp_path):
        """Holds a genuine EXCLUSIVE lock on the database file from a
        separate sqlite3 connection (not a mock) while AdminEventLogger
        tries to write. busy_timeout=3000ms (Step 6, D31) gives the write
        up to 3s to acquire the lock; this test holds the lock for longer
        than that, so the write must fail observably, not report false
        success and not hang forever."""
        db_path = str(tmp_path / "locked.db")
        AdminEventLogger(db_path=db_path)  # create + migrate schema first

        blocker = sqlite3.connect(db_path, timeout=0)
        blocker.execute("BEGIN EXCLUSIVE")

        try:
            logger = AdminEventLogger(db_path=db_path)
            t0 = time.time()
            result = logger.log_event({
                "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
                "file": {"path": "x.exe", "filename": "x.exe", "size": 1, "sha256": "h"},
                "static_analysis": {}, "risk": {"score": 0, "level": "SAFE", "reasons": []},
                "threat_intelligence": {"status": "unknown"}, "explanation": None,
                "recommended_action": "None.", "analysis_status": "completed",
            })
            elapsed = time.time() - t0

            assert result is False
            # Respected the busy_timeout rather than failing instantly or
            # hanging indefinitely.
            assert elapsed < 10, f"took {elapsed:.1f}s — busy_timeout should bound this"
        finally:
            blocker.rollback()
            blocker.close()

    def test_write_succeeds_once_the_lock_is_released_within_the_timeout_window(self, tmp_path):
        """A transient lock (released well within busy_timeout) must NOT
        cause a false failure — the retry-via-wait must actually work."""
        db_path = str(tmp_path / "transient_lock.db")
        AdminEventLogger(db_path=db_path)

        # check_same_thread=False: this connection is intentionally released
        # from a different thread below, to simulate a real transient lock
        # from another process/thread without tying up the test's own
        # thread in a sleep.
        blocker = sqlite3.connect(db_path, timeout=0, check_same_thread=False)
        blocker.execute("BEGIN EXCLUSIVE")

        def release_after_delay():
            time.sleep(0.3)
            blocker.rollback()
            blocker.close()

        releaser = threading.Thread(target=release_after_delay)
        releaser.start()

        logger = AdminEventLogger(db_path=db_path)
        result = logger.log_event({
            "event_id": "e1", "timestamp": "2026-01-01T00:00:00Z",
            "file": {"path": "x.exe", "filename": "x.exe", "size": 1, "sha256": "h"},
            "static_analysis": {}, "risk": {"score": 0, "level": "SAFE", "reasons": []},
            "threat_intelligence": {"status": "unknown"}, "explanation": None,
            "recommended_action": "None.", "analysis_status": "completed",
        })
        releaser.join()

        assert result is True
        assert logger.get_event("e1") is not None
