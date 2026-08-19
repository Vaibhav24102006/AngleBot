"""
tests/test_stress_rapid_events.py

Step 7 — controlled stress test: several distinct benign PE fixtures
dropped in rapid succession through the real DownloadMonitorHandler and a
real (temp-db) pipeline. Establishes actual behavior (are all detected? any
duplicated or lost? does the DB end up consistent?) rather than assuming
it — no premature optimization, no malware, no network.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from watchdog.events import FileCreatedEvent

from monitor.monitor_service import DownloadMonitorHandler
from pipeline.analysis_pipeline import AnalysisPipeline
from event_logging.admin_event_logger import AdminEventLogger
from tests.fixtures.pe_builder import make_valid_pe_bytes, make_suspicious_import_pe_bytes


class TestRapidMultiFileBurst:
    def test_twenty_distinct_files_dropped_rapidly_are_all_analyzed_exactly_once(self, tmp_path):
        db_path = str(tmp_path / "stress.db")
        logger = AdminEventLogger(db_path=db_path)
        pipeline = AnalysisPipeline(persistence=logger)
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.001, retry_interval_seconds=0.001)

        paths = []
        for i in range(20):
            data = make_suspicious_import_pe_bytes() if i % 3 == 0 else make_valid_pe_bytes()
            path = tmp_path / f"burst_file_{i:03d}.exe"
            path.write_bytes(data)
            paths.append(str(path))

        # Fire created events for all 20 in immediate succession — watchdog
        # dispatches serially in real use, and DownloadMonitorHandler has no
        # internal threading of its own, so calling on_created() back-to-back
        # here is a faithful (and deterministic) stand-in for that dispatch.
        for path in paths:
            handler.on_created(FileCreatedEvent(path))

        events = logger.list_events(limit=100)
        analyzed_paths = {e["file"]["path"] for e in events}

        assert len(events) == 20, f"expected 20 persisted events, got {len(events)}"
        assert analyzed_paths == set(paths), "every dropped file must be represented exactly once"
        # No duplicate event_ids (would indicate double-processing collapsed
        # via the idempotent upsert rather than genuinely 20 distinct events).
        event_ids = [e["event_id"] for e in events]
        assert len(event_ids) == len(set(event_ids))

    def test_burst_of_duplicate_events_for_the_same_files_still_yields_exactly_one_row_each(self, tmp_path):
        """The created+modified+moved burst pattern, at volume: 10 files,
        each firing 3 events (as a real download commonly does), must
        still yield exactly 10 persisted rows, not 30."""
        db_path = str(tmp_path / "stress_dup.db")
        logger = AdminEventLogger(db_path=db_path)
        pipeline = AnalysisPipeline(persistence=logger)
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.001, retry_interval_seconds=0.001)

        paths = []
        for i in range(10):
            path = tmp_path / f"dup_burst_{i:03d}.exe"
            path.write_bytes(make_valid_pe_bytes())
            paths.append(str(path))

        for path in paths:
            handler.on_created(FileCreatedEvent(path))
            handler.on_modified(FileCreatedEvent(path))
            handler.on_modified(FileCreatedEvent(path))

        events = logger.list_events(limit=100)
        assert len(events) == 10

    def test_gui_history_panel_reflects_all_events_after_a_burst(self, tmp_path):
        """Confirms the GUI side stays consistent with the DB after a
        burst, not just the DB itself — GUI responsiveness during analysis
        is delegated to the existing thread-decoupling (HistoryPanel never
        touches the pipeline/watchdog thread), verified structurally here
        by simply reading the result after the burst completes."""
        import sys as _sys
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance() or QApplication(_sys.argv)
        from ui.history_panel import HistoryPanel

        db_path = str(tmp_path / "stress_gui.db")
        logger = AdminEventLogger(db_path=db_path)
        pipeline = AnalysisPipeline(persistence=logger)
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.001, retry_interval_seconds=0.001)

        for i in range(8):
            path = tmp_path / f"gui_burst_{i:03d}.exe"
            path.write_bytes(make_valid_pe_bytes())
            handler.on_created(FileCreatedEvent(str(path)))

        panel = HistoryPanel(logger, poll_interval_ms=0)
        panel.refresh()

        assert panel._table.rowCount() == 8
