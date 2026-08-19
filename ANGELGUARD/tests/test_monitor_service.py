"""
tests/test_monitor_service.py

Step 7 — filesystem race/dedup coverage for monitor/monitor_service.py.
There was no dedicated test file for DownloadMonitorHandler before this
step. Uses a FakePipeline (no real analysis) since the point here is
detection/dedup logic, not the pipeline itself (already covered by
tests/test_analysis_pipeline.py). No sleeps longer than necessary — the
handler's own 1s settle delay and up to 5s of PermissionError retries are
exercised directly (they're small and deterministic), not mocked away,
since the retry/backoff behavior itself is part of what's under test.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from watchdog.events import FileCreatedEvent, FileModifiedEvent, FileMovedEvent, DirModifiedEvent

from monitor.monitor_service import DownloadMonitorHandler


class FakePipeline:
    def __init__(self):
        self.calls = []

    def analyze_and_decide(self, file_path):
        self.calls.append(file_path)
        return {
            "analysis_status": "completed",
            "risk": {"score": 0, "level": "SAFE", "reasons": []},
            "persistence_error": None,
            "guidance_triggered": False,
        }


def _write(tmp_path, name, content=b"MZ fake exe content"):
    path = tmp_path / name
    path.write_bytes(content)
    return str(path)


class TestNonExecutableEventsIgnored:
    def test_non_exe_file_is_never_analyzed(self, tmp_path):
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = _write(tmp_path, "notes.txt")

        handler.on_created(FileCreatedEvent(path))

        assert pipeline.calls == []

    def test_directory_event_is_ignored(self, tmp_path):
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        event = DirModifiedEvent(str(tmp_path / "some_dir.exe"))  # directory, despite the name

        handler.on_modified(event)

        assert pipeline.calls == []


class TestDuplicateEventBurstIsDeduped:
    def test_created_modified_moved_burst_for_one_write_analyzes_once(self, tmp_path):
        """watchdog commonly fires created + modified (+ moved, for a
        browser's .crdownload -> .exe rename) for a single physical
        download. All three must collapse into exactly one analysis."""
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = _write(tmp_path, "installer.exe")

        handler.on_created(FileCreatedEvent(path))
        handler.on_modified(FileModifiedEvent(path))
        handler.on_moved(FileMovedEvent(path + ".part", path))

        assert pipeline.calls == [path]


class TestSamePathNewContentIsReanalyzed:
    def test_different_content_at_same_path_is_analyzed_again(self, tmp_path):
        """Step 7 fix: the old path-only dedup cache meant a genuinely new
        file later downloaded to the same filename (browsers commonly
        reuse names like 'installer.exe') was silently never analyzed
        again for the life of the process. Content signature (size,
        mtime) must distinguish them."""
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = _write(tmp_path, "installer.exe", b"first version content")

        handler.on_created(FileCreatedEvent(path))
        assert len(pipeline.calls) == 1

        # Simulate the user deleting and re-downloading a DIFFERENT file to
        # the exact same path. Different size alone already changes the
        # (size, mtime) signature — no need to force an mtime difference.
        with open(path, "wb") as f:
            f.write(b"a completely different, longer replacement payload")

        handler.on_created(FileCreatedEvent(path))

        assert len(pipeline.calls) == 2, "a genuinely new file at the same path must be re-analyzed"


class TestFileDisappearsBeforeAccessible:
    def test_file_deleted_immediately_after_event_does_not_crash_or_call_pipeline(self, tmp_path):
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = str(tmp_path / "ghost.exe")
        # Never actually created — simulates a file that vanished (e.g. an
        # antivirus quarantine, or a browser cancelling a partial download)
        # between the OS event firing and the handler running.

        handler.on_created(FileCreatedEvent(path))  # must not raise

        assert pipeline.calls == []

    def test_no_signature_cached_for_a_file_that_never_existed(self, tmp_path):
        """A vanished file must not poison the dedup cache — if a real
        file later lands at that exact path, it must still be analyzed."""
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = str(tmp_path / "ghost.exe")

        handler.on_created(FileCreatedEvent(path))
        assert pipeline.calls == []

        with open(path, "wb") as f:
            f.write(b"now it actually exists")
        handler.on_created(FileCreatedEvent(path))

        assert len(pipeline.calls) == 1


class TestLockedFileRetry:
    def test_locked_file_is_retried_then_analyzed_once_released(self, tmp_path):
        """A file held open (still being written) must be retried, not
        given up on immediately, and must still be analyzed exactly once
        after it becomes accessible."""
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = _write(tmp_path, "slow_write.exe")

        real_open = open
        call_count = {"n": 0}

        def flaky_open(p, mode="r", *a, **kw):
            if p == path and "rb" in mode:
                call_count["n"] += 1
                if call_count["n"] <= 2:
                    raise PermissionError("still being written")
            return real_open(p, mode, *a, **kw)

        import builtins
        original = builtins.open
        builtins.open = flaky_open
        try:
            handler.on_created(FileCreatedEvent(path))
        finally:
            builtins.open = original

        assert len(pipeline.calls) == 1
        assert call_count["n"] >= 3  # two failures + the succeeding attempt

    def test_file_that_never_becomes_accessible_is_not_analyzed(self, tmp_path):
        pipeline = FakePipeline()
        handler = DownloadMonitorHandler(pipeline, settle_delay_seconds=0.01, retry_interval_seconds=0.01)
        path = _write(tmp_path, "permanently_locked.exe")

        real_open = open

        def always_locked(p, mode="r", *a, **kw):
            if p == path and "rb" in mode:
                raise PermissionError("locked forever")
            return real_open(p, mode, *a, **kw)

        import builtins
        original = builtins.open
        builtins.open = always_locked
        try:
            handler.on_created(FileCreatedEvent(path))
        finally:
            builtins.open = original

        assert pipeline.calls == []
