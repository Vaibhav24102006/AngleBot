"""
tests/test_large_file_handling.py

Step 7 — large-file reliability. analysis/static_analyzer.py reads the
whole file into memory and its entropy/string-extraction cost scales with
file size (measured ~0.42s/MB, memory delta ~1:1 with file size — see
DECISIONS.md Step 7's benchmark). Files above
config.settings.MAX_ANALYSIS_FILE_SIZE_BYTES now skip full analysis with a
controlled result instead of blocking analyze_and_decide() for minutes.

Uses AnalysisPipeline's injectable `max_file_size_bytes` to test the
POLICY with small, fast fixtures — not by actually building a 50MB+ file
in the test suite (that would make this test slow and heavy for no
additional coverage; the real analyzer's raw throughput was already
measured manually, once, to justify the threshold, not something that
needs to run on every test invocation).
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline
from tests.fixtures.pe_builder import make_valid_pe_bytes


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


class TestOversizedFileSkipsAnalysis:
    def test_file_over_the_limit_is_not_analyzed_and_says_so(self, tmp_path):
        path = _write(tmp_path, "huge.exe", b"\x00" * 2000)  # 2000 bytes
        pipeline = AnalysisPipeline(max_file_size_bytes=1000)  # 1000-byte limit

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "skipped:oversized"
        assert event["risk"]["score"] is None
        assert event["risk"]["level"] is None
        assert any("exceeds" in r for r in event["risk"]["reasons"])
        assert any("does NOT mean the file is safe" in r for r in event["risk"]["reasons"])

    def test_oversized_file_is_not_persisted_or_guidance_triggered(self, tmp_path):
        """Matches the existing missing_file/error:<stage> policy (D19):
        only a completed analysis reaches persistence/guidance."""
        path = _write(tmp_path, "huge.exe", b"\x00" * 2000)

        class FakePersistence:
            def __init__(self):
                self.calls = []

            def log_event(self, event):
                self.calls.append(event)
                return True

        class FakeGuidance:
            def __init__(self):
                self.calls = []

            def trigger(self, event):
                self.calls.append(event)

        persistence, guidance = FakePersistence(), FakeGuidance()
        pipeline = AnalysisPipeline(persistence=persistence, guidance=guidance, max_file_size_bytes=1000)

        event = pipeline.analyze_and_decide(path)

        assert event["persistence_error"] is None
        assert event["guidance_triggered"] is False
        assert persistence.calls == []
        assert guidance.calls == []

    def test_oversized_check_happens_before_any_analysis_attempt(self, tmp_path, monkeypatch):
        """The size check must short-circuit before analyze_file() is even
        called — that's the whole point (avoid the expensive read)."""
        import pipeline.analysis_pipeline as mod

        called = {"analyze_file": False}

        def spy_analyze_file(path):
            called["analyze_file"] = True
            return {}

        monkeypatch.setattr(mod, "analyze_file", spy_analyze_file)

        path = _write(tmp_path, "huge.exe", b"\x00" * 2000)
        pipeline = AnalysisPipeline(max_file_size_bytes=1000)
        pipeline.analyze_and_decide(path)

        assert called["analyze_file"] is False


class TestFileWithinLimitIsAnalyzedNormally:
    def test_file_under_the_limit_gets_full_analysis(self, tmp_path):
        path = _write(tmp_path, "normal.exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline(max_file_size_bytes=10_000_000)  # generous limit

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["risk"]["score"] is not None

    def test_file_exactly_at_the_limit_is_analyzed(self, tmp_path):
        data = make_valid_pe_bytes()
        path = _write(tmp_path, "boundary.exe", data)
        exact_size = os.path.getsize(path)
        pipeline = AnalysisPipeline(max_file_size_bytes=exact_size)  # inclusive boundary

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"


class TestDefaultThresholdIsSaneAndConfigurable:
    def test_default_pipeline_uses_config_threshold(self):
        from config.settings import MAX_ANALYSIS_FILE_SIZE_BYTES
        pipeline = AnalysisPipeline()
        assert pipeline._max_file_size_bytes == MAX_ANALYSIS_FILE_SIZE_BYTES
        assert MAX_ANALYSIS_FILE_SIZE_BYTES > 0
