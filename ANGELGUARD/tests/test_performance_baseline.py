"""
tests/test_performance_baseline.py

Step 7 — performance baseline. Measured once, manually, on real fixtures
(see DECISIONS.md Step 7 for the full numbers and the large-file
benchmark that justified config.settings.MAX_ANALYSIS_FILE_SIZE_BYTES):

    valid_small (1KB):          static analysis ~1.0ms,  full pipeline ~1.0ms
    suspicious_imports (1.5KB): static analysis ~1.5ms,  full pipeline ~1.5ms
    high_entropy (5KB):         static analysis ~2.7ms,  full pipeline ~2.9ms
    persistence (log_event):    ~3.9ms/write (temp db, fresh connection per call)
    large file (75MB):          ~31.6s, ~0.42s/MB, memory delta ~1:1 with size

These tests are deliberately loose bounds (hundreds of ms, not single
milliseconds) — the point is to catch a catastrophic regression (e.g. an
accidental O(n^2) reintroduced somewhere), not to chase micro-timing on
a shared/variable-speed CI machine. Do not tighten these without new
measurements to justify it.
"""
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline
from tests.fixtures.pe_builder import make_valid_pe_bytes, make_high_entropy_pe_bytes


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


class TestSmallFileBaseline:
    def test_typical_small_file_completes_well_under_one_second(self, tmp_path):
        path = _write(tmp_path, "typical.exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline()  # no network/AI/persistence overhead

        t0 = time.perf_counter()
        event = pipeline.analyze_and_decide(path)
        elapsed = time.perf_counter() - t0

        assert event["analysis_status"] == "completed"
        assert elapsed < 1.0, f"typical small-file analysis took {elapsed:.2f}s — investigate a regression"

    def test_high_entropy_section_does_not_blow_up_analysis_time(self, tmp_path):
        path = _write(tmp_path, "packed.exe", make_high_entropy_pe_bytes())
        pipeline = AnalysisPipeline()

        t0 = time.perf_counter()
        event = pipeline.analyze_and_decide(path)
        elapsed = time.perf_counter() - t0

        assert event["analysis_status"] == "completed"
        assert elapsed < 1.0


class TestLargeFileIsBoundedByThePolicyNotByAnalysisTime:
    def test_oversized_file_returns_immediately_regardless_of_its_size(self, tmp_path):
        """Proves the size-limit policy actually bounds worst-case latency
        — without it, a file at the measured ~0.42s/MB rate could take
        minutes. A 5MB file well over a small limit must still return in
        milliseconds because the expensive analysis is never attempted."""
        data = b"\x00" * (5 * 1024 * 1024)
        path = _write(tmp_path, "huge.exe", data)
        pipeline = AnalysisPipeline(max_file_size_bytes=1024)  # tiny limit

        t0 = time.perf_counter()
        event = pipeline.analyze_and_decide(path)
        elapsed = time.perf_counter() - t0

        assert event["analysis_status"] == "skipped:oversized"
        assert elapsed < 0.5
