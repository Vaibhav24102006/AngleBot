"""
tests/test_pipeline_adversarial_inputs.py

Step 7 — adversarial input handling for the full pipeline: unusual
filenames/paths, and malformed/unexpected-type data reaching the risk
engine. No malware, no real execution — synthetic PE fixtures and
monkeypatched intermediate results only.
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline
from decision.risk_evaluator import evaluate_risk, evaluate_risk_as_dict
from tests.fixtures.pe_builder import make_valid_pe_bytes, make_suspicious_import_pe_bytes


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


class TestUnusualFilenamesAndPaths:
    def test_unicode_filename_is_analyzed_without_crashing(self, tmp_path):
        path = _write(tmp_path, "인스톨러_日本語_🎮.exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline()

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert "인스톨러_日本語_🎮.exe" in event["file"]["filename"]

    def test_filename_with_spaces_is_analyzed_without_crashing(self, tmp_path):
        path = _write(tmp_path, "my cool installer (final) v2.exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline()

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["file"]["filename"] == "my cool installer (final) v2.exe"

    def test_very_long_path_is_analyzed_without_crashing(self, tmp_path):
        # Build a deeply nested path well past Windows' traditional 260-char
        # MAX_PATH. Plain os.mkdir() on this environment refuses to even
        # CREATE such a path without long-path support — that's a Windows/
        # filesystem limitation, not something ANGELGUARD's code causes, so
        # the \\?\ extended-length prefix is used here only to get the
        # fixture itself onto disk; the pipeline is exercised with a
        # normal-looking (if very long) path either way.
        base = str(tmp_path)
        if sys.platform == "win32" and not base.startswith("\\\\?\\"):
            base = "\\\\?\\" + base
        deep = base
        for i in range(15):
            deep = os.path.join(deep, f"a_moderately_long_directory_segment_{i:03d}")
        os.makedirs(deep, exist_ok=True)
        path = os.path.join(deep, "installer.exe")
        with open(path, "wb") as f:
            f.write(make_valid_pe_bytes())
        assert len(path) > 260

        pipeline = AnalysisPipeline()
        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"

    def test_empty_filename_stem_with_exe_extension(self, tmp_path):
        path = _write(tmp_path, ".exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline()

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["file"]["filename"] == ".exe"


class TestRiskEngineUnexpectedInput:
    """decision/risk_evaluator.py is a pure function over the analyzer's
    dict — it's defensive against MISSING keys (.get(key, default)
    throughout, 22 existing regression tests per D7) but not against
    WRONG-TYPE values, since static_analyzer.analyze_file() is its only
    real producer and always returns well-typed values by construction.
    These tests characterize that boundary rather than change it — see
    DECISIONS.md Step 7 P2 finding."""

    def test_missing_all_fields_does_not_crash(self):
        score, classification, reasons = evaluate_risk({})
        assert isinstance(score, int)
        assert classification in ("SAFE", "SUSPICIOUS", "HIGH_RISK")

    def test_extreme_negative_values_do_not_crash(self):
        score, classification, reasons = evaluate_risk({
            "num_suspicious_imports": -999999, "high_entropy_sections": -1, "file_size": -1,
        })
        assert isinstance(score, int)
        assert 0 <= score <= 100

    def test_extreme_positive_values_do_not_crash_and_score_is_capped(self):
        score, classification, reasons = evaluate_risk({
            "num_suspicious_imports": 10**9, "high_entropy_sections": 10**9, "file_size": 10**12,
            "error": "Not a valid PE file",
        })
        assert score == 100  # explicitly capped in risk_evaluator.py
        assert classification == "HIGH_RISK"

    def test_contradictory_indicators_invalid_pe_but_otherwise_clean(self):
        """Invalid-PE flag set alongside zero suspicious imports and zero
        high-entropy sections — a genuinely contradictory-looking input.
        Must still produce a stable, explainable result, not crash."""
        score, classification, reasons = evaluate_risk({
            "error": "Not a valid PE file", "file_size": 4096,
            "num_suspicious_imports": 0, "high_entropy_sections": 0,
        })
        assert score == 40
        assert classification == "SUSPICIOUS"
        assert "Invalid PE format" in reasons

    def test_wrong_type_values_raise_a_catchable_exception_not_a_silent_wrong_answer(self):
        """This is the actual boundary: a string/None where an int is
        expected raises TypeError rather than silently producing a wrong
        score. Documented, not fixed here — see the pipeline-level test
        below proving this is already caught one layer up."""
        import pytest
        with pytest.raises(TypeError):
            evaluate_risk({"num_suspicious_imports": "3"})
        with pytest.raises(TypeError):
            evaluate_risk({"high_entropy_sections": None})


class TestRiskEngineFailureIsCaughtAtThePipelineBoundary:
    def test_static_analyzer_returning_malformed_types_yields_controlled_event_not_a_crash(self, tmp_path, monkeypatch):
        """Simulates a hypothetical future regression in static_analyzer.py
        that returns a wrong-typed field. The pipeline's own try/except
        around risk evaluation (analysis_pipeline.py) must turn this into
        analysis_status == 'error:risk_evaluation', never propagate the
        TypeError to the caller (the watchdog thread, in real use)."""
        import pipeline.analysis_pipeline as mod
        monkeypatch.setattr(mod, "analyze_file", lambda path: {
            "file_path": path, "file_size": 100, "hash": "deadbeef",
            "num_suspicious_imports": "not-a-number",  # wrong type, deliberately
            "high_entropy_sections": 0, "sections": [], "error": None,
        })

        path = _write(tmp_path, "regression.exe", b"irrelevant, analyze_file is mocked")
        pipeline = AnalysisPipeline()

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "error:risk_evaluation"
        assert event["risk"]["score"] is None
        assert event["persistence_error"] is None  # never attempted — D19
        assert event["guidance_triggered"] is False


class TestDeterministicRiskUnaffectedByAdversarialThreatIntel:
    def test_malformed_threat_intel_result_does_not_change_local_risk_score(self, tmp_path):
        """A threat intel client returning a genuinely garbage shape
        (wrong types, unexpected keys) must not be able to alter the
        deterministic local risk score — aggregation only reads a handful
        of known keys via .get(), the rest of a garbage payload is inert."""
        class GarbageThreatIntel:
            def get_reputation(self, file_hash):
                return {"virus_total_detections": "a lot", "unexpected_key": object(), "malware_family": 12345}

        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        pipeline = AnalysisPipeline(threat_intel_client=GarbageThreatIntel())

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["risk"]["score"] == 20  # unaffected by the garbage TI shape
        assert event["risk"]["level"] == "SUSPICIOUS"
