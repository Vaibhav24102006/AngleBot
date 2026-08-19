"""
Step 4 orchestration tests for pipeline/analysis_pipeline.py.

Runs the REAL analyzer/risk/aggregator chain (via generated PE fixtures)
through AnalysisPipeline, with fakes standing in for every optional
external/UI dependency (threat intel, AI, persistence, guidance) — matching
the same "no live external services in tests" rule as every other suite in
this project. No test starts watchdog; the pipeline is called directly,
proving it's independently invocable.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from pipeline.analysis_pipeline import AnalysisPipeline, build_default_pipeline
from tests.fixtures.pe_builder import (
    make_valid_pe_bytes,
    make_suspicious_import_pe_bytes,
    make_truncated_pe_bytes,
)


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


class FakeThreatIntel:
    def __init__(self, result=None, raises=None):
        self._result = result or {
            "virus_total_detections": 0, "virus_total_total_engines": 70,
            "malwarebazaar_match": False, "malware_family": "Unknown", "confidence": "low",
        }
        self._raises = raises
        self.calls = []

    def get_reputation(self, file_hash):
        self.calls.append(file_hash)
        if self._raises:
            raise self._raises
        return self._result


class FakeAIExplainer:
    def __init__(self, result="AUTO", raises=None):
        self._result = result
        self._raises = raises
        self.calls = []

    def generate_explanation(self, payload):
        self.calls.append(payload)
        if self._raises:
            raise self._raises
        if self._result == "AUTO":
            classification = payload["risk_assessment"]["classification"]
            if classification == "SAFE":
                return None
            return {
                "ai_summary": "fake summary", "threat_explanation": "fake explanation",
                "recommended_action": "fake recommended action", "confidence": "high",
            }
        return self._result


class FakePersistence:
    def __init__(self, raises=None, returns=True):
        self._raises = raises
        self._returns = returns
        self.calls = []

    def log_event(self, final_event):
        self.calls.append(final_event)
        if self._raises:
            raise self._raises
        return self._returns


class FakeGuidance:
    def __init__(self, raises=None):
        self._raises = raises
        self.calls = []

    def trigger(self, payload, explanation):
        self.calls.append((payload, explanation))
        if self._raises:
            raise self._raises


class TestHappyPath:
    def test_full_pipeline_produces_correct_canonical_event(self, tmp_path):
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        ti, ai, persistence, guidance = FakeThreatIntel(), FakeAIExplainer(), FakePersistence(), FakeGuidance()
        pipeline = AnalysisPipeline(threat_intel_client=ti, ai_explainer=ai, persistence=persistence, guidance=guidance)

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["event_id"]
        assert event["file"]["path"] == path
        assert event["file"]["filename"] == "susp.exe"
        assert event["file"]["size"] == os.path.getsize(path)
        assert event["risk"]["score"] == 20
        assert event["risk"]["level"] == "SUSPICIOUS"
        assert event["threat_intelligence"]["confidence"] == "low"
        assert event["explanation"]["ai_summary"] == "fake summary"
        assert event["recommended_action"] == "fake recommended action"
        assert event["persistence_error"] is None
        assert event["guidance_triggered"] is True
        # Persistence receives the canonical final event itself — including
        # event_id — not the intermediate aggregator payload (Step 5B).
        assert len(persistence.calls) == 1
        assert persistence.calls[0]["event_id"] == event["event_id"]
        assert persistence.calls[0] is event

    def test_safe_file_skips_ai_but_still_persists_and_does_not_trigger_guidance(self, tmp_path):
        path = _write(tmp_path, "clean.exe", make_valid_pe_bytes())
        ti, ai, persistence, guidance = FakeThreatIntel(), FakeAIExplainer(), FakePersistence(), FakeGuidance()
        pipeline = AnalysisPipeline(threat_intel_client=ti, ai_explainer=ai, persistence=persistence, guidance=guidance)

        event = pipeline.analyze_and_decide(path)

        assert event["risk"]["level"] == "SAFE"
        assert event["explanation"] is None  # FakeAIExplainer mirrors real skip-on-SAFE behavior
        assert event["recommended_action"] == "No action needed."
        assert len(persistence.calls) == 1
        assert event["guidance_triggered"] is False
        assert len(guidance.calls) == 1  # trigger() is still called; the fake just wasn't a warning

    def test_pipeline_is_independently_callable_without_watchdog(self, tmp_path):
        # No Observer, no monitor_service import anywhere in this file —
        # this test class itself is the proof.
        path = _write(tmp_path, "clean.exe", make_valid_pe_bytes())
        pipeline = AnalysisPipeline()  # zero dependencies at all
        event = pipeline.analyze_and_decide(path)
        assert event["analysis_status"] == "completed"


class TestThreatIntelFailureDegradesGracefully:
    def test_ti_exception_still_yields_a_complete_local_result(self, tmp_path):
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        ti = FakeThreatIntel(raises=ConnectionError("network down"))
        pipeline = AnalysisPipeline(threat_intel_client=ti, ai_explainer=FakeAIExplainer())

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["threat_intelligence"] == {"status": "unknown"}
        assert event["risk"]["score"] == 20  # local risk score unaffected by TI failure
        assert ti.calls  # it was actually attempted


class TestAIFailureDegradesGracefully:
    def test_ai_exception_still_yields_a_complete_local_result(self, tmp_path):
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        ai = FakeAIExplainer(raises=TimeoutError("openai timed out"))
        pipeline = AnalysisPipeline(threat_intel_client=FakeThreatIntel(), ai_explainer=ai)

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["explanation"] is None
        assert event["risk"]["score"] == 20
        # Falls back to the deterministic, non-AI recommended action.
        assert event["recommended_action"] == "Exercise caution — verify the file's source before executing it."


class TestMalformedFileProducesControlledResult:
    def test_truncated_pe_completes_with_correct_risk_no_crash(self, tmp_path):
        path = _write(tmp_path, "trunc.exe", make_truncated_pe_bytes())
        pipeline = AnalysisPipeline()  # no external deps needed for this one

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"  # static_analyzer handled it gracefully
        assert event["risk"]["level"] in ("SUSPICIOUS", "HIGH_RISK")
        assert "Invalid PE format" in event["risk"]["reasons"]
        assert "entropy" not in event["static_analysis"]  # no sections were ever parsed


class TestMissingFileProducesControlledResult:
    def test_nonexistent_path_does_not_crash(self, tmp_path):
        pipeline = AnalysisPipeline(
            threat_intel_client=FakeThreatIntel(), ai_explainer=FakeAIExplainer(),
            persistence=FakePersistence(), guidance=FakeGuidance(),
        )
        missing_path = str(tmp_path / "does_not_exist.exe")

        event = pipeline.analyze_and_decide(missing_path)

        assert event["analysis_status"] == "missing_file"
        assert event["risk"]["score"] is None
        assert event["guidance_triggered"] is False

    def test_missing_file_does_not_attempt_persistence_or_guidance(self, tmp_path):
        persistence, guidance = FakePersistence(), FakeGuidance()
        pipeline = AnalysisPipeline(persistence=persistence, guidance=guidance)
        pipeline.analyze_and_decide(str(tmp_path / "does_not_exist.exe"))
        assert persistence.calls == []
        assert guidance.calls == []


class TestPersistenceFailureIsObservableNotFatal:
    def test_persistence_exception_still_returns_the_analysis_result(self, tmp_path):
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        persistence = FakePersistence(raises=OSError("disk full"))
        pipeline = AnalysisPipeline(
            threat_intel_client=FakeThreatIntel(), ai_explainer=FakeAIExplainer(), persistence=persistence,
        )

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["risk"]["score"] == 20  # the actual result is intact
        assert event["persistence_error"] == "disk full"  # the failure is observable
        assert len(persistence.calls) == 1  # it really was attempted

    def test_persistence_returning_false_is_also_observable(self, tmp_path):
        # The real AdminEventLogger doesn't raise on a DB error — it catches
        # sqlite3.Error internally and returns False. The pipeline must
        # treat that as a failure too, not just an exception.
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        persistence = FakePersistence(returns=False)
        pipeline = AnalysisPipeline(
            threat_intel_client=FakeThreatIntel(), ai_explainer=FakeAIExplainer(), persistence=persistence,
        )

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["persistence_error"] is not None
        assert len(persistence.calls) == 1


class TestGuidanceFailureIsIsolated:
    def test_guidance_exception_does_not_break_the_pipeline(self, tmp_path):
        path = _write(tmp_path, "susp.exe", make_suspicious_import_pe_bytes())
        guidance = FakeGuidance(raises=RuntimeError("Qt not initialized"))
        pipeline = AnalysisPipeline(
            threat_intel_client=FakeThreatIntel(), ai_explainer=FakeAIExplainer(), guidance=guidance,
        )

        event = pipeline.analyze_and_decide(path)

        assert event["analysis_status"] == "completed"
        assert event["guidance_triggered"] is False


class TestNoExecution:
    def test_pipeline_source_contains_no_execution_primitives(self):
        import pipeline.analysis_pipeline as mod
        source = open(mod.__file__, encoding="utf-8").read()
        for forbidden in ("subprocess", "os.system(", "os.startfile", "ShellExecute"):
            assert forbidden not in source


class TestDefaultPipelineFactory:
    def test_build_default_pipeline_wires_real_components(self, tmp_path):
        # AdminEventLogger()'s constructor touches disk at its default path
        # (ANGELGUARD/data/angelguard_events.db) — redirect it to a temp
        # path here so this test doesn't leave an artifact in the real
        # project data directory on every test run.
        with patch("event_logging.admin_event_logger.AdminEventLogger") as MockLogger:
            MockLogger.return_value = object()
            pipeline = build_default_pipeline()

        assert isinstance(pipeline, AnalysisPipeline)
        assert pipeline._threat_intel_client is not None
        assert pipeline._ai_explainer is not None
        assert pipeline._persistence is not None
        assert pipeline._guidance is None  # never defaulted — see its docstring
