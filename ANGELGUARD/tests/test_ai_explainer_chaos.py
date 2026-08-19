"""
tests/test_ai_explainer_chaos.py

Step 7 — deterministic external-service chaos coverage for
ai/ai_explainer.py. tests/test_ai_explainer.py already covers the
SAFE-skip and no-API-key-fallback paths, but its "runs on suspicious
files" test branches its own assertions on whether a real OPENAI_API_KEY
happens to be present in the environment — meaning it could make a REAL
network call on a machine that has one configured. This file replaces
that gap for the failure-mode matrix: every scenario here mocks the
OpenAI client directly, so behavior is identical and network-free
regardless of environment configuration.
"""
import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from unittest.mock import MagicMock

from ai.ai_explainer import AIExplainer


def _suspicious_payload():
    return {
        "file_path": "installer.exe",
        "hash": "abc123",
        "static_analysis": {"entropy": 7.9, "suspicious_imports": 3, "packed_flag": True},
        "risk_assessment": {"risk_score": 68, "classification": "SUSPICIOUS", "reasons": ["high entropy"]},
        "threat_intelligence": {"status": "unknown"},
        "timestamp": "2026-03-06T18:20:00Z",
    }


def _explainer_with_mock_client(chat_completions_create):
    """Builds an AIExplainer with a fully mocked OpenAI client, bypassing
    the real API-key/network path entirely — deterministic regardless of
    what's actually configured in this environment."""
    explainer = AIExplainer.__new__(AIExplainer)  # skip __init__'s real client construction
    explainer.timeout = 5
    explainer.client = MagicMock()
    explainer.client.chat.completions.create = chat_completions_create
    return explainer


def _openai_response(content: str):
    resp = MagicMock()
    resp.choices = [MagicMock(message=MagicMock(content=content))]
    return resp


class TestAISuccess:
    def test_valid_json_response_is_parsed_and_normalized(self):
        explainer = _explainer_with_mock_client(MagicMock(return_value=_openai_response(json.dumps({
            "ai_summary": "This looks like a trojan dropper.",
            "threat_explanation": "High entropy plus suspicious imports.",
            "recommended_action": "Do not execute.",
            "confidence": "high",
        }))))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result["ai_summary"] == "This looks like a trojan dropper."
        assert result["confidence"] == "high"

    def test_response_missing_some_keys_is_normalized_with_safe_defaults(self):
        explainer = _explainer_with_mock_client(MagicMock(return_value=_openai_response(json.dumps({
            "ai_summary": "Partial response.",
            # threat_explanation, recommended_action, confidence all missing
        }))))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result["ai_summary"] == "Partial response."
        assert result["threat_explanation"] == "Explanation unavailable."
        assert result["confidence"] == "unknown"


class TestAIUnavailable:
    def test_client_not_initialized_returns_fallback_not_none(self):
        explainer = AIExplainer.__new__(AIExplainer)
        explainer.timeout = 5
        explainer.client = None

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "unavailable" in result["ai_summary"].lower()
        assert result["confidence"] == "unknown"


class TestAITimeout:
    def test_timeout_exception_returns_fallback_not_raises(self):
        def raise_timeout(*a, **kw):
            raise TimeoutError("request timed out")

        explainer = _explainer_with_mock_client(MagicMock(side_effect=raise_timeout))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "failed" in result["ai_summary"].lower()


class TestAIMalformedResponse:
    def test_non_json_response_returns_fallback_not_raises(self):
        explainer = _explainer_with_mock_client(MagicMock(return_value=_openai_response("not valid json at all")))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "failed" in result["ai_summary"].lower()

    def test_empty_response_content_returns_fallback_not_raises(self):
        explainer = _explainer_with_mock_client(MagicMock(return_value=_openai_response("")))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "failed" in result["ai_summary"].lower()

    def test_none_response_content_returns_fallback_not_raises(self):
        explainer = _explainer_with_mock_client(MagicMock(return_value=_openai_response(None)))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "failed" in result["ai_summary"].lower()


class TestAIUnexpectedException:
    def test_arbitrary_exception_from_the_client_returns_fallback_not_raises(self):
        def raise_weird(*a, **kw):
            raise RuntimeError("some unexpected SDK internal error")

        explainer = _explainer_with_mock_client(MagicMock(side_effect=raise_weird))

        result = explainer.generate_explanation(_suspicious_payload())

        assert result is not None
        assert "failed" in result["ai_summary"].lower()


class TestAINeverInventsAVerdict:
    def test_fallback_never_claims_safe_or_clean(self):
        explainer = AIExplainer.__new__(AIExplainer)
        explainer.timeout = 5
        explainer.client = None

        result = explainer.generate_explanation(_suspicious_payload())

        text = json.dumps(result).lower()
        assert "safe" not in text
        assert "clean" not in text
