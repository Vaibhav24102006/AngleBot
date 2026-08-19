"""
pipeline/analysis_pipeline.py

Step 4 — the one authoritative ANGELGUARD analysis pipeline.

    file path
        -> static analysis        (analysis.static_analyzer)
        -> risk evaluation         (decision.risk_evaluator)
        -> threat intelligence     (threat_intel.threat_intel_client)   [optional]
        -> intelligence aggregation (intelligence.intelligence_aggregator)
        -> AI explanation           (ai.ai_explainer)                    [optional]
        -> canonical final event
        -> persistence              (event_logging.admin_event_logger)  [optional]
        -> employee guidance UI     (ui.employee_guidance)               [optional]

Every stage after risk evaluation is individually optional and individually
fault-isolated: threat intelligence, AI explanation, persistence, and
guidance are all enrichment/side-effect stages that must never take down
the pipeline or discard an already-computed local result. Static analysis
and risk evaluation are the deterministic security core — static_analyzer
already never raises for malformed/empty/non-PE input (see its own
docstring and tests/test_static_analyzer.py), and risk_evaluator is a pure
function over that output — but they're still wrapped individually here so
that if either DOES fail unexpectedly (a real bug, not an anticipated
failure mode), the pipeline reports exactly which stage broke and logs the
full traceback, rather than either crashing the caller or silently
swallowing the error.

This module has no monitoring/UI-framework logic of its own — it is called
by monitor/monitor_service.py, and is equally callable from a test, a CLI,
or any future caller, with zero dependency on watchdog or PyQt5 unless a
caller explicitly injects Qt-based guidance.
"""
import datetime
import logging
import os
import uuid
from typing import Any, Dict, Optional

from analysis.static_analyzer import analyze_file
from decision.risk_evaluator import evaluate_risk_as_dict
from intelligence.intelligence_aggregator import aggregate_intelligence

logger = logging.getLogger(__name__)

_DEFAULT_RECOMMENDED_ACTIONS = {
    "SAFE": "No action needed.",
    "SUSPICIOUS": "Exercise caution — verify the file's source before executing it.",
    "HIGH_RISK": "Do not execute this file. Delete it or contact your system administrator.",
}


def _utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


class AnalysisPipeline:
    """
    Orchestrates one end-to-end analysis. All external/optional
    dependencies are injected — pass None (the default) for any of
    threat_intel_client / ai_explainer / persistence / guidance to disable
    that stage entirely; the pipeline still produces a complete, correct
    result without it. This is what makes the pipeline safe to construct
    bare (`AnalysisPipeline()`) in tests with no network/GUI dependency at
    all, and what makes graceful degradation the DEFAULT behavior rather
    than something bolted on.
    """

    def __init__(
        self,
        *,
        threat_intel_client=None,
        ai_explainer=None,
        persistence=None,
        guidance=None,
    ):
        self._threat_intel_client = threat_intel_client
        self._ai_explainer = ai_explainer
        self._persistence = persistence
        self._guidance = guidance

    def analyze_and_decide(self, file_path: str) -> Dict[str, Any]:
        """
        Run the complete pipeline against one file and return the
        canonical final event (see module docstring for the stage order).
        Never raises — every failure mode becomes a value in the returned
        dict (`analysis_status`), never an exception the caller must
        catch.
        """
        event_id = str(uuid.uuid4())

        if not os.path.isfile(file_path):
            logger.warning(f"[Pipeline] File not found or inaccessible: {file_path}")
            return self._controlled_event(event_id, file_path, "missing_file",
                                           ["File not found or inaccessible at analysis time"])

        try:
            analysis = analyze_file(file_path)
        except Exception:
            logger.exception(f"[Pipeline] Unexpected error during static_analysis for {file_path}")
            return self._controlled_event(event_id, file_path, "error:static_analysis",
                                           ["Static analysis raised an unexpected error"])

        try:
            risk = evaluate_risk_as_dict(analysis)
        except Exception:
            logger.exception(f"[Pipeline] Unexpected error during risk_evaluation for {file_path}")
            return self._controlled_event(event_id, file_path, "error:risk_evaluation",
                                           ["Risk evaluation raised an unexpected error"])

        ti_result = self._run_threat_intel(analysis)

        try:
            payload = aggregate_intelligence(analysis, risk, ti_result)
        except Exception:
            logger.exception(f"[Pipeline] Unexpected error during aggregation for {file_path}")
            return self._controlled_event(event_id, file_path, "error:aggregation",
                                           ["Aggregation raised an unexpected error"])

        explanation = self._run_ai_explanation(payload)

        final_event = self._build_final_event(event_id, payload, explanation, "completed")
        final_event["persistence_error"] = self._run_persistence(payload, explanation)
        final_event["guidance_triggered"] = self._run_guidance(payload, explanation)

        return final_event

    # ------------------------------------------------------------------ #
    # Optional stages — each is individually fault-isolated. A failure
    # here degrades that one piece of enrichment; it never discards the
    # local analysis/risk result already computed above.
    # ------------------------------------------------------------------ #

    def _run_threat_intel(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        if self._threat_intel_client is None:
            return {"status": "unknown"}
        file_hash = analysis.get("hash")
        if not file_hash:
            return {"status": "unknown"}
        try:
            return self._threat_intel_client.get_reputation(file_hash)
        except Exception as exc:
            logger.warning(f"[Pipeline] Threat intelligence lookup failed, continuing without it: {exc}")
            return {"status": "unknown"}

    def _run_ai_explanation(self, payload: Dict[str, Any]) -> Optional[Dict[str, str]]:
        if self._ai_explainer is None:
            return None
        try:
            return self._ai_explainer.generate_explanation(payload)
        except Exception as exc:
            logger.warning(f"[Pipeline] AI explanation failed, continuing without it: {exc}")
            return None

    def _run_persistence(self, payload: Dict[str, Any], explanation: Optional[Dict[str, str]]) -> Optional[str]:
        """Returns None on success, or an observable error string on failure.
        The analysis result itself is always returned to the caller regardless.

        Two failure contracts are handled: a persistence backend that raises
        (e.g. a test fake), and one — like the real AdminEventLogger — that
        catches its own errors internally and reports failure via a `False`
        return value instead. Only an explicit `False` is treated as
        failure; `None`/`True`/no return at all all mean success, so
        backends with no return value don't get misreported as failing."""
        if self._persistence is None:
            return None
        try:
            result = self._persistence.log_event(payload, explanation or {})
            if result is False:
                logger.error("[Pipeline] Persistence backend reported failure logging analysis event.")
                return "Persistence backend reported failure (see logs for details)"
            return None
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to persist analysis event: {exc}")
            return str(exc)

    def _run_guidance(self, payload: Dict[str, Any], explanation: Optional[Dict[str, str]]) -> bool:
        """Returns True if the guidance UI was actually triggered (i.e. the
        classification warranted it and .trigger() did not raise)."""
        if self._guidance is None:
            return False
        try:
            self._guidance.trigger(payload, explanation or {})
            classification = payload.get("risk_assessment", {}).get("classification")
            return classification in ("SUSPICIOUS", "HIGH_RISK")
        except Exception as exc:
            logger.error(f"[Pipeline] Failed to trigger guidance UI: {exc}")
            return False

    # ------------------------------------------------------------------ #
    # Canonical event construction
    # ------------------------------------------------------------------ #

    def _recommended_action(self, classification: Optional[str], explanation: Optional[Dict[str, str]]) -> str:
        if explanation and explanation.get("recommended_action"):
            return explanation["recommended_action"]
        return _DEFAULT_RECOMMENDED_ACTIONS.get(
            classification, "Review this file before executing it."
        )

    def _build_final_event(
        self, event_id: str, payload: Dict[str, Any],
        explanation: Optional[Dict[str, str]], analysis_status: str,
    ) -> Dict[str, Any]:
        risk = payload.get("risk_assessment", {})
        static = payload.get("static_analysis", {})
        file_path = payload.get("file_path")
        return {
            "event_id": event_id,
            "timestamp": payload.get("timestamp", _utc_now_iso()),
            "file": {
                "path": file_path,
                "filename": os.path.basename(file_path) if file_path else None,
                "size": static.get("file_size"),
                "sha256": payload.get("hash"),
            },
            "static_analysis": static,
            "risk": {
                "score": risk.get("risk_score"),
                "level": risk.get("classification"),
                "reasons": risk.get("reasons", []),
            },
            "threat_intelligence": payload.get("threat_intelligence", {}),
            "explanation": explanation,
            "recommended_action": self._recommended_action(risk.get("classification"), explanation),
            "analysis_status": analysis_status,
        }

    def _controlled_event(
        self, event_id: str, file_path: str, analysis_status: str, reasons: list,
    ) -> Dict[str, Any]:
        """Used for the two cases that never reach aggregate_intelligence()
        at all: a missing file, or an unexpected exception in a core
        (non-optional) stage. Same top-level shape as a completed event so
        callers never need two code paths."""
        return {
            "event_id": event_id,
            "timestamp": _utc_now_iso(),
            "file": {
                "path": file_path,
                "filename": os.path.basename(file_path) if file_path else None,
                "size": None,
                "sha256": None,
            },
            "static_analysis": {},
            "risk": {"score": None, "level": None, "reasons": reasons},
            "threat_intelligence": {"status": "unknown"},
            "explanation": None,
            "recommended_action": "Analysis could not be completed — review this file manually before executing it.",
            "analysis_status": analysis_status,
            "persistence_error": None,
            "guidance_triggered": False,
        }


def build_default_pipeline(guidance=None) -> AnalysisPipeline:
    """
    Constructs the pipeline real (non-test) callers should use: a real
    ThreatIntelClient and AIExplainer (both already degrade gracefully with
    no API keys configured — see threat_intel/threat_intel_client.py and
    ai/ai_explainer.py) and a real AdminEventLogger as the canonical
    persistence backend (see DECISIONS.md Step 4 D-series for why
    AdminEventLogger, not logging_bak, is now canonical).

    `guidance` is intentionally NOT defaulted to a real GuidanceController
    here: PyQt5 guidance objects must be constructed on the same thread
    that runs the Qt event loop, which this factory function has no way of
    guaranteeing. Callers that want the warning UI wired in (e.g.
    app/main.py) construct their own GuidanceController on the main thread
    and pass it in explicitly.
    """
    from threat_intel.threat_intel_client import ThreatIntelClient
    from ai.ai_explainer import AIExplainer
    from event_logging.admin_event_logger import AdminEventLogger

    return AnalysisPipeline(
        threat_intel_client=ThreatIntelClient(),
        ai_explainer=AIExplainer(),
        persistence=AdminEventLogger(),
        guidance=guidance,
    )


_default_pipeline = None


def analyze_and_decide(file_path: str, pipeline: Optional[AnalysisPipeline] = None) -> Dict[str, Any]:
    """
    Module-level convenience entry point. Uses a lazily-built shared
    default pipeline (real threat intel + AI + persistence, no GUI) unless
    an explicit `pipeline` is passed — which is what tests and any
    GUI-aware caller should do instead of relying on the shared default.
    """
    global _default_pipeline
    if pipeline is not None:
        return pipeline.analyze_and_decide(file_path)
    if _default_pipeline is None:
        _default_pipeline = build_default_pipeline()
    return _default_pipeline.analyze_and_decide(file_path)
