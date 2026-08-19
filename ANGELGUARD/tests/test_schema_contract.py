"""
Step 3 schema-contract tests.

Unlike tests/test_intelligence_aggregation.py (which unit-tests the
aggregator against hand-shaped dicts), these tests run the REAL
static_analyzer.analyze_file() and risk_evaluator.evaluate_risk_as_dict()
against generated PE fixtures and feed their actual output straight into
aggregate_intelligence() — proving the three modules' contracts genuinely
fit together, not just that each one individually behaves as documented.

No test here requires a real external API — the ThreatIntelClient contract
(a dict, or {"status": "unknown"} on total failure) is exercised directly,
matching threat_intel/threat_intel_client.py's own documented return shape,
without making a network call.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from analysis.static_analyzer import analyze_file
from decision.risk_evaluator import evaluate_risk, evaluate_risk_as_dict
from intelligence.intelligence_aggregator import aggregate_intelligence
from tests.fixtures.pe_builder import (
    make_valid_pe_bytes,
    make_suspicious_import_pe_bytes,
    make_high_entropy_pe_bytes,
    make_truncated_pe_bytes,
)

UNKNOWN_TI = {"status": "unknown"}


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


class TestCompleteAnalysisFlowsThroughAggregation:
    def test_real_analyzer_and_risk_output_aggregate_correctly(self, tmp_path):
        data = make_suspicious_import_pe_bytes()  # 2 suspicious imports, no high entropy
        path = _write(tmp_path, "susp.exe", data)

        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        assert payload["file_path"] == path
        assert payload["hash"] == analysis["hash"]
        assert payload["static_analysis"]["suspicious_imports"] == 2
        assert payload["risk_assessment"]["classification"] == "SUSPICIOUS"
        assert payload["risk_assessment"]["risk_score"] == 20
        assert payload["threat_intelligence"] == {"status": "unknown"}

    def test_high_entropy_real_analysis_populates_entropy_and_packed_flag(self, tmp_path):
        data = make_high_entropy_pe_bytes()
        path = _write(tmp_path, "hi.exe", data)

        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        static = payload["static_analysis"]
        assert static["packed_flag"] is True
        assert static["entropy"] > 7.5  # matches the real .rdata section entropy
        assert static["high_entropy_sections"] == 1


class TestMissingOptionalDataIsNotMisrepresented:
    def test_clean_valid_pe_has_no_entropy_key_fabricated_as_a_lie(self, tmp_path):
        # A clean PE with a single low-entropy section legitimately HAS
        # entropy data (just low) — so the key should be present here,
        # unlike the "no sections at all" case tested below.
        data = make_valid_pe_bytes()
        path = _write(tmp_path, "clean.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        static = payload["static_analysis"]
        assert "entropy" in static
        assert static["entropy"] < 7.5
        assert static["packed_flag"] is False

    def test_unavailable_threat_intel_is_not_reported_as_clean(self, tmp_path):
        data = make_valid_pe_bytes()
        path = _write(tmp_path, "clean.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        # Must be represented as "we don't know", never as
        # virus_total_detections=0 (which would read as "verified clean").
        assert payload["threat_intelligence"] == {"status": "unknown"}
        assert "virus_total_detections" not in payload["threat_intelligence"]


class TestMalformedAnalysisIsHandledSafely:
    def test_truncated_pe_aggregates_without_crashing(self, tmp_path):
        data = make_truncated_pe_bytes()
        path = _write(tmp_path, "trunc.exe", data)
        analysis = analyze_file(path)
        assert analysis["error"] == "Not a valid PE file"

        risk = evaluate_risk_as_dict(analysis)  # must not raise
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)  # must not raise

        static = payload["static_analysis"]
        assert "entropy" not in static  # no sections were ever parsed
        assert payload["file_path"] == path

    def test_invalid_pe_risk_score_and_reasons_survive_into_payload(self, tmp_path):
        data = make_truncated_pe_bytes()
        path = _write(tmp_path, "trunc.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        assert payload["risk_assessment"]["risk_score"] == risk["risk_score"]
        assert payload["risk_assessment"]["classification"] == risk["classification"]
        assert payload["risk_assessment"]["reasons"] == risk["reasons"]
        assert "Invalid PE format" in payload["risk_assessment"]["reasons"]


class TestFieldPreservation:
    def test_suspicious_import_count_survives_aggregation_exactly(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        path = _write(tmp_path, "susp.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        assert payload["static_analysis"]["suspicious_imports"] == analysis["num_suspicious_imports"]

    def test_file_size_and_high_entropy_count_survive_aggregation_exactly(self, tmp_path):
        data = make_high_entropy_pe_bytes()
        path = _write(tmp_path, "hi.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, UNKNOWN_TI)

        static = payload["static_analysis"]
        assert static["file_size"] == analysis["file_size"]
        assert static["high_entropy_sections"] == analysis["high_entropy_sections"]


class TestRiskPreservation:
    def test_risk_score_classification_and_reasons_are_unchanged_by_aggregation(self, tmp_path):
        data = make_suspicious_import_pe_bytes()
        path = _write(tmp_path, "susp.exe", data)
        analysis = analyze_file(path)

        score, classification, reasons = evaluate_risk(analysis)  # the tuple form, directly
        risk_dict = evaluate_risk_as_dict(analysis)

        # evaluate_risk_as_dict must not alter the scoring algorithm's output.
        assert risk_dict == {"risk_score": score, "classification": classification, "reasons": reasons}

        payload = aggregate_intelligence(analysis, risk_dict, UNKNOWN_TI)
        assert payload["risk_assessment"]["risk_score"] == score
        assert payload["risk_assessment"]["classification"] == classification
        assert payload["risk_assessment"]["reasons"] == reasons


class TestThreatIntelFallback:
    def test_status_unknown_is_passed_through_verbatim(self, tmp_path):
        data = make_valid_pe_bytes()
        path = _write(tmp_path, "clean.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        payload = aggregate_intelligence(analysis, risk, {"status": "unknown"})
        assert payload["threat_intelligence"] == {"status": "unknown"}

    def test_real_threat_intel_shape_aggregates_correctly(self, tmp_path):
        # Matches ThreatIntelClient.get_reputation()'s documented success shape.
        data = make_valid_pe_bytes()
        path = _write(tmp_path, "clean.exe", data)
        analysis = analyze_file(path)
        risk = evaluate_risk_as_dict(analysis)
        ti = {
            "hash": analysis["hash"],
            "virus_total_detections": 0,
            "virus_total_total_engines": 70,
            "malwarebazaar_match": False,
            "malware_family": "Unknown",
            "confidence": "low",
        }
        payload = aggregate_intelligence(analysis, risk, ti)
        assert payload["threat_intelligence"]["virus_total_detections"] == 0
        assert payload["threat_intelligence"]["confidence"] == "low"
