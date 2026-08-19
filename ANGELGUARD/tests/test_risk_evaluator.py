"""
Regression suite for decision/risk_evaluator.py.

This locks in the ACTUAL scoring algorithm as implemented, not the four-tier
LOW/MEDIUM/HIGH/CRITICAL scheme from the original vision doc. The real
implementation has three tiers with thresholds at 20 and 60:

    score >= 60           -> HIGH_RISK
    20 <= score < 60       -> SUSPICIOUS
    score < 20              -> SAFE

and five additive, mostly-independent contributions:

    error == "Not a valid PE file"                         -> +40  "Invalid PE format"
    file_size == 0                                          -> +30  "Empty file"
    (elif) error not None and error != "Not a valid PE file" -> +30  "Analysis error: {error}"
    num_suspicious_imports > 0                                -> +20  "Suspicious import detected (N imports)"
    high_entropy_sections > 0                                  -> +40  "High entropy section detected (N sections)"
    score == 0                                                  -> reasons += "No suspicious indicators found"

score is capped at 100 via min(score, 100).

Because contributions only come in fixed chunks of {20, 30, 40}, the
achievable score set is {0, 20, 30, 40, 50, 60, 70, 80, 90, 100} — the
algorithm cannot produce every integer. "Boundary -1/boundary/boundary+1"
is therefore tested using the nearest ACHIEVABLE scores on each side of the
20 and 60 thresholds (0/20/30 and 50/60/70), which is what actually proves
the `>=` (inclusive) comparison is implemented correctly — a literal
score=19 or score=61 is not producible by this function and would not be a
meaningful regression test.
"""
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from decision.risk_evaluator import evaluate_risk


# --------------------------------------------------------------------------- #
# Lowest-risk input
# --------------------------------------------------------------------------- #

class TestLowestRisk:
    def test_clean_file_scores_zero_and_is_safe(self):
        analysis_result = {
            "error": None,
            "file_size": 1024,
            "num_suspicious_imports": 0,
            "high_entropy_sections": 0,
        }
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 0
        assert classification == "SAFE"
        assert reasons == ["No suspicious indicators found"]


# --------------------------------------------------------------------------- #
# Each signal in isolation
# --------------------------------------------------------------------------- #

class TestIndividualSignals:
    def test_invalid_pe_format_alone(self):
        analysis_result = {"error": "Not a valid PE file", "file_size": 100}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 40
        assert classification == "SUSPICIOUS"
        assert reasons == ["Invalid PE format"]

    def test_empty_file_alone(self):
        analysis_result = {"error": None, "file_size": 0}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 30
        assert classification == "SUSPICIOUS"
        assert reasons == ["Empty file"]

    def test_generic_analysis_error_alone(self):
        # Only reachable when file_size != 0 — the elif is attached to the
        # file_size == 0 check, so a nonzero-size file with some other
        # error string takes this branch instead of "Empty file".
        analysis_result = {"error": "PE parsing error: boom", "file_size": 500}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 30
        assert classification == "SUSPICIOUS"
        assert reasons == ["Analysis error: PE parsing error: boom"]

    def test_suspicious_imports_alone(self):
        analysis_result = {
            "error": None, "file_size": 1024,
            "num_suspicious_imports": 3, "high_entropy_sections": 0,
        }
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 20
        assert classification == "SUSPICIOUS"
        assert reasons == ["Suspicious import detected (3 imports)"]

    def test_high_entropy_alone(self):
        analysis_result = {
            "error": None, "file_size": 1024,
            "num_suspicious_imports": 0, "high_entropy_sections": 2,
        }
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 40
        assert classification == "SUSPICIOUS"
        assert reasons == ["High entropy section detected (2 sections)"]


# --------------------------------------------------------------------------- #
# Combined signals
# --------------------------------------------------------------------------- #

class TestCombinedSignals:
    def test_suspicious_imports_plus_high_entropy(self):
        analysis_result = {
            "error": None, "file_size": 1024,
            "num_suspicious_imports": 1, "high_entropy_sections": 1,
        }
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 60
        assert classification == "HIGH_RISK"
        assert reasons == [
            "Suspicious import detected (1 imports)",
            "High entropy section detected (1 sections)",
        ]

    def test_real_empty_file_through_static_analyzer_double_counts(self):
        # This is the ACTUAL shape static_analyzer.analyze_file() produces
        # for a 0-byte file: pefile raises PEFormatError("The file is
        # empty"), which static_analyzer maps to error="Not a valid PE
        # file" — so both the "invalid PE" and "empty file" branches fire
        # for the exact same real-world input.
        analysis_result = {"error": "Not a valid PE file", "file_size": 0}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 70
        assert classification == "HIGH_RISK"
        assert reasons == ["Invalid PE format", "Empty file"]

    def test_invalid_pe_plus_suspicious_plus_entropy(self):
        analysis_result = {
            "error": "Not a valid PE file", "file_size": 100,
            "num_suspicious_imports": 2, "high_entropy_sections": 1,
        }
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 100
        assert classification == "HIGH_RISK"


# --------------------------------------------------------------------------- #
# Classification boundaries (nearest achievable scores — see module docstring)
# --------------------------------------------------------------------------- #

class TestClassificationBoundaries:
    def test_score_0_is_safe(self):
        _, classification, _ = evaluate_risk(
            {"error": None, "file_size": 1024, "num_suspicious_imports": 0, "high_entropy_sections": 0}
        )
        assert classification == "SAFE"

    def test_score_20_is_suspicious_lower_boundary_inclusive(self):
        _, classification, _ = evaluate_risk(
            {"error": None, "file_size": 1024, "num_suspicious_imports": 1, "high_entropy_sections": 0}
        )
        assert classification == "SUSPICIOUS"

    def test_score_30_is_suspicious(self):
        _, classification, _ = evaluate_risk({"error": None, "file_size": 0})
        assert classification == "SUSPICIOUS"

    def test_score_50_is_still_suspicious_just_below_high_risk(self):
        analysis_result = {
            "error": None, "file_size": 0,  # +30
            "num_suspicious_imports": 1, "high_entropy_sections": 0,  # +20
        }
        score, classification, _ = evaluate_risk(analysis_result)
        assert score == 50
        assert classification == "SUSPICIOUS"

    def test_score_60_is_high_risk_upper_boundary_inclusive(self):
        analysis_result = {
            "error": None, "file_size": 1024,
            "num_suspicious_imports": 1, "high_entropy_sections": 1,  # 20 + 40
        }
        score, classification, _ = evaluate_risk(analysis_result)
        assert score == 60
        assert classification == "HIGH_RISK"

    def test_score_70_is_high_risk(self):
        analysis_result = {"error": "Not a valid PE file", "file_size": 0}  # 40 + 30
        score, classification, _ = evaluate_risk(analysis_result)
        assert score == 70
        assert classification == "HIGH_RISK"


# --------------------------------------------------------------------------- #
# Score capping
# --------------------------------------------------------------------------- #

class TestScoreCapping:
    def test_score_is_capped_at_100(self):
        # 40 (invalid PE) + 30 (empty file) + 20 (suspicious) + 40 (entropy) = 130 -> capped
        analysis_result = {
            "error": "Not a valid PE file", "file_size": 0,
            "num_suspicious_imports": 5, "high_entropy_sections": 3,
        }
        score, classification, _ = evaluate_risk(analysis_result)
        assert score == 100
        assert classification == "HIGH_RISK"


# --------------------------------------------------------------------------- #
# Missing / partial input
# --------------------------------------------------------------------------- #

class TestMissingFields:
    def test_completely_empty_dict_does_not_crash(self):
        # Every field falls back to its .get() default. file_size defaults
        # to 0, which is indistinguishable from a real empty file, so this
        # is treated as "Empty file" rather than as "no data available".
        score, classification, reasons = evaluate_risk({})
        assert score == 30
        assert classification == "SUSPICIOUS"
        assert reasons == ["Empty file"]

    def test_missing_optional_indicators_does_not_crash(self):
        # file_size present and nonzero; num_suspicious_imports and
        # high_entropy_sections both absent entirely (not just zero).
        analysis_result = {"error": None, "file_size": 2048}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 0
        assert classification == "SAFE"
        assert reasons == ["No suspicious indicators found"]

    def test_missing_error_key_defaults_to_falsy(self):
        analysis_result = {"file_size": 1024, "num_suspicious_imports": 0, "high_entropy_sections": 0}
        score, classification, reasons = evaluate_risk(analysis_result)
        assert score == 0
        assert classification == "SAFE"


# --------------------------------------------------------------------------- #
# Explainability: every non-zero contribution has a matching reason
# --------------------------------------------------------------------------- #

class TestExplainability:
    def test_zero_score_has_exactly_one_explanatory_reason(self):
        _, _, reasons = evaluate_risk(
            {"error": None, "file_size": 1024, "num_suspicious_imports": 0, "high_entropy_sections": 0}
        )
        assert len(reasons) == 1
        assert reasons[0]

    def test_every_signal_present_produces_its_own_reason_string(self):
        analysis_result = {
            "error": "Not a valid PE file", "file_size": 0,
            "num_suspicious_imports": 4, "high_entropy_sections": 2,
        }
        _, _, reasons = evaluate_risk(analysis_result)
        assert reasons == [
            "Invalid PE format",
            "Empty file",
            "Suspicious import detected (4 imports)",
            "High entropy section detected (2 sections)",
        ]

    def test_reason_count_never_includes_the_safe_fallback_when_score_nonzero(self):
        _, _, reasons = evaluate_risk(
            {"error": None, "file_size": 1024, "num_suspicious_imports": 1, "high_entropy_sections": 0}
        )
        assert "No suspicious indicators found" not in reasons
