import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from intelligence.intelligence_aggregator import aggregate_intelligence

class TestIntelligenceAggregation(unittest.TestCase):
    def setUp(self):
        # Base Mock Inputs — shaped exactly like the REAL output of
        # analysis.static_analyzer.analyze_file() and
        # decision.risk_evaluator.evaluate_risk_as_dict() (Step 3 canonical
        # schema). Earlier versions of this fixture used a fictional
        # top-level "entropy"/"packed" shape that static_analyzer never
        # actually produces — see DECISIONS.md Step 3 for why that was
        # wrong and how it was fixed in intelligence_aggregator.py.
        self.mock_analysis_result = {
            "file_path": "installer.exe",
            "hash": "abc123def456",
            "file_size": 204800,
            "num_suspicious_imports": 3,
            "high_entropy_sections": 2,
            "sections": [
                {"name": ".text", "entropy": 5.1, "size": 4096},
                {"name": ".rdata", "entropy": 7.9, "size": 8192},
            ],
        }

        self.mock_risk_result = {
            "risk_score": 68,
            "classification": "SUSPICIOUS",
            "reasons": ["High entropy", "Suspicious imports detected"]
        }

        self.mock_threat_intel_result = {
            "virus_total_detections": 12,
            "virus_total_total_engines": 70,
            "malwarebazaar_match": True,
            "malware_family": "RedLine Stealer",
            "confidence": "high"
        }

    def test_aggregate_complete_payload(self):
        result = aggregate_intelligence(
            self.mock_analysis_result,
            self.mock_risk_result,
            self.mock_threat_intel_result
        )

        # 1. Check top-level properties
        self.assertEqual(result["file_path"], "installer.exe")
        self.assertEqual(result["hash"], "abc123def456")
        self.assertIn("timestamp", result)

        # 2. Check Static Analysis subsection
        static = result["static_analysis"]
        # entropy is derived as the MAX across all sections (7.9, not 5.1)
        self.assertEqual(static["entropy"], 7.9)
        self.assertEqual(static["suspicious_imports"], 3)
        self.assertTrue(static["packed_flag"])  # derived from high_entropy_sections > 0
        self.assertEqual(static["file_size"], 204800)
        self.assertEqual(static["high_entropy_sections"], 2)

        # 3. Check Risk Assessment subsection
        risk = result["risk_assessment"]
        self.assertEqual(risk["risk_score"], 68)
        self.assertEqual(risk["classification"], "SUSPICIOUS")
        self.assertEqual(len(risk["reasons"]), 2)

        # 4. Check Threat Intelligence subsection
        ti = result["threat_intelligence"]
        self.assertEqual(ti["virus_total_detections"], 12)
        self.assertEqual(ti["malwarebazaar_match"], True)
        self.assertEqual(ti["malware_family"], "RedLine Stealer")
        self.assertEqual(ti["confidence"], "high")

    def test_aggregate_threat_intel_fallback(self):
        # Simulate API unavailable
        unknown_ti_result = {"status": "unknown"}

        result = aggregate_intelligence(
            self.mock_analysis_result,
            self.mock_risk_result,
            unknown_ti_result
        )

        # Verify Fallback cleanly populates
        ti = result["threat_intelligence"]
        self.assertEqual(ti.get("status"), "unknown")
        # Ensure it didn't crash and still parsed other sections
        self.assertEqual(result["static_analysis"]["entropy"], 7.9)
        self.assertEqual(result["risk_assessment"]["risk_score"], 68)

    def test_aggregate_partial_analysis(self):
        # Simulate a genuinely minimal analysis_result — the shape you'd
        # get if only file_path/hash were ever known (e.g. hashing
        # succeeded but PE parsing never got far enough to populate
        # anything else). This is the core Step 3 regression case: no
        # optional indicator here should be silently manufactured.
        partial_analysis = {
            "file_path": "clean.exe",
            "hash": "111222"
        }

        result = aggregate_intelligence(
            partial_analysis,
            self.mock_risk_result,
            self.mock_threat_intel_result
        )

        static = result["static_analysis"]
        # Genuinely unavailable data is OMITTED, not defaulted to a value
        # that would misleadingly read as "verified safe".
        self.assertNotIn("entropy", static)
        self.assertNotIn("packed_flag", static)
        self.assertNotIn("file_size", static)
        self.assertNotIn("high_entropy_sections", static)
        # suspicious_imports still defaults to 0 — num_suspicious_imports
        # is always populated by the real analyzer (even to 0 on total
        # failure), so treating an absent key as "0 known suspicious
        # imports" does not misrepresent anything.
        self.assertEqual(static["suspicious_imports"], 0)

        # Base attributes still fetched
        self.assertEqual(result["file_path"], "clean.exe")

    def test_aggregate_invalid_pe_analysis_omits_entropy_but_keeps_high_entropy_count(self):
        # Shape produced by a REAL failed analysis: static_analyzer's
        # result dict always includes high_entropy_sections (defaulted to
        # 0) even when the PE never parsed, but "sections" stays empty —
        # so there is no entropy value to report, yet high_entropy_sections
        # and packed_flag remain meaningful (both correctly False/0).
        invalid_pe_analysis = {
            "file_path": "corrupt.exe",
            "hash": "deadbeef",
            "file_size": 128,
            "num_suspicious_imports": 0,
            "high_entropy_sections": 0,
            "sections": [],
            "error": "Not a valid PE file",
        }
        result = aggregate_intelligence(
            invalid_pe_analysis, self.mock_risk_result, self.mock_threat_intel_result
        )
        static = result["static_analysis"]
        self.assertNotIn("entropy", static)
        self.assertEqual(static["high_entropy_sections"], 0)
        self.assertFalse(static["packed_flag"])


if __name__ == '__main__':
    unittest.main()
