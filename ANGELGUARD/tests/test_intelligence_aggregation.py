import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from intelligence.intelligence_aggregator import aggregate_intelligence

class TestIntelligenceAggregation(unittest.TestCase):
    def setUp(self):
        # Base Mock Inputs
        self.mock_analysis_result = {
            "file_path": "installer.exe",
            "hash": "abc123def456",
            "entropy": 7.9,
            "num_suspicious_imports": 3,
            "packed": True
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
        self.assertEqual(static["entropy"], 7.9)
        self.assertEqual(static["suspicious_imports"], 3)
        self.assertTrue(static["packed_flag"])

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
        # Simulate basic file without extra flags
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
        # Defaults applied
        self.assertEqual(static["entropy"], 0.0)
        self.assertEqual(static["suspicious_imports"], 0)
        self.assertFalse(static["packed_flag"])
        
        # Base attributes still fetched
        self.assertEqual(result["file_path"], "clean.exe")
        
        
if __name__ == '__main__':
    unittest.main()
