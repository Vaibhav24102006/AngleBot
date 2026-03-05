import unittest
import sys
import os
import logging
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ai.ai_explainer import AIExplainer

class TestAIExplainer(unittest.TestCase):
    def setUp(self):
        self.explainer = AIExplainer(timeout=5)
        
        self.mock_suspicious_payload = {
            "file_path": "installer.exe",
            "hash": "abc123def456",
            "static_analysis": {
                "entropy": 7.9,
                "suspicious_imports": 3,
                "packed_flag": True
            },
            "risk_assessment": {
                "risk_score": 68,
                "classification": "SUSPICIOUS",
                "reasons": ["high entropy", "suspicious imports"]
            },
            "threat_intelligence": {
                "virus_total_detections": 12,
                "virus_total_total_engines": 70,
                "malwarebazaar_match": True,
                "malware_family": "RedLine Stealer"
            },
            "timestamp": "2026-03-06T18:20:00Z"
        }
        
        self.mock_safe_payload = {
            "file_path": "notepad.exe",
            "hash": "saf123",
            "static_analysis": {
                "entropy": 4.1,
                "suspicious_imports": 0,
                "packed_flag": False
            },
            "risk_assessment": {
                "risk_score": 0,
                "classification": "SAFE",
                "reasons": ["No suspicious indicators found"]
            },
            "threat_intelligence": {
                "status": "unknown"
            },
            "timestamp": "2026-03-06T18:20:00Z"
        }

    def test_explainer_skips_safe_files(self):
        """AI Engine should return None for SAFE files to prevent API cost/latency."""
        result = self.explainer.generate_explanation(self.mock_safe_payload)
        self.assertIsNone(result)

    def test_explainer_runs_on_suspicious_files(self):
        """AI Engine runs and formats fallback successfully on SUSPICIOUS files if no API key present."""
        result = self.explainer.generate_explanation(self.mock_suspicious_payload)
        
        # If the environment has a valid key, it's a real response
        # If it doesn't, we expect our clean fallback structure
        self.assertIsNotNone(result)
        self.assertIn("ai_summary", result)
        self.assertIn("threat_explanation", result)
        self.assertIn("recommended_action", result)
        self.assertIn("confidence", result)
        
        # Checking fallback mapping to prevent pipeline crashes
        if not self.explainer.client:
            self.assertEqual(result["confidence"], "unknown")
            self.assertTrue("unavailable" in result["ai_summary"])

if __name__ == '__main__':
    # Add a CLI runner that prints out the struct directly like requested
    if len(sys.argv) > 1 and sys.argv[1] == '--run-explainer':
        import json
        explainer = AIExplainer()
        
        payload = {
            "file_path": "installer.exe",
            "hash": "abc123def456",
            "static_analysis": {
                "entropy": 7.9,
                "suspicious_imports": 3,
                "packed_flag": True
            },
            "risk_assessment": {
                "risk_score": 68,
                "classification": "HIGH_RISK",
                "reasons": ["high entropy", "suspicious imports"]
            },
            "threat_intelligence": {
                "virus_total_detections": 12,
                "virus_total_total_engines": 70,
                "malwarebazaar_match": True,
                "malware_family": "RedLine Stealer"
            },
            "timestamp": "2026-03-06T18:20:00Z"
        }
        
        print("Testing AI Explainer with simulated payload:")
        print("-" * 40)
        res = explainer.generate_explanation(payload)
        print(json.dumps(res, indent=2))
        sys.exit(0)
        
    unittest.main()
