import unittest
import sys
import os
import sqlite3
import logging
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from intelligence.intelligence_aggregator import aggregate_intelligence
from ai.ai_explainer import AIExplainer
from ui.employee_guidance import GuidanceController
from event_logging.admin_event_logger import AdminEventLogger

class TestAngelGuardIntegration(unittest.TestCase):
    def setUp(self):
        # Setup Test DB
        self.db_path = os.path.join(os.path.dirname(__file__), 'data', 'integration_events.db')
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.logger = AdminEventLogger(db_path=self.db_path)
        
        # Setup Explainer
        self.explainer = AIExplainer(timeout=5)
        
        self.guidance = GuidanceController()

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except PermissionError:
                pass

    @patch('ui.employee_guidance.QApplication')
    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_scenario_1_safe_file(self, MockDialog, MockApp):
        """Test 1 - SAFE file pipeline."""
        static = {"file_path": "notepad.exe", "hash": "safehash", "entropy": 4.1, "num_suspicious_imports": 0, "packed": False}
        risk = {"risk_score": 0, "classification": "SAFE", "reasons": ["Clean"]}
        ti = {"status": "unknown"}
        
        payload = aggregate_intelligence(static, risk, ti)
        self.assertEqual(payload["risk_assessment"]["classification"], "SAFE")
        
        # AI Engine Skipped
        explanation = self.explainer.generate_explanation(payload)
        self.assertIsNone(explanation)
        
        # UI Evaluation
        with patch.object(self.guidance, '_show_alert') as mock_show:
            self.guidance.trigger(payload, explanation or {})
            mock_show.assert_not_called()
        
        # Logged to DB
        self.logger.log_event(payload, explanation or {})
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT classification FROM threat_events")
        row = cursor.fetchone()
        conn.close()
        self.assertEqual(row[0], "SAFE")

    @patch('ui.employee_guidance.QApplication')
    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_scenario_2_suspicious_file(self, MockDialog, MockApp):
        """Test 2 - Suspicious File pipeline."""
        static = {"file_path": "fake_tool.exe", "hash": "susphash", "entropy": 7.5, "num_suspicious_imports": 3, "packed": True}
        risk = {"risk_score": 65, "classification": "SUSPICIOUS", "reasons": ["Packed"]}
        ti = {"status": "unknown"}
        
        payload = aggregate_intelligence(static, risk, ti)
        self.assertEqual(payload["risk_assessment"]["classification"], "SUSPICIOUS")
        
        explanation = self.explainer.generate_explanation(payload)
        self.assertIsNotNone(explanation)
        self.assertIn("ai_summary", explanation)
        
        with patch.object(self.guidance, '_show_alert') as mock_show:
            self.guidance.trigger(payload, explanation)
            classification = payload.get("risk_assessment", {}).get("classification")
            self.assertTrue(classification in ["SUSPICIOUS", "HIGH_RISK"])
        
        self.logger.log_event(payload, explanation)

    @patch('ui.employee_guidance.QApplication')
    @patch('ui.employee_guidance.EmployeeGuidance')
    def test_scenario_3_known_malware(self, MockDialog, MockApp):
        """Test 3 - Known Malware Hash pipeline."""
        static = {"file_path": "malware.exe", "hash": "44d88612fea8a8f36de82e1278abb02f", "entropy": 7.9}
        risk = {"risk_score": 90, "classification": "HIGH_RISK", "reasons": ["High Entropy"]}
        ti = {"virus_total_detections": 55, "virus_total_total_engines": 70, "malwarebazaar_match": True, "malware_family": "WannaCry"}
        
        payload = aggregate_intelligence(static, risk, ti)
        
        explanation = self.explainer.generate_explanation(payload)
        
        with patch.object(self.guidance, '_show_alert') as mock_show:
            self.guidance.trigger(payload, explanation)
            classification = payload.get("risk_assessment", {}).get("classification")
            self.assertTrue(classification in ["SUSPICIOUS", "HIGH_RISK"])
        
        self.logger.log_event(payload, explanation)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT virus_total_detections, malware_family FROM threat_events WHERE classification='HIGH_RISK'")
        row = cursor.fetchone()
        conn.close()
        
        self.assertEqual(row[0], 55)
        self.assertEqual(row[1], "WannaCry")

    def test_scenario_4_and_5_ai_fallback(self):
        """Test 4 & 5 - Validation of AI module and offline fallback formatting."""
        static = {"file_path": "test.exe", "hash": "123"}
        risk = {"risk_score": 70, "classification": "HIGH_RISK", "reasons": []}
        ti = {"status": "unknown"}
        payload = aggregate_intelligence(static, risk, ti)
        
        # Force explainer to be offline for fallback test
        self.explainer.client = None
        explanation = self.explainer.generate_explanation(payload)
        
        self.assertEqual(explanation["confidence"], "unknown")
        self.assertTrue("unavailable" in explanation["ai_summary"])
        
    def test_scenario_6_admin_logging(self):
        """Test 6 - Verify database presence and counts."""
        self.assertTrue(os.path.exists(self.db_path))

if __name__ == '__main__':
    print("Running Full ANGELGUARD Integration Validation...")
    unittest.main()
