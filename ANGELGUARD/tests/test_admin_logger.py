import unittest
import sys
import os
import sqlite3

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from event_logging.admin_event_logger import AdminEventLogger

class TestAdminLogger(unittest.TestCase):
    def setUp(self):
        # Use an isolated test database inside the tests/data directory
        test_db_dir = os.path.join(os.path.dirname(__file__), 'data')
        os.makedirs(test_db_dir, exist_ok=True)
        self.test_db_path = os.path.join(test_db_dir, 'test_events.db')
        
        # Fresh initialization for each suite
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
            
        self.logger = AdminEventLogger(db_path=self.test_db_path)
        
    def tearDown(self):
        if os.path.exists(self.test_db_path):
            try:
                os.remove(self.test_db_path)
            except PermissionError:
                pass # Depending on environment SQLite may hold lock shortly

    def test_logger_stores_full_payload(self):
        """Simulates recording a complete suspicious incident into the database."""
        
        mock_payload = {
            "timestamp": "2026-03-06T18:20:00Z",
            "file_path": "installer.exe",
            "hash": "abc123def456",
            "risk_assessment": {
                "risk_score": 68,
                "classification": "SUSPICIOUS"
            },
            "threat_intelligence": {
                "virus_total_detections": 12,
                "malware_family": "RedLine Stealer"
            }
        }
        
        mock_ai_explanation = {
            "ai_summary": "Packed executable likely associated with trojan loaders.",
            "confidence": "high"
        }
        
        # 1. Store Record
        success = self.logger.log_event(mock_payload, mock_ai_explanation)
        self.assertTrue(success, "AdminLogger failed to store the payload.")
        
        # 2. Verify Database Integrity
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_events")
        row = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(row, "No row was written to the database.")
        
        # ID, timestamp, file_path, file_hash, risk, class, vt, malware, ai, confidence
        self.assertEqual(row[1], "2026-03-06T18:20:00Z")
        self.assertEqual(row[2], "installer.exe")
        self.assertEqual(row[3], "abc123def456")
        self.assertEqual(row[4], 68)
        self.assertEqual(row[5], "SUSPICIOUS")
        self.assertEqual(row[6], 12)
        self.assertEqual(row[7], "RedLine Stealer")
        self.assertEqual(row[8], "Packed executable likely associated with trojan loaders.")
        self.assertEqual(row[9], "high")

    def test_logger_handles_fallback_safely(self):
        """Validates that a missing AI prompt or failed intel lookup logs safely."""
        mock_payload = {
            "timestamp": "2026-03-06T19:00:00Z",
            "file_path": "safe.exe",
            "hash": "clean123",
            "risk_assessment": {
                "risk_score": 0,
                "classification": "SAFE"
            },
            "threat_intelligence": {
                "status": "unknown"
            }
        }
        
        mock_ai_explanation = {
            "ai_summary": "unavailable"
        }
        
        self.logger.log_event(mock_payload, mock_ai_explanation)
        
        conn = sqlite3.connect(self.test_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM threat_events WHERE classification = 'SAFE'")
        row = cursor.fetchone()
        conn.close()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[5], "SAFE")
        self.assertEqual(row[6], 0) # VT default
        self.assertEqual(row[7], "Unknown") # Malfam default
        self.assertEqual(row[8], "unavailable") # AI Summary

if __name__ == '__main__':
    unittest.main()
