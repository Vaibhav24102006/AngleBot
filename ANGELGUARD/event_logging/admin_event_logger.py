import sqlite3
import os
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

class AdminEventLogger:
    """
    Phase 6.5 - Admin Threat Dashboard Logging
    
    A pure persistence layer that logs detection metadata, static indicators, 
    risk evaluation, threat intelligence, and AI explanations into SQLite.
    This database sets the foundation for a future dashboard UI.
    """
    
    def __init__(self, db_path: str = "data/angelguard_events.db"):
        self.db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', db_path))
        self._ensure_db_exists()

    def _ensure_db_exists(self):
        """Creates the database and schema if they do not exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    file_path TEXT,
                    file_hash TEXT,
                    risk_score INTEGER,
                    classification TEXT,
                    virus_total_detections INTEGER,
                    malware_family TEXT,
                    ai_summary TEXT,
                    confidence TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")

    def log_event(self, payload: Dict[str, Any], ai_explanation: Dict[str, str]) -> bool:
        """
        Extracts unified information from pipeline components and stores it natively.
        Resilient against missing properties.
        """
        # Base mapping
        timestamp = payload.get("timestamp", "")
        file_path = payload.get("file_path", "unknown")
        file_hash = payload.get("hash", "unknown")
        
        # Risk Mapping
        risk = payload.get("risk_assessment", {})
        risk_score = risk.get("risk_score", 0)
        classification = risk.get("classification", "UNKNOWN")
        
        # Threat Intel Mapping
        ti = payload.get("threat_intelligence", {})
        vt_detections = ti.get("virus_total_detections", 0)
        malware_family = ti.get("malware_family")
        
        # Handles cases where Malfam may be None in payload or omitted
        if not malware_family:
            malware_family = "Unknown"
            
        # AI Explanation Mapping (with fallback protection built-in)
        ai_summary = ai_explanation.get("ai_summary", "unavailable")
        confidence = ai_explanation.get("confidence", "unknown")

        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_events (
                    timestamp, file_path, file_hash, risk_score, classification,
                    virus_total_detections, malware_family, ai_summary, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (timestamp, file_path, file_hash, risk_score, classification, 
                  vt_detections, malware_family, ai_summary, confidence))
            conn.commit()
            conn.close()
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to log event to database: {e}")
            return False
