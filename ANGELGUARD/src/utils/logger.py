import logging
import sqlite3
import json
from datetime import datetime
import os

class AngelLogger:
    def __init__(self, db_path="data/events.db"):
        self.db_path = db_path
        self._setup_logging()
        self._setup_db()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("angel_guard.log"),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger("AngelGuard")

    def _setup_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                file_path TEXT,
                risk_score REAL,
                details TEXT
            )
        ''')
        conn.commit()
        conn.close()

    def log_event(self, event_type, file_path, risk_score=0.0, details=None):
        self.logger.info(f"Event: {event_type} | File: {file_path} | Score: {risk_score}")
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO events (timestamp, event_type, file_path, risk_score, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), event_type, file_path, risk_score, json.dumps(details or {})))
            conn.commit()
            conn.close()
        except Exception as e:
            self.logger.error(f"Failed to log to DB: {e}")

# Global instance
guardian_logger = AngelLogger()
