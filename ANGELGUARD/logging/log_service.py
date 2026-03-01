import sqlite3
import os
import json
import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "guardian_logs.db")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analysis_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            file_path TEXT NOT NULL,
            sha256 TEXT,
            risk_score INTEGER,
            classification TEXT,
            reasons TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_analysis(file_path: str, sha256: str, risk_score: int, classification: str, reasons: list):
    """
    Persistently logs the analysis event into the SQLite database.
    """
    try:
        init_db()
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        timestamp = datetime.datetime.now().isoformat()
        reasons_json = json.dumps(reasons)
        
        cursor.execute('''
            INSERT INTO analysis_logs (timestamp, file_path, sha256, risk_score, classification, reasons)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, file_path, sha256, risk_score, classification, reasons_json))
        
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Guardian] Failed to log analysis event: {e}")
