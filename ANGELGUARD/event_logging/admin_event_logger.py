import sqlite3
import os
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class AdminEventLogger:
    """
    Canonical MVP persistence layer for ANGELGUARD analysis events.

    threat_events keeps its original 10 columns (Phase 6.5) and gains 8
    more via ALTER TABLE ADD COLUMN (Step 5B) to store the pipeline's
    canonical event_id and the full analysis detail that used to be
    dropped — see DECISIONS.md Step 5B. A fresh database and a
    pre-existing one both run through the same migration step on
    construction, so there is only one schema-evolution path to maintain
    and old rows are never rewritten (new columns are NULL for them).
    """

    _LEGACY_COLUMNS = (
        "id INTEGER PRIMARY KEY AUTOINCREMENT",
        "timestamp TEXT",
        "file_path TEXT",
        "file_hash TEXT",
        "risk_score INTEGER",
        "classification TEXT",
        "virus_total_detections INTEGER",
        "malware_family TEXT",
        "ai_summary TEXT",
        "confidence TEXT",
    )

    # (column name, SQL type), added additively to both fresh and
    # pre-existing databases. Callers should use get_event/list_events
    # (named dicts) rather than positional row access, which is why
    # ordering here isn't treated as part of the public contract.
    _NEW_COLUMNS = (
        ("event_id", "TEXT"),
        ("file_size", "INTEGER"),
        ("risk_reasons", "TEXT"),
        ("static_analysis_json", "TEXT"),
        ("threat_intelligence_json", "TEXT"),
        ("explanation_json", "TEXT"),
        ("recommended_action", "TEXT"),
        ("analysis_status", "TEXT"),
    )

    def __init__(self, db_path: str = "data/angelguard_events.db"):
        self.db_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', db_path))
        self._ensure_db_exists()

    def _connect(self) -> sqlite3.Connection:
        """A short-lived connection with a busy timeout set. Step 6 adds
        the first real concurrent accessor of this database — a GUI-thread
        HistoryPanel polling list_events()/get_event() alongside the
        watchdog-thread pipeline calling log_event() — so a write landing
        mid-read (or vice versa) can now actually happen, where before
        (Step 5 audit) this database had zero readers. A busy timeout lets
        the loser of that race wait briefly for the lock instead of
        raising immediately; WAL/broader concurrency tuning stays deferred
        per the audit, since this single PRAGMA is enough for one writer
        plus one lightweight poller."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA busy_timeout = 3000")
        return conn

    def _ensure_db_exists(self):
        """Creates the database/table if missing, then runs the additive
        migration unconditionally. Cheap and idempotent, so it's safe to
        repeat on every construction — this is the only place a database
        created before Step 5B picks up the new columns."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute(f'''
                CREATE TABLE IF NOT EXISTS threat_events (
                    {", ".join(self._LEGACY_COLUMNS)}
                )
            ''')
            conn.commit()
            self._migrate_schema(conn)
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
        finally:
            conn.close()

    def _migrate_schema(self, conn: sqlite3.Connection):
        cursor = conn.cursor()
        existing = {row[1] for row in cursor.execute("PRAGMA table_info(threat_events)")}
        for name, col_type in self._NEW_COLUMNS:
            if name not in existing:
                cursor.execute(f"ALTER TABLE threat_events ADD COLUMN {name} {col_type}")
        # A plain UNIQUE index allows any number of historical NULL
        # event_id rows (SQL NULLs are never equal to one another) while
        # still enforcing uniqueness for every real event_id going forward.
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_threat_events_event_id "
            "ON threat_events(event_id)"
        )
        conn.commit()

    def log_event(self, final_event: Dict[str, Any]) -> bool:
        """
        Persists the canonical final event produced by
        AnalysisPipeline._build_final_event. Idempotent on event_id:
        re-logging the same event_id updates the existing row (last write
        wins) instead of creating a duplicate — see DECISIONS.md Step 5B
        for why. A final_event with no event_id always inserts a new row.
        """
        event_id = final_event.get("event_id")
        timestamp = final_event.get("timestamp", "")

        file_info = final_event.get("file") or {}
        file_path = file_info.get("path") or "unknown"
        file_hash = file_info.get("sha256") or "unknown"
        file_size = file_info.get("size")

        risk = final_event.get("risk") or {}
        risk_score = risk.get("score", 0)
        classification = risk.get("level", "UNKNOWN")
        risk_reasons = risk.get("reasons", [])

        static_analysis = final_event.get("static_analysis") or {}

        ti = final_event.get("threat_intelligence") or {}
        vt_detections = ti.get("virus_total_detections", 0)
        malware_family = ti.get("malware_family") or "Unknown"

        explanation = final_event.get("explanation") or {}
        ai_summary = explanation.get("ai_summary", "unavailable")
        confidence = explanation.get("confidence", "unknown")

        recommended_action = final_event.get("recommended_action")
        analysis_status = final_event.get("analysis_status")

        conn = self._connect()
        try:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_events (
                    event_id, timestamp, file_path, file_hash, file_size,
                    risk_score, classification, virus_total_detections,
                    malware_family, ai_summary, confidence, risk_reasons,
                    static_analysis_json, threat_intelligence_json,
                    explanation_json, recommended_action, analysis_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(event_id) DO UPDATE SET
                    timestamp=excluded.timestamp,
                    file_path=excluded.file_path,
                    file_hash=excluded.file_hash,
                    file_size=excluded.file_size,
                    risk_score=excluded.risk_score,
                    classification=excluded.classification,
                    virus_total_detections=excluded.virus_total_detections,
                    malware_family=excluded.malware_family,
                    ai_summary=excluded.ai_summary,
                    confidence=excluded.confidence,
                    risk_reasons=excluded.risk_reasons,
                    static_analysis_json=excluded.static_analysis_json,
                    threat_intelligence_json=excluded.threat_intelligence_json,
                    explanation_json=excluded.explanation_json,
                    recommended_action=excluded.recommended_action,
                    analysis_status=excluded.analysis_status
            ''', (
                event_id, timestamp, file_path, file_hash, file_size,
                risk_score, classification, vt_detections, malware_family,
                ai_summary, confidence,
                json.dumps(risk_reasons, sort_keys=True),
                json.dumps(static_analysis, sort_keys=True),
                json.dumps(ti, sort_keys=True),
                json.dumps(explanation, sort_keys=True) if explanation else None,
                recommended_action, analysis_status,
            ))
            conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Failed to log event to database: {e}")
            return False
        finally:
            conn.close()

    def get_event(self, event_id: str) -> Optional[Dict[str, Any]]:
        """Returns the stored event as a canonical-shaped dict, or None if
        no row with this event_id exists."""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute(
                "SELECT * FROM threat_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        finally:
            conn.close()
        return self._row_to_event(row) if row is not None else None

    def list_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Most recent events first. A flat, unfiltered history is all the
        MVP needs — no query/paging framework warranted yet."""
        conn = self._connect()
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                "SELECT * FROM threat_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        finally:
            conn.close()
        return [self._row_to_event(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Dict[str, Any]:
        """Decodes a stored row back into the same shape
        AnalysisPipeline._build_final_event produces, so a retrieved event
        is structurally interchangeable with the one the pipeline returned
        at analysis time."""
        def _load(value, default):
            if not value:
                return default
            try:
                return json.loads(value)
            except (TypeError, ValueError):
                return default

        file_path = row["file_path"]
        return {
            "event_id": row["event_id"],
            "timestamp": row["timestamp"],
            "file": {
                "path": file_path,
                "filename": os.path.basename(file_path) if file_path and file_path != "unknown" else None,
                "size": row["file_size"],
                "sha256": row["file_hash"],
            },
            "static_analysis": _load(row["static_analysis_json"], {}),
            "risk": {
                "score": row["risk_score"],
                "level": row["classification"],
                "reasons": _load(row["risk_reasons"], []),
            },
            "threat_intelligence": _load(row["threat_intelligence_json"], {}),
            "explanation": _load(row["explanation_json"], None),
            "recommended_action": row["recommended_action"],
            "analysis_status": row["analysis_status"],
        }
