"""
behavior/process_monitor.py

Phase 7A: Continuous background process behavior monitor.

Detects:
  - New processes (PID not seen before)
  - Parent → child relationships (ppid of new process)
  - Rapid spawn bursts (>5 new PIDs within a 3-second rolling window)

Logs all events to the behavior_events table in guardian_logs.db.
No UI logic. No AI. No network monitoring.
"""

import os
import json
import sqlite3
import datetime
import time
from collections import deque

import psutil
from PyQt5.QtCore import QObject, QThread, pyqtSignal


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

POLL_INTERVAL_SEC   = 2          # how often to sample process list
BURST_WINDOW_SEC    = 3          # rolling window for burst detection
BURST_THRESHOLD     = 5          # >N new processes in window → burst event

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "guardian_logs.db"
)


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────

def _init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS behavior_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT,
            event_type  TEXT,
            event_json  TEXT
        )
    ''')
    conn.commit()
    conn.close()


def _log_event(event: dict) -> None:
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute(
            "INSERT INTO behavior_events (timestamp, event_type, event_json) VALUES (?, ?, ?)",
            (event["timestamp"], event["event_type"], json.dumps(event))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ProcessMonitor] DB log error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Monitor
# ─────────────────────────────────────────────────────────────────────────────

class ProcessMonitor(QObject):
    """
    Continuously polls running processes in a background thread.

    Usage (from main thread):
        self._monitor_thread = QThread()
        self._monitor = ProcessMonitor()
        self._monitor.moveToThread(self._monitor_thread)
        self._monitor_thread.started.connect(self._monitor.start)
        self._monitor_thread.start()

        # On shutdown:
        self._monitor.stop()
        self._monitor_thread.quit()
        self._monitor_thread.wait()
    """

    # Optional signal that UI layers may connect to for live event display
    event_detected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running          = False
        self._previous_pids: set[int] = set()
        # deque of spawn timestamps for burst detection
        self._spawn_times: deque[float] = deque()

    # ── Public API ─────────────────────────────────────────────────────────── #

    def start(self) -> None:
        """Entry point called by QThread.started — begins the monitor loop."""
        _init_db()
        self._running = True
        self._previous_pids = self._current_pids()
        print("[ProcessMonitor] Started — polling every"
              f" {POLL_INTERVAL_SEC}s.")
        self._run_loop()

    def stop(self) -> None:
        """Signal the loop to exit cleanly on the next iteration."""
        self._running = False
        print("[ProcessMonitor] Stop requested.")

    # ── Internal loop ──────────────────────────────────────────────────────── #

    def _run_loop(self) -> None:
        while self._running:
            try:
                self._poll()
            except Exception as e:
                print(f"[ProcessMonitor] Poll error: {e}")
            # Interruptible sleep: check _running every 0.25 s
            elapsed = 0.0
            while self._running and elapsed < POLL_INTERVAL_SEC:
                time.sleep(0.25)
                elapsed += 0.25

    def _poll(self) -> None:
        now        = time.monotonic()
        now_iso    = datetime.datetime.now().isoformat()
        current    = self._snapshot_map()
        current_pids = set(current.keys())

        new_pids = current_pids - self._previous_pids

        # ── Per-process events ─────────────────────────────────────────────── #
        for pid in new_pids:
            info  = current[pid]
            event = {
                "event_type": "new_process",
                "pid":        pid,
                "name":       info.get("name", ""),
                "ppid":       info.get("ppid", 0),
                "timestamp":  now_iso,
            }
            _log_event(event)
            self.event_detected.emit(event)
            self._spawn_times.append(now)

        # ── Burst detection ────────────────────────────────────────────────── #
        # Prune events outside the rolling window
        cutoff = now - BURST_WINDOW_SEC
        while self._spawn_times and self._spawn_times[0] < cutoff:
            self._spawn_times.popleft()

        if len(self._spawn_times) > BURST_THRESHOLD:
            burst_event = {
                "event_type":  "spawn_burst",
                "count":       len(self._spawn_times),
                "time_window": f"{BURST_WINDOW_SEC} seconds",
                "timestamp":   now_iso,
            }
            _log_event(burst_event)
            self.event_detected.emit(burst_event)
            # Reset after reporting to avoid repeated burst alerts
            self._spawn_times.clear()

        self._previous_pids = current_pids

    # ── Helpers ────────────────────────────────────────────────────────────── #

    @staticmethod
    def _current_pids() -> set[int]:
        """Return the set of currently running PIDs (best-effort)."""
        pids: set[int] = set()
        for proc in psutil.process_iter(['pid']):
            try:
                pids.add(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        return pids

    @staticmethod
    def _snapshot_map() -> dict[int, dict]:
        """Return {pid: {name, ppid}} for all running processes."""
        result: dict[int, dict] = {}
        for proc in psutil.process_iter(['pid', 'name', 'ppid']):
            try:
                info = proc.info
                pid  = info.get('pid')
                if pid is not None:
                    result[pid] = {
                        "name": info.get('name', '') or '',
                        "ppid": info.get('ppid', 0) or 0,
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied,
                    psutil.ZombieProcess):
                pass
        return result
