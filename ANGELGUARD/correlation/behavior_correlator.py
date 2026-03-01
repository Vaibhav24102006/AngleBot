"""
correlation/behavior_correlator.py

Phase 7C: Deterministic behavioral correlation engine.

Subscribes to ProcessMonitor.event_detected and NetworkMonitor.event_detected.
Maintains a 10-second rolling memory of raw events and applies three
deterministic correlation rules to surface higher-level anomalies.

Runs in the MAIN THREAD — signal connections are direct, no sleep loops,
no blocking, no threads of its own.

Rules
-----
1. process_network_correlation
   new_process(PID X) + new_connection(PID X) within 5 s

2. coordinated_behavior_anomaly
   spawn_burst + connection_burst within 5 s

3. suspicious_exfil_pattern
   new_process(PID X) + suspicious_port(PID X) within 5 s
"""

import os
import json
import sqlite3
import datetime
import time
from collections import deque

from PyQt5.QtCore import QObject, pyqtSignal


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

MEMORY_WINDOW_SEC    = 10   # how long to keep raw events in memory
CORRELATION_WINDOW_SEC = 5   # max gap between events to count as correlated

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
        CREATE TABLE IF NOT EXISTS correlation_events (
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
            "INSERT INTO correlation_events (timestamp, event_type, event_json) "
            "VALUES (?, ?, ?)",
            (event["timestamp"], event["event_type"], json.dumps(event))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[Correlator] DB log error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Correlator
# ─────────────────────────────────────────────────────────────────────────────

class BehaviorCorrelator(QObject):
    """
    Lightweight, main-thread correlation engine.

    Connect both monitors' event_detected signals to handle_event:

        process_monitor.event_detected.connect(correlator.handle_event)
        network_monitor.event_detected.connect(correlator.handle_event)

    The correlator emits correlation_detected(dict) for every rule hit.
    Future AI layer subscribes to that signal.
    """

    correlation_detected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        _init_db()
        # Each entry: (monotonic_time, event_dict)
        self._process_events: deque[tuple[float, dict]] = deque()
        self._network_events:  deque[tuple[float, dict]] = deque()

        # Track already-emitted correlations to avoid duplicate alerts
        # within the same memory window.
        self._emitted_proc_net:   set[int]  = set()   # PIDs
        self._emitted_exfil_pids: set[int]  = set()   # PIDs
        self._last_coordinated_emission: float = 0.0

    # ── Public slot ───────────────────────────────────────────────────────── #

    def handle_event(self, event: dict) -> None:
        """
        Slot connected to both ProcessMonitor and NetworkMonitor
        event_detected signals. Classifies the event, stores it, then
        evaluates all correlation rules.
        """
        now = time.monotonic()
        etype = event.get("event_type", "")

        if etype in ("new_process", "spawn_burst"):
            self._process_events.append((now, event))
        elif etype in ("new_connection", "new_remote_ip",
                       "suspicious_port", "connection_burst"):
            self._network_events.append((now, event))

        self._prune(now)
        self._evaluate_rules(now)

    # ── Rule evaluation ───────────────────────────────────────────────────── #

    def _evaluate_rules(self, now: float) -> None:
        self._rule_process_network_correlation(now)
        self._rule_coordinated_behavior_anomaly(now)
        self._rule_suspicious_exfil_pattern(now)

    # ── Rule 1: new_process(PID) + new_connection(PID) within 5 s ─────────── #

    def _rule_process_network_correlation(self, now: float) -> None:
        new_proc_pids = {
            e["pid"]: t
            for t, e in self._process_events
            if e.get("event_type") == "new_process"
            and e.get("pid") not in self._emitted_proc_net
        }
        if not new_proc_pids:
            return

        for t, e in self._network_events:
            if e.get("event_type") != "new_connection":
                continue
            pid = e.get("pid")
            if pid not in new_proc_pids:
                continue
            if abs(t - new_proc_pids[pid]) > CORRELATION_WINDOW_SEC:
                continue

            self._emitted_proc_net.add(pid)
            self._emit({
                "event_type": "process_network_correlation",
                "pid":        pid,
                "timestamp":  datetime.datetime.now().isoformat(),
                "detail":     f"PID {pid} initiated outbound connection "
                              f"within {CORRELATION_WINDOW_SEC}s of spawning.",
            })

    # ── Rule 2: spawn_burst + connection_burst within 5 s ─────────────────── #

    def _rule_coordinated_behavior_anomaly(self, now: float) -> None:
        # Debounce: only emit once per CORRELATION_WINDOW_SEC
        if now - self._last_coordinated_emission < CORRELATION_WINDOW_SEC:
            return

        has_spawn_burst = any(
            e.get("event_type") == "spawn_burst"
            for _, e in self._process_events
        )
        has_conn_burst = any(
            e.get("event_type") == "connection_burst"
            for _, e in self._network_events
        )
        if not (has_spawn_burst and has_conn_burst):
            return

        # Check both bursts occurred within the correlation window
        spawn_times = [t for t, e in self._process_events
                       if e.get("event_type") == "spawn_burst"]
        conn_times  = [t for t, e in self._network_events
                       if e.get("event_type") == "connection_burst"]

        for st in spawn_times:
            for ct in conn_times:
                if abs(st - ct) <= CORRELATION_WINDOW_SEC:
                    self._last_coordinated_emission = now
                    self._emit({
                        "event_type": "coordinated_behavior_anomaly",
                        "timestamp":  datetime.datetime.now().isoformat(),
                        "detail":     "Spawn burst and connection burst "
                                      "detected within "
                                      f"{CORRELATION_WINDOW_SEC}s window.",
                    })
                    return

    # ── Rule 3: new_process(PID) + suspicious_port(PID) within 5 s ─────────── #

    def _rule_suspicious_exfil_pattern(self, now: float) -> None:
        new_proc_pids = {
            e["pid"]: t
            for t, e in self._process_events
            if e.get("event_type") == "new_process"
            and e.get("pid") not in self._emitted_exfil_pids
        }
        if not new_proc_pids:
            return

        for t, e in self._network_events:
            if e.get("event_type") != "suspicious_port":
                continue
            pid = e.get("pid")
            if pid not in new_proc_pids:
                continue
            if abs(t - new_proc_pids[pid]) > CORRELATION_WINDOW_SEC:
                continue

            self._emitted_exfil_pids.add(pid)
            self._emit({
                "event_type":  "suspicious_exfil_pattern",
                "pid":         pid,
                "remote_ip":   e.get("remote_ip", ""),
                "remote_port": e.get("remote_port", 0),
                "timestamp":   datetime.datetime.now().isoformat(),
                "detail":      f"PID {pid} connected to suspicious port "
                               f"{e.get('remote_port')} within "
                               f"{CORRELATION_WINDOW_SEC}s of spawning.",
            })

    # ── Helpers ───────────────────────────────────────────────────────────── #

    def _emit(self, event: dict) -> None:
        print(f"[Correlator] ⚠  {event['event_type']} — {event.get('detail', '')}")
        _log_event(event)
        self.correlation_detected.emit(event)

    def _prune(self, now: float) -> None:
        """Remove events older than MEMORY_WINDOW_SEC from both queues."""
        cutoff = now - MEMORY_WINDOW_SEC
        while self._process_events and self._process_events[0][0] < cutoff:
            self._process_events.popleft()
        while self._network_events and self._network_events[0][0] < cutoff:
            self._network_events.popleft()
        # Also prune emitted-PID sets if the underlying process events are gone
        active_pids = {e["pid"] for _, e in self._process_events
                       if "pid" in e}
        self._emitted_proc_net   &= active_pids
        self._emitted_exfil_pids &= active_pids
