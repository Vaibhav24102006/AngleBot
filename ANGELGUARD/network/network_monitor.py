"""
network/network_monitor.py

Phase 7B: Continuous outbound TCP network monitor.

Detects:
  - New outbound connections (ESTABLISHED / SYN_SENT, non-loopback)
  - First-time remote IP addresses
  - Suspicious ports (not in SAFE_PORTS)
  - Rapid outbound burst (>5 new connections in 3 seconds)

Logs all events to the network_events table in guardian_logs.db.
No UI logic. No packet capture. No admin privileges required.
"""

import os
import json
import sqlite3
import datetime
import time
from collections import deque

import psutil
from PyQt5.QtCore import QObject, pyqtSignal


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

POLL_INTERVAL_SEC  = 2
BURST_WINDOW_SEC   = 3
BURST_THRESHOLD    = 5

SAFE_PORTS = {80, 443, 53, 22}
LOOPBACK   = {"127.0.0.1", "::1", "0.0.0.0"}
ACTIVE_STATUSES = {"ESTABLISHED", "SYN_SENT"}

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
        CREATE TABLE IF NOT EXISTS network_events (
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
            "INSERT INTO network_events (timestamp, event_type, event_json) "
            "VALUES (?, ?, ?)",
            (event["timestamp"], event["event_type"], json.dumps(event))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[NetworkMonitor] DB log error: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Monitor
# ─────────────────────────────────────────────────────────────────────────────

class NetworkMonitor(QObject):
    """
    Polls TCP connections every POLL_INTERVAL_SEC seconds in a QThread.

    Usage (identical pattern to ProcessMonitor):
        self._net_thread  = QThread()
        self._net_monitor = NetworkMonitor()
        self._net_monitor.moveToThread(self._net_thread)
        self._net_thread.started.connect(self._net_monitor.start)
        self._net_thread.start()

        # On shutdown:
        self._net_monitor.stop()
        self._net_thread.quit()
        self._net_thread.wait(5000)
    """

    event_detected = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._running = False
        # Connection identity set: (local_ip, local_port, remote_ip, remote_port, pid)
        self._previous_conns: set[tuple] = set()
        # Set of all remote IPs ever seen (first-time detection)
        self._seen_remote_ips: set[str] = set()
        # Rolling deque of (monotonic_time) for burst detection
        self._burst_times: deque[float] = deque()

    # ── Public API ─────────────────────────────────────────────────────────── #

    def start(self) -> None:
        """Entry point called by QThread.started."""
        _init_db()
        self._running = True
        self._previous_conns = self._snapshot()
        # Pre-populate seen IPs from baseline so we don't spam on first poll
        self._seen_remote_ips = {k[2] for k in self._previous_conns}
        print("[NetworkMonitor] Started — polling every"
              f" {POLL_INTERVAL_SEC}s.")
        self._run_loop()

    def stop(self) -> None:
        """Signal the loop to exit cleanly."""
        self._running = False
        print("[NetworkMonitor] Stop requested.")

    # ── Internal loop ──────────────────────────────────────────────────────── #

    def _run_loop(self) -> None:
        while self._running:
            try:
                self._poll()
            except Exception as e:
                print(f"[NetworkMonitor] Poll error: {e}")
            # Interruptible sleep
            elapsed = 0.0
            while self._running and elapsed < POLL_INTERVAL_SEC:
                time.sleep(0.25)
                elapsed += 0.25

    def _poll(self) -> None:
        now     = time.monotonic()
        now_iso = datetime.datetime.now().isoformat()

        current = self._snapshot()
        new_conns = current - self._previous_conns

        for conn_key in new_conns:
            local_ip, local_port, remote_ip, remote_port, pid = conn_key

            # ── 1. New outbound connection event ──────────────────────────── #
            event = {
                "event_type":  "new_connection",
                "pid":         pid,
                "remote_ip":   remote_ip,
                "remote_port": remote_port,
                "local_port":  local_port,
                "timestamp":   now_iso,
            }
            _log_event(event)
            self.event_detected.emit(event)
            self._burst_times.append(now)

            # ── 2. First-time remote IP ───────────────────────────────────── #
            if remote_ip not in self._seen_remote_ips:
                self._seen_remote_ips.add(remote_ip)
                first_ip_event = {
                    "event_type":  "new_remote_ip",
                    "pid":         pid,
                    "remote_ip":   remote_ip,
                    "remote_port": remote_port,
                    "timestamp":   now_iso,
                }
                _log_event(first_ip_event)
                self.event_detected.emit(first_ip_event)

            # ── 3. Suspicious port ────────────────────────────────────────── #
            if remote_port not in SAFE_PORTS:
                sus_event = {
                    "event_type":  "suspicious_port",
                    "pid":         pid,
                    "remote_ip":   remote_ip,
                    "remote_port": remote_port,
                    "timestamp":   now_iso,
                }
                _log_event(sus_event)
                self.event_detected.emit(sus_event)

        # ── 4. Burst detection ────────────────────────────────────────────── #
        cutoff = now - BURST_WINDOW_SEC
        while self._burst_times and self._burst_times[0] < cutoff:
            self._burst_times.popleft()

        if len(self._burst_times) > BURST_THRESHOLD:
            burst_event = {
                "event_type":  "connection_burst",
                "count":       len(self._burst_times),
                "time_window": f"{BURST_WINDOW_SEC} seconds",
                "timestamp":   now_iso,
            }
            _log_event(burst_event)
            self.event_detected.emit(burst_event)
            self._burst_times.clear()

        self._previous_conns = current

    # ── Helpers ────────────────────────────────────────────────────────────── #

    @staticmethod
    def _snapshot() -> set[tuple]:
        """
        Returns the set of active outbound connection identity tuples:
        (local_ip, local_port, remote_ip, remote_port, pid)
        Filters: TCP only, ESTABLISHED/SYN_SENT, non-loopback remote.
        """
        result: set[tuple] = set()
        try:
            conns = psutil.net_connections(kind="tcp")
        except psutil.AccessDenied:
            return result

        for c in conns:
            if c.status not in ACTIVE_STATUSES:
                continue
            if not c.raddr:
                continue
            remote_ip = c.raddr.ip
            if remote_ip in LOOPBACK:
                continue
            result.add((
                c.laddr.ip if c.laddr else "",
                c.laddr.port if c.laddr else 0,
                remote_ip,
                c.raddr.port,
                c.pid,
            ))
        return result
