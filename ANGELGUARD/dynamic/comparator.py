"""
dynamic/comparator.py

Phase 5B: Deterministic snapshot comparator.
Accepts pure dictionary input. No SQLite dependency.
No AI, no threading, no UI.
"""


def compare_snapshots(baseline_snapshot: dict, current_snapshot: dict) -> dict:
    """
    Compares a baseline snapshot against a current snapshot.

    Args:
        baseline_snapshot: Snapshot dict from get_snapshot_by_id or get_latest_snapshot.
        current_snapshot:  Snapshot dict captured after a system event.

    Returns:
        diff dict with:
            new_processes        – PIDs present in current but not baseline
            terminated_processes – PIDs present in baseline but not current
            new_connections      – tuples present in current but not baseline
            terminated_connections – tuples present in baseline but not current
    """

    # ------------------------------------------------------------------ #
    # Process comparison (keyed on PID)
    # ------------------------------------------------------------------ #
    baseline_procs = {p["pid"]: p for p in baseline_snapshot.get("processes", [])}
    current_procs  = {p["pid"]: p for p in current_snapshot.get("processes", [])}

    baseline_pids = set(baseline_procs.keys())
    current_pids  = set(current_procs.keys())

    new_processes = [current_procs[pid] for pid in (current_pids - baseline_pids)]
    terminated_processes = [baseline_procs[pid] for pid in (baseline_pids - current_pids)]

    # ------------------------------------------------------------------ #
    # Connection comparison (keyed on 4-tuple identity)
    # ------------------------------------------------------------------ #
    def _conn_key(conn: dict) -> tuple:
        return (
            conn.get("local", ""),
            conn.get("remote", ""),
            conn.get("status", ""),
            conn.get("pid"),
        )

    baseline_conns = {_conn_key(c): c for c in baseline_snapshot.get("connections", [])}
    current_conns  = {_conn_key(c): c for c in current_snapshot.get("connections", [])}

    baseline_keys = set(baseline_conns.keys())
    current_keys  = set(current_conns.keys())

    new_connections        = [current_conns[k] for k in (current_keys - baseline_keys)]
    terminated_connections = [baseline_conns[k] for k in (baseline_keys - current_keys)]

    return {
        "new_processes":         new_processes,
        "terminated_processes":  terminated_processes,
        "new_connections":       new_connections,
        "terminated_connections": terminated_connections,
    }
