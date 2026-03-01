import psutil
import sqlite3
import datetime
import socket
import json
import os
from typing import Optional
from .models import ProcessSnapshot, ConnectionSnapshot, SystemSnapshot

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "guardian_logs.db")

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            device_id TEXT,
            snapshot_type TEXT,
            snapshot_json TEXT
        )
    ''')
    conn.commit()
    conn.close()

def build_snapshot_data() -> SystemSnapshot:
    processes: list[ProcessSnapshot] = []
    connections: list[ConnectionSnapshot] = []

    # 1. Running Processes
    for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
        try:
            info = proc.info
            processes.append({
                "pid": info.get('pid', 0) or 0,
                "name": info.get('name', "") or "",
                "exe": info.get('exe', "") or "",
                "ppid": info.get('ppid', 0) or 0
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
            
    # 2. Network Connections (TCP only)
    try:
        conns = psutil.net_connections(kind='tcp')
        for conn in conns:
            local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
            remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
            connections.append({
                "local": local,
                "remote": remote,
                "status": conn.status,
                "pid": conn.pid
            })
    except psutil.AccessDenied:
        pass
        
    return {
        "processes": processes,
        "connections": connections
    }
    
def create_snapshot(snapshot_type="baseline") -> int:
    """
    Captures system state and stores it.
    Returns snapshot_id.
    """
    init_db()
    
    snapshot_data = build_snapshot_data()
    snapshot_json = json.dumps(snapshot_data)
    timestamp = datetime.datetime.now().isoformat()
    device_id = socket.gethostname()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO snapshots (timestamp, device_id, snapshot_type, snapshot_json)
        VALUES (?, ?, ?, ?)
    ''', (timestamp, device_id, snapshot_type, snapshot_json))
    
    snapshot_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    print(f"[Snapshot Service] Captured '{snapshot_type}' snapshot ID {snapshot_id}")
    return snapshot_id

def get_latest_snapshot() -> Optional[dict]:
    """
    Returns most recent snapshot record.
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, timestamp, device_id, snapshot_type, snapshot_json 
        FROM snapshots 
        ORDER BY id DESC LIMIT 1
    ''')
    
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return {
            "id": row[0],
            "timestamp": row[1],
            "device_id": row[2],
            "snapshot_type": row[3],
            "snapshot_data": json.loads(row[4])
        }
    return None


def get_snapshot_by_id(snapshot_id: int) -> Optional[dict]:
    """
    Fetches a specific snapshot by ID.
    Returns the deserialized snapshot dict, or None if not found.
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, timestamp, device_id, snapshot_type, snapshot_json
        FROM snapshots
        WHERE id = ?
    ''', (snapshot_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "id": row[0],
            "timestamp": row[1],
            "device_id": row[2],
            "snapshot_type": row[3],
            "snapshot_data": json.loads(row[4])
        }
    return None
