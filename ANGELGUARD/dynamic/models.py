from typing import TypedDict, List, Optional

class ProcessSnapshot(TypedDict):
    pid: int
    name: str
    exe: str
    ppid: int

class ConnectionSnapshot(TypedDict):
    local: str
    remote: str
    status: str
    pid: Optional[int]

class SystemSnapshot(TypedDict):
    processes: List[ProcessSnapshot]
    connections: List[ConnectionSnapshot]
