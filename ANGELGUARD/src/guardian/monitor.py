import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
from src.utils.logger import guardian_logger

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        self.callback = callback

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path)
            
    def _process(self, file_path):
        # We act only on PE files (Windows Executables)
        if file_path.lower().endswith(('.exe', '.dll', '.scr', '.com', '.bat', '.ps1')):
            guardian_logger.log_event("FILE_DETECTED", file_path, details={"action": "monitor_trigger"})
            self.callback(file_path)

class GuardianMonitor:
    def __init__(self, callback, paths_to_watch=None):
        self.callback = callback
        self.paths_to_watch = paths_to_watch or [os.path.expanduser("~/Downloads"), os.path.expanduser("~/Desktop")]
        self.observer = Observer()

    def start(self):
        event_handler = FileEventHandler(self.callback)
        for path in self.paths_to_watch:
            if os.path.exists(path):
                self.observer.schedule(event_handler, path, recursive=False)
                guardian_logger.logger.info(f"Monitoring started on: {path}")
            else:
                guardian_logger.logger.warning(f"Path not found: {path}")
        
        self.observer.start()

    def stop(self):
        self.observer.stop()
        self.observer.join()
