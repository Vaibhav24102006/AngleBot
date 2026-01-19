from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.guardian.analyzer import analyze_file
import time

class DownloadMonitor(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".exe"):
            print(f"[Guardian] New executable detected: {event.src_path}")

            report = analyze_file(event.src_path)
            print("[Analysis]")
            for k, v in report.items():
                print(f"  {k}: {v}")

def start_monitor(path):
    observer = Observer()
    observer.schedule(DownloadMonitor(), path, recursive=False)
    observer.start()
    print(f"[Guardian] Monitoring: {path}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
