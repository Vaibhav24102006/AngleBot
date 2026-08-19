import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pipeline.analysis_pipeline import build_default_pipeline

class DownloadMonitorHandler(FileSystemEventHandler):
    """
    Responsible ONLY for detection: watching the directory, filtering to
    relevant events, deduplication, and waiting out locked/incomplete
    files. Once a file is confirmed accessible, it hands the path to the
    analysis pipeline and does nothing else — no static analysis, risk
    scoring, threat intel, or persistence logic lives here (see
    pipeline/analysis_pipeline.py and DECISIONS.md Step 4).
    """
    def __init__(self, pipeline):
        super().__init__()
        self.pipeline = pipeline
        self.processed_files = set()

    def on_created(self, event):
        self._process_event(event)

    def on_moved(self, event):
        self._process_event(event)

    def on_modified(self, event):
        self._process_event(event)

    def _process_event(self, event):
        if event.is_directory:
            return

        # Handle creation, modified, and rename/move events.
        # NOTE: watchdog's FileCreatedEvent/FileModifiedEvent also carry a
        # dest_path attribute (set to ''), so a plain getattr(..., default)
        # never falls back to src_path for those events. Fall back on an
        # empty/falsy dest_path instead of on attribute absence.
        file_path = getattr(event, 'dest_path', '') or event.src_path

        if file_path.lower().endswith('.exe'):

            # Simple in-memory cache to prevent duplicate processing
            if file_path in self.processed_files:
                return

            print(f"[Guardian] New executable detected: {file_path}")
            print(f"[Guardian] Analyzing...")

            # Add to cache immediately to prevent re-entrancy
            self.processed_files.add(file_path)

            # Short wait to allow the OS/browser to finish writing the file
            time.sleep(1.0)

            max_retries = 10
            is_accessible = False
            for _ in range(max_retries):
                try:
                    with open(file_path, "rb"):
                        is_accessible = True
                        break
                except PermissionError:
                    time.sleep(0.5)
                except FileNotFoundError:
                    # If file doesn't exist anymore, we shouldn't process it but keep it in cache
                    # in case of transient renames until next process run
                    return

            if not is_accessible:
                print(f"[Guardian] Could not access file for analysis: {file_path}")
                return

            event_result = self.pipeline.analyze_and_decide(file_path)

            risk = event_result["risk"]
            print(f"[Guardian] Analysis status: {event_result['analysis_status']}")
            print(f"[Guardian] Risk Score: {risk['score']}  Classification: {risk['level']}")
            for reason in risk["reasons"]:
                print(f"  - {reason}")
            if event_result.get("persistence_error"):
                print(f"[Guardian] WARNING: failed to persist this event: {event_result['persistence_error']}")
            else:
                print("[Guardian] Analysis event successfully logged to database.")
            if event_result.get("guidance_triggered"):
                print("[Guardian] Security warning shown to user.")
            print()

def start_monitoring(pipeline=None):
    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_path):
        print(f"[Guardian] Downloads folder not found: {downloads_path}")
        return None

    if pipeline is None:
        pipeline = build_default_pipeline()

    event_handler = DownloadMonitorHandler(pipeline)
    observer = Observer()
    observer.schedule(event_handler, downloads_path, recursive=False)

    observer.start()
    print(f"[Guardian] Started monitoring Downloads folder: {downloads_path}")
    return observer
