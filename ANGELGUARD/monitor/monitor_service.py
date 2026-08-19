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
    def __init__(self, pipeline, settle_delay_seconds=1.0, retry_interval_seconds=0.5, max_retries=10):
        super().__init__()
        self.pipeline = pipeline
        self._settle_delay_seconds = settle_delay_seconds
        self._retry_interval_seconds = retry_interval_seconds
        self._max_retries = max_retries
        # Maps file_path -> (size, mtime) of the last content actually
        # analyzed at that path. Keyed on content signature, not just path
        # (Step 7 fix — see DECISIONS.md): a plain path-only cache meant
        # that once ANY file had been seen at e.g. "installer.exe", a
        # genuinely different file later downloaded to that same path
        # (common — browsers reuse filenames) was silently never analyzed
        # again for the lifetime of the process. Keying on (size, mtime)
        # still collapses the created/modified/moved event burst that
        # fires for one physical write (same signature each time), while
        # letting a real new download at the same path through.
        self._last_signature = {}

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

            print(f"[Guardian] New executable detected: {file_path}")
            print(f"[Guardian] Analyzing...")

            # Short wait to allow the OS/browser to finish writing the file
            time.sleep(self._settle_delay_seconds)

            is_accessible = False
            for _ in range(self._max_retries):
                try:
                    with open(file_path, "rb"):
                        is_accessible = True
                        break
                except PermissionError:
                    time.sleep(self._retry_interval_seconds)
                except FileNotFoundError:
                    # File disappeared before we could read it — nothing to
                    # analyze. Deliberately do NOT cache a signature here;
                    # if a real file later lands at this path, it must be
                    # evaluated on its own merits.
                    return

            if not is_accessible:
                print(f"[Guardian] Could not access file for analysis: {file_path}")
                return

            try:
                stat = os.stat(file_path)
                signature = (stat.st_size, stat.st_mtime)
            except OSError:
                # Vanished between the accessibility check and now.
                return

            if self._last_signature.get(file_path) == signature:
                # Duplicate watchdog event (created+modified+moved often
                # all fire for one physical write) for content already
                # analyzed — skip without reprocessing.
                return
            self._last_signature[file_path] = signature

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
