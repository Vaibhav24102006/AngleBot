import argparse
import sys
import os
import time

# Ensure the root project directory is in PYTHONPATH so absolute imports work
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from PyQt5.QtWidgets import QApplication
from monitor.monitor_service import start_monitoring
from pipeline.analysis_pipeline import build_default_pipeline
from ui.employee_guidance import GuidanceController
from event_logging.admin_event_logger import AdminEventLogger

def main():
    parser = argparse.ArgumentParser(description="ANGELGUARD")
    parser.add_argument(
        "--headless", action="store_true",
        help="Run without the main ANGELGUARD window (console output + alert "
             "popups only). Useful for development/testing — see DECISIONS.md Step 6.",
    )
    args = parser.parse_args()

    print("[Guardian] Initializing ANGELGUARD System...")

    # QApplication (and the GuidanceController built on it) must be
    # constructed on this thread — the main thread — before the watchdog
    # observer starts its own background thread. GuidanceController's
    # signal is then safely emit-able from that background thread; Qt
    # queues it and delivers it here once the loop below starts pumping
    # events. See DECISIONS.md Step 4 for why this isn't a full
    # app.exec_() event loop (Ctrl+C handling).
    app = QApplication(sys.argv)
    guidance = GuidanceController()
    pipeline = build_default_pipeline(guidance=guidance)

    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    window = None
    if not args.headless:
        # A second AdminEventLogger instance, same default db path as the
        # one build_default_pipeline() constructed internally for writing.
        # This is read-only usage of the same class/API (no persistence
        # logic duplicated in the GUI) — SQLite is the shared boundary, not
        # a shared Python object, which keeps the writer (watchdog thread)
        # and this reader (GUI thread, via HistoryPanel's poll) decoupled.
        # See DECISIONS.md Step 6 for the busy_timeout this relies on.
        from ui.app_window import AngelGuardWindow
        history_logger = AdminEventLogger()
        window = AngelGuardWindow(history_logger, monitored_path=downloads_path)
        window.show()

    observer = start_monitoring(pipeline=pipeline)

    if observer:
        try:
            print("[Guardian] System active. Press Ctrl+C to stop.")
            while True:
                app.processEvents()
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[Guardian] Stopping monitor...")
            observer.stop()

        observer.join()
        print("[Guardian] Monitor stopped gracefully.")
    else:
        print("[Guardian] Failed to start monitor. Exiting.")

if __name__ == "__main__":
    main()
