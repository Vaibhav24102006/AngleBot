import sys
import os
import time

# Ensure the root project directory is in PYTHONPATH so absolute imports work
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from monitor.monitor_service import start_monitoring

def main():
    print("[Guardian] Initializing ANGELGUARD System...")
    
    observer = start_monitoring()
    
    if observer:
        try:
            print("[Guardian] System active. Press Ctrl+C to stop.")
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[Guardian] Stopping monitor...")
            observer.stop()
        
        observer.join()
        print("[Guardian] Monitor stopped gracefully.")
    else:
        print("[Guardian] Failed to start monitor. Exiting.")

if __name__ == "__main__":
    main()
