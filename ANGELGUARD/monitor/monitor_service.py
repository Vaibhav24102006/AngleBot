import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from analysis.static_analyzer import analyze_file, get_analysis_summary
from decision.risk_evaluator import evaluate_risk
from logging.log_service import log_analysis

class DownloadMonitorHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
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
            
        # Handle creation, modified, and rename/move events
        file_path = getattr(event, 'dest_path', event.src_path)
        
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
            
            try:
                # 1. Detection -> Analysis
                result = analyze_file(file_path)
                
                # We need to compute file side constraints that the evaluate_risk expects
                if result.get("error") is None:
                    # In case analyse_file failed gracefully, we populate empty/malformed error.
                    if result.get("file_size", 0) == 0:
                        result["error"] = "Empty file"
                
                summary = get_analysis_summary(result)
                print(summary)
                
                # 2. Analysis -> Decision
                score, classification, reasons = evaluate_risk(result)
                
                print("=== Risk Evaluation ===")
                print(f"Risk Score: {score}")
                print(f"Classification: {classification}")
                print("Reasons:")
                for reason in reasons:
                    print(f"  - {reason}")
                print()
                
                # 3. Decision -> Persistent Logging
                file_hash = result.get('hash', 'N/A')
                log_analysis(file_path, file_hash, score, classification, reasons)
                print("[Guardian] Analysis event successfully logged to database.\n")
                
            except Exception as e:
                print(f"[Guardian] Error during analysis/decision logic: {str(e)}")

def start_monitoring():
    downloads_path = os.path.join(os.path.expanduser("~"), "Downloads")
    if not os.path.exists(downloads_path):
        print(f"[Guardian] Downloads folder not found: {downloads_path}")
        return None
        
    event_handler = DownloadMonitorHandler()
    observer = Observer()
    observer.schedule(event_handler, downloads_path, recursive=False)
    
    observer.start()
    print(f"[Guardian] Started monitoring Downloads folder: {downloads_path}")
    return observer
