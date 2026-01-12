import sys
import threading
from PyQt5.QtWidgets import QApplication
from src.ui.angel_interface import AngelInterface
from src.guardian.monitor import GuardianMonitor
from src.guardian.analyzer import StaticAnalyzer
from src.guardian.risk_engine import RiskEngine
from src.utils.logger import guardian_logger

class AngelGuardApp:
    def __init__(self):
        self.updated_ui_signal = None 
        
    def set_ui_callback(self, signal_emitter):
        self.updated_ui_signal = signal_emitter

    def on_file_detected(self, file_path):
        guardian_logger.logger.info(f"Analyzing: {file_path}")
        
        # 1. Static Analysis
        analyzer = StaticAnalyzer()
        analysis_results = analyzer.analyze(file_path)
        
        # 2. Risk Scoring
        engine = RiskEngine()
        risk_assessment = engine.assess_risk(analysis_results)
        
        guardian_logger.log_event("ANALYSIS_COMPLETE", file_path, 
                                  risk_score=risk_assessment["score"], 
                                  details=risk_assessment)
        
        # 3. Notify UI
        if self.updated_ui_signal:
            payload = {
                "file_path": file_path,
                "risk_level": risk_assessment["level"],
                "risk_score": risk_assessment["score"],
                "reasons": risk_assessment["reasons"]
            }
            self.updated_ui_signal.emit(payload)

def main():
    guardian_logger.logger.info("Starting ANGELGUARD...")
    
    # Core Logic Controller
    app_logic = AngelGuardApp()
    
    # Monitor Service
    monitor = GuardianMonitor(callback=app_logic.on_file_detected)
    
    # UI
    app = QApplication(sys.argv)
    ui = AngelInterface(guardian_control=monitor)
    app_logic.set_ui_callback(ui.signaller.alert_signal)
    
    # Start Monitor
    monitor_thread = threading.Thread(target=monitor.start)
    monitor_thread.daemon = True
    monitor_thread.start()
    
    # Show UI
    ui.show()
    
    exit_code = app.exec_()
    monitor.stop()
    sys.exit(exit_code)

if __name__ == "__main__":
    main()
