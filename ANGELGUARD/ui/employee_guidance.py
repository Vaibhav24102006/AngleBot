import os
import sys
from typing import Dict, Any

from PyQt5.QtWidgets import (
    QApplication, QDialog, QVBoxLayout, QHBoxLayout, 
    QLabel, QPushButton, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

class GuidanceSignals(QObject):
    """Signals for thread-safe UI updates."""
    trigger_alert = pyqtSignal(dict, dict)

class EmployeeGuidance(QDialog):
    """
    Phase 6.4: Employee Security Guidance Interface
    
    A non-blocking, always-on-top alert dialog that presents actionable intelligence
    to the user when a STOP/SUSPICIOUS file is detected by the pipeline.
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("ANGELGUARD Security Alert")
        self.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.CustomizeWindowHint | Qt.WindowTitleHint | Qt.WindowCloseButtonHint)
        self.setMinimumWidth(500)
        self._setup_ui()
        
    def _setup_ui(self):
        """Builds the visual components of the alert."""
        # Main Layout
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(20, 20, 20, 20)
        self.layout.setSpacing(15)

        # Header Warning
        self.header_label = QLabel("⚠️ SECURITY WARNING")
        font = QFont("Arial", 16, QFont.Bold)
        self.header_label.setFont(font)
        self.header_label.setStyleSheet("color: #d32f2f;")
        self.header_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.header_label)
        
        # Sub-header
        self.subheader = QLabel("A suspicious executable has been detected.")
        self.subheader.setAlignment(Qt.AlignCenter)
        self.subheader.setStyleSheet("font-size: 14px; margin-bottom: 10px;")
        self.layout.addWidget(self.subheader)

        # Separator
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        self.layout.addWidget(line)

        # File & Risk Info Layout
        self.info_layout = QVBoxLayout()
        self.file_label = QLabel("File: Unknown")
        self.file_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.risk_label = QLabel("Risk Score: 0")
        self.risk_label.setStyleSheet("font-weight: bold; font-size: 13px;")
        self.info_layout.addWidget(self.file_label)
        self.info_layout.addWidget(self.risk_label)
        self.layout.addLayout(self.info_layout)

        # AI Advisor Section
        self.ai_title = QLabel("AI Security Advisor:")
        self.ai_title.setStyleSheet("font-weight: bold; color: #1565c0; margin-top: 10px;")
        self.layout.addWidget(self.ai_title)
        
        self.ai_summary = QLabel("Loading...")
        self.ai_summary.setWordWrap(True)
        self.ai_summary.setStyleSheet("font-size: 13px; font-style: italic;")
        self.layout.addWidget(self.ai_summary)

        # Threat Explanation Section
        self.threat_title = QLabel("Threat Explanation:")
        self.threat_title.setStyleSheet("font-weight: bold; color: #e65100; margin-top: 5px;")
        self.layout.addWidget(self.threat_title)
        
        self.threat_explain = QLabel("Loading...")
        self.threat_explain.setWordWrap(True)
        self.threat_explain.setStyleSheet("font-size: 13px;")
        self.layout.addWidget(self.threat_explain)

        # Recommended Action Section
        self.action_title = QLabel("Recommended Action:")
        self.action_title.setStyleSheet("font-weight: bold; color: #2e7d32; margin-top: 5px;")
        self.layout.addWidget(self.action_title)
        
        self.action_explain = QLabel("Loading...")
        self.action_explain.setWordWrap(True)
        self.action_explain.setStyleSheet("font-size: 13px; font-weight: bold;")
        self.layout.addWidget(self.action_explain)

        # Bottom Buttons
        self.button_layout = QHBoxLayout()
        self.button_layout.addStretch()
        
        self.close_btn = QPushButton("Acknowledge & Close")
        self.close_btn.setMinimumHeight(35)
        self.close_btn.setMinimumWidth(150)
        self.close_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        self.close_btn.clicked.connect(self.accept)
        self.button_layout.addWidget(self.close_btn)
        
        self.layout.addLayout(self.button_layout)

    def populate_data(self, payload: Dict[str, Any], ai_explanation: Dict[str, str]):
        """Fills the UI elements with pipeline data."""
        
        # 1. Base Info
        file_name = os.path.basename(payload.get("file_path", "Unknown"))
        self.file_label.setText(f"File: {file_name}")
        
        risk = payload.get("risk_assessment", {})
        score = risk.get("risk_score", 0)
        
        if score >= 60:
            self.risk_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #d32f2f;")
        elif score >= 20:
            self.risk_label.setStyleSheet("font-weight: bold; font-size: 13px; color: #f57c00;")
            
        self.risk_label.setText(f"Risk Score: {score}")
        
        # 2. AI Section or Fallback
        is_fallback = "unavailable" in ai_explanation.get("ai_summary", "").lower()
        
        if is_fallback:
            self.ai_summary.setText("Risk indicators suggest this file may be unsafe.\nExercise caution before executing.")
            self.threat_title.hide()
            self.threat_explain.hide()
            self.action_explain.setText("• Do not execute this file\n• Verify the download source\n• Contact your system administrator")
        else:
            self.threat_title.show()
            self.threat_explain.show()
            
            self.ai_summary.setText(ai_explanation.get("ai_summary", "Unknown condition."))
            self.threat_explain.setText(ai_explanation.get("threat_explanation", "No explanation available."))
            
            action_text = ai_explanation.get("recommended_action", "Exercise caution.")
            # Format bullets if not already
            if not action_text.strip().startswith("•") and "\n" not in action_text:
                action_text = f"• {action_text}\n• Contact your system administrator"
            self.action_explain.setText(action_text)

class GuidanceController:
    """
    Manages the lifecycle of EmployeeGuidance windows, guaranteeing thread safety.
    Can be invoked from any background monitoring thread cleanly.
    """
    def __init__(self):
        # Determine if a QApplication already exists (useful if integrating with main interface)
        self.app = QApplication.instance()
        self.owns_app = False
        
        if not self.app:
            self.app = QApplication(sys.argv)
            self.owns_app = True
        
        self.signals = GuidanceSignals()
        self.signals.trigger_alert.connect(self._show_alert)
        
        self.active_dialogs = []

    def trigger(self, payload: Dict[str, Any], ai_explanation: Dict[str, str]):
        """
        Public entry point. Can be called from any thread safely.
        Will only trigger on SUSPICIOUS or HIGH_RISK classifications.
        """
        classification = payload.get("risk_assessment", {}).get("classification", "SAFE")
        if classification not in ["SUSPICIOUS", "HIGH_RISK"]:
            return
            
        self.signals.trigger_alert.emit(payload, ai_explanation)

    def _show_alert(self, payload: Dict[str, Any], ai_explanation: Dict[str, str]):
        """Slot executed on the main GUI thread."""
        dialog = EmployeeGuidance()
        dialog.populate_data(payload, ai_explanation)
        
        # Keep reference to prevent GC
        self.active_dialogs.append(dialog)
        
        # Clean up reference on close
        dialog.finished.connect(lambda: self.active_dialogs.remove(dialog) if dialog in self.active_dialogs else None)
        
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()
        
    def exec_(self):
        """Only call if running purely standalone without a primary event loop."""
        if self.owns_app:
            return self.app.exec_()
        
# Global singleton for easy thread-safe invocation across the pipeline without passing instances
_controller_instance = None

def trigger_guidance(payload: Dict[str, Any], ai_explanation: Dict[str, str]):
    """
    Shows a security warning asynchronously without blocking the calling thread.
    Requires a running QApplication event loop in the main thread (or initializes one silently).
    """
    global _controller_instance
    if _controller_instance is None:
        _controller_instance = GuidanceController()
        
    _controller_instance.trigger(payload, ai_explanation)
