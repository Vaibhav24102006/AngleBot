import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QVBoxLayout, QPushButton, QMessageBox, QSystemTrayIcon, QMenu, QAction
from PyQt5.QtCore import Qt, pyqtSignal, QObject
from PyQt5.QtGui import QIcon, QFont, QColor, QPalette

class Signaller(QObject):
    alert_signal = pyqtSignal(dict)

class AngelInterface(QWidget):
    def __init__(self, guardian_control):
        super().__init__()
        self.guardian = guardian_control
        self.signaller = Signaller()
        self.signaller.alert_signal.connect(self.show_alert)
        self.init_ui()

    def init_ui(self):
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        # Dimensions
        self.setGeometry(100, 100, 300, 150)
        
        # Layout
        layout = QVBoxLayout()
        
        # Title
        self.lbl_title = QLabel("ANGELGUARD")
        self.lbl_title.setStyleSheet("color: white; font-size: 16px; font-weight: bold;")
        self.lbl_title.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.lbl_title)
        
        # Status
        self.lbl_status = QLabel("Monitoring...")
        self.lbl_status.setStyleSheet("color: #00FF00; font-size: 12px;")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.lbl_status)
        
        # Main background style
        self.setStyleSheet("""
            QWidget {
                background-color: rgba(30, 30, 40, 220);
                border-radius: 15px;
                border: 1px solid #444;
            }
        """)
        
        self.setLayout(layout)
        
        # System Tray
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(QIcon("assets/icon.png")) # Placeholder
        
        menu = QMenu()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_app)
        menu.addAction(exit_action)
        self.tray_icon.setContextMenu(menu)
        self.tray_icon.show()

    def show_alert(self, data):
        # Bring to front
        self.show()
        self.activateWindow()
        
        risk_level = data.get("risk_level", "Unknown")
        file_path = data.get("file_path", "Unknown")
        score = data.get("risk_score", 0)
        reasons = "\n".join(data.get("reasons", []))
        
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning if risk_level == "Suspicious" else QMessageBox.Information)
        msg.setText(f"New Executable Detected!")
        msg.setInformativeText(f"File: {file_path}\nRisk Level: {risk_level} (Score: {score})\n\n{reasons}")
        msg.setWindowTitle("ANGELGUARD Alert")
        msg.setStandardButtons(QMessageBox.Ok)
        msg.exec_()

    def close_app(self):
        self.guardian.stop()
        QApplication.quit()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_position = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.drag_position)
            event.accept()
