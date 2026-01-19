from PyQt5.QtWidgets import QApplication, QWidget, QLabel
from PyQt5.QtCore import Qt, QPropertyAnimation, QRect
from PyQt5.QtGui import QColor
import sys

class AngelInterface(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool
        )

        self.setAttribute(Qt.WA_TranslucentBackground)

        self.setGeometry(1600, 850, 60, 60)  # bottom-right-ish

        self.label = QLabel("👼", self)
        self.label.setAlignment(Qt.AlignCenter)
        self.label.setStyleSheet("""
            QLabel {
                font-size: 28px;
                background-color: rgba(30, 30, 30, 180);
                border-radius: 30px;
                color: white;
            }
        """)
        self.label.setGeometry(0, 0, 60, 60)

        self.show()

    def show_alert(self, message):
        alert = QLabel(message, self)
        alert.setWordWrap(True)
        alert.setAlignment(Qt.AlignCenter)
        alert.setStyleSheet("""
            QLabel {
                background-color: rgba(200, 60, 60, 220);
                color: white;
                padding: 10px;
                border-radius: 12px;
                font-size: 11px;
            }
        """)
        alert.setGeometry(-160, -60, 220, 50)
        alert.show()

        animation = QPropertyAnimation(alert, b"geometry")
        animation.setDuration(400)
        animation.setStartValue(QRect(-160, -60, 0, 0))
        animation.setEndValue(QRect(-220, -60, 220, 50))
        animation.start()

    def run(self):
        # QApplication is already created in main.py
        app = QApplication.instance()
        self.show()
        if app:
            sys.exit(app.exec_())
