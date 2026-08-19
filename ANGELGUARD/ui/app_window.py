"""
ui/app_window.py

Step 6 — ANGELGUARD's one user-facing MVP entry point window. Hosts a
status header and the analysis History panel.

Not to be confused with ui/main_window.py, which is a separate, deliberately
untouched Phase 7 ("Employee Mode" process/network monitoring + snapshot
dashboard) launcher — see DECISIONS.md D2 and Step 6's own audit for why
that stays as-is and this is a new, MVP-only window instead of a rewrite
of it.

The "Guardian / Warning" surface remains the existing EmployeeGuidance
popup (GuidanceController), constructed and wired into the pipeline by
app/main.py independently of this window. This window does not own or
duplicate that wiring — it only reads already-persisted events via
AdminEventLogger, so it needs no coupling to the pipeline or the watchdog
thread at all.
"""
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel
from PyQt5.QtGui import QFont

from event_logging.admin_event_logger import AdminEventLogger
from ui.history_panel import HistoryPanel


class AngelGuardWindow(QMainWindow):
    def __init__(self, admin_logger: AdminEventLogger, monitored_path: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("ANGELGUARD")
        self.resize(900, 600)

        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        header = QHBoxLayout()
        title = QLabel("ANGELGUARD")
        title.setFont(QFont("Segoe UI", 16, QFont.Bold))
        title.setStyleSheet("color: #7aaefc;")
        header.addWidget(title)
        header.addStretch()

        status_text = f"●  Monitoring: {monitored_path}" if monitored_path else "●  Monitoring active"
        status = QLabel(status_text)
        status.setStyleSheet("color: #5dde7a; font-weight: 600;")
        header.addWidget(status)
        layout.addLayout(header)

        self.history_panel = HistoryPanel(admin_logger)
        layout.addWidget(self.history_panel)

        self.setCentralWidget(central)
