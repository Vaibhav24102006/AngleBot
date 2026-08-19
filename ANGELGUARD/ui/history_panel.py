"""
ui/history_panel.py

Step 6 — the smallest useful analysis-history experience: a table backed
directly by AdminEventLogger.list_events()/get_event(). No new database,
no new event schema, no persistence logic duplicated here — this widget
only ever reads.

Refresh is a simple GUI-thread QTimer poll plus a manual button, not a
push notification from the pipeline. This avoids adding any new
cross-thread signal path: the watchdog thread already delivers alerts
via GuidanceController's existing signal (see ui/employee_guidance.py);
history merely re-queries the database on its own schedule, which is
sufficient for "the smallest useful history experience" and keeps this
widget fully decoupled from the pipeline/monitor internals.
"""
from typing import Optional

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QPushButton, QLabel, QHeaderView, QAbstractItemView,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor

from event_logging.admin_event_logger import AdminEventLogger
from ui.analysis_details import AnalysisDetailsDialog

_COLUMNS = ("Timestamp", "Filename", "Classification", "Score", "SHA-256", "Event ID")
_EVENT_ID_COLUMN = len(_COLUMNS) - 1

_LEVEL_COLORS = {
    "SAFE": "#2e7d32",
    "SUSPICIOUS": "#f57c00",
    "HIGH_RISK": "#d32f2f",
}


class HistoryPanel(QWidget):
    """Displays past analysis events, most recent first. Selecting a row
    (double-click, or the "View Details" button) retrieves the full event
    by event_id and shows it in AnalysisDetailsDialog."""

    def __init__(self, admin_logger: AdminEventLogger, limit: int = 50,
                 poll_interval_ms: int = 3000, parent=None):
        super().__init__(parent)
        self._logger = admin_logger
        self._limit = limit
        self._build_ui()
        self.refresh()

        self._timer: Optional[QTimer] = None
        if poll_interval_ms:
            self._timer = QTimer(self)
            self._timer.timeout.connect(self.refresh)
            self._timer.start(poll_interval_ms)

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QHBoxLayout()
        title = QLabel("Analysis History")
        title.setStyleSheet("font-weight: bold; font-size: 13px; color: #aaaacc;")
        header.addWidget(title)
        header.addStretch()
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        header.addWidget(refresh_btn)
        layout.addLayout(header)

        self._table = QTableWidget(0, len(_COLUMNS))
        self._table.setHorizontalHeaderLabels(_COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.doubleClicked.connect(self._open_selected)
        layout.addWidget(self._table)

        open_row = QHBoxLayout()
        open_row.addStretch()
        open_btn = QPushButton("View Details")
        open_btn.clicked.connect(self._open_selected)
        open_row.addWidget(open_btn)
        layout.addLayout(open_row)

    def refresh(self):
        """Re-queries list_events() and repopulates the table. Never
        computes risk — every displayed value is read straight from the
        stored event."""
        events = self._logger.list_events(limit=self._limit)
        self._table.setRowCount(len(events))
        for row, event in enumerate(events):
            risk = event.get("risk") or {}
            file_info = event.get("file") or {}
            level = risk.get("level") or "UNKNOWN"
            score = risk.get("score")
            values = (
                event.get("timestamp") or "",
                file_info.get("filename") or "",
                level,
                str(score) if score is not None else "",
                (file_info.get("sha256") or "")[:16],
                event.get("event_id") or "",
            )
            for col, value in enumerate(values):
                item = QTableWidgetItem(value)
                if col == 2:
                    item.setForeground(QColor("white"))
                    item.setBackground(QColor(_LEVEL_COLORS.get(level, "#555555")))
                self._table.setItem(row, col, item)

    def _open_selected(self):
        row = self._table.currentRow()
        if row < 0:
            return
        event_id_item = self._table.item(row, _EVENT_ID_COLUMN)
        if event_id_item is None or not event_id_item.text():
            return
        event = self._logger.get_event(event_id_item.text())
        if event is None:
            return
        dialog = AnalysisDetailsDialog(event, parent=self)
        dialog.exec_()
