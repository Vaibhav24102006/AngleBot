"""
ui/employee_dashboard.py

Phase 5C: ANGELGUARD Employee Mode – main dashboard widget.

Snapshot capture and comparison run inside dedicated QThread workers
so the UI never freezes. All UI updates happen in main-thread slots.
"""

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFrame, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, QObject, pyqtSignal
from PyQt5.QtGui import QFont, QColor

from dynamic.snapshot_service import create_snapshot, get_snapshot_by_id
from dynamic.comparator import compare_snapshots


# ─────────────────────────────────────────────────────────────────────────────
# Background Workers
# ─────────────────────────────────────────────────────────────────────────────

class BaselineWorker(QObject):
    """Captures a baseline snapshot in a background thread."""
    finished = pyqtSignal(int)          # snapshot_id
    error    = pyqtSignal(str)

    def run(self):
        try:
            snapshot_id = create_snapshot("baseline")
            self.finished.emit(snapshot_id)
        except Exception as e:
            self.error.emit(str(e))


class CompareWorker(QObject):
    """Captures a post-event snapshot and runs the comparator."""
    finished = pyqtSignal(dict, int, int)   # diff, baseline_id, post_id
    error    = pyqtSignal(str)

    def __init__(self, baseline_id: int):
        super().__init__()
        self._baseline_id = baseline_id

    def run(self):
        try:
            post_id  = create_snapshot("post")
            baseline = get_snapshot_by_id(self._baseline_id)
            current  = get_snapshot_by_id(post_id)

            if baseline is None or current is None:
                self.error.emit("Could not retrieve snapshots from database.")
                return

            diff = compare_snapshots(
                baseline["snapshot_data"],
                current["snapshot_data"]
            )
            self.finished.emit(diff, self._baseline_id, post_id)
        except Exception as e:
            self.error.emit(str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _format_diff(diff: dict) -> str:
    """Convert a comparator diff dict to a human-readable string."""
    lines = ["=== Snapshot Comparison Result ===\n"]

    def section(title, items, fmt_fn):
        lines.append(f"{title}:")
        if items:
            for item in items:
                lines.append(f"  • {fmt_fn(item)}")
        else:
            lines.append("  (none)")
        lines.append("")

    section(
        "New Processes",
        diff.get("new_processes", []),
        lambda p: f"{p['name']}  (PID {p['pid']})"
    )
    section(
        "Terminated Processes",
        diff.get("terminated_processes", []),
        lambda p: f"{p['name']}  (PID {p['pid']})"
    )
    section(
        "New Connections",
        diff.get("new_connections", []),
        lambda c: f"{c['local']}  →  {c['remote']}  [{c['status']}]"
    )
    section(
        "Terminated Connections",
        diff.get("terminated_connections", []),
        lambda c: f"{c['local']}  →  {c['remote']}  [{c['status']}]"
    )

    all_empty = all(
        len(diff.get(k, [])) == 0
        for k in ("new_processes", "terminated_processes",
                  "new_connections", "terminated_connections")
    )
    if all_empty:
        lines.append("✔  No behavioral changes detected.")

    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main Dashboard Widget
# ─────────────────────────────────────────────────────────────────────────────

BUTTON_STYLE = """
QPushButton {{
    background-color: {bg};
    color: #dce0f0;
    border: 1px solid {border};
    border-radius: 6px;
    padding: 10px 22px;
    font-size: 13px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: {hover};
    border-color: {hover};
}}
QPushButton:disabled {{
    background-color: #2a2a3a;
    color: #666680;
    border-color: #3a3a50;
}}
"""


class EmployeeDashboard(QWidget):

    def __init__(self, parent=None):
        super().__init__(parent)
        self._baseline_id: int | None = None
        self._thread: QThread | None = None
        self._worker = None
        self._build_ui()

    # ── UI Construction ───────────────────────────────────────────────────── #

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 24, 30, 24)
        root.setSpacing(18)

        # ── Header ──────────────────────────────────────────────────────── #
        header = QHBoxLayout()

        title_font = QFont("Segoe UI", 18, QFont.Bold)
        title = QLabel("ANGELGUARD")
        title.setFont(title_font)
        title.setStyleSheet("color: #7aaefc; letter-spacing: 2px;")

        sub = QLabel("Employee Monitoring Dashboard")
        sub.setStyleSheet("color: #8888aa; font-size: 12px;")

        header.addWidget(title)
        header.addSpacing(12)
        header.addWidget(sub)
        header.addStretch()

        self._status_label = QLabel("●  System Protected")
        self._status_label.setStyleSheet(
            "color: #5dde7a; font-weight: 600; font-size: 13px;"
        )
        header.addWidget(self._status_label)

        root.addLayout(header)

        # ── Divider ─────────────────────────────────────────────────────── #
        divider = QFrame()
        divider.setFrameShape(QFrame.HLine)
        divider.setStyleSheet("color: #3a3a50;")
        root.addWidget(divider)

        # ── Action Buttons ───────────────────────────────────────────────── #
        btn_row = QHBoxLayout()
        btn_row.setSpacing(14)

        self._btn_baseline = QPushButton("⬛  Register Baseline Snapshot")
        self._btn_baseline.setStyleSheet(
            BUTTON_STYLE.format(
                bg="#1e3a5f", border="#3060a0", hover="#2a4f80"
            )
        )
        self._btn_baseline.setCursor(Qt.PointingHandCursor)
        self._btn_baseline.clicked.connect(self._on_register_baseline)

        self._btn_compare = QPushButton("🔍  Compare With Latest Snapshot")
        self._btn_compare.setStyleSheet(
            BUTTON_STYLE.format(
                bg="#1e4a30", border="#306040", hover="#286040"
            )
        )
        self._btn_compare.setCursor(Qt.PointingHandCursor)
        self._btn_compare.clicked.connect(self._on_compare)

        btn_row.addWidget(self._btn_baseline)
        btn_row.addWidget(self._btn_compare)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Results Panel ────────────────────────────────────────────────── #
        panel_label = QLabel("Analysis Output")
        panel_label.setStyleSheet(
            "color: #aaaacc; font-size: 11px; font-weight: 600;"
            "letter-spacing: 1px; text-transform: uppercase;"
        )
        root.addWidget(panel_label)

        self._results = QTextEdit()
        self._results.setReadOnly(True)
        self._results.setPlaceholderText(
            "Register a baseline snapshot, then compare to see behavioral diff results here…"
        )
        self._results.setStyleSheet("""
            QTextEdit {
                background-color: #12121e;
                color: #c8cce8;
                border: 1px solid #2e2e46;
                border-radius: 8px;
                padding: 14px;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 12px;
                line-height: 1.6;
            }
        """)
        self._results.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        root.addWidget(self._results)

    # ── Slot: Register Baseline ──────────────────────────────────────────── #

    def _on_register_baseline(self):
        self._set_busy(True)
        self._set_status("⏳  Capturing baseline…", "#f0c040")
        self._results.setPlainText("Registering baseline snapshot. Please wait…")

        self._thread = QThread()
        self._worker = BaselineWorker()
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_baseline_done)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _on_baseline_done(self, snapshot_id: int):
        self._baseline_id = snapshot_id
        self._set_status("●  System Protected", "#5dde7a")
        self._results.setPlainText(
            f"✔  Baseline snapshot registered successfully.\n"
            f"   Snapshot ID : {snapshot_id}\n\n"
            f"You may now click 'Compare With Latest Snapshot' after\n"
            f"the event you wish to inspect has occurred."
        )
        self._set_busy(False)

    # ── Slot: Compare ────────────────────────────────────────────────────── #

    def _on_compare(self):
        if self._baseline_id is None:
            self._results.setPlainText(
                "⚠  No baseline snapshot registered.\n\n"
                "Please click 'Register Baseline Snapshot' first."
            )
            return

        self._set_busy(True)
        self._set_status("⏳  Comparing snapshots…", "#f0c040")
        self._results.setPlainText("Capturing post-event snapshot and running comparator…")

        self._thread = QThread()
        self._worker = CompareWorker(self._baseline_id)
        self._worker.moveToThread(self._thread)

        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_compare_done)
        self._worker.error.connect(self._on_error)
        self._worker.finished.connect(self._thread.quit)
        self._worker.error.connect(self._thread.quit)
        self._thread.finished.connect(self._thread.deleteLater)

        self._thread.start()

    def _on_compare_done(self, diff: dict, baseline_id: int, post_id: int):
        self._set_status("●  System Protected", "#5dde7a")
        header = (
            f"Baseline ID : {baseline_id}    Post-event ID : {post_id}\n"
            "─" * 50 + "\n"
        )
        self._results.setPlainText(header + _format_diff(diff))
        self._set_busy(False)

    # ── Error Handler ────────────────────────────────────────────────────── #

    def _on_error(self, message: str):
        self._set_status("⚠  Error", "#e05555")
        self._results.setPlainText(f"Error encountered:\n\n{message}")
        self._set_busy(False)

    # ── Helpers ──────────────────────────────────────────────────────────── #

    def _set_busy(self, busy: bool):
        self._btn_baseline.setEnabled(not busy)
        self._btn_compare.setEnabled(not busy)

    def _set_status(self, text: str, color: str):
        self._status_label.setText(text)
        self._status_label.setStyleSheet(
            f"color: {color}; font-weight: 600; font-size: 13px;"
        )
