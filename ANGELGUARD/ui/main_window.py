"""
ui/main_window.py

ANGELGUARD Employee Mode – application entry point.
Initialises QApplication, applies dark theme, loads EmployeeDashboard,
and manages the ProcessMonitor (7A), NetworkMonitor (7B),
and BehaviorCorrelator (7C) lifecycles.
"""

import sys
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt, QThread
from ui.employee_dashboard import EmployeeDashboard
from behavior.process_monitor import ProcessMonitor
from network.network_monitor import NetworkMonitor
from correlation.behavior_correlator import BehaviorCorrelator


def apply_dark_theme(app: QApplication) -> None:
    """Apply a clean dark QPalette to the entire application."""
    palette = QPalette()

    dark_bg   = QColor(28, 28, 36)
    mid_bg    = QColor(38, 38, 50)
    text      = QColor(220, 220, 230)
    highlight = QColor(80, 130, 220)
    disabled  = QColor(100, 100, 115)

    palette.setColor(QPalette.Window,          dark_bg)
    palette.setColor(QPalette.WindowText,      text)
    palette.setColor(QPalette.Base,            mid_bg)
    palette.setColor(QPalette.AlternateBase,   dark_bg)
    palette.setColor(QPalette.ToolTipBase,     dark_bg)
    palette.setColor(QPalette.ToolTipText,     text)
    palette.setColor(QPalette.Text,            text)
    palette.setColor(QPalette.Button,          mid_bg)
    palette.setColor(QPalette.ButtonText,      text)
    palette.setColor(QPalette.BrightText,      Qt.red)
    palette.setColor(QPalette.Link,            highlight)
    palette.setColor(QPalette.Highlight,       highlight)
    palette.setColor(QPalette.HighlightedText, Qt.white)
    palette.setColor(QPalette.Disabled, QPalette.Text,       disabled)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, disabled)

    app.setPalette(palette)
    app.setStyle("Fusion")


def _start_monitor(monitor: QObject) -> tuple[QThread, QObject]:
    """
    Generic helper: moves any QObject monitor onto a new QThread,
    connects thread.started → monitor.start, then starts the thread.
    Returns (thread, monitor) — caller must keep both alive.
    """
    thread = QThread()
    monitor.moveToThread(thread)
    thread.started.connect(monitor.start)
    thread.start()
    return thread, monitor


def _stop_monitor(thread: QThread, monitor) -> None:
    """Generic clean shutdown for any monitor."""
    monitor.stop()
    thread.quit()
    thread.wait(5000)


def launch():
    """Launch the ANGELGUARD Employee UI with background monitoring."""
    app = QApplication(sys.argv)
    apply_dark_theme(app)

    # ── Start background monitors (each on its own QThread) ─────────────── #
    proc_monitor = ProcessMonitor()
    net_monitor  = NetworkMonitor()
    proc_thread, proc_monitor = _start_monitor(proc_monitor)
    net_thread,  net_monitor  = _start_monitor(net_monitor)

    # ── Correlation engine (main thread — signal-driven only) ────────────── #
    correlator = BehaviorCorrelator()
    proc_monitor.event_detected.connect(correlator.handle_event)
    net_monitor.event_detected.connect(correlator.handle_event)
    # Future AI layer: correlator.correlation_detected.connect(<ai_handler>)

    # ── Main window ──────────────────────────────────────────────────────── #
    window = EmployeeDashboard()
    window.setWindowTitle("ANGELGUARD — Employee Mode")
    window.resize(1000, 700)
    window.show()

    # ── Clean shutdown — stop both monitor threads before Qt tears down ──── #
    def _shutdown():
        _stop_monitor(proc_thread, proc_monitor)
        _stop_monitor(net_thread,  net_monitor)

    app.aboutToQuit.connect(_shutdown)

    sys.exit(app.exec_())


if __name__ == "__main__":
    launch()

