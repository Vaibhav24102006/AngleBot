from src.ui.angel_interface import AngelInterface
from src.guardian.monitor import start_monitor
from PyQt5.QtWidgets import QApplication
import threading
import os
import sys

def main():
    print("ANGELGUARD starting...")

    # Qt Application MUST be created before any QWidget (AngelInterface)
    app = QApplication(sys.argv)

    downloads = os.path.join(os.path.expanduser("~"), "Downloads")

    monitor_thread = threading.Thread(
        target=start_monitor,
        args=(downloads,),
        daemon=True
    )
    monitor_thread.start()

    ui = AngelInterface()
    ui.run()

if __name__ == "__main__":
    main()
