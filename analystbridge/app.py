"""AnalystBridge GUI entry point.

Run with:
    python -m analystbridge.app
"""
from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from analystbridge.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("AnalystBridge")
    app.setOrganizationName("AnalystBridge")
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
