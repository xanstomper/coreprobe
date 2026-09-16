"""Launch opensleuth studio: python3 -m opensleuth.studio"""

import sys

from PyQt6.QtWidgets import QApplication

from .app import MainWindow
from .theme import QSS


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("opensleuth studio")
    app.setOrganizationName("opensleuth")
    app.setStyleSheet(QSS)
    w = MainWindow()
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
