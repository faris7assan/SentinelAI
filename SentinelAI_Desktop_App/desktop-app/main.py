import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PyQt5.QtWidgets import QApplication, QSplashScreen
from PyQt5.QtCore    import Qt, QTimer
from PyQt5.QtGui     import QPixmap, QFont, QColor, QPainter

from ui.main_window  import MainWindow
from utils.styles    import DARK


def make_splash() -> QSplashScreen:
    px = QPixmap(520, 300)
    px.fill(QColor("#0D1117"))
    p = QPainter(px)
    p.setPen(QColor("#58A6FF"))
    p.setFont(QFont("Segoe UI", 36, QFont.Bold))
    p.drawText(px.rect().adjusted(0, 40, 0, 0), Qt.AlignHCenter, "🛡️  SentinelAI")
    p.setFont(QFont("Segoe UI", 13))
    p.setPen(QColor("#738FAF"))
    p.drawText(px.rect().adjusted(0, 130, 0, 0), Qt.AlignHCenter,
               "Autonomous AI-Powered SOC Platform")
    p.setFont(QFont("Segoe UI", 11))
    p.drawText(px.rect().adjusted(0, 170, 0, 0), Qt.AlignHCenter,
               "Desktop Control Panel  v1.0")
    p.setFont(QFont("Segoe UI", 10))
    p.setPen(QColor("#9DA2A8"))
    p.drawText(px.rect().adjusted(0, 220, 0, -20), Qt.AlignHCenter | Qt.AlignBottom,
               "Hassan Hamed Faris  •  FUE 2026")
    p.end()
    splash = QSplashScreen(px, Qt.WindowStaysOnTopHint)
    splash.setFont(QFont("Segoe UI", 11))
    return splash


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SentinelAI")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Hassan Hamed Faris")
    app.setStyleSheet(DARK)

    splash = make_splash()
    splash.show()
    splash.showMessage("  Loading modules…", Qt.AlignBottom | Qt.AlignLeft, QColor("#58A6FF"))
    app.processEvents()

    window = MainWindow()

    def finish_splash():
        splash.finish(window)
        window.show()

    QTimer.singleShot(1800, finish_splash)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
