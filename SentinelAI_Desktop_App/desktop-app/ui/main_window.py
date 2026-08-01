import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLabel, QPushButton, QStatusBar, QApplication, QAction)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui  import QFont, QKeySequence

from ui.tabs.dashboard_tab import DashboardTab
from ui.tabs.alerts_tab    import AlertsTab
from ui.tabs.ai_tab        import AICopilotTab
from ui.tabs.intel_tab     import ThreatIntelTab
from ui.tabs.soar_tab      import SOARTab
from ui.tabs.redteam_tab   import RedTeamTab
from ui.tabs.other_tabs    import CloudTab, SandboxTab, HoneypotTab, VPNTab
from ui.tabs.reports_tab   import ReportsTab
from ui.tabs.logs_tab      import LogsTab
from ui.tabs.settings_tab  import SettingsTab
from utils.styles          import DARK, LIGHT
from utils.worker          import Worker
import api.client as api


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self._theme = "dark"
        self.setWindowTitle("SentinelAI — Desktop Control Panel")
        self.setMinimumSize(1280, 800)
        self.resize(1440, 900)
        self._build_ui()
        self._apply_theme("dark")
        self._init_websocket()
        self._start_status_timer()

    def _init_websocket(self):
        from utils.ws_client import WSClient
        # Attempt to connect to gateway service WebSocket
        ws_url = api.BASE_URLS.get("gateway", "http://localhost:8000").replace("http://", "ws://").replace("https://", "wss://") + "/ws/stream"
        self._ws_client = WSClient(ws_url)
        self._ws_client.connected.connect(lambda: self._lbl_live.setStyleSheet("color:#10B981;font-weight:700;font-size:12px;"))
        self._ws_client.disconnected.connect(lambda: self._lbl_live.setStyleSheet("color:#94A3B8;font-weight:700;font-size:12px;"))
        self._ws_client.message_received.connect(self._handle_ws_message)
        self._ws_client.start()

    def _handle_ws_message(self, data):
        # When we receive a ping or an alert via websocket, update dashboard seamlessly
        msg_type = data.get("type", "")
        if msg_type == "ping":
            pass  # Keep alive
        elif msg_type == "alert":
            try:
                self._t_dash._refresh_alerts()
                self._t_alerts._load()
            except Exception:
                pass
        elif msg_type == "metrics":
            try:
                self._t_dash._refresh_metrics()
            except Exception:
                pass

    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)
        self._header = self._build_header()
        root.addWidget(self._header)

        self.tabs = QTabWidget()
        self.tabs.setTabPosition(QTabWidget.West)
        self.tabs.setDocumentMode(True)

        self._t_dash     = DashboardTab()
        self._t_alerts   = AlertsTab()
        self._t_ai       = AICopilotTab()
        self._t_intel    = ThreatIntelTab()
        self._t_soar     = SOARTab()
        self._t_redteam  = RedTeamTab()
        self._t_cloud    = CloudTab()
        self._t_sandbox  = SandboxTab()
        self._t_honeypot = HoneypotTab()
        self._t_vpn      = VPNTab()
        self._t_reports  = ReportsTab()
        self._t_logs     = LogsTab()
        self._t_settings = SettingsTab(on_theme_change=self._apply_theme)

        nav = [
            ("⬡\nDashboard",   self._t_dash),
            ("🚨\nAlerts",      self._t_alerts),
            ("🤖\nAI Copilot",  self._t_ai),
            ("🌐\nThreat Intel",self._t_intel),
            ("⚡\nSOAR",        self._t_soar),
            ("🎯\nRed Team",    self._t_redteam),
            ("☁\nCloud",        self._t_cloud),
            ("🔬\nSandbox",     self._t_sandbox),
            ("🍯\nHoneypot",    self._t_honeypot),
            ("🔒\nVPN",         self._t_vpn),
            ("📊\nReports",     self._t_reports),
            ("📜\nLogs",        self._t_logs),
            ("⚙\nSettings",    self._t_settings),
        ]
        for label, widget in nav:
            self.tabs.addTab(widget, label)

        self.tabs.setStyleSheet("""
            QTabBar::tab { width:88px;height:68px;font-size:11px;
                           font-weight:600;padding:6px 4px;text-align:center; }
        """)
        root.addWidget(self.tabs, 1)

        self._sb = QStatusBar()
        self.setStatusBar(self._sb)
        self._lbl_status = QLabel("Ready")
        self._lbl_ws     = QLabel("⬤ API")
        self._lbl_ver    = QLabel("SentinelAI v1.0  •  Hassan Hamed Faris  •  FUE 2026")
        self._lbl_ver.setStyleSheet("color:#484F58;")
        self._sb.addWidget(self._lbl_status)
        self._sb.addPermanentWidget(self._lbl_ws)
        self._sb.addPermanentWidget(self._lbl_ver)

        for seq, idx in [("Ctrl+1",0),("Ctrl+2",1),("Ctrl+3",2),("Ctrl+4",3),
                         ("Ctrl+5",4),("Ctrl+6",5),("Ctrl+7",6),("Ctrl+8",7),
                         ("Ctrl+9",8)]:
            act = QAction(self)
            act.setShortcut(QKeySequence(seq))
            act.triggered.connect(lambda _, i=idx: self.tabs.setCurrentIndex(i))
            self.addAction(act)

    def _build_header(self) -> QWidget:
        hdr = QWidget()
        hdr.setFixedHeight(50)
        lay = QHBoxLayout(hdr)
        lay.setContentsMargins(16, 0, 16, 0)
        lay.setSpacing(12)
        lbl = QLabel("🛡️  SentinelAI")
        lbl.setStyleSheet("font-size:17px;font-weight:800;color:#00E5FF;")
        self._lbl_alerts_cnt = QLabel("⬤ 0 alerts")
        self._lbl_alerts_cnt.setStyleSheet("color:#94A3B8;font-size:12px;")
        self._lbl_live = QLabel("● LIVE")
        self._lbl_live.setStyleSheet("color:#10B981;font-weight:700;font-size:12px;")
        self._status_panel = QWidget()
        self._status_panel.setObjectName("statusPanel")
        panel_lay = QVBoxLayout(self._status_panel)
        panel_lay.setContentsMargins(10, 6, 10, 6)
        panel_lay.setSpacing(2)
        self._lbl_backend_ready = QLabel("Backend: checking…")
        self._lbl_backend_ready.setObjectName("sub")
        self._lbl_sync_time = QLabel("Last sync: never")
        self._lbl_sync_time.setObjectName("sub")
        panel_lay.addWidget(self._lbl_backend_ready)
        panel_lay.addWidget(self._lbl_sync_time)
        self._btn_theme = QPushButton("🌙 Dark")
        self._btn_theme.setFixedWidth(90)
        self._btn_theme.clicked.connect(self._toggle_theme)
        btn_ref = QPushButton("↺ Refresh All")
        btn_ref.clicked.connect(self._refresh_all)
        lay.addWidget(lbl)
        lay.addSpacing(16)
        lay.addWidget(self._lbl_alerts_cnt)
        lay.addStretch()
        lay.addWidget(self._lbl_live)
        lay.addWidget(self._status_panel)
        lay.addWidget(btn_ref)
        lay.addWidget(self._btn_theme)
        hdr.setStyleSheet("background:#161B22;border-bottom:1px solid #21262D;")
        return hdr

    def _apply_theme(self, theme: str):
        self._theme = theme
        QApplication.instance().setStyleSheet(DARK if theme == "dark" else LIGHT)
        self._btn_theme.setText("☀️ Light" if theme == "dark" else "🌙 Dark")
        bg  = "#161B22" if theme == "dark" else "#EAEEF2"
        bdr = "#21262D" if theme == "dark" else "#D0D7DE"
        self._header.setStyleSheet(f"background:{bg};border-bottom:1px solid {bdr};")
        panel_bg = "#0D1117" if theme == "dark" else "#FFFFFF"
        panel_bdr = "#30363D" if theme == "dark" else "#D0D7DE"
        self._status_panel.setStyleSheet(
            f"QWidget#statusPanel {{ background:{panel_bg}; border:1px solid {panel_bdr}; border-radius:8px; }}"
        )

    def _toggle_theme(self):
        self._apply_theme("light" if self._theme == "dark" else "dark")

    def _start_status_timer(self):
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._check_status)
        self._timer.start(60_000)
        QTimer.singleShot(1200, self._check_status)

    def _check_status(self):
        w = Worker(api.health_all)
        w.result.connect(self._on_health)
        w.error.connect(lambda e: None)
        w.start()
        self._hw = w

    def _on_health(self, res: dict):
        up = sum(1 for v in res.values() if v)
        total = len(res)
        col = "#10B981" if up == total else "#F59E0B" if up > total // 2 else "#EF4444"
        self._lbl_ws.setStyleSheet(f"color:{col};font-weight:700;")
        self._lbl_ws.setText(f"⬤ {up}/{total} services")
        readiness = "ready" if up == total else f"degraded ({up}/{total})"
        self._lbl_backend_ready.setText(f"Backend: {readiness}")
        self._lbl_backend_ready.setStyleSheet(f"color:{col};font-weight:700;font-size:12px;")
        from datetime import datetime
        self._lbl_status.setText(f"Services {up}/{total} online  |  {datetime.now().strftime('%H:%M:%S')}")
        last_sync = api.get_last_sync_at() or "never"
        self._lbl_sync_time.setText(f"Last sync: {last_sync}")
        # Update header alert count
        try:
            total_alerts = sum(1 for _ in [])  # Will be updated from dashboard
        except Exception:
            pass

    def _refresh_all(self):
        try:
            self._t_dash._auto_refresh()
        except Exception:
            pass
        try:
            self._t_alerts._load()
        except Exception:
            pass
        self._check_status()
        self._lbl_status.setText("All panels refreshed")

    def closeEvent(self, event):
        """Clean shutdown of WebSocket client and worker threads."""
        try:
            if hasattr(self, '_ws_client'):
                self._ws_client.stop()
        except Exception:
            pass
        try:
            if hasattr(self, '_timer'):
                self._timer.stop()
        except Exception:
            pass
        event.accept()
