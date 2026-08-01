import json
from pathlib import Path
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QGroupBox,QLineEdit,QSpinBox,QCheckBox,QComboBox,QTextEdit,QTabWidget,
    QFormLayout)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont
from utils.worker import Worker
import api.client as api

CONFIG_FILE = Path.home() / ".sentinelai" / "desktop_config.json"


class SettingsTab(QWidget):
    def __init__(self, on_theme_change=None):
        super().__init__()
        self._workers=[]
        self._on_theme=on_theme_change
        CONFIG_FILE.parent.mkdir(parents=True,exist_ok=True)
        self._cfg=self._load_cfg()
        self._build()
        self._apply_cfg()

    def _load_cfg(self):
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                cfg.setdefault("base_urls", api.BASE_URLS.copy())
                cfg.setdefault("token", "")
                return cfg
            except Exception:
                pass
        return {
            "theme": "dark",
            "refresh_interval": 30,
            "auto_refresh": True,
            "base_urls": api.BASE_URLS.copy(),
            "token": "",
        }

    def _save_cfg(self):
        self._cfg["base_urls"] = api.BASE_URLS.copy()
        if hasattr(api, "_token"):
            self._cfg["token"] = api._token
        try:
            CONFIG_FILE.write_text(json.dumps(self._cfg, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._conn_tab(),"🔌 Connection")
        tabs.addTab(self._appear_tab(),"🎨 Appearance")
        tabs.addTab(self._auth_tab(),"🔐 Authentication")
        tabs.addTab(self._about_tab(),"ℹ About")
        root.addWidget(tabs)

    def _conn_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(16,16,16,16)
        lay.setSpacing(12)
        grp=QGroupBox("Service Endpoints")
        g=QVBoxLayout(grp)
        self._fields={}
        form=QFormLayout()
        for name,url in api.BASE_URLS.items():
            le=QLineEdit(url)
            self._fields[name]=le
            form.addRow(f"{name}:",le)
        g.addLayout(form)
        lay.addWidget(grp)
        r=QHBoxLayout()
        bs=QPushButton("💾 Save")
        bs.setObjectName("primary")
        bs.clicked.connect(self._save_endpoints)
        bt=QPushButton("🔍 Test All")
        bt.clicked.connect(self._test)
        br=QPushButton("🔄 Reset to Default")
        br.clicked.connect(self._reset_endpoints)
        r.addWidget(bs)
        r.addWidget(bt)
        r.addWidget(br)
        r.addStretch()
        lay.addLayout(r)
        self.te_log=QTextEdit()
        self.te_log.setReadOnly(True)
        self.te_log.setFont(QFont("Courier New",11))
        self.te_log.setMaximumHeight(160)
        lay.addWidget(self.te_log)
        grp2=QGroupBox("Auto-Refresh")
        g2=QHBoxLayout(grp2)
        self.chk_auto=QCheckBox("Enable auto-refresh")
        self.sp_int=QSpinBox()
        self.sp_int.setRange(5,300)
        self.sp_int.setValue(30)
        self.sp_int.setSuffix(" sec")
        g2.addWidget(self.chk_auto)
        g2.addSpacing(16)
        g2.addWidget(QLabel("Interval:"))
        g2.addWidget(self.sp_int)
        g2.addStretch()
        lay.addWidget(grp2)
        lay.addStretch()
        return w

    def _appear_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(16,16,16,16)
        lay.setSpacing(16)
        grp=QGroupBox("Theme")
        g=QHBoxLayout(grp)
        self.cb_theme=QComboBox()
        self.cb_theme.addItems(["dark","light"])
        self.cb_theme.setMinimumWidth(140)
        ba=QPushButton("Apply")
        ba.setObjectName("primary")
        ba.clicked.connect(self._apply_theme)
        g.addWidget(QLabel("Color Theme:"))
        g.addWidget(self.cb_theme)
        g.addWidget(ba)
        g.addStretch()
        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _auth_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(16,16,16,16)
        lay.setSpacing(12)
        grp=QGroupBox("API Authentication")
        g=QFormLayout(grp)
        self.le_u=QLineEdit("admin")
        self.le_p=QLineEdit()
        self.le_p.setEchoMode(QLineEdit.Password)
        self.le_m=QLineEdit()
        self.le_m.setMaximumWidth(160)
        self.le_m.setPlaceholderText("Leave blank if MFA disabled")
        self.le_t=QLineEdit()
        self.le_t.setPlaceholderText("Existing JWT token (optional)")
        g.addRow("Username:",self.le_u)
        g.addRow("Password:",self.le_p)
        g.addRow("MFA Code:",self.le_m)
        g.addRow("Token:",self.le_t)
        lay.addWidget(grp)
        br=QHBoxLayout()
        bl=QPushButton("🔐 Login")
        bl.setObjectName("primary")
        bl.setMinimumHeight(38)
        bl.clicked.connect(self._login)
        bst=QPushButton("💾 Save Token")
        bst.clicked.connect(self._save_token)
        bcl=QPushButton("🗑 Clear Token")
        bcl.clicked.connect(self._clear_token)
        br.addWidget(bl)
        br.addWidget(bst)
        br.addWidget(bcl)
        br.addStretch()
        lay.addLayout(br)
        self.lbl_auth=QLabel("")
        self.lbl_auth.setObjectName("sub")
        lay.addWidget(self.lbl_auth)
        # Show current token status
        if api._token:
            self.lbl_auth.setText("✅ Token loaded from config")
            self.le_t.setText(api._token)
        lay.addStretch()
        return w

    def _about_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(24,24,24,24)
        lay.setSpacing(10)
        logo=QLabel("🛡️")
        logo.setAlignment(Qt.AlignCenter)
        logo.setStyleSheet("font-size:60px;")
        lay.addWidget(logo)
        for line,style in [
            ("SentinelAI Desktop Control Panel","font-size:19px;font-weight:800;color:#00E5FF;"),
            ("Version 1.0.0","font-size:13px;color:#94A3B8;"),
            ("Autonomous AI-Powered SOC Platform","font-size:13px;color:#94A3B8;"),
            ("",""),
            ("Built by Hassan Hamed Faris","font-size:13px;font-weight:600;color:#E6EDF3;"),
            ("Cybersecurity Engineering — Future University in Egypt (FUE), 2026","font-size:12px;color:#94A3B8;"),
            ("GitHub: github.com/faris7assan","font-size:12px;color:#00E5FF;"),
        ]:
            lbl=QLabel(line)
            lbl.setAlignment(Qt.AlignCenter)
            if style:
                lbl.setStyleSheet(style)
            lay.addWidget(lbl)
        grp=QGroupBox("Stack")
        g=QVBoxLayout(grp)
        tech=QLabel("Python · PyQt5 · FastAPI · SQLite-backed local dev backend · requests · LangChain · Ollama")
        tech.setWordWrap(True)
        tech.setAlignment(Qt.AlignCenter)
        tech.setStyleSheet("color:#94A3B8;font-size:11px;")
        g.addWidget(tech)
        lay.addWidget(grp)
        lay.addStretch()
        return w

    def _apply_cfg(self):
        self.cb_theme.setCurrentText(self._cfg.get("theme","dark"))
        self.sp_int.setValue(self._cfg.get("refresh_interval",30))
        self.chk_auto.setChecked(self._cfg.get("auto_refresh",True))

    def _save_endpoints(self):
        for name,le in self._fields.items():
            val = le.text().strip()
            if val:
                api.BASE_URLS[name]=val
        self._save_cfg()
        self.te_log.append("✅ Endpoints saved")

    def _reset_endpoints(self):
        defaults = {
            "gateway":"http://localhost:8000","auth":"http://localhost:8001",
            "logs":"http://localhost:8002","detection":"http://localhost:8003",
            "ai":"http://localhost:8004","soar":"http://localhost:8005",
            "threatintel":"http://localhost:8006","alerts":"http://localhost:8007",
            "reports":"http://localhost:8008","vpn":"http://localhost:8009",
            "honeypot":"http://localhost:8010","sandbox":"http://localhost:8011",
            "cloud":"http://localhost:8012","redteam":"http://localhost:8013",
            "agents":"http://localhost:8014","metrics":"http://localhost:8015",
        }
        for name, url in defaults.items():
            api.BASE_URLS[name] = url
            if name in self._fields:
                self._fields[name].setText(url)
        self._save_cfg()
        self.te_log.append("✅ Endpoints reset to defaults")

    def _test(self):
        self.te_log.clear()
        self.te_log.append("Testing all endpoints…")
        w=Worker(api.health_all)
        w.result.connect(self._on_test)
        w.error.connect(lambda e:self.te_log.append(f"❌ {e}"))
        self._workers.append(w)
        w.start()

    def _on_test(self,res):
        up = 0
        total = len(res)
        for name,ok in sorted(res.items()):
            self.te_log.append(f"{'✅' if ok else '❌'}  {name:14s}  {api.BASE_URLS.get(name,'')}")
            if ok:
                up += 1
        self.te_log.append(f"\n{'='*40}\n{up}/{total} services online")

    def _apply_theme(self):
        theme=self.cb_theme.currentText()
        self._cfg["theme"]=theme
        self._save_cfg()
        if self._on_theme:
            self._on_theme(theme)

    def _login(self):
        u,p,m=self.le_u.text().strip(),self.le_p.text(),self.le_m.text().strip()
        if not u or not p:
            self.lbl_auth.setText("❌ Username and password required")
            return
        self.lbl_auth.setText("Logging in…")
        w=Worker(api.login,u,p,m)
        w.result.connect(self._on_login)
        w.error.connect(lambda e:self.lbl_auth.setText(f"❌ {e}"))
        self._workers.append(w)
        w.start()

    def _on_login(self,d):
        token=d.get("access_token","")
        if token:
            api.set_token(token)
            self.le_t.setText(token)
            user=d.get("user",{})
            self.lbl_auth.setText(f"✅ Logged in as {user.get('username','')} [{user.get('role','')}]")
            self._save_cfg()
        else:
            self.lbl_auth.setText("❌ No token received")

    def _save_token(self):
        token=self.le_t.text().strip()
        if token:
            api.set_token(token)
            self._cfg["token"]=token
            self._save_cfg()
            self.lbl_auth.setText("✅ Token saved")
        else:
            self.lbl_auth.setText("⚠ No token to save")

    def _clear_token(self):
        api.set_token("")
        self.le_t.clear()
        self._cfg["token"] = ""
        self._save_cfg()
        self.lbl_auth.setText("Token cleared")
