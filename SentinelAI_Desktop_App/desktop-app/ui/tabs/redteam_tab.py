import json
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QTableWidget,QTableWidgetItem,QHeaderView,QGroupBox,QTextEdit,QComboBox,
    QLineEdit,QCheckBox,QProgressBar,QTabWidget,QSpinBox,QMessageBox,QApplication)
from PyQt5.QtGui import QFont
from utils.worker import Worker
import api.client as api


class RedTeamTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._scenarios=[]
        self._build()
        self._load_scenarios()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._sim_tab(),"🎯 Attack Simulation")
        tabs.addTab(self._phish_tab(),"🎣 Phishing Generator")
        tabs.addTab(self._hist_tab(),"📜 History")
        root.addWidget(tabs)

    def _sim_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(12)
        warn=QLabel("⚠️ Simulations inject real log events into SentinelAI. Use in controlled environments only.")
        warn.setStyleSheet("background:#4A3800;color:#F59E0B;border-radius:6px;padding:8px 12px;border:1px solid #9E6A03;")
        warn.setWordWrap(True)
        lay.addWidget(warn)
        grp=QGroupBox("Parameters")
        g=QVBoxLayout(grp)
        r1=QHBoxLayout()
        self.cb_sc=QComboBox()
        self.cb_sc.setMinimumWidth(240)
        br=QPushButton("↺")
        br.setFixedWidth(32)
        br.clicked.connect(self._load_scenarios)
        r1.addWidget(QLabel("Scenario:"))
        r1.addWidget(self.cb_sc,1)
        r1.addWidget(br)
        g.addLayout(r1)
        r2=QHBoxLayout()
        self.le_aip=QLineEdit()
        self.le_aip.setPlaceholderText("Attacker IP (auto)")
        self.le_tgt=QLineEdit()
        self.le_tgt.setPlaceholderText("Target host (auto)")
        r2.addWidget(QLabel("Attacker IP:"))
        r2.addWidget(self.le_aip)
        r2.addSpacing(10)
        r2.addWidget(QLabel("Target:"))
        r2.addWidget(self.le_tgt)
        g.addLayout(r2)
        r3=QHBoxLayout()
        self.chk_dry=QCheckBox("Dry run (preview only)")
        self.sp_delay=QSpinBox()
        self.sp_delay.setRange(0,2000)
        self.sp_delay.setValue(100)
        self.sp_delay.setSuffix(" ms")
        self.sp_delay.setFixedWidth(110)
        r3.addWidget(self.chk_dry)
        r3.addStretch()
        r3.addWidget(self.sp_delay)
        g.addLayout(r3)
        lay.addWidget(grp)
        br2=QHBoxLayout()
        self.btn_run=QPushButton("🎯 Launch Simulation")
        self.btn_run.setObjectName("danger")
        self.btn_run.setMinimumHeight(40)
        self.btn_run.clicked.connect(self._run)
        btn_apt=QPushButton("💀 Full APT Chain")
        btn_apt.setObjectName("danger")
        btn_apt.setMinimumHeight(40)
        btn_apt.clicked.connect(self._run_apt)
        br2.addWidget(self.btn_run)
        br2.addWidget(btn_apt)
        br2.addStretch()
        lay.addLayout(br2)
        self.pb=QProgressBar()
        self.pb.setVisible(False)
        lay.addWidget(self.pb)
        self.te=QTextEdit()
        self.te.setReadOnly(True)
        self.te.setFont(QFont("Courier New",11))
        lay.addWidget(self.te,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        lay.addWidget(self.lbl_st)
        self.tbl=QTableWidget(0,3)
        self.tbl.setHorizontalHeaderLabels(["ID","Name","MITRE"])
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setMaximumHeight(170)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.clicked.connect(self._select_sc)
        lay.addWidget(QLabel("Available Scenarios:"))
        lay.addWidget(self.tbl)
        return w

    def _phish_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        grp=QGroupBox("Phishing Parameters")
        g=QVBoxLayout(grp)
        r1=QHBoxLayout()
        self.le_email=QLineEdit()
        self.le_email.setPlaceholderText("user@company.com")
        self.le_dom=QLineEdit()
        self.le_dom.setPlaceholderText("company-secure.net")
        r1.addWidget(QLabel("Target:"))
        r1.addWidget(self.le_email)
        r1.addSpacing(10)
        r1.addWidget(QLabel("Sender Domain:"))
        r1.addWidget(self.le_dom)
        g.addLayout(r1)
        r2=QHBoxLayout()
        self.cb_lure=QComboBox()
        self.cb_lure.addItems(["vpn_credentials","payroll","hr_policy","it_support"])
        r2.addWidget(QLabel("Lure Type:"))
        r2.addWidget(self.cb_lure)
        r2.addStretch()
        g.addLayout(r2)
        lay.addWidget(grp)
        btn=QPushButton("🎣 Generate Email")
        btn.setObjectName("warning")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._gen_phish)
        lay.addWidget(btn)
        self.te_p=QTextEdit()
        self.te_p.setReadOnly(True)
        self.te_p.setFont(QFont("Courier New",11))
        lay.addWidget(self.te_p,1)
        br=QHBoxLayout()
        bc=QPushButton("📋 Copy")
        bc.clicked.connect(lambda:QApplication.clipboard().setText(self.te_p.toPlainText()))
        self.lbl_p=QLabel("")
        self.lbl_p.setObjectName("sub")
        br.addWidget(bc)
        br.addStretch()
        br.addWidget(self.lbl_p)
        lay.addLayout(br)
        return w

    def _hist_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        btn=QPushButton("↺ Refresh")
        btn.clicked.connect(self._load_hist)
        lay.addWidget(btn)
        self.tbl_h=QTableWidget(0,5)
        self.tbl_h.setHorizontalHeaderLabels(["Sim ID","Scenario","Attacker IP","Events","Timestamp"])
        self.tbl_h.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl_h.setAlternatingRowColors(True)
        self.tbl_h.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tbl_h,1)
        self.lbl_h=QLabel("")
        self.lbl_h.setObjectName("sub")
        lay.addWidget(self.lbl_h)
        return w

    def _load_scenarios(self):
        w=Worker(api.get_redteam_scenarios)
        w.result.connect(self._on_sc)
        w.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_sc(self,d):
        self._scenarios=d.get("scenarios",[])
        self.tbl.setRowCount(0)
        self.cb_sc.clear()
        for s in self._scenarios:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            self.tbl.setItem(r,0,QTableWidgetItem(s.get("id","")))
            self.tbl.setItem(r,1,QTableWidgetItem(s.get("name","")))
            self.tbl.setItem(r,2,QTableWidgetItem(s.get("mitre","")))
            self.cb_sc.addItem(f"{s['name']}  [{s['id']}]",s["id"])

    def _select_sc(self):
        row=self.tbl.currentRow()
        if row>=0 and row<len(self._scenarios):
            sid=self._scenarios[row]["id"]
            for i in range(self.cb_sc.count()):
                if self.cb_sc.itemData(i)==sid:
                    self.cb_sc.setCurrentIndex(i)
                    break

    def _run(self):
        sid=self.cb_sc.currentData()
        if not sid:
            return
        if not self.chk_dry.isChecked():
            if QMessageBox.question(self,"Confirm",f"Launch '{sid}'? Events will be injected.",
                QMessageBox.Yes|QMessageBox.No)!=QMessageBox.Yes:
                return
        self.btn_run.setEnabled(False)
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText(f"Running '{sid}'…")
        w=Worker(api.run_simulation,sid,self.le_aip.text().strip(),self.le_tgt.text().strip(),self.chk_dry.isChecked())
        w.result.connect(self._on_done)
        w.error.connect(lambda e:(self.lbl_st.setText(f"Error: {e}"),self.pb.setVisible(False),self.btn_run.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _run_apt(self):
        for i in range(self.cb_sc.count()):
            if "full_attack_chain" in (self.cb_sc.itemData(i) or ""):
                self.cb_sc.setCurrentIndex(i)
                break
        self._run()

    def _on_done(self,d):
        self.pb.setVisible(False)
        self.btn_run.setEnabled(True)
        self.te.setPlainText(json.dumps(d,indent=2))
        self.lbl_st.setText(f"✅ '{d.get('scenario','')}' — {d.get('events_shipped',0)} events  "
                            f"Attacker:{d.get('attacker_ip','')} Target:{d.get('target_host','')}")

    def _gen_phish(self):
        email=self.le_email.text().strip()
        domain=self.le_dom.text().strip()
        if not email:
            self.lbl_p.setText("⚠ Enter a target email address")
            return
        if not domain:
            self.lbl_p.setText("⚠ Enter a sender domain")
            return
        lure=self.cb_lure.currentText()
        self.lbl_p.setText("Generating…")
        w=Worker(api._post,"redteam","/redteam/phishing",{"target_email":email,"sender_domain":domain,"lure_type":lure})
        w.result.connect(lambda d:(self.te_p.setPlainText(json.dumps(d,indent=2)),
                                    self.lbl_p.setText("Generated — for training only")))
        w.error.connect(lambda e:self.lbl_p.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _load_hist(self):
        w=Worker(api._get,"redteam","/redteam/history")
        w.result.connect(self._on_hist)
        w.error.connect(lambda e:self.lbl_h.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_hist(self,items):
        if not isinstance(items,list):
            return
        self.tbl_h.setRowCount(0)
        for s in items:
            r=self.tbl_h.rowCount()
            self.tbl_h.insertRow(r)
            self.tbl_h.setItem(r,0,QTableWidgetItem(s.get("sim_id","")))
            self.tbl_h.setItem(r,1,QTableWidgetItem(s.get("scenario","")))
            self.tbl_h.setItem(r,2,QTableWidgetItem(s.get("attacker_ip","")))
            self.tbl_h.setItem(r,3,QTableWidgetItem(str(s.get("events",0))))
            self.tbl_h.setItem(r,4,QTableWidgetItem(s.get("timestamp","")[:19].replace("T"," ")))
        self.lbl_h.setText(f"{len(items)} simulations")
