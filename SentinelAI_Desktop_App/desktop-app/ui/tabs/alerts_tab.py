import json
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QHeaderView,QComboBox,QGroupBox,QTextEdit,
    QSplitter,QLineEdit,QFileDialog,QTableView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont
from utils.worker import Worker
from ui.models import DataTableModel
import api.client as api

SEV={"critical":"#EF4444","high":"#F59E0B","medium":"#0EA5E9","low":"#10B981","info":"#00E5FF"}


class AlertsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._alerts=[]
        self._build()
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(800,self._load)

    def _build(self):
        root=QVBoxLayout(self)
        root.setSpacing(10)
        root.setContentsMargins(20,20,20,20)

        bar=QHBoxLayout()
        bar.setSpacing(8)
        self.cb_sev=QComboBox()
        self.cb_sev.addItems(["All","critical","high","medium","low"])
        self.le_s=QLineEdit()
        self.le_s.setPlaceholderText("Filter by IP / rule / technique…")
        self.le_s.textChanged.connect(self._filter)
        btn_ref=QPushButton("↺ Refresh")
        btn_ref.clicked.connect(self._load)
        btn_exp=QPushButton("💾 Export CSV")
        btn_exp.clicked.connect(self._export)
        self.cb_sev.currentTextChanged.connect(self._filter)
        self.lbl_cnt=QLabel("0")
        self.lbl_cnt.setObjectName("sub")
        bar.addWidget(QLabel("Sev:"))
        bar.addWidget(self.cb_sev)
        bar.addWidget(self.le_s,1)
        bar.addWidget(btn_ref)
        bar.addWidget(btn_exp)
        bar.addStretch()
        bar.addWidget(self.lbl_cnt)
        root.addLayout(bar)

        sp=QSplitter(Qt.Vertical)

        self.tbl=QTableView()
        self._headers = [
            {"title": "Severity", "key": "severity"},
            {"title": "Rule", "key": "rule_name"},
            {"title": "Source IP", "key": "source_ip"},
            {"title": "Hostname", "key": "hostname"},
            {"title": "Tactic", "key": "mitre_tactic"},
            {"title": "Technique", "key": "mitre_technique"},
            {"title": "Time", "key": "timestamp"}
        ]
        self._model = DataTableModel(headers=self._headers)
        self.tbl.setModel(self._model)

        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableView.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableView.SelectRows)
        self.tbl.clicked.connect(self._select)
        sp.addWidget(self.tbl)

        grp=QGroupBox("Alert Detail & Actions")
        gl=QVBoxLayout(grp)
        gl.setContentsMargins(8,8,8,8)
        self.te=QTextEdit()
        self.te.setReadOnly(True)
        self.te.setFont(QFont("Courier New",11))
        self.te.setMaximumHeight(160)
        br=QHBoxLayout()
        self.btn_ai=QPushButton("🤖 AI Analysis")
        self.btn_ai.setObjectName("primary")
        self.btn_pb=QPushButton("⚡ Run Playbook")
        self.btn_pb.setObjectName("success")
        self.btn_it=QPushButton("🔍 Intel Lookup")
        self.btn_it.setObjectName("warning")
        self.btn_ai.clicked.connect(self._ai)
        self.btn_pb.clicked.connect(self._playbook)
        self.btn_it.clicked.connect(self._intel)
        br.addWidget(self.btn_ai)
        br.addWidget(self.btn_pb)
        br.addWidget(self.btn_it)
        br.addStretch()
        gl.addWidget(self.te)
        gl.addLayout(br)
        sp.addWidget(grp)
        sp.setSizes([400,220])
        root.addWidget(sp,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _load(self):
        sev=self.cb_sev.currentText()
        sev=None if sev=="All" else sev
        self.lbl_st.setText("Loading…")
        w=Worker(api.get_recent_alerts,200,sev)
        w.result.connect(self._on_loaded)
        w.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()
        # Clean up finished workers
        self._workers = [w for w in self._workers if w.isRunning()]

    def _on_loaded(self, a):
        if not isinstance(a, list):
            self.lbl_st.setText("Unexpected response format")
            return
        self._alerts = a
        self._filter()
        self.lbl_st.setText(f"Loaded {len(a)} alerts")

    def _filter(self):
        q=self.le_s.text().lower()
        sev=self.cb_sev.currentText().lower()
        shown=[a for a in self._alerts if
               (sev=="all" or a.get("severity","")==sev) and
               (not q or any(q in str(v).lower() for v in a.values()))]

        # Format data for the model
        model_data = []
        for a in shown:
            s = a.get("severity", "low")
            row_data = {
                "severity": s.upper(),
                "rule_name": a.get("rule_name", ""),
                "source_ip": a.get("source_ip", ""),
                "hostname": a.get("hostname", ""),
                "mitre_tactic": a.get("mitre_tactic", ""),
                "mitre_technique": a.get("mitre_technique", ""),
                "timestamp": str(a.get("timestamp", ""))[:19].replace("T", " "),
                "color": SEV.get(s, "#00E5FF"),
                "raw": a
            }
            model_data.append(row_data)

        self._model.update_data(model_data)
        self.lbl_cnt.setText(f"{len(shown)} alerts")

    def _get_alert(self):
        idx = self.tbl.selectionModel().currentIndex()
        if not idx.isValid():
            return None
        return self._model.get_raw_data(idx.row())

    def _select(self):
        a=self._get_alert()
        if a:
            self.te.setPlainText(json.dumps(a,indent=2))

    def _ai(self):
        a=self._get_alert()
        if not a:
            self.lbl_st.setText("Select an alert first")
            return
        self.btn_ai.setEnabled(False)
        self.lbl_st.setText("Running AI analysis…")
        w=Worker(api.analyze_alert_ai,a)
        w.result.connect(lambda d:(self.te.setPlainText(d.get("analysis","No response")),
                                    self.btn_ai.setEnabled(True),self.lbl_st.setText("AI analysis complete")))
        w.error.connect(lambda e:(self.lbl_st.setText(f"AI error: {e}"),self.btn_ai.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _playbook(self):
        a=self._get_alert()
        if not a:
            self.lbl_st.setText("Select an alert first")
            return
        name=a.get("detection_type","default")
        self.lbl_st.setText(f"Running playbook '{name}'…")
        self.btn_pb.setEnabled(False)
        w=Worker(api.run_playbook,name,a)
        w.result.connect(lambda d:(self.lbl_st.setText(f"Playbook '{name}' → {d.get('status','')}"),
                                    self.btn_pb.setEnabled(True)))
        w.error.connect(lambda e:(self.lbl_st.setText(f"SOAR error: {e}"),self.btn_pb.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _intel(self):
        a=self._get_alert()
        if not a:
            self.lbl_st.setText("Select an alert first")
            return
        ip=a.get("source_ip","")
        if not ip:
            self.lbl_st.setText("No IP in this alert")
            return
        self.lbl_st.setText(f"Looking up {ip}…")
        self.btn_it.setEnabled(False)
        w=Worker(api.lookup_ip,ip)
        w.result.connect(lambda d:(self.te.setPlainText(json.dumps(d,indent=2)),
                                    self.lbl_st.setText(f"Intel: {d.get('threat_score',{}).get('verdict','—')}"),
                                    self.btn_it.setEnabled(True)))
        w.error.connect(lambda e:(self.lbl_st.setText(f"Intel error: {e}"),self.btn_it.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _export(self):
        if not self._alerts:
            self.lbl_st.setText("No alerts to export")
            return
        p,_=QFileDialog.getSaveFileName(self,"Export CSV","alerts.csv","CSV (*.csv)")
        if not p:
            return
        keys=["alert_id","severity","rule_name","source_ip","hostname","mitre_technique","timestamp"]
        try:
            with open(p,"w",newline="",encoding="utf-8") as f:
                import csv as _csv
                w=_csv.DictWriter(f,fieldnames=keys,extrasaction="ignore")
                w.writeheader()
                w.writerows(self._alerts)
            self.lbl_st.setText(f"Exported {len(self._alerts)} rows → {p}")
        except Exception as e:
            self.lbl_st.setText(f"Export error: {e}")
