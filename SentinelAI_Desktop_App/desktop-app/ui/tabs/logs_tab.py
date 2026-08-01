import json,csv
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QGroupBox,QComboBox,QLineEdit,QTextEdit,QFileDialog,
    QHeaderView,QSpinBox,QTabWidget,QTableView)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont
from utils.worker import Worker
from ui.models import DataTableModel
import api.client as api

SEV={"critical":"#EF4444","high":"#F59E0B","medium":"#0EA5E9","low":"#10B981","info":"#00E5FF"}


class LogsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._logs=[]
        self._build()
        from PyQt5.QtCore import QTimer
        QTimer.singleShot(1000, self._load_recent)

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._search_tab(),"🔍 Search Logs")
        tabs.addTab(self._ingest_tab(),"📥 Ingest Event")
        tabs.addTab(self._stats_tab(),"📊 Log Stats")
        root.addWidget(tabs)

    def _search_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        bar=QHBoxLayout()
        self.le_q=QLineEdit()
        self.le_q.setPlaceholderText("Search query e.g. failed_login")
        self.le_q.setMinimumHeight(36)
        self.le_q.returnPressed.connect(self._search)
        self.cb_sev=QComboBox()
        self.cb_sev.addItems(["All","critical","high","medium","low","info"])
        self.sp_size=QSpinBox()
        self.sp_size.setRange(10,1000)
        self.sp_size.setValue(100)
        self.sp_size.setSuffix(" rows")
        self.sp_size.setFixedWidth(90)
        bs=QPushButton("🔍 Search")
        bs.setObjectName("primary")
        bs.setMinimumHeight(36)
        bs.clicked.connect(self._search)
        br=QPushButton("↺ Recent")
        br.setMinimumHeight(36)
        br.clicked.connect(self._load_recent)
        be=QPushButton("💾 Export CSV")
        be.clicked.connect(self._export)
        bar.addWidget(self.le_q,1)
        bar.addWidget(QLabel("Sev:"))
        bar.addWidget(self.cb_sev)
        bar.addWidget(self.sp_size)
        bar.addWidget(bs)
        bar.addWidget(br)
        bar.addWidget(be)
        lay.addLayout(bar)

        self.tbl=QTableView()
        self._headers = [
            {"title": "Severity", "key": "severity"},
            {"title": "Source", "key": "log_source"},
            {"title": "Event", "key": "event_type"},
            {"title": "Source IP", "key": "source_ip"},
            {"title": "Hostname", "key": "hostname"},
            {"title": "Timestamp", "key": "timestamp"}
        ]
        self._model = DataTableModel(headers=self._headers)
        self.tbl.setModel(self._model)

        self.tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableView.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableView.SelectRows)
        self.tbl.clicked.connect(self._show_raw)
        lay.addWidget(self.tbl,1)
        grp=QGroupBox("Raw Log")
        g=QVBoxLayout(grp)
        self.te_raw=QTextEdit()
        self.te_raw.setReadOnly(True)
        self.te_raw.setFont(QFont("Courier New",11))
        self.te_raw.setMaximumHeight(100)
        g.addWidget(self.te_raw)
        lay.addWidget(grp)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        lay.addWidget(self.lbl_st)
        return w

    def _ingest_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        grp=QGroupBox("Manual Log Event")
        g=QVBoxLayout(grp)
        r1=QHBoxLayout()
        self.le_ip=QLineEdit()
        self.le_ip.setPlaceholderText("Source IP")
        self.le_host=QLineEdit()
        self.le_host.setPlaceholderText("Hostname")
        r1.addWidget(QLabel("IP:"))
        r1.addWidget(self.le_ip)
        r1.addSpacing(8)
        r1.addWidget(QLabel("Host:"))
        r1.addWidget(self.le_host)
        g.addLayout(r1)
        r2=QHBoxLayout()
        self.cb_src=QComboBox()
        self.cb_src.addItems(["syslog","auditd","zeek","suricata","winevent","osquery","cloud"])
        self.cb_sev2=QComboBox()
        self.cb_sev2.addItems(["info","low","medium","high","critical"])
        self.le_evt=QLineEdit()
        self.le_evt.setPlaceholderText("event_type")
        r2.addWidget(QLabel("Source:"))
        r2.addWidget(self.cb_src)
        r2.addSpacing(8)
        r2.addWidget(QLabel("Sev:"))
        r2.addWidget(self.cb_sev2)
        r2.addSpacing(8)
        r2.addWidget(QLabel("Event:"))
        r2.addWidget(self.le_evt,1)
        g.addLayout(r2)
        self.te_raw2=QTextEdit()
        self.te_raw2.setMaximumHeight(100)
        self.te_raw2.setPlaceholderText("Paste raw log line…")
        g.addWidget(QLabel("Raw Log:"))
        g.addWidget(self.te_raw2)
        lay.addWidget(grp)
        br=QHBoxLayout()
        bi=QPushButton("📥 Ingest")
        bi.setObjectName("primary")
        bi.setMinimumHeight(36)
        bi.clicked.connect(self._ingest)
        bf=QPushButton("📂 Ingest from File")
        bf.setMinimumHeight(36)
        bf.clicked.connect(self._ingest_file)
        br.addWidget(bi)
        br.addWidget(bf)
        br.addStretch()
        lay.addLayout(br)
        self.te_log=QTextEdit()
        self.te_log.setReadOnly(True)
        self.te_log.setFont(QFont("Courier New",11))
        lay.addWidget(self.te_log,1)
        return w

    def _stats_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        btn=QPushButton("↺ Load Stats")
        btn.setObjectName("primary")
        btn.clicked.connect(self._load_stats)
        lay.addWidget(btn)
        from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
        self.tbl_s=QTableWidget(0,2)
        self.tbl_s.setHorizontalHeaderLabels(["Metric","Value"])
        self.tbl_s.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
        self.tbl_s.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl_s.setAlternatingRowColors(True)
        self.tbl_s.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tbl_s,1)
        self.lbl_s=QLabel("")
        self.lbl_s.setObjectName("sub")
        lay.addWidget(self.lbl_s)
        return w

    def _search(self):
        q=self.le_q.text().strip()
        if not q:
            self._load_recent()
            return
        self.lbl_st.setText("Searching…")
        w=Worker(api.search_logs,q,self.sp_size.value())
        w.result.connect(self._on_search)
        w.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_search(self, d):
        if not isinstance(d, dict):
            self.lbl_st.setText("Unexpected response format")
            return
        results = d.get("results", [])
        self._populate(results)
        self.lbl_st.setText(f"Found {len(results)} events (Total: {d.get('total', 0)})")

    def _load_recent(self):
        sev=self.cb_sev.currentText()
        sev=None if sev=="All" else sev
        self.lbl_st.setText("Loading…")
        w=Worker(api.get_recent_alerts,self.sp_size.value(),sev)
        w.result.connect(lambda items:(self._populate(items if isinstance(items, list) else []),
                                        self.lbl_st.setText(f"{len(items) if isinstance(items, list) else 0} events")))
        w.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _populate(self,items):
        if not isinstance(items, list):
            items = []
        self._logs=items

        model_data = []
        for ev in items:
            sev=ev.get("severity","info")
            row_data = {
                "severity": sev.upper(),
                "log_source": ev.get("log_source",""),
                "event_type": ev.get("event_type",""),
                "source_ip": ev.get("source_ip",""),
                "hostname": ev.get("hostname",""),
                "timestamp": str(ev.get("timestamp",""))[:19].replace("T"," "),
                "color": SEV.get(sev,"#00E5FF"),
                "raw": ev
            }
            model_data.append(row_data)

        self._model.update_data(model_data)

    def _show_raw(self):
        idx = self.tbl.selectionModel().currentIndex()
        if not idx.isValid():
            return
        r = self._model.get_raw_data(idx.row())
        if r:
            self.te_raw.setPlainText(json.dumps(r,indent=2))

    def _ingest(self):
        ip_text = self.le_ip.text().strip()
        host_text = self.le_host.text().strip()
        evt_text = self.le_evt.text().strip()
        raw_text = self.te_raw2.toPlainText().strip()
        
        if not ip_text or not host_text or not evt_text or not raw_text:
            self.te_log.append("⚠ Please provide IP, hostname, event type, and raw log")
            return
            
        event={"source_ip": ip_text,
               "hostname": host_text,
               "log_source":self.cb_src.currentText(),
               "event_type": evt_text,
               "severity":self.cb_sev2.currentText(),
               "raw_log": raw_text,
               "parsed":{},"os_type":"linux"}
        w=Worker(api.ingest_log,event)
        w.result.connect(lambda d:self.te_log.append(f"✅ Ingested — hash:{d.get('event_hash','')[:12]}"))
        w.error.connect(lambda e:self.te_log.append(f"❌ {e}"))
        self._workers.append(w)
        w.start()

    def _ingest_file(self):
        path,_=QFileDialog.getOpenFileName(self,"Select Log File","","Log files (*.log *.txt *.json);;All Files (*)")
        if not path:
            return
        try:
            with open(path,"r",errors="replace") as f:
                lines=[l.strip() for l in f if l.strip()]
        except Exception as e:
            self.te_log.append(f"❌ Cannot read: {e}")
            return
        if not lines:
            self.te_log.append("⚠ File is empty")
            return
        events=[{"source_ip":"file-import","hostname":"file-import","log_source":"syslog",
                 "event_type":"log_entry","severity":"info","raw_log":line,"parsed":{},"os_type":"linux"}
                for line in lines[:1000]]
        self.te_log.append(f"Ingesting {len(events)} lines from {path}…")
        w=Worker(api._post,"logs","/logs/bulk",{"events":events})
        w.result.connect(lambda d:self.te_log.append(f"✅ Bulk ingested {len(events)} lines"))
        w.error.connect(lambda e:self.te_log.append(f"❌ {e}"))
        self._workers.append(w)
        w.start()

    def _export(self):
        if not self._logs:
            self.lbl_st.setText("No logs to export")
            return
        p,_=QFileDialog.getSaveFileName(self,"Export Logs","sentinelai_logs.csv","CSV (*.csv)")
        if not p:
            return
        keys=["severity","log_source","event_type","source_ip","hostname","timestamp"]
        try:
            with open(p,"w",newline="",encoding="utf-8") as f:
                wcsv=csv.DictWriter(f,fieldnames=keys,extrasaction="ignore")
                wcsv.writeheader()
                wcsv.writerows(self._logs)
            self.lbl_st.setText(f"Exported {len(self._logs)} rows")
        except Exception as e:
            self.lbl_st.setText(f"Export error: {e}")

    def _load_stats(self):
        self.lbl_s.setText("Loading…")
        w=Worker(api.get_log_stats)
        w.result.connect(self._on_stats)
        w.error.connect(lambda e:self.lbl_s.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_stats(self,d):
        from PyQt5.QtWidgets import QTableWidgetItem
        if not isinstance(d, dict):
            self.lbl_s.setText("Unexpected response format")
            return
        self.tbl_s.setRowCount(0)
        for b in d.get("by_severity",{}).get("buckets",[]):
            r=self.tbl_s.rowCount()
            self.tbl_s.insertRow(r)
            self.tbl_s.setItem(r,0,QTableWidgetItem(f"Severity: {b.get('key','')}"))
            self.tbl_s.setItem(r,1,QTableWidgetItem(str(b.get("doc_count",0))))
        for b in d.get("by_source",{}).get("buckets",[]):
            r=self.tbl_s.rowCount()
            self.tbl_s.insertRow(r)
            self.tbl_s.setItem(r,0,QTableWidgetItem(f"Source: {b.get('key','')}"))
            self.tbl_s.setItem(r,1,QTableWidgetItem(str(b.get("doc_count",0))))
        self.lbl_s.setText("Stats loaded")
