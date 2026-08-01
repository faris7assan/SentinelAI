import os
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QTableWidget,QTableWidgetItem,QHeaderView,QGroupBox,QTextEdit,QComboBox,
    QLineEdit,QProgressBar,QFileDialog,QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont,QColor
from utils.worker import Worker
import api.client as api


class CloudTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._check_data=[]
        self._build()
        self._load_hist()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(12,12,12,12)
        root.setSpacing(10)
        grp=QGroupBox("Cloud Posture Scan")
        g=QHBoxLayout(grp)
        self.cb_p=QComboBox()
        self.cb_p.addItems(["aws","azure","gcp"])
        self.le_acc=QLineEdit()
        self.le_acc.setPlaceholderText("Account / Subscription ID")
        self.le_reg=QLineEdit()
        self.le_reg.setText("us-east-1")
        self.le_reg.setFixedWidth(120)
        self.btn=QPushButton("▶ Run Scan")
        self.btn.setObjectName("primary")
        self.btn.setMinimumHeight(36)
        self.btn.clicked.connect(self._scan)
        g.addWidget(QLabel("Provider:"))
        g.addWidget(self.cb_p)
        g.addSpacing(8)
        g.addWidget(QLabel("Account:"))
        g.addWidget(self.le_acc,1)
        g.addSpacing(8)
        g.addWidget(QLabel("Region:"))
        g.addWidget(self.le_reg)
        g.addWidget(self.btn)
        root.addWidget(grp)
        self.pb=QProgressBar()
        self.pb.setVisible(False)
        root.addWidget(self.pb)
        self.lbl_score=QLabel("")
        self.lbl_score.setTextFormat(Qt.RichText)
        root.addWidget(self.lbl_score)
        sp=QSplitter(Qt.Horizontal)
        self.tbl=QTableWidget(0,4)
        self.tbl.setHorizontalHeaderLabels(["ID","Check","Severity","Status"])
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.clicked.connect(self._show_detail)
        sp.addWidget(self.tbl)
        self.te=QTextEdit()
        self.te.setReadOnly(True)
        self.te.setFont(QFont("Courier New",11))
        self.te.setMaximumWidth(320)
        sp.addWidget(self.te)
        sp.setSizes([500,250])
        root.addWidget(sp,1)
        grp2=QGroupBox("Scan History")
        g2=QVBoxLayout(grp2)
        g2.setContentsMargins(6,6,6,6)
        self.tbl_h=QTableWidget(0,4)
        self.tbl_h.setHorizontalHeaderLabels(["Provider","Score","Grade","Scanned At"])
        self.tbl_h.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
        self.tbl_h.setMaximumHeight(120)
        self.tbl_h.setAlternatingRowColors(True)
        self.tbl_h.setEditTriggers(QTableWidget.NoEditTriggers)
        g2.addWidget(self.tbl_h)
        root.addWidget(grp2)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _scan(self):
        self.btn.setEnabled(False)
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText(f"Scanning {self.cb_p.currentText().upper()}…")
        w=Worker(api.cloud_scan,self.cb_p.currentText(),self.le_acc.text().strip(),self.le_reg.text().strip())
        w.result.connect(self._on_scan)
        w.error.connect(lambda e:(self.lbl_st.setText(f"Error: {e}"),self.pb.setVisible(False),self.btn.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _on_scan(self,d):
        self.pb.setVisible(False)
        self.btn.setEnabled(True)
        score=d.get("posture_score",0)
        grade=d.get("grade","?")
        col="#10B981" if score>=75 else "#F59E0B" if score>=50 else "#EF4444"
        self.lbl_score.setText(f'<span style="font-size:24px;font-weight:800;color:{col};">{score}/100</span>'
            f'  <span style="font-size:16px;color:{col};">Grade: {grade}</span>'
            f'  <span style="color:#94A3B8;font-size:12px;">PASS:{d.get("summary",{}).get("passing",0)} '
            f'FAIL:{d.get("summary",{}).get("failing",0)}</span>')
        checks=d.get("checks",[])
        self._check_data=checks
        self.tbl.setRowCount(0)
        for c in checks:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            st=c.get("status","")
            sev=c.get("severity","")
            self.tbl.setItem(r,0,QTableWidgetItem(c.get("check_id","")))
            self.tbl.setItem(r,1,QTableWidgetItem(c.get("title","")))
            si=QTableWidgetItem(sev)
            si.setForeground(QColor({"critical":"#EF4444","high":"#F59E0B","medium":"#0EA5E9","low":"#10B981"}.get(sev,"#00E5FF")))
            self.tbl.setItem(r,2,si)
            sti=QTableWidgetItem(st)
            sti.setForeground(QColor("#10B981" if st=="PASS" else "#EF4444" if st=="FAIL" else "#00E5FF"))
            self.tbl.setItem(r,3,sti)
        self.lbl_st.setText(f"Scan complete — {d.get('provider','').upper()}  Framework: {d.get('framework','')}")
        self._load_hist()

    def _show_detail(self):
        row=self.tbl.currentRow()
        if row<len(self._check_data):
            c=self._check_data[row]
            self.te.setPlainText(f"Check: {c.get('check_id','')}\nTitle: {c.get('title','')}\nStatus: {c.get('status','')}\n"
                f"NIST: {c.get('nist_ref','')}\n\nDescription:\n{c.get('description','')}\n\n"
                f"Details:\n{c.get('details','')}\n\nRemediation:\n{c.get('remediation','')}")

    def _load_hist(self):
        w=Worker(api.get_cloud_scan_history)
        w.result.connect(self._on_hist)
        w.error.connect(lambda e:None)
        self._workers.append(w)
        w.start()

    def _on_hist(self,items):
        self.tbl_h.setRowCount(0)
        for s in items:
            r=self.tbl_h.rowCount()
            self.tbl_h.insertRow(r)
            self.tbl_h.setItem(r,0,QTableWidgetItem(s.get("provider","")))
            score=s.get("posture_score",0)
            si=QTableWidgetItem(str(score))
            si.setForeground(QColor("#10B981" if score>=75 else "#F59E0B" if score>=50 else "#EF4444"))
            self.tbl_h.setItem(r,1,si)
            self.tbl_h.setItem(r,2,QTableWidgetItem(s.get("grade","?")))
            self.tbl_h.setItem(r,3,QTableWidgetItem(s.get("scanned_at","")[:19].replace("T"," ")))


class SandboxTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()
        self._load()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(12,12,12,12)
        root.setSpacing(10)
        grp=QGroupBox("File Analysis")
        g=QHBoxLayout(grp)
        self.le_f=QLineEdit()
        self.le_f.setPlaceholderText("Select suspicious file…")
        bb=QPushButton("Browse…")
        bb.clicked.connect(self._browse)
        self.btn=QPushButton("🔬 Analyze")
        self.btn.setObjectName("primary")
        self.btn.setMinimumHeight(36)
        self.btn.clicked.connect(self._analyze)
        g.addWidget(self.le_f,1)
        g.addWidget(bb)
        g.addWidget(self.btn)
        root.addWidget(grp)
        self.pb=QProgressBar()
        self.pb.setVisible(False)
        root.addWidget(self.pb)
        sp=QSplitter(Qt.Horizontal)
        left=QWidget()
        ll=QVBoxLayout(left)
        ll.setContentsMargins(0,0,0,0)
        self.lbl_v=QLabel("")
        self.lbl_v.setTextFormat(Qt.RichText)
        ll.addWidget(self.lbl_v)
        self.tbl=QTableWidget(0,2)
        self.tbl.setHorizontalHeaderLabels(["Field","Value"])
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        ll.addWidget(self.tbl,1)
        sp.addWidget(left)
        right=QWidget()
        rl=QVBoxLayout(right)
        rl.setContentsMargins(0,0,0,0)
        rl.addWidget(QLabel("YARA / Suspicious Strings:"))
        self.te=QTextEdit()
        self.te.setReadOnly(True)
        self.te.setFont(QFont("Courier New",11))
        rl.addWidget(self.te,1)
        sp.addWidget(right)
        sp.setSizes([450,300])
        root.addWidget(sp,1)
        grp2=QGroupBox("Recent Results")
        g2=QVBoxLayout(grp2)
        g2.setContentsMargins(6,6,6,6)
        self.tbl_h=QTableWidget(0,4)
        self.tbl_h.setHorizontalHeaderLabels(["File","Verdict","Score","Timestamp"])
        self.tbl_h.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tbl_h.setMaximumHeight(130)
        self.tbl_h.setAlternatingRowColors(True)
        self.tbl_h.setEditTriggers(QTableWidget.NoEditTriggers)
        g2.addWidget(self.tbl_h)
        root.addWidget(grp2)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _browse(self):
        p,_=QFileDialog.getOpenFileName(self,"Select File")
        if p:
            self.le_f.setText(p)

    def _analyze(self):
        path=self.le_f.text().strip()
        if not path or not os.path.isfile(path):
            self.lbl_st.setText("Select valid file")
            return
        self.btn.setEnabled(False)
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText(f"Analyzing {os.path.basename(path)}…")
        w=Worker(api.analyze_file,path)
        w.result.connect(self._on_result)
        w.error.connect(lambda e:(self.lbl_st.setText(f"Error: {e}"),self.pb.setVisible(False),self.btn.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _on_result(self,d):
        self.pb.setVisible(False)
        self.btn.setEnabled(True)
        verdict=d.get("verdict","UNKNOWN")
        score=d.get("threat_score",0)
        col="#EF4444" if score>=50 else "#F59E0B" if score>=25 else "#10B981"
        self.lbl_v.setText(f'<span style="font-size:22px;font-weight:800;color:{col};">{verdict}</span>'
                           f'  <span style="font-size:15px;color:{col};">Score: {score}/100</span>')
        self.tbl.setRowCount(0)
        static=d.get("static_analysis",{})
        fields=[("File Name",d.get("file_name","")),("File Type",d.get("file_type","")),
            ("Size",f"{d.get('file_size',0):,} bytes"),("SHA256",d.get("file_hash_sha256","")[:32]+"…"),
            ("Entropy",f"{static.get('entropy',0):.4f}  {static.get('entropy_note','')}"),
            ("Dangerous Ext",str(static.get("dangerous_ext",False))),
            ("YARA Hits",str(len(d.get("yara_matches",[])))),
            ("Susp. Strings",str(len(static.get("suspicious_strings",[]))))]
        for k,v in fields:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            self.tbl.setItem(r,0,QTableWidgetItem(k))
            self.tbl.setItem(r,1,QTableWidgetItem(str(v)))
        yara=("\n".join(d.get("yara_matches",[]))) or "No YARA matches"
        susp=("\n".join(static.get("suspicious_strings",[]))) or "No suspicious strings"
        self.te.setPlainText(f"YARA Matches:\n{yara}\n\nSuspicious Strings:\n{susp}")
        self.lbl_st.setText(f"Done — {verdict} (score {score}/100)")
        self._load()

    def _load(self):
        w=Worker(api.get_sandbox_results)
        w.result.connect(self._on_hist)
        w.error.connect(lambda e:None)
        self._workers.append(w)
        w.start()

    def _on_hist(self,items):
        self.tbl_h.setRowCount(0)
        for s in items[:20]:
            r=self.tbl_h.rowCount()
            self.tbl_h.insertRow(r)
            self.tbl_h.setItem(r,0,QTableWidgetItem(s.get("file_name","")))
            v=s.get("verdict","")
            vi=QTableWidgetItem(v)
            vi.setForeground(QColor("#EF4444" if "MAL" in v else "#F59E0B" if "SUS" in v else "#10B981"))
            self.tbl_h.setItem(r,1,vi)
            self.tbl_h.setItem(r,2,QTableWidgetItem(str(s.get("threat_score",0))))
            self.tbl_h.setItem(r,3,QTableWidgetItem(s.get("timestamp","")[:19].replace("T"," ")))


class HoneypotTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()
        self._load()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(12,12,12,12)
        root.setSpacing(10)
        bar=QHBoxLayout()
        br=QPushButton("↺ Refresh")
        br.clicked.connect(self._load)
        bar.addWidget(br)
        bar.addStretch()
        root.addLayout(bar)
        sp=QSplitter(Qt.Horizontal)
        grp1=QGroupBox("Honeypot Log")
        g1=QVBoxLayout(grp1)
        self.tbl=QTableWidget(0,4)
        self.tbl.setHorizontalHeaderLabels(["Attacker IP","Trap","Event","Time"])
        self.tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        g1.addWidget(self.tbl)
        sp.addWidget(grp1)
        grp2=QGroupBox("Top Attackers")
        g2=QVBoxLayout(grp2)
        self.tbl2=QTableWidget(0,2)
        self.tbl2.setHorizontalHeaderLabels(["IP","Hits"])
        self.tbl2.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tbl2.setMaximumWidth(240)
        self.tbl2.setAlternatingRowColors(True)
        self.tbl2.setEditTriggers(QTableWidget.NoEditTriggers)
        g2.addWidget(self.tbl2)
        sp.addWidget(grp2)
        sp.setSizes([600,200])
        root.addWidget(sp,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _load(self):
        self.lbl_st.setText("Loading…")
        w1=Worker(api.get_honeypot_log)
        w1.result.connect(self._on_log)
        w1.error.connect(lambda e:None)
        w2=Worker(api.get_top_attackers)
        w2.result.connect(self._on_top)
        w2.error.connect(lambda e:None)
        self._workers+=[w1,w2]
        w1.start()
        w2.start()

    def _on_log(self,items):
        self.tbl.setRowCount(0)
        for h in items:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            ip=QTableWidgetItem(h.get("attacker_ip",""))
            ip.setForeground(QColor("#EF4444"))
            self.tbl.setItem(r,0,ip)
            self.tbl.setItem(r,1,QTableWidgetItem(h.get("honeypot_type","")))
            self.tbl.setItem(r,2,QTableWidgetItem(h.get("event_type","")))
            self.tbl.setItem(r,3,QTableWidgetItem(h.get("timestamp","")[:19].replace("T"," ")))
        self.lbl_st.setText(f"{len(items)} interactions")

    def _on_top(self,items):
        self.tbl2.setRowCount(0)
        for h in items:
            r=self.tbl2.rowCount()
            self.tbl2.insertRow(r)
            ip=QTableWidgetItem(h.get("ip",""))
            ip.setForeground(QColor("#EF4444"))
            self.tbl2.setItem(r,0,ip)
            self.tbl2.setItem(r,1,QTableWidgetItem(str(h.get("hits",0))))


class VPNTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()
        self._load()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(12,12,12,12)
        root.setSpacing(10)
        bar=QHBoxLayout()
        br=QPushButton("↺ Refresh")
        br.clicked.connect(self._load)
        self.lbl_stats=QLabel("")
        self.lbl_stats.setObjectName("sub")
        bar.addWidget(br)
        bar.addStretch()
        bar.addWidget(self.lbl_stats)
        root.addLayout(bar)
        self.tbl=QTableWidget(0,6)
        self.tbl.setHorizontalHeaderLabels(["Username","Peer IP","Country","City","Protocol","Event"])
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        root.addWidget(self.tbl,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _load(self):
        self.lbl_st.setText("Loading…")
        w1=Worker(api.get_vpn_sessions)
        w1.result.connect(self._on_sessions)
        w1.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        w2=Worker(api.get_vpn_stats)
        w2.result.connect(self._on_stats)
        w2.error.connect(lambda e:None)
        self._workers+=[w1,w2]
        w1.start()
        w2.start()

    def _on_sessions(self,items):
        self.tbl.setRowCount(0)
        for s in items:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            geo=s.get("geo",{}) or {}
            ev=s.get("event","")
            self.tbl.setItem(r,0,QTableWidgetItem(s.get("username","")))
            ip=QTableWidgetItem(s.get("peer_ip",""))
            if geo.get("is_proxy"):
                ip.setForeground(QColor("#F59E0B"))
            self.tbl.setItem(r,1,ip)
            self.tbl.setItem(r,2,QTableWidgetItem(geo.get("country","")))
            self.tbl.setItem(r,3,QTableWidgetItem(geo.get("city","")))
            self.tbl.setItem(r,4,QTableWidgetItem(s.get("protocol","")))
            ei=QTableWidgetItem(ev)
            ei.setForeground(QColor("#10B981" if ev=="connect" else "#EF4444" if ev=="disconnect" else "#00E5FF"))
            self.tbl.setItem(r,5,ei)
        self.lbl_st.setText(f"{len(items)} sessions")

    def _on_stats(self,d):
        self.lbl_stats.setText(f"Active: {d.get('active_users',0)}  Total: {d.get('total_sessions',0)}")
