import json
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QLineEdit,QTabWidget,QTextEdit,QGroupBox,QProgressBar,QTableWidget,
    QTableWidgetItem,QHeaderView,QComboBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QFont,QColor
from utils.worker import Worker
import api.client as api

VC={"CRITICAL":"#EF4444","HIGH":"#F59E0B","MEDIUM":"#0EA5E9","LOW":"#10B981","CLEAN":"#10B981","UNKNOWN":"#00E5FF"}


class ThreatIntelTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._ip_tab(),"🌐 IP Lookup")
        tabs.addTab(self._hash_tab(),"🔑 Hash Lookup")
        tabs.addTab(self._domain_tab(),"🌍 Domain Lookup")
        tabs.addTab(self._cve_tab(),"⚠ CVE Lookup")
        tabs.addTab(self._bulk_tab(),"📋 Bulk Lookup")
        root.addWidget(tabs)

    def _box(self):
        te=QTextEdit()
        te.setReadOnly(True)
        te.setFont(QFont("Courier New",11))
        return te

    def _score_html(self,score,verdict):
        col=VC.get(verdict,"#00E5FF")
        return (f'<span style="font-size:26px;font-weight:800;color:{col};">{score}/100</span>'
                f'  <span style="font-size:15px;color:{col};font-weight:700;">{verdict}</span>')

    def _ip_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        row=QHBoxLayout()
        self.le_ip=QLineEdit()
        self.le_ip.setPlaceholderText("Enter IP — e.g. 185.220.101.45")
        self.le_ip.setMinimumHeight(36)
        self.le_ip.returnPressed.connect(self._lookup_ip)
        self.cb_mode=QComboBox()
        self.cb_mode.addItems(["Standard (3 sources)","Full (6 sources)"])
        btn=QPushButton("🔍 Lookup")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._lookup_ip)
        row.addWidget(QLabel("IP:"))
        row.addWidget(self.le_ip,1)
        row.addWidget(self.cb_mode)
        row.addWidget(btn)
        lay.addLayout(row)
        self.lbl_score=QLabel("")
        self.lbl_score.setTextFormat(Qt.RichText)
        lay.addWidget(self.lbl_score)
        grp=QGroupBox("Intelligence Results")
        gl=QVBoxLayout(grp)
        self.tbl=QTableWidget(0,3)
        self.tbl.setHorizontalHeaderLabels(["Source","Field","Value"])
        self.tbl.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setMaximumHeight(240)
        gl.addWidget(self.tbl)
        lay.addWidget(grp)
        self.te=self._box()
        self.te.setMaximumHeight(150)
        lay.addWidget(QLabel("Raw JSON:"))
        lay.addWidget(self.te)
        self.pb=QProgressBar()
        self.pb.setVisible(False)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        lay.addWidget(self.pb)
        lay.addWidget(self.lbl_st)
        return w

    def _lookup_ip(self):
        ip=self.le_ip.text().strip()
        if not ip:
            return
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText(f"Looking up {ip}…")
        full=self.cb_mode.currentIndex()==1
        fn=api.lookup_ip_full if full else api.lookup_ip
        w=Worker(fn,ip)
        w.result.connect(self._on_ip)
        w.error.connect(lambda e:(self.lbl_st.setText(f"Error: {e}"),self.pb.setVisible(False)))
        self._workers.append(w)
        w.start()

    def _on_ip(self,d):
        self.pb.setVisible(False)
        ts=d.get("threat_score",{})
        self.lbl_score.setText(self._score_html(ts.get("score",0),ts.get("verdict","UNKNOWN")))
        self.tbl.setRowCount(0)
        for src in ["virustotal","abuseipdb","otx","shodan","misp","opencti"]:
            info=d.get(src,{})
            if not info:
                continue
            for k,v in info.items():
                if k=="source":
                    continue
                r=self.tbl.rowCount()
                self.tbl.insertRow(r)
                self.tbl.setItem(r,0,QTableWidgetItem(src))
                self.tbl.setItem(r,1,QTableWidgetItem(str(k)))
                self.tbl.setItem(r,2,QTableWidgetItem(str(v)))
        self.te.setPlainText(json.dumps(d,indent=2))
        self.lbl_st.setText(f"Verdict: {ts.get('verdict','—')}  Score: {ts.get('score',0)}/100")

    def _hash_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        row=QHBoxLayout()
        self.le_h=QLineEdit()
        self.le_h.setPlaceholderText("MD5 / SHA1 / SHA256")
        self.le_h.setMinimumHeight(36)
        self.le_h.returnPressed.connect(self._lookup_hash)
        btn=QPushButton("🔍 Lookup")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._lookup_hash)
        row.addWidget(QLabel("Hash:"))
        row.addWidget(self.le_h,1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.lbl_hv=QLabel("")
        self.lbl_hv.setTextFormat(Qt.RichText)
        lay.addWidget(self.lbl_hv)
        self.te_h=self._box()
        lay.addWidget(self.te_h,1)
        self.lbl_h_st=QLabel("")
        self.lbl_h_st.setObjectName("sub")
        lay.addWidget(self.lbl_h_st)
        return w

    def _lookup_hash(self):
        h=self.le_h.text().strip()
        if not h:
            return
        self.lbl_h_st.setText("Looking up…")
        w=Worker(api.lookup_hash,h)
        w.result.connect(lambda d:(self.lbl_hv.setText(self._score_html(
            90 if d.get("is_malicious") else 5,d.get("verdict","UNKNOWN"))),
            self.te_h.setPlainText(json.dumps(d,indent=2)),
            self.lbl_h_st.setText(f"Verdict: {d.get('verdict','—')}")))
        w.error.connect(lambda e:self.lbl_h_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _domain_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        row=QHBoxLayout()
        self.le_d=QLineEdit()
        self.le_d.setPlaceholderText("e.g. malware-c2.xyz")
        self.le_d.setMinimumHeight(36)
        self.le_d.returnPressed.connect(self._lookup_domain)
        btn=QPushButton("🔍 Lookup")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._lookup_domain)
        row.addWidget(QLabel("Domain:"))
        row.addWidget(self.le_d,1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.te_d=self._box()
        lay.addWidget(self.te_d,1)
        self.lbl_d_st=QLabel("")
        self.lbl_d_st.setObjectName("sub")
        lay.addWidget(self.lbl_d_st)
        return w

    def _lookup_domain(self):
        d=self.le_d.text().strip()
        if not d:
            return
        self.lbl_d_st.setText("Looking up…")
        w=Worker(api.lookup_domain,d)
        w.result.connect(lambda r:(self.te_d.setPlainText(json.dumps(r,indent=2)),self.lbl_d_st.setText("Done")))
        w.error.connect(lambda e:self.lbl_d_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _cve_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        row=QHBoxLayout()
        self.le_c=QLineEdit()
        self.le_c.setPlaceholderText("e.g. CVE-2021-44228")
        self.le_c.setMinimumHeight(36)
        self.le_c.returnPressed.connect(self._lookup_cve)
        btn=QPushButton("🔍 Lookup")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._lookup_cve)
        row.addWidget(QLabel("CVE:"))
        row.addWidget(self.le_c,1)
        row.addWidget(btn)
        lay.addLayout(row)
        self.tbl_c=QTableWidget(0,2)
        self.tbl_c.setHorizontalHeaderLabels(["Field","Value"])
        self.tbl_c.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl_c.setAlternatingRowColors(True)
        self.tbl_c.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tbl_c,1)
        self.lbl_c_st=QLabel("")
        self.lbl_c_st.setObjectName("sub")
        lay.addWidget(self.lbl_c_st)
        return w

    def _lookup_cve(self):
        c=self.le_c.text().strip()
        if not c:
            return
        w=Worker(api.lookup_cve,c)
        w.result.connect(self._on_cve)
        w.error.connect(lambda e:self.lbl_c_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_cve(self,d):
        self.tbl_c.setRowCount(0)
        for k,v in d.items():
            r=self.tbl_c.rowCount()
            self.tbl_c.insertRow(r)
            self.tbl_c.setItem(r,0,QTableWidgetItem(str(k)))
            item=QTableWidgetItem(str(v))
            if k=="cvss_score":
                try:
                    score=float(v)
                except Exception:
                    score=0
                col="#EF4444" if score>=9 else "#F59E0B" if score>=7 else "#0EA5E9"
                item.setForeground(QColor(col))
                item.setFont(QFont("Segoe UI",12,QFont.Bold))
            self.tbl_c.setItem(r,1,item)
        self.lbl_c_st.setText(f"CVSS: {d.get('cvss_score','N/A')}  Severity: {d.get('severity','N/A')}")

    def _bulk_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        lay.addWidget(QLabel("Enter one IOC per line (IP / hash / domain):"))
        self.te_in=QTextEdit()
        self.te_in.setMaximumHeight(140)
        self.te_in.setPlaceholderText("185.220.101.45\nmalware.xyz")
        lay.addWidget(self.te_in)
        row=QHBoxLayout()
        self.cb_type=QComboBox()
        self.cb_type.addItems(["ip","domain","hash"])
        btn=QPushButton("🔍 Bulk Lookup")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._bulk)
        self.pb_b=QProgressBar()
        self.pb_b.setVisible(False)
        row.addWidget(QLabel("Type:"))
        row.addWidget(self.cb_type)
        row.addWidget(btn)
        row.addWidget(self.pb_b,1)
        lay.addLayout(row)
        self.tbl_b=QTableWidget(0,3)
        self.tbl_b.setHorizontalHeaderLabels(["IOC","Verdict","Score"])
        self.tbl_b.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tbl_b.setAlternatingRowColors(True)
        self.tbl_b.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tbl_b,1)
        self.lbl_b_st=QLabel("")
        self.lbl_b_st.setObjectName("sub")
        lay.addWidget(self.lbl_b_st)
        return w

    def _bulk(self):
        lines=[l.strip() for l in self.te_in.toPlainText().splitlines() if l.strip()]
        if not lines:
            return
        t=self.cb_type.currentText()
        iocs=[{"ioc":l,"ioc_type":t} for l in lines[:50]]
        self.pb_b.setVisible(True)
        self.pb_b.setRange(0,0)
        self.lbl_b_st.setText(f"Checking {len(iocs)} IOCs…")
        w=Worker(api._post,"threatintel","/intel/bulk",{"iocs":iocs})
        w.result.connect(self._on_bulk)
        w.error.connect(lambda e:(self.lbl_b_st.setText(f"Error: {e}"),self.pb_b.setVisible(False)))
        self._workers.append(w)
        w.start()

    def _on_bulk(self,d):
        self.pb_b.setVisible(False)
        results=d.get("results",[]) if isinstance(d,dict) else []
        self.tbl_b.setRowCount(0)
        for r_item in results:
            ts=r_item.get("threat_score",{})
            verdict=ts.get("verdict",r_item.get("verdict","UNKNOWN"))
            score=ts.get("score",r_item.get("threat_score",0))
            ioc_val=r_item.get("ip") or r_item.get("domain") or r_item.get("hash","?")
            r=self.tbl_b.rowCount()
            self.tbl_b.insertRow(r)
            self.tbl_b.setItem(r,0,QTableWidgetItem(str(ioc_val)))
            vi=QTableWidgetItem(str(verdict))
            vi.setForeground(QColor(VC.get(str(verdict),"#00E5FF")))
            self.tbl_b.setItem(r,1,vi)
            self.tbl_b.setItem(r,2,QTableWidgetItem(str(score)))
        self.lbl_b_st.setText(f"Checked {len(results)} IOCs")
