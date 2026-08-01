import json,os
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QGroupBox,QComboBox,QSpinBox,QTextEdit,QFileDialog,QProgressBar,
    QTableWidget,QTableWidgetItem,QHeaderView,QLineEdit)
from PyQt5.QtGui import QFont,QColor
from utils.worker import Worker
import api.client as api


class ReportsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(14)
        grp=QGroupBox("Report Configuration")
        g=QHBoxLayout(grp)
        self.cb_type=QComboBox()
        self.cb_type.addItems(["executive","technical","summary","compliance"])
        self.sp_h=QSpinBox()
        self.sp_h.setRange(1,720)
        self.sp_h.setValue(24)
        self.sp_h.setSuffix(" h")
        self.sp_h.setFixedWidth(80)
        self.le_by=QLineEdit()
        self.le_by.setText("SentinelAI Auto-Reporter")
        self.le_out=QLineEdit()
        self.le_out.setPlaceholderText("Output dir (default: Desktop)")
        bo=QPushButton("Browse…")
        bo.clicked.connect(self._browse)
        g.addWidget(QLabel("Type:"))
        g.addWidget(self.cb_type)
        g.addSpacing(10)
        g.addWidget(QLabel("Period:"))
        g.addWidget(self.sp_h)
        g.addSpacing(10)
        g.addWidget(QLabel("Prepared by:"))
        g.addWidget(self.le_by,1)
        g.addSpacing(10)
        g.addWidget(QLabel("Output:"))
        g.addWidget(self.le_out,1)
        g.addWidget(bo)
        root.addWidget(grp)
        br=QHBoxLayout()
        self.btn_pdf=QPushButton("📄 Generate PDF")
        self.btn_pdf.setObjectName("primary")
        self.btn_pdf.setMinimumHeight(40)
        self.btn_pdf.clicked.connect(self._pdf)
        self.btn_json=QPushButton("📊 Generate JSON")
        self.btn_json.setObjectName("success")
        self.btn_json.setMinimumHeight(40)
        self.btn_json.clicked.connect(self._json)
        bs=QPushButton("📈 Platform Stats")
        bs.setMinimumHeight(40)
        bs.clicked.connect(self._stats)
        br.addWidget(self.btn_pdf)
        br.addWidget(self.btn_json)
        br.addWidget(bs)
        br.addStretch()
        root.addLayout(br)
        self.pb=QProgressBar()
        self.pb.setVisible(False)
        root.addWidget(self.pb)
        grp2=QGroupBox("Platform Statistics")
        g2=QVBoxLayout(grp2)
        self.tbl=QTableWidget(0,2)
        self.tbl.setHorizontalHeaderLabels(["Metric","Value"])
        self.tbl.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeToContents)
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setMaximumHeight(200)
        g2.addWidget(self.tbl)
        root.addWidget(grp2)
        grp3=QGroupBox("Report Preview (JSON)")
        g3=QVBoxLayout(grp3)
        self.te=QTextEdit()
        self.te.setReadOnly(True)
        self.te.setFont(QFont("Courier New",11))
        g3.addWidget(self.te)
        root.addWidget(grp3,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _browse(self):
        d=QFileDialog.getExistingDirectory(self,"Select Output Directory")
        if d:
            self.le_out.setText(d)

    def _out(self,ext):
        d=self.le_out.text().strip() or os.path.join(os.path.expanduser("~"),"Desktop")
        if not os.path.isdir(d):
            d=os.path.expanduser("~")
        from datetime import datetime
        return os.path.join(d,f"SentinelAI_{self.cb_type.currentText()}_{datetime.now().strftime('%Y%m%d_%H%M')}{ext}")

    def _pdf(self):
        dest=self._out(".pdf")
        self.btn_pdf.setEnabled(False)
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText("Generating PDF…")
        w=Worker(api.download_pdf_report,self.cb_type.currentText(),self.sp_h.value(),dest)
        w.result.connect(lambda p:(self.lbl_st.setText(f"✅ Saved → {p}"),self.pb.setVisible(False),self.btn_pdf.setEnabled(True)))
        w.error.connect(lambda e:(self.lbl_st.setText(f"❌ {e}"),self.pb.setVisible(False),self.btn_pdf.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _json(self):
        self.btn_json.setEnabled(False)
        self.pb.setVisible(True)
        self.pb.setRange(0,0)
        self.lbl_st.setText("Generating JSON…")
        w=Worker(api.generate_report,self.cb_type.currentText(),self.sp_h.value())
        w.result.connect(self._on_json)
        w.error.connect(lambda e:(self.lbl_st.setText(f"❌ {e}"),self.pb.setVisible(False),self.btn_json.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _on_json(self,d):
        self.pb.setVisible(False)
        self.btn_json.setEnabled(True)
        self.te.setPlainText(json.dumps(d,indent=2))
        dest=self._out(".json")
        with open(dest,"w") as f:
            json.dump(d,f,indent=2)
        self.lbl_st.setText(f"✅ Saved → {dest}")

    def _stats(self):
        self.lbl_st.setText("Loading…")
        w=Worker(api.generate_report,"summary",self.sp_h.value())
        w.result.connect(self._on_stats)
        w.error.connect(lambda e:self.lbl_st.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_stats(self,d):
        s=d.get("summary",{})
        self.tbl.setRowCount(0)
        rows=[("Total Alerts",s.get("total_alerts","—")),
              ("Critical",s.get("by_severity",{}).get("critical",0)),
              ("High",s.get("by_severity",{}).get("high",0)),
              ("Medium",s.get("by_severity",{}).get("medium",0)),
              ("Low",s.get("by_severity",{}).get("low",0)),
              ("Attack Chains",s.get("attack_chains",0)),
              ("Period(h)",d.get("period_hours","—")),
              ("Type",d.get("report_type","—"))]
        for k,v in sorted(s.get("by_type",{}).items(),key=lambda x:-x[1])[:3]:
            rows.append((f"Top: {k.replace('_',' ').title()}",v))
        for k,v in rows:
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            self.tbl.setItem(r,0,QTableWidgetItem(str(k)))
            vi=QTableWidgetItem(str(v))
            if k=="Critical" and int(v or 0)>0:
                vi.setForeground(QColor("#EF4444"))
            self.tbl.setItem(r,1,vi)
        self.lbl_st.setText(f"Stats loaded — {s.get('total_alerts',0)} alerts")
