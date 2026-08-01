import json
from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QTableWidget,QTableWidgetItem,QHeaderView,QGroupBox,QTextEdit,QComboBox,
    QTabWidget,QSplitter)
from PyQt5.QtCore import Qt
from PyQt5.QtGui  import QColor,QFont
from utils.worker import Worker
import api.client as api

SC={"open":"#EF4444","in_progress":"#F59E0B","resolved":"#10B981","closed":"#00E5FF"}


class SOARTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()
        self._load_playbooks()
        self._load_tickets()
        self._load_history()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._pb_tab(),"⚡ Playbooks")
        tabs.addTab(self._tk_tab(),"🎫 Tickets")
        tabs.addTab(self._hist_tab(),"📜 History")
        root.addWidget(tabs)

    def _pb_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        grp=QGroupBox("Manual Execution")
        g=QHBoxLayout(grp)
        self.cb_pb=QComboBox()
        self.cb_pb.setMinimumWidth(200)
        btn=QPushButton("⚡ Execute")
        btn.setObjectName("success")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._run_pb)
        g.addWidget(QLabel("Playbook:"))
        g.addWidget(self.cb_pb)
        g.addWidget(btn)
        g.addStretch()
        lay.addWidget(grp)
        grp2=QGroupBox("Custom Alert Payload (JSON)")
        g2=QVBoxLayout(grp2)
        self.te_json=QTextEdit()
        self.te_json.setFont(QFont("Courier New",11))
        self.te_json.setMaximumHeight(150)
        self.te_json.setPlaceholderText('{\n  "alert_id":"test-1","severity":"high",\n  "source_ip":"185.220.101.45","detection_type":"brute_force",\n  "hostname":"server-01"\n}')
        g2.addWidget(self.te_json)
        lay.addWidget(grp2)
        self.tbl=QTableWidget(0,3)
        self.tbl.setHorizontalHeaderLabels(["Playbook","Description","Trigger"])
        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.tbl,1)
        self.lbl_pb=QLabel("")
        self.lbl_pb.setObjectName("sub")
        lay.addWidget(self.lbl_pb)
        return w

    def _tk_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        bar=QHBoxLayout()
        br=QPushButton("↺ Refresh")
        br.clicked.connect(self._load_tickets)
        self.cb_status=QComboBox()
        self.cb_status.addItems(["open","in_progress","resolved","closed"])
        bu=QPushButton("Update Status")
        bu.setObjectName("primary")
        bu.clicked.connect(self._update_ticket)
        bar.addWidget(br)
        bar.addStretch()
        bar.addWidget(QLabel("Set status:"))
        bar.addWidget(self.cb_status)
        bar.addWidget(bu)
        lay.addLayout(bar)
        self.tbl_t=QTableWidget(0,5)
        self.tbl_t.setHorizontalHeaderLabels(["Ticket ID","Rule","Severity","Status","Created"])
        self.tbl_t.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl_t.setAlternatingRowColors(True)
        self.tbl_t.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_t.setSelectionBehavior(QTableWidget.SelectRows)
        lay.addWidget(self.tbl_t,1)
        self.lbl_t=QLabel("")
        self.lbl_t.setObjectName("sub")
        lay.addWidget(self.lbl_t)
        return w

    def _hist_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        bar=QHBoxLayout()
        br=QPushButton("↺ Refresh")
        br.clicked.connect(self._load_history)
        bar.addWidget(br)
        bar.addStretch()
        lay.addLayout(bar)
        sp=QSplitter(Qt.Vertical)
        self.tbl_h=QTableWidget(0,4)
        self.tbl_h.setHorizontalHeaderLabels(["Playbook","Status","Time(ms)","Timestamp"])
        self.tbl_h.horizontalHeader().setSectionResizeMode(0,QHeaderView.Stretch)
        self.tbl_h.setAlternatingRowColors(True)
        self.tbl_h.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl_h.clicked.connect(self._show_exec)
        sp.addWidget(self.tbl_h)
        grp=QGroupBox("Steps")
        g=QVBoxLayout(grp)
        self.te_steps=QTextEdit()
        self.te_steps.setReadOnly(True)
        self.te_steps.setFont(QFont("Courier New",11))
        self.te_steps.setMaximumHeight(180)
        g.addWidget(self.te_steps)
        sp.addWidget(grp)
        sp.setSizes([300,200])
        lay.addWidget(sp,1)
        return w

    def _load_playbooks(self):
        w=Worker(api.get_soar_playbooks)
        w.result.connect(self._on_pb)
        w.error.connect(lambda e:None)
        self._workers.append(w)
        w.start()

    def _on_pb(self,d):
        self.tbl.setRowCount(0)
        self.cb_pb.clear()
        for pb in d.get("playbooks",[]):
            r=self.tbl.rowCount()
            self.tbl.insertRow(r)
            self.tbl.setItem(r,0,QTableWidgetItem(pb.get("name","")))
            self.tbl.setItem(r,1,QTableWidgetItem(pb.get("description","")))
            self.tbl.setItem(r,2,QTableWidgetItem("Auto: HIGH/CRITICAL"))
            self.cb_pb.addItem(pb.get("name",""),pb.get("name",""))

    def _run_pb(self):
        name=self.cb_pb.currentData()
        if not name:
            return
        txt=self.te_json.toPlainText().strip()
        if not txt:
            self.lbl_pb.setText("⚠ Paste a valid alert JSON payload above first")
            return
        try:
            alert=json.loads(txt)
        except Exception:
            self.lbl_pb.setText("❌ Invalid JSON — check your payload syntax")
            return
        self.lbl_pb.setText(f"Executing '{name}'…")
        w=Worker(api.run_playbook,name,alert)
        w.result.connect(lambda d:self.lbl_pb.setText(f"'{name}' → {d.get('status','')} in {d.get('total_time_ms',0):.0f}ms"))
        w.error.connect(lambda e:self.lbl_pb.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _load_tickets(self):
        w=Worker(api.get_tickets)
        w.result.connect(self._on_tickets)
        w.error.connect(lambda e:self.lbl_t.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _on_tickets(self,tickets):
        self.tbl_t.setRowCount(0)
        for t in tickets:
            r=self.tbl_t.rowCount()
            self.tbl_t.insertRow(r)
            self.tbl_t.setItem(r,0,QTableWidgetItem(t.get("ticket_id","")))
            self.tbl_t.setItem(r,1,QTableWidgetItem(t.get("rule_name","")))
            sev=t.get("severity","")
            si=QTableWidgetItem(sev.upper())
            si.setForeground(QColor({"critical":"#EF4444","high":"#F59E0B","medium":"#0EA5E9","low":"#10B981"}.get(sev,"#00E5FF")))
            self.tbl_t.setItem(r,2,si)
            st=t.get("status","")
            sti=QTableWidgetItem(st)
            sti.setForeground(QColor(SC.get(st,"#00E5FF")))
            self.tbl_t.setItem(r,3,sti)
            self.tbl_t.setItem(r,4,QTableWidgetItem(t.get("created_at","")[:19].replace("T"," ")))
        self.lbl_t.setText(f"{len(tickets)} tickets")

    def _update_ticket(self):
        row=self.tbl_t.currentRow()
        if row<0:
            return
        tid=self.tbl_t.item(row,0).text()
        status=self.cb_status.currentText()
        w=Worker(api.update_ticket,tid,status)
        w.result.connect(lambda _:(self._load_tickets(),self.lbl_t.setText(f"{tid} → {status}")))
        w.error.connect(lambda e:self.lbl_t.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _load_history(self):
        w=Worker(api.get_soar_executions)
        w.result.connect(self._on_hist)
        w.error.connect(lambda e:None)
        self._workers.append(w)
        w.start()

    def _on_hist(self,execs):
        self.tbl_h.setRowCount(0)
        self._exec=execs
        for e in execs:
            r=self.tbl_h.rowCount()
            self.tbl_h.insertRow(r)
            self.tbl_h.setItem(r,0,QTableWidgetItem(e.get("playbook_name","")))
            st=e.get("status","")
            si=QTableWidgetItem(st)
            si.setForeground(QColor("#10B981" if st=="completed" else "#EF4444"))
            self.tbl_h.setItem(r,1,si)
            self.tbl_h.setItem(r,2,QTableWidgetItem(f"{e.get('total_time_ms',0):.0f}"))
            self.tbl_h.setItem(r,3,QTableWidgetItem(e.get("timestamp","")[:19].replace("T"," ")))

    def _show_exec(self):
        row=self.tbl_h.currentRow()
        data=getattr(self,"_exec",[])
        if row<len(data):
            steps=data[row].get("steps_executed",[])
            lines=[f"{s.get('status_icon','')}  {s.get('action','')}  →  {s.get('status','')}" for s in steps]
            self.te_steps.setPlainText("\n".join(lines) if lines else "No step data")
