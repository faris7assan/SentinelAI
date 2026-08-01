from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,
    QPushButton,QHeaderView,QGroupBox,QGridLayout,QTableView, QFrame)
from PyQt5.QtCore import Qt,QTimer
from PyQt5.QtGui  import QColor,QFont,QPen
from utils.worker import Worker
from ui.models import DataTableModel
import api.client as api
import pyqtgraph as pg
import collections

SEV = {"critical":"#EF4444","high":"#F59E0B","medium":"#0EA5E9","low":"#10B981"}

class MetricCard(QWidget):
    def __init__(self,label,accent):
        super().__init__()
        self._accent=accent
        lay=QVBoxLayout(self)
        lay.setContentsMargins(14,12,14,12)
        self.val=QLabel("—")
        self.val.setAlignment(Qt.AlignCenter)
        self.val.setFont(QFont("Inter",26,QFont.Bold))
        self.val.setStyleSheet(f"color:{accent};")
        self.lbl=QLabel(label)
        self.lbl.setAlignment(Qt.AlignCenter)
        self.lbl.setObjectName("sub")
        lay.addWidget(self.val)
        lay.addWidget(self.lbl)
        self.setStyleSheet(f"border:1px solid #1C2331;border-top:3px solid {accent};border-radius:8px;background:#131822;")

    def set_value(self,v):
        self.val.setText(str(v))

class LiveGraphCard(QFrame):
    def __init__(self, title, color_hex):
        super().__init__()
        self.setStyleSheet("border: 1px solid #1C2331; border-radius: 8px; background: #0B0E14;")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(10, 10, 10, 10)
        lbl = QLabel(title)
        lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 600; border: none; background: transparent;")
        lay.addWidget(lbl)
        
        pg.setConfigOption('background', '#0B0E14')
        pg.setConfigOption('foreground', '#64748B')
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setStyleSheet("border: none;")
        self.plot_widget.hideAxis('bottom')
        self.plot_widget.setMouseEnabled(x=False, y=False)
        self.plot_widget.setMenuEnabled(False)
        self.plot_widget.setYRange(0, 100)
        
        self.data = collections.deque([0]*60, maxlen=60)
        pen = pg.mkPen(color=color_hex, width=2)
        self.curve = self.plot_widget.plot(list(self.data), pen=pen)
        
        lay.addWidget(self.plot_widget)

    def add_data_point(self, value):
        self.data.append(value)
        self.curve.setData(list(self.data))


class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self._ws=[]
        self._build()
        QTimer.singleShot(600,self._auto_refresh)
        # Set up periodic auto-refresh every 60 seconds
        self._refresh_timer = QTimer(self)
        self._refresh_timer.timeout.connect(self._auto_refresh)
        self._refresh_timer.start(2_000)

    def _build(self):
        root=QVBoxLayout(self)
        root.setSpacing(14)
        root.setContentsMargins(20,20,20,20)

        hdr=QHBoxLayout()
        lbl=QLabel("🛡️  Security Operations Center")
        lbl.setStyleSheet("font-size:19px;font-weight:800;color:#00E5FF;")
        self._lbl_time=QLabel()
        self._lbl_time.setObjectName("sub")
        self._lbl_live=QLabel("● LIVE")
        self._lbl_live.setStyleSheet("color:#10B981;font-weight:700;")
        hdr.addWidget(lbl)
        hdr.addStretch()
        hdr.addWidget(self._lbl_live)
        hdr.addSpacing(10)
        hdr.addWidget(self._lbl_time)
        root.addLayout(hdr)

        cards=QHBoxLayout()
        cards.setSpacing(10)
        self.c_total=MetricCard("Total Alerts (24h)","#EF4444")
        self.c_crit =MetricCard("Critical Alerts","#EF4444")
        self.c_high =MetricCard("High Alerts","#F59E0B")
        self.c_chain=MetricCard("Attack Chains","#8B5CF6")
        self.c_logs =MetricCard("Logs Ingested","#0EA5E9")
        self.c_soar =MetricCard("SOAR Executed","#10B981")
        for c in (self.c_total,self.c_crit,self.c_high,self.c_chain,self.c_logs,self.c_soar):
            cards.addWidget(c)
        root.addLayout(cards)
        
        sys_cards = QHBoxLayout()
        sys_cards.setSpacing(10)
        self.g_cpu = LiveGraphCard("CPU Utilization (%)", "#00E5FF")
        self.g_mem = LiveGraphCard("Memory Usage (%)", "#8B5CF6")
        self.c_net = MetricCard("Active Conns", "#00E5FF")
        
        sys_cards.addWidget(self.g_cpu, 2)
        sys_cards.addWidget(self.g_mem, 2)
        sys_cards.addWidget(self.c_net, 1)
        root.addLayout(sys_cards)

        mid=QHBoxLayout()
        mid.setSpacing(12)
        grp_svc=QGroupBox("Service Health")
        grp_svc.setMaximumWidth(320)
        grid=QGridLayout(grp_svc)
        grid.setSpacing(5)
        self._svc_lbls={}
        svcs=["auth","logs","detection","ai","soar","threatintel","alerts","reports",
              "vpn","honeypot","sandbox","cloud","redteam","agents","metrics"]
        for i,n in enumerate(svcs):
            r,c=divmod(i,3)
            lbl=QLabel(f"⬤ {n}")
            lbl.setStyleSheet("color:#484F58;font-size:11px;")
            grid.addWidget(lbl,r,c)
            self._svc_lbls[n]=lbl
        btn_r=QPushButton("↺ Refresh Health")
        btn_r.clicked.connect(self._refresh_health)
        grid.addWidget(btn_r,len(svcs)//3+1,0,1,3)
        mid.addWidget(grp_svc)

        grp_al=QGroupBox("Recent Alerts")
        lay_al=QVBoxLayout(grp_al)

        self.tbl=QTableView()
        self._headers = [
            {"title": "Severity", "key": "severity"},
            {"title": "Rule", "key": "rule_name"},
            {"title": "Source IP", "key": "source_ip"},
            {"title": "Technique", "key": "mitre_technique"},
            {"title": "Time", "key": "timestamp"}
        ]
        self._model = DataTableModel(headers=self._headers)
        self.tbl.setModel(self._model)

        self.tbl.horizontalHeader().setSectionResizeMode(1,QHeaderView.Stretch)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setEditTriggers(QTableView.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableView.SelectRows)
        lay_al.addWidget(self.tbl)
        mid.addWidget(grp_al,1)
        root.addLayout(mid,1)
        self.lbl_st=QLabel("")
        self.lbl_st.setObjectName("sub")
        root.addWidget(self.lbl_st)

    def _auto_refresh(self):
        from datetime import datetime
        self._lbl_time.setText(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self._refresh_metrics()
        self._refresh_health()
        self._refresh_alerts()

    def _refresh_metrics(self):
        w=Worker(api.get_metrics)
        w.result.connect(self._on_metrics)
        w.error.connect(lambda e:self.lbl_st.setText(f"Metrics error: {e}"))
        self._ws.append(w)
        w.start()

    def _on_metrics(self,d):
        c=d.get("counters",{})
        s=d.get("system",{})
        self.c_total.set_value(c.get("total_alerts","—"))
        self.c_crit.set_value(c.get("critical_alerts","—"))
        self.c_high.set_value(c.get("high_alerts","—"))
        self.c_chain.set_value(c.get("attack_chains","—"))
        n=c.get("logs_ingested",0)
        self.c_logs.set_value(f"{n:,}" if isinstance(n,int) else n)
        self.c_soar.set_value(c.get("soar_executions","—"))
        
        cpu_val = s.get('cpu', 0)
        mem_val = s.get('mem', 0)
        self.g_cpu.add_data_point(cpu_val)
        self.g_mem.add_data_point(mem_val)
        self.c_net.set_value(s.get("net", "—"))
        # Clean up finished workers to prevent memory leak
        self._ws = [w for w in self._ws if w.isRunning()]

    def _refresh_health(self):
        w=Worker(api.health_all)
        w.result.connect(self._on_health)
        w.error.connect(lambda e:self.lbl_st.setText(f"Health check error: {e}"))
        self._ws.append(w)
        w.start()

    def _on_health(self,res):
        ok,fail=0,0
        for name,up in res.items():
            if name in self._svc_lbls:
                col="#10B981" if up else "#EF4444"
                self._svc_lbls[name].setStyleSheet(f"color:{col};font-size:11px;font-weight:{'600' if up else '400'};")
                ok+=int(up)
                fail+=int(not up)
        from datetime import datetime
        self.lbl_st.setText(f"Services: {ok} online  {fail} offline  —  {datetime.now().strftime('%H:%M:%S')}")

    def _refresh_alerts(self):
        w=Worker(api.get_recent_alerts,20)
        w.result.connect(self._on_alerts)
        w.error.connect(lambda e:self.lbl_st.setText(f"Alert refresh error: {e}"))
        self._ws.append(w)
        w.start()

    def _on_alerts(self,alerts):
        if not isinstance(alerts, list):
            return
        model_data = []
        for a in alerts:
            s=a.get("severity","low")
            row_data = {
                "severity": s.upper(),
                "rule_name": a.get("rule_name",""),
                "source_ip": a.get("source_ip",""),
                "mitre_technique": a.get("mitre_technique",""),
                "timestamp": str(a.get("timestamp",""))[:19].replace("T"," "),
                "color": SEV.get(s,"#00E5FF"),
                "raw": a
            }
            model_data.append(row_data)

        self._model.update_data(model_data)
