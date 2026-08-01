from PyQt5.QtWidgets import (QWidget,QVBoxLayout,QHBoxLayout,QLabel,QPushButton,
    QTextEdit,QLineEdit,QComboBox,QGroupBox,QTabWidget,QSpinBox,QFileDialog,QApplication)
from PyQt5.QtGui import QFont
from utils.worker import Worker
import api.client as api

PRESETS=["Find suspicious PowerShell execution","Hunt for C2 beaconing",
         "Identify lateral movement via SMB","Detect impossible travel logins",
         "Find data exfiltration attempts","Look for ransomware indicators"]


class AICopilotTab(QWidget):
    def __init__(self):
        super().__init__()
        self._workers=[]
        self._build()

    def _build(self):
        root=QVBoxLayout(self)
        root.setContentsMargins(20,20,20,20)
        root.setSpacing(0)
        tabs=QTabWidget()
        tabs.addTab(self._chat_tab(),"🤖  AI Analyst Chat")
        tabs.addTab(self._hunt_tab(),"🔍  Threat Hunting")
        tabs.addTab(self._sigma_tab(),"⚙  Generate Sigma")
        tabs.addTab(self._yara_tab(),"🦠  Generate YARA")
        root.addWidget(tabs)

    def _chat_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        pre=QHBoxLayout()
        pre.addWidget(QLabel("Quick:"))
        for p in PRESETS[:3]:
            b=QPushButton(p[:32]+"…" if len(p)>32 else p)
            b.clicked.connect(lambda _,t=p:(self.le_chat.setText(t),self._chat_send()))
            pre.addWidget(b)
        pre.addStretch()
        lay.addLayout(pre)
        self.te_chat=QTextEdit()
        self.te_chat.setReadOnly(True)
        self.te_chat.setFont(QFont("Segoe UI",12))
        lay.addWidget(self.te_chat,1)
        self._chat_append("system","SentinelAI Copilot ready. Ask me anything about threats or alerts.")
        inp=QHBoxLayout()
        self.le_chat=QLineEdit()
        self.le_chat.setPlaceholderText("Ask about threats, explain alerts…")
        self.le_chat.setMinimumHeight(38)
        self.le_chat.returnPressed.connect(self._chat_send)
        self.btn_chat=QPushButton("Send")
        self.btn_chat.setObjectName("primary")
        self.btn_chat.setMinimumHeight(38)
        self.btn_chat.clicked.connect(self._chat_send)
        btn_clr=QPushButton("Clear")
        btn_clr.clicked.connect(self.te_chat.clear)
        inp.addWidget(self.le_chat,1)
        inp.addWidget(self.btn_chat)
        inp.addWidget(btn_clr)
        lay.addLayout(inp)
        return w

    def _hunt_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        top=QHBoxLayout()
        self.le_hunt=QLineEdit()
        self.le_hunt.setPlaceholderText("e.g. Find PowerShell reverse shells")
        self.le_hunt.setMinimumHeight(36)
        self.sp_hrs=QSpinBox()
        self.sp_hrs.setRange(1,168)
        self.sp_hrs.setValue(24)
        self.sp_hrs.setSuffix(" h")
        self.sp_hrs.setFixedWidth(70)
        btn=QPushButton("🔍 Hunt")
        btn.setObjectName("primary")
        btn.setMinimumHeight(36)
        btn.clicked.connect(self._run_hunt)
        top.addWidget(QLabel("Query:"))
        top.addWidget(self.le_hunt,1)
        top.addWidget(QLabel("Range:"))
        top.addWidget(self.sp_hrs)
        top.addWidget(btn)
        lay.addLayout(top)
        for p in PRESETS:
            b=QPushButton(p)
            b.setStyleSheet("text-align:left;padding:5px 10px;")
            b.clicked.connect(lambda _,t=p:(self.le_hunt.setText(t),self._run_hunt()))
            lay.addWidget(b)
        self.te_hunt=QTextEdit()
        self.te_hunt.setReadOnly(True)
        self.te_hunt.setFont(QFont("Courier New",11))
        lay.addWidget(self.te_hunt,1)
        self.lbl_hunt=QLabel("")
        self.lbl_hunt.setObjectName("sub")
        lay.addWidget(self.lbl_hunt)
        return w

    def _sigma_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        grp=QGroupBox("Parameters")
        g=QVBoxLayout(grp)
        self.le_sd=QLineEdit()
        self.le_sd.setPlaceholderText("e.g. Attacker uses certutil.exe to download malware from C2")
        self.le_st=QLineEdit()
        self.le_st.setPlaceholderText("T1105")
        self.le_st.setFixedWidth(120)
        self.cb_ss=QComboBox()
        self.cb_ss.addItems(["windows","linux","network","cloud"])
        r1=QHBoxLayout()
        r1.addWidget(QLabel("Description:"))
        r1.addWidget(self.le_sd,1)
        r2=QHBoxLayout()
        r2.addWidget(QLabel("Technique:"))
        r2.addWidget(self.le_st)
        r2.addSpacing(10)
        r2.addWidget(QLabel("Log Source:"))
        r2.addWidget(self.cb_ss)
        r2.addStretch()
        g.addLayout(r1)
        g.addLayout(r2)
        lay.addWidget(grp)
        self.btn_gsig=QPushButton("⚙ Generate Sigma Rule")
        self.btn_gsig.setObjectName("primary")
        self.btn_gsig.setMinimumHeight(36)
        self.btn_gsig.clicked.connect(self._gen_sigma)
        lay.addWidget(self.btn_gsig)
        self.te_sig=QTextEdit()
        self.te_sig.setFont(QFont("Courier New",11))
        lay.addWidget(self.te_sig,1)
        br=QHBoxLayout()
        bc=QPushButton("📋 Copy")
        bc.clicked.connect(lambda:QApplication.clipboard().setText(self.te_sig.toPlainText()))
        bs=QPushButton("💾 Save .yml")
        bs.clicked.connect(self._save_sigma)
        self.lbl_sig=QLabel("")
        self.lbl_sig.setObjectName("sub")
        br.addWidget(bc)
        br.addWidget(bs)
        br.addStretch()
        br.addWidget(self.lbl_sig)
        lay.addLayout(br)
        return w

    def _yara_tab(self):
        w=QWidget()
        lay=QVBoxLayout(w)
        lay.setContentsMargins(12,12,12,12)
        lay.setSpacing(10)
        grp=QGroupBox("YARA Rule Parameters")
        g=QVBoxLayout(grp)
        self.le_yd=QLineEdit()
        self.le_yd.setPlaceholderText("e.g. Ransomware that encrypts files and drops ransom note")
        self.le_yf=QLineEdit()
        self.le_yf.setPlaceholderText("e.g. LockBit")
        self.le_yf.setFixedWidth(160)
        self.cb_yp=QComboBox()
        self.cb_yp.addItems(["windows","linux","macos"])
        r1=QHBoxLayout()
        r1.addWidget(QLabel("Description:"))
        r1.addWidget(self.le_yd,1)
        r2=QHBoxLayout()
        r2.addWidget(QLabel("Malware:"))
        r2.addWidget(self.le_yf)
        r2.addSpacing(10)
        r2.addWidget(QLabel("Platform:"))
        r2.addWidget(self.cb_yp)
        r2.addStretch()
        g.addLayout(r1)
        g.addLayout(r2)
        lay.addWidget(grp)
        self.btn_gyar=QPushButton("🦠 Generate YARA Rule")
        self.btn_gyar.setObjectName("primary")
        self.btn_gyar.setMinimumHeight(36)
        self.btn_gyar.clicked.connect(self._gen_yara)
        lay.addWidget(self.btn_gyar)
        self.te_yar=QTextEdit()
        self.te_yar.setFont(QFont("Courier New",11))
        lay.addWidget(self.te_yar,1)
        br=QHBoxLayout()
        bc=QPushButton("📋 Copy")
        bc.clicked.connect(lambda:QApplication.clipboard().setText(self.te_yar.toPlainText()))
        bs=QPushButton("💾 Save .yar")
        bs.clicked.connect(self._save_yara)
        self.lbl_yar=QLabel("")
        self.lbl_yar.setObjectName("sub")
        br.addWidget(bc)
        br.addWidget(bs)
        br.addStretch()
        br.addWidget(self.lbl_yar)
        lay.addLayout(br)
        return w

    def _chat_append(self,role,msg):
        cols={"user":"#0EA5E9","system":"#00E5FF","assistant":"#10B981","error":"#EF4444"}
        self.te_chat.append(f'<b style="color:{cols.get(role,"#E6EDF3")};">{"You" if role=="user" else "🤖 AI"}:</b><br>'
                            f'<span style="color:#E6EDF3;">{msg.replace(chr(10),"<br>")}</span><br>')

    def _chat_send(self):
        txt=self.le_chat.text().strip()
        if not txt:
            return
        self.le_chat.clear()
        self._chat_append("user",txt)
        self.btn_chat.setEnabled(False)
        w=Worker(api.threat_hunt,txt,24)
        w.result.connect(lambda d:(self._chat_append("assistant",d.get("result","No response")),self.btn_chat.setEnabled(True)))
        w.error.connect(lambda e:(self._chat_append("error",f"Error: {e}"),self.btn_chat.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _run_hunt(self):
        q=self.le_hunt.text().strip()
        if not q:
            return
        self.lbl_hunt.setText("Hunting…")
        self.te_hunt.clear()
        w=Worker(api.threat_hunt,q,self.sp_hrs.value())
        w.result.connect(lambda d:(self.te_hunt.setPlainText(d.get("result","")),
                                    self.lbl_hunt.setText(f"Context events: {d.get('context_events',0)}")))
        w.error.connect(lambda e:self.lbl_hunt.setText(f"Error: {e}"))
        self._workers.append(w)
        w.start()

    def _gen_sigma(self):
        d=self.le_sd.text().strip()
        t=self.le_st.text().strip()
        if not d or not t:
            self.lbl_sig.setText("⚠ Please provide description and technique")
            return
        self.btn_gsig.setEnabled(False)
        self.lbl_sig.setText("Generating…")
        w=Worker(api.generate_sigma_rule,d,t,self.cb_ss.currentText())
        w.result.connect(lambda r:(self.te_sig.setPlainText(r.get("rule_text","# Failed")),
                                    self.lbl_sig.setText("Generated ✅"),self.btn_gsig.setEnabled(True)))
        w.error.connect(lambda e:(self.lbl_sig.setText(f"Error: {e}"),self.btn_gsig.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _gen_yara(self):
        d=self.le_yd.text().strip()
        m=self.le_yf.text().strip()
        if not d or not m:
            self.lbl_yar.setText("⚠ Please provide description and malware family")
            return
        self.btn_gyar.setEnabled(False)
        self.lbl_yar.setText("Generating…")
        w=Worker(api.generate_yara_rule,d,m,self.cb_yp.currentText())
        w.result.connect(lambda r:(self.te_yar.setPlainText(r.get("rule_text","// Failed")),
                                    self.lbl_yar.setText("Generated ✅"),self.btn_gyar.setEnabled(True)))
        w.error.connect(lambda e:(self.lbl_yar.setText(f"Error: {e}"),self.btn_gyar.setEnabled(True)))
        self._workers.append(w)
        w.start()

    def _save_sigma(self):
        p,_=QFileDialog.getSaveFileName(self,"Save Sigma Rule","rule.yml","YAML (*.yml)")
        if p:
            try:
                with open(p,"w",encoding="utf-8") as f:
                    f.write(self.te_sig.toPlainText())
                self.lbl_sig.setText(f"Saved → {p}")
            except Exception as e:
                self.lbl_sig.setText(f"Save error: {e}")

    def _save_yara(self):
        p,_=QFileDialog.getSaveFileName(self,"Save YARA Rule","rule.yar","YARA (*.yar)")
        if p:
            try:
                with open(p,"w",encoding="utf-8") as f:
                    f.write(self.te_yar.toPlainText())
                self.lbl_yar.setText(f"Saved → {p}")
            except Exception as e:
                self.lbl_yar.setText(f"Save error: {e}")
