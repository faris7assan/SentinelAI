import { useState, useEffect, useRef, useCallback } from "react";
import {
  LineChart, Line, AreaChart, Area, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell
} from "recharts";

// ─── Theme & Constants ────────────────────────────────────────
const API = typeof window !== "undefined"
  ? (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000")
  : "http://localhost:8000";
const WS_URL = typeof window !== "undefined"
  ? (process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000")
  : "ws://localhost:8000";

const SEV_COLOR = { critical: "#FF3B3B", high: "#FF8C00", medium: "#FFD700", low: "#00C851", info: "#00D4FF" };
const CHART_COLORS = ["#00D4FF", "#FF3B3B", "#FF8C00", "#FFD700", "#00C851", "#9B59B6"];

const MITRE_TACTICS = [
  "Initial Access","Execution","Persistence","Privilege Escalation",
  "Defense Evasion","Credential Access","Discovery","Lateral Movement",
  "Collection","Command and Control","Exfiltration","Impact"
];

// ─── Mock data generators ─────────────────────────────────────
const genAlerts = (n = 15) => Array.from({ length: n }, (_, i) => ({
  alert_id: `ALR-${1000 + i}`,
  rule_name: ["SSH Brute Force","Reverse Shell Detected","Ransomware Pattern","DNS Tunneling","Lateral Movement SMB","Mimikatz Detected","Port Scan","DDoS SYN Flood","Data Exfiltration","PowerShell Bypass"][i % 10],
  severity: ["critical","critical","high","high","medium","medium","low","high","critical","medium"][i % 10],
  source_ip: `${10 + (i % 9)}.${20 + i}.${i % 255}.${(i * 7) % 254 + 1}`,
  hostname: `server-${String.fromCharCode(65 + (i % 8))}-${i + 1}`,
  mitre_technique: ["T1110","T1059","T1486","T1071","T1021","T1003","T1046","T1498","T1041","T1059.001"][i % 10],
  mitre_tactic: MITRE_TACTICS[i % MITRE_TACTICS.length],
  detection_type: ["brute_force","reverse_shell","ransomware","dns_tunneling","lateral_movement","credential_dumping","port_scan","ddos","data_exfiltration","malware_execution"][i % 10],
  timestamp: new Date(Date.now() - i * 180000).toISOString(),
  correlated: i % 4 === 0,
}));

const genTimelineData = () => Array.from({ length: 24 }, (_, i) => ({
  hour: `${String(i).padStart(2,"0")}:00`,
  critical: Math.floor(Math.random() * 8),
  high: Math.floor(Math.random() * 15),
  medium: Math.floor(Math.random() * 25),
  low: Math.floor(Math.random() * 20),
}));

// ─── Components ───────────────────────────────────────────────
function Sidebar({ activePage, setActivePage, collapsed, setCollapsed }) {
  const nav = [
    { id: "dashboard",      icon: "⬡",  label: "Dashboard" },
    { id: "incidents",      icon: "🚨", label: "Incidents" },
    { id: "threat-hunting", icon: "🔍", label: "Threat Hunt" },
    { id: "ai-assistant",   icon: "🤖", label: "AI Copilot" },
    { id: "threat-intel",   icon: "🌐", label: "Threat Intel" },
    { id: "network",        icon: "🔗", label: "Network View" },
    { id: "reports",        icon: "📊", label: "Reports" },
    { id: "settings",       icon: "⚙️", label: "Settings" },
  ];
  return (
    <aside style={{
      width: collapsed ? 64 : 220, minHeight: "100vh",
      background: "linear-gradient(180deg,#0A0E1A 0%,#0D1424 100%)",
      borderRight: "1px solid #1A2540",
      display: "flex", flexDirection: "column",
      transition: "width .25s", flexShrink: 0,
    }}>
      <div style={{ padding: "20px 16px 16px", borderBottom: "1px solid #1A2540", display: "flex", alignItems: "center", gap: 10 }}>
        <span style={{ fontSize: 22, flexShrink: 0 }}>🛡️</span>
        {!collapsed && <span style={{ color: "#00D4FF", fontWeight: 700, fontSize: 16, letterSpacing: 1 }}>SentinelAI</span>}
        <button onClick={() => setCollapsed(!collapsed)} style={{ marginLeft: "auto", background: "none", border: "none", color: "#4A5578", cursor: "pointer", fontSize: 14 }}>
          {collapsed ? "›" : "‹"}
        </button>
      </div>
      <nav style={{ flex: 1, padding: "12px 8px" }}>
        {nav.map(item => (
          <button key={item.id} onClick={() => setActivePage(item.id)} style={{
            width: "100%", display: "flex", alignItems: "center", gap: 12,
            padding: "10px 12px", borderRadius: 8, marginBottom: 4,
            border: "none", cursor: "pointer", textAlign: "left",
            background: activePage === item.id ? "rgba(0,212,255,.12)" : "transparent",
            color: activePage === item.id ? "#00D4FF" : "#6B7DB3",
            borderLeft: activePage === item.id ? "3px solid #00D4FF" : "3px solid transparent",
            fontSize: 13, transition: "all .15s",
          }}>
            <span style={{ fontSize: 16, flexShrink: 0 }}>{item.icon}</span>
            {!collapsed && <span>{item.label}</span>}
          </button>
        ))}
      </nav>
      {!collapsed && (
        <div style={{ padding: "12px 16px", borderTop: "1px solid #1A2540" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,#00D4FF,#0050FF)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 13, fontWeight: 700, color: "#fff" }}>H</div>
            <div>
              <div style={{ color: "#E2E8FF", fontSize: 12, fontWeight: 600 }}>Hassan Faris</div>
              <div style={{ color: "#4A5578", fontSize: 10 }}>SOC Analyst</div>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}

function StatCard({ label, value, icon, color, delta }) {
  return (
    <div style={{
      background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12,
      padding: "18px 22px", display: "flex", flexDirection: "column", gap: 6,
      borderTop: `3px solid ${color}`,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ color: "#6B7DB3", fontSize: 12, fontWeight: 500, textTransform: "uppercase", letterSpacing: .5 }}>{label}</span>
        <span style={{ fontSize: 20 }}>{icon}</span>
      </div>
      <div style={{ color: color, fontSize: 32, fontWeight: 800, lineHeight: 1 }}>{value}</div>
      {delta !== undefined && (
        <div style={{ color: delta > 0 ? "#FF3B3B" : "#00C851", fontSize: 11 }}>
          {delta > 0 ? "▲" : "▼"} {Math.abs(delta)}% vs last 24h
        </div>
      )}
    </div>
  );
}

function AlertRow({ alert, onSelect }) {
  const sev = alert.severity;
  return (
    <tr onClick={() => onSelect(alert)} style={{ cursor: "pointer", borderBottom: "1px solid #131929" }}
      onMouseEnter={e => e.currentTarget.style.background = "#0F1830"}
      onMouseLeave={e => e.currentTarget.style.background = "transparent"}>
      <td style={{ padding: "10px 12px" }}>
        <span style={{
          background: SEV_COLOR[sev] + "22", color: SEV_COLOR[sev],
          padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
          border: `1px solid ${SEV_COLOR[sev]}44`, textTransform: "uppercase",
        }}>{sev}</span>
      </td>
      <td style={{ padding: "10px 12px", color: "#E2E8FF", fontSize: 13 }}>{alert.rule_name}</td>
      <td style={{ padding: "10px 12px", color: "#00D4FF", fontSize: 12, fontFamily: "monospace" }}>{alert.source_ip}</td>
      <td style={{ padding: "10px 12px", color: "#6B7DB3", fontSize: 12 }}>{alert.hostname}</td>
      <td style={{ padding: "10px 12px" }}>
        <span style={{ background: "#1A2035", color: "#FFD700", padding: "2px 6px", borderRadius: 3, fontSize: 11, fontFamily: "monospace" }}>{alert.mitre_technique}</span>
      </td>
      <td style={{ padding: "10px 12px", color: "#6B7DB3", fontSize: 11 }}>{new Date(alert.timestamp).toLocaleTimeString()}</td>
      <td style={{ padding: "10px 12px" }}>
        {alert.correlated && <span style={{ background: "#FF3B3B22", color: "#FF3B3B", padding: "2px 6px", borderRadius: 3, fontSize: 10, border: "1px solid #FF3B3B44" }}>⛓ CHAIN</span>}
      </td>
    </tr>
  );
}

function AlertModal({ alert, onClose }) {
  if (!alert) return null;
  return (
    <div style={{ position: "fixed", inset: 0, background: "rgba(0,0,0,.75)", zIndex: 1000, display: "flex", alignItems: "center", justifyContent: "center" }} onClick={onClose}>
      <div onClick={e => e.stopPropagation()} style={{
        background: "#0D1424", border: "1px solid #1A2540", borderRadius: 14,
        width: 680, maxHeight: "85vh", overflow: "auto", padding: 28,
      }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
          <div>
            <div style={{ color: SEV_COLOR[alert.severity], fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: 1, marginBottom: 4 }}>
              {alert.severity} SEVERITY
            </div>
            <h2 style={{ color: "#E2E8FF", margin: 0, fontSize: 18 }}>{alert.rule_name}</h2>
          </div>
          <button onClick={onClose} style={{ background: "none", border: "none", color: "#4A5578", fontSize: 20, cursor: "pointer" }}>✕</button>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 20 }}>
          {[
            ["Alert ID",    alert.alert_id],
            ["Source IP",   alert.source_ip],
            ["Hostname",    alert.hostname],
            ["Detection",   alert.detection_type?.replace(/_/g, " ")],
            ["Tactic",      alert.mitre_tactic],
            ["Technique",   alert.mitre_technique],
            ["Timestamp",   new Date(alert.timestamp).toLocaleString()],
            ["Correlated",  alert.correlated ? "Yes — Attack Chain" : "No"],
          ].map(([k, v]) => (
            <div key={k} style={{ background: "#0A0E1A", borderRadius: 8, padding: "10px 14px" }}>
              <div style={{ color: "#4A5578", fontSize: 10, textTransform: "uppercase", letterSpacing: .5, marginBottom: 4 }}>{k}</div>
              <div style={{ color: "#E2E8FF", fontSize: 13, fontFamily: k === "Source IP" || k === "Technique" ? "monospace" : "inherit" }}>{v}</div>
            </div>
          ))}
        </div>

        {alert.attack_chain?.length > 0 && (
          <div style={{ marginBottom: 20 }}>
            <div style={{ color: "#FF3B3B", fontSize: 12, fontWeight: 700, marginBottom: 8 }}>⛓ ATTACK CHAIN DETECTED</div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              {alert.attack_chain.map((step, i) => (
                <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <span style={{ background: "#FF3B3B22", color: "#FF3B3B", padding: "4px 10px", borderRadius: 4, fontSize: 12 }}>{step.replace(/_/g," ")}</span>
                  {i < alert.attack_chain.length - 1 && <span style={{ color: "#4A5578" }}>→</span>}
                </span>
              ))}
            </div>
          </div>
        )}

        <div style={{ display: "flex", gap: 10 }}>
          {["Acknowledge","Block IP","Run Playbook","Create Ticket"].map(action => (
            <button key={action} style={{
              padding: "8px 16px", borderRadius: 6, border: "1px solid #1A2540",
              background: action === "Block IP" ? "#FF3B3B22" : "#1A2540",
              color: action === "Block IP" ? "#FF3B3B" : "#E2E8FF",
              cursor: "pointer", fontSize: 12,
            }}>{action}</button>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── Pages ────────────────────────────────────────────────────
function DashboardPage({ alerts, timelineData, wsAlerts }) {
  const sevCounts = alerts.reduce((acc, a) => { acc[a.severity] = (acc[a.severity] || 0) + 1; return acc; }, {});
  const typeCounts = alerts.slice(0, 6).reduce((acc, a) => {
    const k = a.detection_type?.replace(/_/g," ") || "unknown";
    acc[k] = (acc[k] || 0) + 1; return acc;
  }, {});
  const pieData = Object.entries(sevCounts).map(([name, value]) => ({ name, value }));
  const barData = Object.entries(typeCounts).map(([name, value]) => ({ name, value }));
  const [selAlert, setSelAlert] = useState(null);

  return (
    <div style={{ padding: 24, display: "flex", flexDirection: "column", gap: 20 }}>
      {/* Live indicator */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h1 style={{ color: "#E2E8FF", margin: 0, fontSize: 22, fontWeight: 700 }}>Security Operations Center</h1>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#00C851", animation: "pulse 2s infinite" }}/>
          <span style={{ color: "#00C851", fontSize: 12 }}>LIVE MONITORING</span>
          <span style={{ color: "#4A5578", fontSize: 12 }}>{new Date().toLocaleString()}</span>
        </div>
      </div>

      {/* Stat cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 16 }}>
        <StatCard label="Total Alerts (24h)" value={alerts.length} icon="🚨" color="#FF3B3B" delta={12} />
        <StatCard label="Critical" value={sevCounts.critical || 0} icon="🔴" color="#FF3B3B" delta={8} />
        <StatCard label="High" value={sevCounts.high || 0} icon="🟠" color="#FF8C00" delta={-5} />
        <StatCard label="Attack Chains" value={alerts.filter(a => a.correlated).length} icon="⛓" color="#9B59B6" delta={25} />
      </div>

      {/* Charts row */}
      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Alert Volume — Last 24 Hours</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timelineData}>
              <defs>
                {["critical","high","medium"].map((k, i) => (
                  <linearGradient key={k} id={`grad${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={[SEV_COLOR.critical, SEV_COLOR.high, SEV_COLOR.medium][i]} stopOpacity={0.3}/>
                    <stop offset="95%" stopColor={[SEV_COLOR.critical, SEV_COLOR.high, SEV_COLOR.medium][i]} stopOpacity={0}/>
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1A2540"/>
              <XAxis dataKey="hour" tick={{ fill: "#4A5578", fontSize: 10 }} interval={3}/>
              <YAxis tick={{ fill: "#4A5578", fontSize: 10 }}/>
              <Tooltip contentStyle={{ background: "#0A0E1A", border: "1px solid #1A2540", borderRadius: 8 }} labelStyle={{ color: "#E2E8FF" }}/>
              {["critical","high","medium"].map((k, i) => (
                <Area key={k} type="monotone" dataKey={k} stroke={[SEV_COLOR.critical,SEV_COLOR.high,SEV_COLOR.medium][i]}
                  fill={`url(#grad${k})`} strokeWidth={2}/>
              ))}
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={pieData} cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={3} dataKey="value">
                {pieData.map((entry, i) => <Cell key={i} fill={SEV_COLOR[entry.name] || CHART_COLORS[i]}/>)}
              </Pie>
              <Tooltip contentStyle={{ background: "#0A0E1A", border: "1px solid #1A2540" }}/>
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 8, justifyContent: "center" }}>
            {pieData.map(d => (
              <span key={d.name} style={{ display: "flex", alignItems: "center", gap: 4, fontSize: 11, color: "#6B7DB3" }}>
                <span style={{ width: 8, height: 8, borderRadius: 2, background: SEV_COLOR[d.name] || "#888", display: "inline-block" }}/>
                {d.name} ({d.value})
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Attack types bar */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Top Attack Types</h3>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={barData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1A2540"/>
              <XAxis type="number" tick={{ fill: "#4A5578", fontSize: 10 }}/>
              <YAxis type="category" dataKey="name" tick={{ fill: "#6B7DB3", fontSize: 10 }} width={120}/>
              <Tooltip contentStyle={{ background: "#0A0E1A", border: "1px solid #1A2540" }}/>
              <Bar dataKey="value" fill="#00D4FF" radius={[0,4,4,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* MITRE ATT&CK mini heatmap */}
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
          <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>MITRE ATT&CK Coverage</h3>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4,1fr)", gap: 4 }}>
            {MITRE_TACTICS.map((tactic, i) => {
              const count = alerts.filter(a => a.mitre_tactic === tactic).length;
              const intensity = Math.min(count / 3, 1);
              return (
                <div key={tactic} title={`${tactic}: ${count} alerts`} style={{
                  background: count > 0 ? `rgba(255,59,59,${0.2 + intensity * 0.8})` : "#1A2035",
                  borderRadius: 4, padding: "4px 6px", fontSize: 9, color: count > 0 ? "#FFB0B0" : "#4A5578",
                  textAlign: "center", cursor: "default", lineHeight: 1.3,
                }}>
                  {tactic.split(" ").map(w => w[0]).join("")}
                  {count > 0 && <div style={{ color: "#FF3B3B", fontWeight: 700 }}>{count}</div>}
                </div>
              );
            })}
          </div>
          <div style={{ marginTop: 8, fontSize: 10, color: "#4A5578" }}>Hover cell for tactic name · Red = active threats</div>
        </div>
      </div>

      {/* Alert table */}
      <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
        <div style={{ padding: "14px 20px", borderBottom: "1px solid #1A2540", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <h3 style={{ color: "#E2E8FF", margin: 0, fontSize: 14 }}>Recent Alerts</h3>
          <span style={{ color: "#4A5578", fontSize: 12 }}>{alerts.length} total</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: "#0A0E1A" }}>
                {["Severity","Rule","Source IP","Hostname","MITRE","Time","Chain"].map(h => (
                  <th key={h} style={{ padding: "10px 12px", color: "#4A5578", fontWeight: 600, textAlign: "left", fontSize: 11, textTransform: "uppercase", letterSpacing: .5 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.slice(0, 12).map(a => <AlertRow key={a.alert_id} alert={a} onSelect={setSelAlert}/>)}
            </tbody>
          </table>
        </div>
      </div>

      <AlertModal alert={selAlert} onClose={() => setSelAlert(null)}/>
    </div>
  );
}

function IncidentsPage({ alerts }) {
  const [filter, setFilter] = useState("all");
  const [selAlert, setSelAlert] = useState(null);
  const filtered = filter === "all" ? alerts : alerts.filter(a => a.severity === filter);
  return (
    <div style={{ padding: 24 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <h1 style={{ color: "#E2E8FF", margin: 0, fontSize: 22 }}>Incidents & Alerts</h1>
        <div style={{ display: "flex", gap: 8 }}>
          {["all","critical","high","medium","low"].map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              padding: "6px 14px", borderRadius: 6, border: "1px solid",
              borderColor: filter === f ? (SEV_COLOR[f] || "#00D4FF") : "#1A2540",
              background: filter === f ? (SEV_COLOR[f] || "#00D4FF") + "22" : "transparent",
              color: filter === f ? (SEV_COLOR[f] || "#00D4FF") : "#6B7DB3",
              cursor: "pointer", fontSize: 12, textTransform: "capitalize",
            }}>{f}</button>
          ))}
        </div>
      </div>
      <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
          <thead>
            <tr style={{ background: "#0A0E1A" }}>
              {["Severity","Rule Name","Source IP","Hostname","Tactic","Technique","Time","Action"].map(h => (
                <th key={h} style={{ padding: "12px 14px", color: "#4A5578", fontWeight: 600, textAlign: "left", fontSize: 11, textTransform: "uppercase" }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {filtered.map(a => (
              <tr key={a.alert_id} style={{ borderBottom: "1px solid #131929" }}>
                <td style={{ padding: "12px 14px" }}>
                  <span style={{ background: SEV_COLOR[a.severity] + "22", color: SEV_COLOR[a.severity], padding: "3px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700, textTransform: "uppercase" }}>{a.severity}</span>
                </td>
                <td style={{ padding: "12px 14px", color: "#E2E8FF", fontSize: 13 }}>{a.rule_name}</td>
                <td style={{ padding: "12px 14px", color: "#00D4FF", fontFamily: "monospace", fontSize: 12 }}>{a.source_ip}</td>
                <td style={{ padding: "12px 14px", color: "#6B7DB3", fontSize: 12 }}>{a.hostname}</td>
                <td style={{ padding: "12px 14px", color: "#9B59B6", fontSize: 11 }}>{a.mitre_tactic}</td>
                <td style={{ padding: "12px 14px" }}>
                  <span style={{ background: "#1A2035", color: "#FFD700", padding: "2px 6px", borderRadius: 3, fontSize: 11, fontFamily: "monospace" }}>{a.mitre_technique}</span>
                </td>
                <td style={{ padding: "12px 14px", color: "#4A5578", fontSize: 11 }}>{new Date(a.timestamp).toLocaleString()}</td>
                <td style={{ padding: "12px 14px" }}>
                  <button onClick={() => setSelAlert(a)} style={{ background: "#00D4FF22", color: "#00D4FF", border: "1px solid #00D4FF44", borderRadius: 5, padding: "4px 10px", cursor: "pointer", fontSize: 11 }}>Investigate</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <AlertModal alert={selAlert} onClose={() => setSelAlert(null)}/>
    </div>
  );
}

function AIAssistantPage() {
  const [messages, setMessages] = useState([
    { role: "assistant", content: "👋 I'm your AI Security Copilot. I can analyze alerts, explain attack techniques, hunt for threats, or help with incident response. What do you need?" }
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  const presets = [
    "Explain MITRE T1110 brute force",
    "What should I do if ransomware is detected?",
    "How does DNS tunneling work?",
    "Analyze the latest critical alerts",
    "What is impossible travel detection?",
    "Write a Sigma rule for PowerShell abuse",
  ];

  const sendMessage = async (text) => {
    if (!text.trim()) return;
    const userMsg = { role: "user", content: text };
    setMessages(m => [...m, userMsg]);
    setInput("");
    setLoading(true);

    try {
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          system: "You are an elite SOC analyst and cybersecurity expert for SentinelAI. Provide concise, actionable security analysis. Use MITRE ATT&CK framework references, technical accuracy, and practical recommendations. Format responses with clear sections. Keep responses focused and professional.",
          messages: [...messages, userMsg].map(m => ({ role: m.role, content: m.content })),
        }),
      });
      const data = await res.json();
      const reply = data.content?.[0]?.text || "Unable to get response.";
      setMessages(m => [...m, { role: "assistant", content: reply }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", content: "⚠️ AI service unavailable. Please check the Ollama/LLM configuration." }]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior: "smooth" }); }, [messages]);

  return (
    <div style={{ padding: 24, height: "calc(100vh - 48px)", display: "flex", flexDirection: "column", gap: 16 }}>
      <h1 style={{ color: "#E2E8FF", margin: 0, fontSize: 22 }}>🤖 AI Security Copilot</h1>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        {presets.map(p => (
          <button key={p} onClick={() => sendMessage(p)} style={{
            padding: "5px 12px", borderRadius: 16, background: "#00D4FF11", border: "1px solid #00D4FF33",
            color: "#00D4FF", fontSize: 11, cursor: "pointer",
          }}>{p}</button>
        ))}
      </div>
      <div style={{ flex: 1, background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20, overflowY: "auto", display: "flex", flexDirection: "column", gap: 16 }}>
        {messages.map((m, i) => (
          <div key={i} style={{ display: "flex", gap: 12, justifyContent: m.role === "user" ? "flex-end" : "flex-start" }}>
            {m.role === "assistant" && (
              <div style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,#00D4FF,#0050FF)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 16, flexShrink: 0 }}>🤖</div>
            )}
            <div style={{
              maxWidth: "72%", padding: "12px 16px", borderRadius: m.role === "user" ? "14px 14px 4px 14px" : "14px 14px 14px 4px",
              background: m.role === "user" ? "linear-gradient(135deg,#0050FF,#00D4FF)" : "#131929",
              color: "#E2E8FF", fontSize: 13, lineHeight: 1.6,
              whiteSpace: "pre-wrap",
            }}>{m.content}</div>
          </div>
        ))}
        {loading && (
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{ width: 32, height: 32, borderRadius: "50%", background: "linear-gradient(135deg,#00D4FF,#0050FF)", display: "flex", alignItems: "center", justifyContent: "center" }}>🤖</div>
            <div style={{ background: "#131929", padding: "12px 16px", borderRadius: "14px 14px 14px 4px", color: "#6B7DB3", fontSize: 13 }}>
              <span style={{ animation: "pulse 1s infinite" }}>Analyzing...</span>
            </div>
          </div>
        )}
        <div ref={bottomRef}/>
      </div>
      <div style={{ display: "flex", gap: 10 }}>
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === "Enter" && !e.shiftKey && sendMessage(input)}
          placeholder="Ask about threats, analyze alerts, get IR guidance..."
          style={{ flex: 1, background: "#0D1424", border: "1px solid #1A2540", borderRadius: 10, padding: "12px 16px", color: "#E2E8FF", fontSize: 13, outline: "none" }}
        />
        <button onClick={() => sendMessage(input)} disabled={loading || !input.trim()} style={{
          padding: "12px 24px", borderRadius: 10, background: "linear-gradient(135deg,#0050FF,#00D4FF)",
          border: "none", color: "#fff", fontWeight: 700, cursor: "pointer", fontSize: 13,
          opacity: loading || !input.trim() ? 0.5 : 1,
        }}>Send</button>
      </div>
    </div>
  );
}

function ThreatHuntPage({ alerts }) {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState([]);
  const [searched, setSearched] = useState(false);

  const hunt = () => {
    if (!query) return;
    const q = query.toLowerCase();
    const found = alerts.filter(a =>
      a.rule_name.toLowerCase().includes(q) ||
      a.source_ip.includes(q) ||
      a.hostname.toLowerCase().includes(q) ||
      a.mitre_technique.toLowerCase().includes(q) ||
      a.detection_type?.toLowerCase().includes(q)
    );
    setResults(found);
    setSearched(true);
  };

  const presets = ["T1110","brute_force","powershell","ransomware","lateral_movement","T1003","reverse_shell"];

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ color: "#E2E8FF", margin: "0 0 20px", fontSize: 22 }}>🔍 Threat Hunting</h1>
      <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20, marginBottom: 20 }}>
        <div style={{ marginBottom: 12, color: "#6B7DB3", fontSize: 13 }}>Search by IP, hostname, technique, or attack type:</div>
        <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
          <input value={query} onChange={e => setQuery(e.target.value)} onKeyDown={e => e.key === "Enter" && hunt()}
            placeholder='e.g. "T1110" or "192.168.1.50" or "ransomware"'
            style={{ flex: 1, background: "#0A0E1A", border: "1px solid #1A2540", borderRadius: 8, padding: "10px 14px", color: "#E2E8FF", fontSize: 13, outline: "none" }}
          />
          <button onClick={hunt} style={{ padding: "10px 24px", borderRadius: 8, background: "linear-gradient(135deg,#0050FF,#00D4FF)", border: "none", color: "#fff", fontWeight: 700, cursor: "pointer" }}>Hunt</button>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          {presets.map(p => (
            <button key={p} onClick={() => { setQuery(p); }} style={{ padding: "4px 10px", borderRadius: 12, background: "#1A2035", border: "1px solid #1A2540", color: "#6B7DB3", fontSize: 11, cursor: "pointer" }}>{p}</button>
          ))}
        </div>
      </div>

      {searched && (
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "14px 20px", borderBottom: "1px solid #1A2540" }}>
            <span style={{ color: results.length > 0 ? "#00D4FF" : "#6B7DB3", fontSize: 14 }}>
              {results.length > 0 ? `✅ Found ${results.length} matching events` : `❌ No events found for "${query}"`}
            </span>
          </div>
          {results.length > 0 && (
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ background: "#0A0E1A" }}>
                  {["Severity","Rule","Source IP","Hostname","Technique","Timestamp"].map(h => (
                    <th key={h} style={{ padding: "10px 14px", color: "#4A5578", fontWeight: 600, textAlign: "left", fontSize: 11, textTransform: "uppercase" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {results.map(a => (
                  <tr key={a.alert_id} style={{ borderBottom: "1px solid #131929" }}>
                    <td style={{ padding: "10px 14px" }}>
                      <span style={{ background: SEV_COLOR[a.severity] + "22", color: SEV_COLOR[a.severity], padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700 }}>{a.severity}</span>
                    </td>
                    <td style={{ padding: "10px 14px", color: "#E2E8FF" }}>{a.rule_name}</td>
                    <td style={{ padding: "10px 14px", color: "#00D4FF", fontFamily: "monospace" }}>{a.source_ip}</td>
                    <td style={{ padding: "10px 14px", color: "#6B7DB3" }}>{a.hostname}</td>
                    <td style={{ padding: "10px 14px" }}><span style={{ background: "#1A2035", color: "#FFD700", padding: "2px 6px", borderRadius: 3, fontSize: 11, fontFamily: "monospace" }}>{a.mitre_technique}</span></td>
                    <td style={{ padding: "10px 14px", color: "#4A5578" }}>{new Date(a.timestamp).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatIntelPage() {
  const [ip, setIp] = useState("");
  const [hash, setHash] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("ip");

  const lookup = async () => {
    setLoading(true);
    setResult(null);
    await new Promise(r => setTimeout(r, 800));
    // Simulated response
    const mockIpResult = {
      ip: ip || "185.220.101.45",
      threat_score: { score: 87, verdict: "HIGH", reasons: ["VirusTotal: 8 detections", "AbuseIPDB confidence: 95%", "OTX pulses: 12"] },
      virustotal: { malicious: 8, suspicious: 2, harmless: 65, country: "DE", as_owner: "AS-CHOOPA", reputation: -15 },
      abuseipdb: { abuse_confidence: 95, total_reports: 234, country_code: "DE", isp: "Vultr Holdings LLC", usage_type: "Data Center/Web Hosting/Transit" },
      otx: { pulse_count: 12, reputation: -3, country_name: "Germany" },
    };
    const mockHashResult = {
      hash: hash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      is_malicious: true,
      verdict: "MALICIOUS",
      virustotal: { malicious: 62, suspicious: 3, harmless: 4, name: "Emotet.trojan", type: "Win32 EXE", size: 204800 },
    };
    setResult(activeTab === "ip" ? mockIpResult : mockHashResult);
    setLoading(false);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ color: "#E2E8FF", margin: "0 0 20px", fontSize: 22 }}>🌐 Threat Intelligence</h1>
      <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
        {["ip","hash","domain","cve"].map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: "6px 16px", borderRadius: 6, border: "1px solid",
            borderColor: activeTab === t ? "#00D4FF" : "#1A2540",
            background: activeTab === t ? "#00D4FF22" : "transparent",
            color: activeTab === t ? "#00D4FF" : "#6B7DB3",
            cursor: "pointer", fontSize: 12, textTransform: "uppercase",
          }}>{t}</button>
        ))}
      </div>

      <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20, marginBottom: 20 }}>
        <div style={{ display: "flex", gap: 10 }}>
          <input
            value={activeTab === "ip" ? ip : hash}
            onChange={e => activeTab === "ip" ? setIp(e.target.value) : setHash(e.target.value)}
            placeholder={activeTab === "ip" ? "Enter IP address (e.g. 185.220.101.45)" : "Enter file hash (MD5/SHA1/SHA256)"}
            onKeyDown={e => e.key === "Enter" && lookup()}
            style={{ flex: 1, background: "#0A0E1A", border: "1px solid #1A2540", borderRadius: 8, padding: "10px 14px", color: "#E2E8FF", fontSize: 13, outline: "none" }}
          />
          <button onClick={lookup} disabled={loading} style={{
            padding: "10px 24px", borderRadius: 8, background: "linear-gradient(135deg,#0050FF,#00D4FF)",
            border: "none", color: "#fff", fontWeight: 700, cursor: "pointer",
          }}>{loading ? "Checking..." : "Analyze"}</button>
        </div>
      </div>

      {result && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
          <div style={{ gridColumn: "1/-1", background: "#0D1424", border: `2px solid ${result.threat_score?.score > 60 ? "#FF3B3B" : result.threat_score?.score > 30 ? "#FF8C00" : "#00C851"}`, borderRadius: 12, padding: 20 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ color: "#6B7DB3", fontSize: 11, textTransform: "uppercase", marginBottom: 4 }}>Threat Score</div>
                <div style={{ color: result.threat_score?.score > 60 ? "#FF3B3B" : "#00C851", fontSize: 40, fontWeight: 800 }}>{result.threat_score?.score ?? (result.is_malicious ? 95 : 5)}/100</div>
                <div style={{ color: "#E2E8FF", fontSize: 16, fontWeight: 600 }}>{result.threat_score?.verdict ?? result.verdict}</div>
              </div>
              <div style={{ textAlign: "right" }}>
                {(result.threat_score?.reasons || []).map((r, i) => (
                  <div key={i} style={{ color: "#6B7DB3", fontSize: 12, marginBottom: 4 }}>• {r}</div>
                ))}
              </div>
            </div>
          </div>

          {result.virustotal && (
            <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 16 }}>
              <div style={{ color: "#00D4FF", fontSize: 12, fontWeight: 700, marginBottom: 12 }}>VirusTotal</div>
              {[["Malicious", result.virustotal.malicious, "#FF3B3B"],["Suspicious", result.virustotal.suspicious, "#FF8C00"],["Harmless", result.virustotal.harmless, "#00C851"]].map(([k,v,c]) => (
                <div key={k} style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
                  <span style={{ color: "#6B7DB3", fontSize: 12 }}>{k}</span>
                  <span style={{ color: c, fontWeight: 700, fontSize: 12 }}>{v}</span>
                </div>
              ))}
              {result.virustotal.country && <div style={{ color: "#6B7DB3", fontSize: 11, marginTop: 8 }}>📍 {result.virustotal.country} · {result.virustotal.as_owner}</div>}
            </div>
          )}

          {result.abuseipdb && (
            <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 16 }}>
              <div style={{ color: "#00D4FF", fontSize: 12, fontWeight: 700, marginBottom: 12 }}>AbuseIPDB</div>
              <div style={{ color: "#FF3B3B", fontSize: 28, fontWeight: 800, marginBottom: 4 }}>{result.abuseipdb.abuse_confidence}%</div>
              <div style={{ color: "#6B7DB3", fontSize: 11, marginBottom: 8 }}>Confidence Score</div>
              <div style={{ color: "#6B7DB3", fontSize: 12 }}>Reports: <span style={{ color: "#E2E8FF" }}>{result.abuseipdb.total_reports}</span></div>
              <div style={{ color: "#6B7DB3", fontSize: 12 }}>ISP: <span style={{ color: "#E2E8FF" }}>{result.abuseipdb.isp}</span></div>
              <div style={{ color: "#6B7DB3", fontSize: 12 }}>Type: <span style={{ color: "#E2E8FF" }}>{result.abuseipdb.usage_type}</span></div>
            </div>
          )}

          {result.otx && (
            <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 16 }}>
              <div style={{ color: "#00D4FF", fontSize: 12, fontWeight: 700, marginBottom: 12 }}>AlienVault OTX</div>
              <div style={{ color: "#FF8C00", fontSize: 28, fontWeight: 800, marginBottom: 4 }}>{result.otx.pulse_count}</div>
              <div style={{ color: "#6B7DB3", fontSize: 11, marginBottom: 8 }}>Threat Pulses</div>
              <div style={{ color: "#6B7DB3", fontSize: 12 }}>Country: <span style={{ color: "#E2E8FF" }}>{result.otx.country_name}</span></div>
              <div style={{ color: "#6B7DB3", fontSize: 12 }}>Reputation: <span style={{ color: result.otx.reputation < 0 ? "#FF3B3B" : "#00C851" }}>{result.otx.reputation}</span></div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ReportsPage() {
  const [generating, setGenerating] = useState(false);
  const [reportType, setReportType] = useState("executive");
  const [timeRange, setTimeRange] = useState(24);
  const [generated, setGenerated] = useState(false);

  const generate = async () => {
    setGenerating(true);
    await new Promise(r => setTimeout(r, 1500));
    setGenerating(false);
    setGenerated(true);
  };

  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ color: "#E2E8FF", margin: "0 0 20px", fontSize: 22 }}>📊 Reports</h1>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 2fr", gap: 20 }}>
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20, height: "fit-content" }}>
          <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Generate Report</h3>
          <div style={{ marginBottom: 14 }}>
            <label style={{ color: "#6B7DB3", fontSize: 12, display: "block", marginBottom: 6 }}>Report Type</label>
            {["executive","technical","summary","compliance"].map(t => (
              <button key={t} onClick={() => setReportType(t)} style={{
                display: "block", width: "100%", padding: "8px 12px", marginBottom: 4,
                borderRadius: 6, border: "1px solid",
                borderColor: reportType === t ? "#00D4FF" : "#1A2540",
                background: reportType === t ? "#00D4FF22" : "transparent",
                color: reportType === t ? "#00D4FF" : "#6B7DB3",
                cursor: "pointer", fontSize: 12, textAlign: "left", textTransform: "capitalize",
              }}>{t} Report</button>
            ))}
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ color: "#6B7DB3", fontSize: 12, display: "block", marginBottom: 6 }}>Time Range</label>
            {[6,12,24,48,168].map(h => (
              <button key={h} onClick={() => setTimeRange(h)} style={{
                display: "inline-block", padding: "5px 10px", margin: "0 4px 4px 0",
                borderRadius: 5, border: `1px solid ${timeRange === h ? "#00D4FF" : "#1A2540"}`,
                background: timeRange === h ? "#00D4FF22" : "transparent",
                color: timeRange === h ? "#00D4FF" : "#6B7DB3",
                cursor: "pointer", fontSize: 11,
              }}>{h === 168 ? "7d" : `${h}h`}</button>
            ))}
          </div>
          <button onClick={generate} disabled={generating} style={{
            width: "100%", padding: "10px", borderRadius: 8,
            background: "linear-gradient(135deg,#0050FF,#00D4FF)",
            border: "none", color: "#fff", fontWeight: 700, cursor: "pointer", fontSize: 13,
          }}>{generating ? "Generating..." : "Generate PDF Report"}</button>
        </div>

        <div>
          {generated && (
            <div style={{ background: "#0D1424", border: "1px solid #00C85144", borderRadius: 12, padding: 20, marginBottom: 16 }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div>
                  <div style={{ color: "#00C851", fontSize: 13, fontWeight: 700, marginBottom: 4 }}>✅ Report Generated</div>
                  <div style={{ color: "#6B7DB3", fontSize: 12 }}>SentinelAI_{reportType}_report_{new Date().toISOString().slice(0,10)}.pdf</div>
                </div>
                <button style={{ padding: "8px 20px", borderRadius: 8, background: "#00C85122", border: "1px solid #00C85144", color: "#00C851", cursor: "pointer", fontSize: 12 }}>⬇ Download</button>
              </div>
            </div>
          )}

          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
            <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Scheduled Reports</h3>
            {[
              { name: "Daily Executive Brief", schedule: "Every day 08:00", last: "Today 08:00", type: "executive" },
              { name: "Weekly Technical Summary", schedule: "Every Monday 09:00", last: "Mon 09:00", type: "technical" },
              { name: "Monthly Compliance Report", schedule: "1st of month 07:00", last: "Jun 1 07:00", type: "compliance" },
            ].map(r => (
              <div key={r.name} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "12px 0", borderBottom: "1px solid #131929" }}>
                <div>
                  <div style={{ color: "#E2E8FF", fontSize: 13 }}>{r.name}</div>
                  <div style={{ color: "#4A5578", fontSize: 11 }}>{r.schedule} · Last: {r.last}</div>
                </div>
                <span style={{ background: "#00D4FF22", color: "#00D4FF", padding: "3px 8px", borderRadius: 4, fontSize: 10, textTransform: "uppercase" }}>{r.type}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function SettingsPage() {
  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ color: "#E2E8FF", margin: "0 0 20px", fontSize: 22 }}>⚙️ Settings</h1>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 20 }}>
        {[
          { title: "🔑 API Keys", items: ["VirusTotal API Key","AbuseIPDB API Key","AlienVault OTX Key","Shodan API Key"] },
          { title: "📡 Integrations", items: ["Kafka Broker URL","OpenSearch Host","Ollama LLM URL","SMTP Server"] },
          { title: "🔔 Notifications", items: ["Slack Webhook","Email Alerts (SOC)","PagerDuty","SMS Alerts"] },
          { title: "🛡️ Security", items: ["MFA Enforcement","Session Timeout","IP Whitelist","Audit Logging"] },
        ].map(section => (
          <div key={section.title} style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
            <h3 style={{ color: "#E2E8FF", margin: "0 0 14px", fontSize: 14 }}>{section.title}</h3>
            {section.items.map(item => (
              <div key={item} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: "1px solid #131929" }}>
                <span style={{ color: "#6B7DB3", fontSize: 12 }}>{item}</span>
                <button style={{ padding: "4px 12px", borderRadius: 5, background: "#1A2035", border: "1px solid #1A2540", color: "#00D4FF", cursor: "pointer", fontSize: 11 }}>Configure</button>
              </div>
            ))}
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────
export default function App() {
  const [activePage, setActivePage]   = useState("dashboard");
  const [collapsed, setCollapsed]     = useState(false);
  const [alerts]                      = useState(genAlerts(20));
  const [timelineData]                = useState(genTimelineData());
  const [wsAlerts, setWsAlerts]       = useState([]);

  // WebSocket connection for real-time alerts
  useEffect(() => {
    try {
      const ws = new WebSocket(`${WS_URL}/ws/alerts`);
      ws.onmessage = e => {
        const msg = JSON.parse(e.data);
        if (msg.type === "alert") setWsAlerts(prev => [msg.data, ...prev].slice(0, 50));
      };
      return () => ws.close();
    } catch {}
  }, []);

  const pages = { dashboard: DashboardPage, incidents: IncidentsPage, "threat-hunting": ThreatHuntPage, "ai-assistant": AIAssistantPage, "threat-intel": ThreatIntelPage, network: NetworkSummaryEmbed, reports: ReportsPage, settings: SettingsPage };
  const PageComponent = pages[activePage] || DashboardPage;

  return (
    <div style={{ display: "flex", minHeight: "100vh", background: "#070B14", fontFamily: "'Inter',system-ui,sans-serif" }}>
      <style>{`
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 4px; height: 4px; }
        ::-webkit-scrollbar-track { background: #0A0E1A; }
        ::-webkit-scrollbar-thumb { background: #1A2540; borderRadius: 2px; }
        @keyframes pulse { 0%,100% { opacity:1; } 50% { opacity:.4; } }
        input::placeholder { color: #2A3555; }
      `}</style>
      <Sidebar activePage={activePage} setActivePage={setActivePage} collapsed={collapsed} setCollapsed={setCollapsed}/>
      <main style={{ flex: 1, overflowY: "auto", maxHeight: "100vh" }}>
        <PageComponent alerts={[...wsAlerts, ...alerts]} timelineData={timelineData} wsAlerts={wsAlerts}/>
      </main>
    </div>
  );
}

// ─── Dynamic network page loader ─────────────────────────────
// index.jsx patch: wire network page into router
// The pages object in App() needs to include "network"
// This is auto-handled because network.jsx is a Next.js page at /network
// For the SPA routing in index.jsx, we embed a lightweight network summary:
export function NetworkSummaryEmbed() {
  return (
    <div style={{ padding: 24 }}>
      <h1 style={{ color: "#E2E8FF", margin: "0 0 12px", fontSize: 22 }}>🔗 Network View</h1>
      <div style={{ color: "#4A5578", fontSize: 13, marginBottom: 20 }}>
        Full network topology available at <a href="/network" style={{ color: "#00D4FF" }}>/network</a> — opens in full page mode.
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
        {[
          ["Active Nodes",    "24",      "#00D4FF"],
          ["Compromised",     "2",       "#FF3B3B"],
          ["Live Connections","147",     "#00C851"],
          ["Threat Sources",  "8",       "#FF8C00"],
          ["Port Scans/hr",   "1,240",   "#FFD700"],
          ["Traffic",         "2.4 Gbps","#9B59B6"],
        ].map(([label, val, col]) => (
          <div key={label} style={{ background: "#0D1424", border: `1px solid #1A2540`, borderTop: `3px solid ${col}`, borderRadius: 10, padding: "14px 18px" }}>
            <div style={{ color: "#4A5578", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>{label}</div>
            <div style={{ color: col, fontSize: 26, fontWeight: 800 }}>{val}</div>
          </div>
        ))}
      </div>
      <div style={{ marginTop: 20, background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20, textAlign: "center" }}>
        <div style={{ fontSize: 40, marginBottom: 12 }}>🔗</div>
        <div style={{ color: "#E2E8FF", fontSize: 14, marginBottom: 8 }}>Interactive Network Topology</div>
        <div style={{ color: "#4A5578", fontSize: 12, marginBottom: 16 }}>Full topology map with live connections, GeoIP threat map, and port scan analysis</div>
        <a href="/network">
          <button style={{ padding: "10px 28px", borderRadius: 8, background: "linear-gradient(135deg,#0050FF,#00D4FF)", border: "none", color: "#fff", fontWeight: 700, cursor: "pointer", fontSize: 13 }}>
            Open Network View →
          </button>
        </a>
      </div>
    </div>
  );
}
