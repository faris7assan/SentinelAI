/**
 * SentinelAI — Network View Page
 * Interactive network topology, live connections, port scan detection,
 * lateral movement visualization, and GeoIP threat map
 * Spec §19: "Network View" page — now complete.
 */
import { useState, useEffect, useRef } from "react";

const SEV_COLOR = { critical: "#FF3B3B", high: "#FF8C00", medium: "#FFD700", low: "#00C851", info: "#00D4FF" };

// ─── Mock network topology data ──────────────────────────────
const MOCK_NODES = [
  { id: "fw-01",      label: "Firewall",       type: "firewall",   x: 400, y: 60,  ip: "10.0.0.1",   status: "healthy",  connections: 24 },
  { id: "sw-core",    label: "Core Switch",    type: "switch",     x: 400, y: 180, ip: "10.0.0.2",   status: "healthy",  connections: 87 },
  { id: "srv-web",    label: "Web Server",     type: "server",     x: 160, y: 300, ip: "10.0.1.10",  status: "alert",    connections: 12 },
  { id: "srv-db",     label: "DB Server",      type: "database",   x: 400, y: 300, ip: "10.0.1.20",  status: "healthy",  connections: 5  },
  { id: "srv-app",    label: "App Server",     type: "server",     x: 640, y: 300, ip: "10.0.1.30",  status: "healthy",  connections: 18 },
  { id: "ws-01",      label: "Workstation-01", type: "workstation",x: 80,  y: 440, ip: "10.0.2.10",  status: "critical", connections: 3  },
  { id: "ws-02",      label: "Workstation-02", type: "workstation",x: 240, y: 440, ip: "10.0.2.11",  status: "healthy",  connections: 2  },
  { id: "srv-vpn",    label: "VPN Gateway",    type: "vpn",        x: 560, y: 440, ip: "10.0.3.1",   status: "healthy",  connections: 7  },
  { id: "srv-siem",   label: "SentinelAI",     type: "siem",       x: 720, y: 440, ip: "10.0.4.1",   status: "healthy",  connections: 99 },
  { id: "attacker",   label: "Threat Actor",   type: "threat",     x: 80,  y: 560, ip: "185.220.101.45", status: "critical", connections: 0 },
];

const MOCK_EDGES = [
  { from: "fw-01",   to: "sw-core",  traffic: "high",   label: "1.2 Gbps" },
  { from: "sw-core", to: "srv-web",  traffic: "medium", label: "450 Mbps" },
  { from: "sw-core", to: "srv-db",   traffic: "low",    label: "120 Mbps" },
  { from: "sw-core", to: "srv-app",  traffic: "medium", label: "380 Mbps" },
  { from: "sw-core", to: "ws-01",    traffic: "alert",  label: "⚠ Suspicious" },
  { from: "sw-core", to: "ws-02",    traffic: "low",    label: "45 Mbps"  },
  { from: "sw-core", to: "srv-vpn",  traffic: "low",    label: "200 Mbps" },
  { from: "sw-core", to: "srv-siem", traffic: "medium", label: "Event feed" },
  { from: "srv-web", to: "srv-db",   traffic: "medium", label: "DB queries" },
  { from: "attacker",to: "srv-web",  traffic: "critical",label:"🚨 Attack!" },
  { from: "ws-01",   to: "srv-db",   traffic: "alert",  label: "⚠ Lateral?" },
];

const MOCK_CONNECTIONS = [
  { src_ip: "185.220.101.45", dst_ip: "10.0.1.10", port: 80,   proto: "TCP", bytes: 52400, alert: true,  type: "Web Scan" },
  { src_ip: "10.0.2.10",      dst_ip: "10.0.1.20", port: 5432, proto: "TCP", bytes: 1800,  alert: true,  type: "Lateral Move" },
  { src_ip: "10.0.1.30",      dst_ip: "10.0.1.20", port: 5432, proto: "TCP", bytes: 340,   alert: false, type: "App→DB" },
  { src_ip: "10.0.2.11",      dst_ip: "8.8.8.8",   port: 53,   proto: "UDP", bytes: 120,   alert: false, type: "DNS" },
  { src_ip: "10.0.3.1",       dst_ip: "203.0.113.5",port:443,  proto: "TLS", bytes: 8400,  alert: false, type: "VPN Tunnel" },
  { src_ip: "185.220.101.45", dst_ip: "10.0.1.10", port: 22,   proto: "TCP", bytes: 680,   alert: true,  type: "SSH BruteForce" },
];

const GEO_THREATS = [
  { country: "Germany",       count: 8,  lat: 51.2, lon: 10.5, severity: "critical" },
  { country: "Russia",        count: 5,  lat: 61.5, lon: 90.0, severity: "high"     },
  { country: "China",         count: 12, lat: 35.8, lon: 104.2, severity: "critical" },
  { country: "United States", count: 3,  lat: 37.1, lon: -95.7, severity: "medium"  },
  { country: "Netherlands",   count: 4,  lat: 52.1, lon: 5.3,  severity: "high"    },
  { country: "Brazil",        count: 2,  lat: -14.2, lon: -51.9, severity: "low"   },
  { country: "South Korea",   count: 6,  lat: 36.5, lon: 127.8, severity: "high"   },
  { country: "Iran",          count: 3,  lat: 32.4, lon: 53.7,  severity: "high"   },
];

// ─── Sub-components ──────────────────────────────────────────
function NodeIcon({ type, status }) {
  const icons = {
    firewall:   "🛡️", switch: "🔀", server: "🖥️", database: "🗄️",
    workstation:"💻", vpn:    "🔒", siem:   "👁️", threat:   "💀",
  };
  const col = status === "critical" ? "#FF3B3B" : status === "alert" ? "#FF8C00" : status === "healthy" ? "#00C851" : "#6B7DB3";
  return (
    <div style={{
      width: 44, height: 44, borderRadius: "50%",
      background: `${col}22`, border: `2px solid ${col}`,
      display: "flex", alignItems: "center", justifyContent: "center",
      fontSize: 18, boxShadow: status === "critical" ? `0 0 12px ${col}88` : "none",
      animation: status === "critical" ? "pulse 1.5s infinite" : "none",
    }}>
      {icons[type] || "⬡"}
    </div>
  );
}

function NetworkCanvas({ nodes, edges, selectedNode, onSelect }) {
  return (
    <svg width="800" height="620" style={{ background: "#070B14", borderRadius: 12 }}>
      <defs>
        <marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#1E2C4A"/>
        </marker>
        <marker id="arrow-alert" markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto">
          <path d="M0,0 L0,6 L8,3 z" fill="#FF3B3B"/>
        </marker>
      </defs>

      {/* Grid lines */}
      {Array.from({length: 16}, (_, i) => (
        <line key={`h${i}`} x1="0" y1={i*40} x2="800" y2={i*40} stroke="#0D1424" strokeWidth="1"/>
      ))}
      {Array.from({length: 21}, (_, i) => (
        <line key={`v${i}`} x1={i*40} y1="0" x2={i*40} y2="620" stroke="#0D1424" strokeWidth="1"/>
      ))}

      {/* Edges */}
      {edges.map((e, i) => {
        const from = nodes.find(n => n.id === e.from);
        const to   = nodes.find(n => n.id === e.to);
        if (!from || !to) return null;
        const isAlert    = e.traffic === "alert" || e.traffic === "critical";
        const strokeCol  = e.traffic === "critical" ? "#FF3B3B" : e.traffic === "alert" ? "#FF8C00" : e.traffic === "high" ? "#00D4FF44" : "#1E2C4A";
        const strokeW    = isAlert ? 3 : 2;
        const mx = (from.x + to.x) / 2;
        const my = (from.y + to.y) / 2;
        return (
          <g key={i}>
            <line
              x1={from.x} y1={from.y} x2={to.x} y2={to.y}
              stroke={strokeCol} strokeWidth={strokeW}
              strokeDasharray={isAlert ? "6,3" : "none"}
              markerEnd={isAlert ? "url(#arrow-alert)" : "url(#arrow)"}
              style={{ animation: isAlert ? "pulse 1s infinite" : "none" }}
            />
            <text x={mx} y={my - 6} fill={isAlert ? "#FF8C00" : "#2A3555"} fontSize="9" textAnchor="middle">
              {e.label}
            </text>
          </g>
        );
      })}

      {/* Nodes */}
      {nodes.map(node => {
        const isSelected = selectedNode?.id === node.id;
        const col = node.status === "critical" ? "#FF3B3B" : node.status === "alert" ? "#FF8C00" : node.status === "healthy" ? "#00C851" : "#6B7DB3";
        const icons = { firewall:"🛡️", switch:"🔀", server:"🖥️", database:"🗄️", workstation:"💻", vpn:"🔒", siem:"👁️", threat:"💀" };
        return (
          <g key={node.id} transform={`translate(${node.x},${node.y})`}
             style={{ cursor: "pointer" }} onClick={() => onSelect(node)}>
            {/* Selection ring */}
            {isSelected && <circle r={28} fill="none" stroke="#00D4FF" strokeWidth={2} strokeDasharray="4,2" opacity={0.8}/>}
            {/* Node circle */}
            <circle r={22}
              fill={`${col}22`}
              stroke={isSelected ? "#00D4FF" : col}
              strokeWidth={isSelected ? 3 : 2}
              style={{ filter: node.status === "critical" ? `drop-shadow(0 0 8px ${col})` : "none" }}
            />
            {/* Icon */}
            <text textAnchor="middle" dominantBaseline="central" fontSize={16}>{icons[node.type] || "⬡"}</text>
            {/* Alert dot */}
            {(node.status === "critical" || node.status === "alert") && (
              <circle cx={16} cy={-16} r={6} fill={col}/>
            )}
            {/* Label */}
            <text y={32} textAnchor="middle" fill="#6B7DB3" fontSize={10}>{node.label}</text>
            <text y={44} textAnchor="middle" fill="#2A3555" fontSize={9} fontFamily="monospace">{node.ip}</text>
          </g>
        );
      })}
    </svg>
  );
}

// ─── Main Network View Page ───────────────────────────────────
export default function NetworkViewPage() {
  const [selectedNode, setSelectedNode]   = useState(null);
  const [activeTab, setActiveTab]         = useState("topology");
  const [liveConnections, setLiveConns]   = useState(MOCK_CONNECTIONS);
  const [pulseConn, setPulseConn]         = useState(null);

  // Simulate new live connections appearing
  useEffect(() => {
    const interval = setInterval(() => {
      const newConn = {
        src_ip: `${10 + Math.floor(Math.random()*5)}.0.${Math.floor(Math.random()*4)}.${Math.floor(Math.random()*254)+1}`,
        dst_ip: `10.0.1.${Math.floor(Math.random()*30)+1}`,
        port:   [22, 80, 443, 3306, 5432, 8080][Math.floor(Math.random()*6)],
        proto:  ["TCP","UDP","TLS"][Math.floor(Math.random()*3)],
        bytes:  Math.floor(Math.random()*10000),
        alert:  Math.random() > 0.7,
        type:   ["HTTP","SSH","DB Query","DNS","HTTPS"][Math.floor(Math.random()*5)],
      };
      setLiveConns(prev => [newConn, ...prev].slice(0,20));
      if (newConn.alert) setPulseConn(newConn);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const alertNodes  = MOCK_NODES.filter(n => n.status === "critical" || n.status === "alert");
  const totalTraffic = "2.4 Gbps";

  return (
    <div style={{ padding: 24, color: "#E2E8FF" }}>
      {/* Header */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700 }}>🔗 Network View</h1>
          <div style={{ color: "#4A5578", fontSize: 12, marginTop: 4 }}>
            Live network topology · {MOCK_NODES.length} nodes · {MOCK_EDGES.length} links
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <div style={{ width: 8, height: 8, borderRadius: "50%", background: "#00C851", animation: "pulse 2s infinite" }}/>
            <span style={{ color: "#00C851", fontSize: 12 }}>LIVE</span>
          </div>
          {alertNodes.length > 0 && (
            <div style={{ background: "#FF3B3B22", border: "1px solid #FF3B3B44", borderRadius: 6, padding: "4px 12px", color: "#FF3B3B", fontSize: 12 }}>
              🚨 {alertNodes.length} nodes compromised
            </div>
          )}
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(5,1fr)", gap: 12, marginBottom: 20 }}>
        {[
          ["Total Nodes",     MOCK_NODES.length,                             "#00D4FF"],
          ["Compromised",     alertNodes.length,                             "#FF3B3B"],
          ["Active Conns",    liveConnections.length,                        "#00C851"],
          ["Threat Sources",  GEO_THREATS.length,                            "#FF8C00"],
          ["Total Traffic",   totalTraffic,                                  "#9B59B6"],
        ].map(([label, val, col]) => (
          <div key={label} style={{ background: "#0D1424", border: `1px solid #1A2540`, borderTop: `3px solid ${col}`, borderRadius: 10, padding: "12px 16px" }}>
            <div style={{ color: "#4A5578", fontSize: 10, textTransform: "uppercase", letterSpacing: 0.5, marginBottom: 4 }}>{label}</div>
            <div style={{ color: col, fontSize: 24, fontWeight: 800 }}>{val}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{ display: "flex", gap: 4, marginBottom: 16 }}>
        {["topology","connections","geo-map","port-scan"].map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: "7px 16px", borderRadius: 7, border: "1px solid",
            borderColor: activeTab === t ? "#00D4FF" : "#1A2540",
            background:  activeTab === t ? "#00D4FF22" : "transparent",
            color:       activeTab === t ? "#00D4FF" : "#6B7DB3",
            cursor: "pointer", fontSize: 12, fontWeight: activeTab === t ? 600 : 400,
            textTransform: "capitalize",
          }}>{t.replace("-"," ")}</button>
        ))}
      </div>

      {/* ── TOPOLOGY TAB ── */}
      {activeTab === "topology" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 280px", gap: 16 }}>
          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A2540", display: "flex", justifyContent: "space-between" }}>
              <span style={{ color: "#E2E8FF", fontSize: 13, fontWeight: 600 }}>Network Topology Map</span>
              <span style={{ color: "#4A5578", fontSize: 11 }}>Click a node to inspect · Dashed = active threat path</span>
            </div>
            <NetworkCanvas nodes={MOCK_NODES} edges={MOCK_EDGES} selectedNode={selectedNode} onSelect={setSelectedNode}/>
          </div>

          {/* Node detail panel */}
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            {selectedNode ? (
              <div style={{ background: "#0D1424", border: `2px solid ${selectedNode.status === "critical" ? "#FF3B3B" : "#1A2540"}`, borderRadius: 12, padding: 16 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
                  <NodeIcon type={selectedNode.type} status={selectedNode.status}/>
                  <div>
                    <div style={{ color: "#E2E8FF", fontWeight: 700, fontSize: 14 }}>{selectedNode.label}</div>
                    <div style={{ color: "#00D4FF", fontFamily: "monospace", fontSize: 12 }}>{selectedNode.ip}</div>
                  </div>
                </div>
                {[
                  ["Type",        selectedNode.type],
                  ["Status",      selectedNode.status.toUpperCase()],
                  ["Connections", selectedNode.connections],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: "flex", justifyContent: "space-between", padding: "6px 0", borderBottom: "1px solid #131929" }}>
                    <span style={{ color: "#4A5578", fontSize: 12 }}>{k}</span>
                    <span style={{ color: "#E2E8FF", fontSize: 12, fontWeight: 500 }}>{v}</span>
                  </div>
                ))}
                <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
                  {["Investigate","Block","Isolate"].map(a => (
                    <button key={a} style={{
                      padding: "5px 10px", borderRadius: 5, fontSize: 11, cursor: "pointer",
                      background: a === "Block" || a === "Isolate" ? "#FF3B3B22" : "#00D4FF22",
                      border: `1px solid ${a === "Block" || a === "Isolate" ? "#FF3B3B44" : "#00D4FF44"}`,
                      color: a === "Block" || a === "Isolate" ? "#FF3B3B" : "#00D4FF",
                    }}>{a}</button>
                  ))}
                </div>
              </div>
            ) : (
              <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 16, color: "#4A5578", fontSize: 12, textAlign: "center" }}>
                Click a node to view details
              </div>
            )}

            {/* Legend */}
            <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 14 }}>
              <div style={{ color: "#E2E8FF", fontSize: 12, fontWeight: 600, marginBottom: 10 }}>Legend</div>
              {[["🟢 Healthy","Normal operation"],["🟠 Alert","Suspicious activity"],["🔴 Critical","Active compromise"],["💀 Threat Actor","External attacker"]].map(([c,d]) => (
                <div key={c} style={{ display: "flex", gap: 8, marginBottom: 6, alignItems: "center" }}>
                  <span style={{ fontSize: 11 }}>{c}</span>
                  <span style={{ color: "#4A5578", fontSize: 10 }}>{d}</span>
                </div>
              ))}
              <div style={{ marginTop: 8, borderTop: "1px solid #131929", paddingTop: 8, color: "#4A5578", fontSize: 10 }}>
                Dashed red line = active attack path<br/>
                Pulsing node = immediate action needed
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── LIVE CONNECTIONS TAB ── */}
      {activeTab === "connections" && (
        <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
          <div style={{ padding: "12px 20px", borderBottom: "1px solid #1A2540", display: "flex", justifyContent: "space-between" }}>
            <span style={{ color: "#E2E8FF", fontSize: 13, fontWeight: 600 }}>Live Network Connections</span>
            <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
              <div style={{ width: 7, height: 7, borderRadius: "50%", background: "#00C851", animation: "pulse 1s infinite" }}/>
              <span style={{ color: "#00C851", fontSize: 11 }}>Updating every 3s</span>
            </div>
          </div>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
            <thead>
              <tr style={{ background: "#0A0E1A" }}>
                {["","Source IP","Destination IP","Port","Protocol","Bytes","Type"].map(h => (
                  <th key={h} style={{ padding: "10px 14px", color: "#4A5578", fontWeight: 600, textAlign: "left", fontSize: 11, textTransform: "uppercase" }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {liveConnections.map((c, i) => (
                <tr key={i} style={{ borderBottom: "1px solid #131929", background: c.alert ? "rgba(255,59,59,0.04)" : "transparent" }}>
                  <td style={{ padding: "10px 14px" }}>
                    {c.alert && <span style={{ background: "#FF3B3B22", color: "#FF3B3B", padding: "2px 6px", borderRadius: 3, fontSize: 10, border: "1px solid #FF3B3B44" }}>⚠</span>}
                  </td>
                  <td style={{ padding: "10px 14px", color: c.alert ? "#FF8C00" : "#E2E8FF", fontFamily: "monospace" }}>{c.src_ip}</td>
                  <td style={{ padding: "10px 14px", color: "#E2E8FF", fontFamily: "monospace" }}>{c.dst_ip}</td>
                  <td style={{ padding: "10px 14px", color: "#FFD700", fontFamily: "monospace" }}>{c.port}</td>
                  <td style={{ padding: "10px 14px", color: "#6B7DB3" }}>{c.proto}</td>
                  <td style={{ padding: "10px 14px", color: "#4A5578" }}>{c.bytes.toLocaleString()} B</td>
                  <td style={{ padding: "10px 14px", color: c.alert ? "#FF3B3B" : "#6B7DB3" }}>{c.type}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── GEO MAP TAB ── */}
      {activeTab === "geo-map" && (
        <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 16 }}>
          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "12px 20px", borderBottom: "1px solid #1A2540" }}>
              <span style={{ color: "#E2E8FF", fontSize: 13, fontWeight: 600 }}>Global Threat Origins</span>
            </div>
            {/* SVG world map (simplified) */}
            <div style={{ padding: 20, position: "relative" }}>
              <svg viewBox="0 0 800 400" style={{ width: "100%", background: "#070B14", borderRadius: 8 }}>
                {/* Simplified world outline */}
                <rect x="0" y="0" width="800" height="400" fill="#0A0E1A"/>
                {/* Grid */}
                {Array.from({length:9},(_,i)=>( <line key={i} x1={i*100} y1="0" x2={i*100} y2="400" stroke="#0D1424" strokeWidth="1"/> ))}
                {Array.from({length:5},(_,i)=>( <line key={i} x1="0" y1={i*100} x2="800" y2={i*100} stroke="#0D1424" strokeWidth="1"/> ))}
                {/* Equator */}
                <line x1="0" y1="200" x2="800" y2="200" stroke="#1E2C4A" strokeWidth="1" strokeDasharray="4,4"/>
                <text x="10" y="196" fill="#2A3555" fontSize="9">Equator</text>
                {/* Threat bubbles */}
                {GEO_THREATS.map((t, i) => {
                  const x = ((t.lon + 180) / 360) * 800;
                  const y = ((90 - t.lat) / 180) * 400;
                  const col = SEV_COLOR[t.severity];
                  const r   = Math.sqrt(t.count) * 5 + 8;
                  return (
                    <g key={i}>
                      <circle cx={x} cy={y} r={r} fill={`${col}33`} stroke={col} strokeWidth={2}>
                        <animate attributeName="r" values={`${r};${r+4};${r}`} dur="2s" repeatCount="indefinite"/>
                      </circle>
                      <text x={x} y={y+4} textAnchor="middle" fill={col} fontSize={9} fontWeight="bold">{t.count}</text>
                      <text x={x} y={y-r-5} textAnchor="middle" fill="#6B7DB3" fontSize={8}>{t.country}</text>
                    </g>
                  );
                })}
                {/* Target - Egypt */}
                <circle cx={545} cy={175} r={8} fill="#00D4FF33" stroke="#00D4FF" strokeWidth={2}/>
                <text x={545} y={179} textAnchor="middle" fill="#00D4FF" fontSize={7}>🏠</text>
                <text x={545} y={165} textAnchor="middle" fill="#00D4FF" fontSize={8}>Your Network</text>
                {/* Attack lines */}
                {GEO_THREATS.filter(t => t.severity === "critical").map((t, i) => {
                  const x = ((t.lon + 180) / 360) * 800;
                  const y = ((90 - t.lat) / 180) * 400;
                  return <line key={i} x1={x} y1={y} x2={545} y2={175} stroke="#FF3B3B" strokeWidth={1} strokeDasharray="4,4" opacity={0.5}/>;
                })}
              </svg>
              <div style={{ marginTop: 8, color: "#4A5578", fontSize: 11 }}>
                Bubble size = attack volume · Lines = active attack paths toward your network
              </div>
            </div>
          </div>

          {/* Threat country table */}
          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, overflow: "hidden" }}>
            <div style={{ padding: "12px 16px", borderBottom: "1px solid #1A2540" }}>
              <span style={{ color: "#E2E8FF", fontSize: 13, fontWeight: 600 }}>Top Threat Countries</span>
            </div>
            {GEO_THREATS.sort((a,b) => b.count - a.count).map((t, i) => (
              <div key={t.country} style={{ padding: "12px 16px", borderBottom: "1px solid #131929", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <span style={{ color: "#4A5578", fontSize: 12, width: 16 }}>#{i+1}</span>
                  <span style={{ color: "#E2E8FF", fontSize: 13 }}>{t.country}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                  <div style={{ width: 60, height: 6, background: "#1A2035", borderRadius: 3, overflow: "hidden" }}>
                    <div style={{ width: `${(t.count / 12) * 100}%`, height: "100%", background: SEV_COLOR[t.severity], borderRadius: 3 }}/>
                  </div>
                  <span style={{ color: SEV_COLOR[t.severity], fontSize: 12, fontWeight: 700, width: 20, textAlign: "right" }}>{t.count}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── PORT SCAN TAB ── */}
      {activeTab === "port-scan" && (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
            <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Port Scan Activity (Last 24h)</h3>
            {[
              { port: 22,   service: "SSH",          scans: 1240, severity: "critical" },
              { port: 3389, service: "RDP",           scans: 820,  severity: "critical" },
              { port: 80,   service: "HTTP",          scans: 650,  severity: "high"     },
              { port: 443,  service: "HTTPS",         scans: 480,  severity: "medium"   },
              { port: 3306, service: "MySQL",         scans: 340,  severity: "high"     },
              { port: 5432, service: "PostgreSQL",    scans: 290,  severity: "high"     },
              { port: 1433, service: "MSSQL",         scans: 210,  severity: "high"     },
              { port: 6379, service: "Redis",         scans: 180,  severity: "medium"   },
              { port: 27017,service: "MongoDB",       scans: 160,  severity: "medium"   },
              { port: 9200, service: "Elasticsearch", scans: 140,  severity: "medium"   },
            ].map(row => (
              <div key={row.port} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 0", borderBottom: "1px solid #131929" }}>
                <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
                  <span style={{ background: "#1A2035", color: "#FFD700", padding: "2px 8px", borderRadius: 4, fontSize: 11, fontFamily: "monospace", width: 48, textAlign: "center" }}>{row.port}</span>
                  <span style={{ color: "#E2E8FF", fontSize: 12 }}>{row.service}</span>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                  <div style={{ width: 80, height: 5, background: "#1A2035", borderRadius: 3 }}>
                    <div style={{ width: `${(row.scans / 1240) * 100}%`, height: "100%", background: SEV_COLOR[row.severity], borderRadius: 3 }}/>
                  </div>
                  <span style={{ color: SEV_COLOR[row.severity], fontSize: 12, fontWeight: 700, width: 40, textAlign: "right" }}>{row.scans}</span>
                </div>
              </div>
            ))}
          </div>

          <div style={{ background: "#0D1424", border: "1px solid #1A2540", borderRadius: 12, padding: 20 }}>
            <h3 style={{ color: "#E2E8FF", margin: "0 0 16px", fontSize: 14 }}>Top Scanning IPs</h3>
            {[
              { ip: "185.220.101.45", scans: 840, country: "DE 🇩🇪", verdict: "MALICIOUS" },
              { ip: "45.33.32.156",   scans: 620, country: "US 🇺🇸", verdict: "SUSPICIOUS" },
              { ip: "194.165.16.92",  scans: 580, country: "RU 🇷🇺", verdict: "MALICIOUS"  },
              { ip: "198.98.49.112",  scans: 410, country: "US 🇺🇸", verdict: "SUSPICIOUS" },
              { ip: "80.82.77.33",    scans: 380, country: "NL 🇳🇱", verdict: "MALICIOUS"  },
              { ip: "89.248.172.16",  scans: 350, country: "NL 🇳🇱", verdict: "MALICIOUS"  },
              { ip: "51.68.36.142",   scans: 290, country: "FR 🇫🇷", verdict: "SUSPICIOUS" },
            ].map(row => (
              <div key={row.ip} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: "1px solid #131929" }}>
                <div>
                  <div style={{ color: "#00D4FF", fontFamily: "monospace", fontSize: 12 }}>{row.ip}</div>
                  <div style={{ color: "#4A5578", fontSize: 11 }}>{row.country} · {row.scans} scans</div>
                </div>
                <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <span style={{
                    background: row.verdict === "MALICIOUS" ? "#FF3B3B22" : "#FF8C0022",
                    color:      row.verdict === "MALICIOUS" ? "#FF3B3B"   : "#FF8C00",
                    border:     `1px solid ${row.verdict === "MALICIOUS" ? "#FF3B3B44" : "#FF8C0044"}`,
                    padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 700,
                  }}>{row.verdict}</span>
                  <button style={{ padding: "4px 10px", borderRadius: 5, background: "#FF3B3B22", border: "1px solid #FF3B3B44", color: "#FF3B3B", cursor: "pointer", fontSize: 11 }}>Block</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
