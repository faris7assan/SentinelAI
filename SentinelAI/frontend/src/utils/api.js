/**
 * SentinelAI — Frontend API Client
 * Typed async functions for every backend service
 */

const BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── Auth helper ─────────────────────────────────────────────
function getToken() {
  if (typeof window === "undefined") return "";
  return localStorage.getItem("sentinelai_token") || "";
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...options.headers,
  };
  const res = await fetch(`${BASE}${path}`, { ...options, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || `HTTP ${res.status}`);
  }
  return res.json();
}

// ─── Auth API ─────────────────────────────────────────────────
export const AuthAPI = {
  login: (username, password, mfa_token) =>
    apiFetch("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, mfa_token }),
    }),

  logout: () => apiFetch("/auth/logout", { method: "POST" }),

  me: () => apiFetch("/auth/me"),

  refreshToken: (refresh_token) =>
    apiFetch("/auth/refresh", {
      method: "POST",
      body: JSON.stringify({ refresh_token }),
    }),

  setupMFA: () => apiFetch("/auth/mfa/setup", { method: "POST" }),

  enableMFA: (token) =>
    apiFetch(`/auth/mfa/enable?token=${token}`, { method: "POST" }),

  listUsers: () => apiFetch("/auth/users"),
};

// ─── Logs API ─────────────────────────────────────────────────
export const LogsAPI = {
  ingest: (event) =>
    apiFetch("/logs/ingest", { method: "POST", body: JSON.stringify(event) }),

  bulkIngest: (events) =>
    apiFetch("/logs/bulk", { method: "POST", body: JSON.stringify({ events }) }),

  search: (query, size = 100, from_ = 0, time_from, time_to) =>
    apiFetch("/logs/search", {
      method: "POST",
      body: JSON.stringify({ query, size, from: from_, time_from, time_to }),
    }),

  stats: () => apiFetch("/logs/stats"),

  recent: (size = 50, severity) =>
    apiFetch(`/logs/recent?size=${size}${severity ? `&severity=${severity}` : ""}`),
};

// ─── Alerts API ───────────────────────────────────────────────
export const AlertsAPI = {
  recent: (size = 50, severity) =>
    apiFetch(`/alerts/recent?size=${size}${severity ? `&severity=${severity}` : ""}`),

  stats: () => apiFetch("/alerts/stats"),

  timeline: (limit = 100, offset = 0) =>
    apiFetch(`/alerts/timeline?limit=${limit}&offset=${offset}`),

  countBySeverity: () => apiFetch("/alerts/count-by-severity"),

  acknowledge: (alertId, analyst) =>
    apiFetch(`/alerts/${alertId}/acknowledge?analyst=${encodeURIComponent(analyst)}`),

  detect: (logEvent) =>
    apiFetch("/detect", { method: "POST", body: JSON.stringify({ log_event: logEvent }) }),

  rules: () => apiFetch("/rules"),

  correlationChains: () => apiFetch("/correlation/chains"),
};

// ─── AI API ───────────────────────────────────────────────────
export const AIAPI = {
  analyzeAlert: (alert) =>
    apiFetch("/ai/analyze-alert", { method: "POST", body: JSON.stringify({ alert }) }),

  detectAnomaly: (features, source_ip) =>
    apiFetch("/ai/anomaly-detect", {
      method: "POST",
      body: JSON.stringify({ features, source_ip }),
    }),

  classifyAttack: (features, source_ip, raw_log) =>
    apiFetch("/ai/classify-attack", {
      method: "POST",
      body: JSON.stringify({ features, source_ip, raw_log }),
    }),

  threatHunt: (query, time_range_hours = 24) =>
    apiFetch("/ai/threat-hunt", {
      method: "POST",
      body: JSON.stringify({ query, time_range_hours }),
    }),

  generateReport: (incident_ids, report_type = "executive") =>
    apiFetch("/ai/generate-report", {
      method: "POST",
      body: JSON.stringify({ incident_ids, report_type }),
    }),

  predictThreat: (ip, recent_events) =>
    apiFetch("/ai/predict-threat", {
      method: "POST",
      body: JSON.stringify({ ip, recent_events }),
    }),

  stats: () => apiFetch("/ai/stats"),
};

// ─── SOAR API ─────────────────────────────────────────────────
export const SOARAPI = {
  executePlaybook: (playbookName, alert) =>
    apiFetch(`/soar/execute/${playbookName}`, {
      method: "POST",
      body: JSON.stringify(alert),
    }),

  getExecutions: (limit = 50) => apiFetch(`/soar/executions?limit=${limit}`),

  getTickets: () => apiFetch("/soar/tickets"),

  updateTicketStatus: (ticketId, status) =>
    apiFetch(`/soar/tickets/${ticketId}/status?status=${status}`, { method: "PUT" }),

  listPlaybooks: () => apiFetch("/soar/playbooks"),
};

// ─── Threat Intel API ─────────────────────────────────────────
export const ThreatIntelAPI = {
  lookupIP: (ip) => apiFetch(`/intel/ip/${ip}`),

  lookupHash: (hash) => apiFetch(`/intel/hash/${hash}`),

  lookupDomain: (domain) => apiFetch(`/intel/domain/${domain}`),

  bulkLookup: (iocs) =>
    apiFetch("/intel/bulk", { method: "POST", body: JSON.stringify({ iocs }) }),

  maliciousIPs: () => apiFetch("/intel/feed/malicious-ips"),

  lookupCVE: (cveId) => apiFetch(`/intel/cve/${cveId}`),
};

// ─── Reports API ─────────────────────────────────────────────
export const ReportsAPI = {
  generateJSON: (options) =>
    apiFetch("/reports/json", { method: "POST", body: JSON.stringify(options) }),

  generatePDF: async (options) => {
    const token = getToken();
    const res = await fetch(`${BASE}/reports/pdf`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(options),
    });
    if (!res.ok) throw new Error("PDF generation failed");
    const blob = await res.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href     = url;
    a.download = `SentinelAI_Report_${new Date().toISOString().slice(0,10)}.pdf`;
    a.click();
    URL.revokeObjectURL(url);
  },

  stats: (hours = 24) => apiFetch(`/reports/stats?hours=${hours}`),
};

// ─── VPN Monitor API ─────────────────────────────────────────
export const VPNAPI = {
  reportSession: (session) =>
    apiFetch("/vpn/session", { method: "POST", body: JSON.stringify(session) }),

  getSessions: (limit = 100) => apiFetch(`/vpn/sessions?limit=${limit}`),

  getActiveUsers: () => apiFetch("/vpn/active"),

  stats: () => apiFetch("/vpn/stats"),
};

// ─── Cloud Security API ──────────────────────────────────────
export const CloudAPI = {
  scan: (provider, account_id, region) =>
    apiFetch("/cloud/scan", {
      method: "POST",
      body: JSON.stringify({ provider, account_id, region }),
    }),

  ingestEvent: (event) =>
    apiFetch("/cloud/event", { method: "POST", body: JSON.stringify(event) }),

  suspiciousActions: () => apiFetch("/cloud/events/suspicious"),

  scanHistory: () => apiFetch("/cloud/scan/history"),
};

// ─── Multi-Agent API ─────────────────────────────────────────
export const AgentsAPI = {
  orchestrate: (alert, agents, async_mode = true) =>
    apiFetch("/api/orchestrate", {
      method: "POST",
      body: JSON.stringify({ alert, agents, async_mode }),
    }),

  getResult: (sessionId) => apiFetch(`/api/orchestrate/result/${sessionId}`),

  status: () => apiFetch("/api/agents/status"),

  runAgent: (agentName, task_type, payload) =>
    apiFetch(`/api/agents/${agentName}/run`, {
      method: "POST",
      body: JSON.stringify({ agent: agentName, task_type, payload }),
    }),

  hunt: (hypothesis, time_range_h = 24) =>
    apiFetch("/api/agents/hunt", {
      method: "POST",
      body: JSON.stringify({ hypothesis, time_range_h }),
    }),
};

// ─── WebSocket factory ───────────────────────────────────────
export function createAlertWebSocket(onAlert, onPing) {
  const WS = (process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000").replace("http","ws");
  const ws = new WebSocket(`${WS}/ws/alerts`);

  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      if (msg.type === "alert" || msg.type === "history") {
        onAlert && onAlert(msg.data);
      } else if (msg.type === "ping") {
        onPing && onPing(msg.ts);
      }
    } catch {}
  };

  ws.onerror = (e) => console.warn("WS error:", e);
  ws.onclose = ()  => console.log("WS closed");
  return ws;
}

export function createAgentWebSocket(onUpdate) {
  const WS = (process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000").replace("http","ws");
  const ws = new WebSocket(`${WS}/ws/agents`);
  ws.onmessage = (e) => {
    try {
      const msg = JSON.parse(e.data);
      onUpdate && onUpdate(msg);
    } catch {}
  };
  return ws;
}
