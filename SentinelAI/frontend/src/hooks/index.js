/**
 * SentinelAI — Custom React Hooks
 * useAlertWebSocket, useStats, useAgents, useThreatHunt, useSOAR
 */
import { useState, useEffect, useRef, useCallback } from "react";
import { AlertsAPI, ReportsAPI, AgentsAPI } from "../utils/api";

const WS_BASE = (process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000").replace(/^http/, "ws");
const API_BASE =  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// ─── useAlertWebSocket ────────────────────────────────────────
/**
 * Connects to the SentinelAI real-time alert WebSocket.
 * Returns: { alerts, connected, reconnecting, lastPing }
 */
export function useAlertWebSocket() {
  const [alerts, setAlerts]             = useState([]);
  const [connected, setConnected]       = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [lastPing, setLastPing]         = useState(null);
  const wsRef   = useRef(null);
  const retryRef = useRef(0);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    try {
      const ws = new WebSocket(`${WS_BASE}/ws/alerts`);
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        setReconnecting(false);
        retryRef.current = 0;
      };

      ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data);
          if (msg.type === "alert") {
            setAlerts(prev => [msg.data, ...prev].slice(0, 200));
          } else if (msg.type === "history") {
            setAlerts(prev => [...prev, msg.data].slice(0, 200));
          } else if (msg.type === "ping") {
            setLastPing(msg.ts);
          }
        } catch {}
      };

      ws.onclose = () => {
        setConnected(false);
        // Exponential backoff reconnect
        const delay = Math.min(1000 * Math.pow(2, retryRef.current), 30000);
        retryRef.current += 1;
        setReconnecting(true);
        setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    } catch {}
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, [connect]);

  return { alerts, connected, reconnecting, lastPing };
}

// ─── useMetricsSSE ────────────────────────────────────────────
/**
 * Connects to the Go metrics service Server-Sent Events stream.
 * Returns live platform counters, updated every 3 seconds.
 */
export function useMetricsSSE() {
  const [metrics, setMetrics] = useState({
    total_alerts: 0, critical: 0, high: 0,
    logs_ingested: 0, soar_executions: 0, attack_chains: 0,
  });
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const GO_URL = process.env.NEXT_PUBLIC_GO_METRICS_URL || "http://localhost:8015";
    let es;
    try {
      es = new EventSource(`${GO_URL}/metrics/stream`);
      es.onopen    = () => setConnected(true);
      es.onmessage = (e) => {
        try { setMetrics(JSON.parse(e.data)); } catch {}
      };
      es.onerror = () => {
        setConnected(false);
        es.close();
      };
    } catch {}
    return () => es?.close();
  }, []);

  return { metrics, connected };
}

// ─── useStats ────────────────────────────────────────────────
/**
 * Polls the report-service for platform stats every 30 seconds.
 */
export function useStats(hours = 24) {
  const [stats, setStats]     = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState(null);

  const fetch = useCallback(async () => {
    try {
      const data = await ReportsAPI.stats(hours);
      setStats(data);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [hours]);

  useEffect(() => {
    fetch();
    const interval = setInterval(fetch, 30_000);
    return () => clearInterval(interval);
  }, [fetch]);

  return { stats, loading, error, refetch: fetch };
}

// ─── useRecentAlerts ─────────────────────────────────────────
/**
 * Fetches recent alerts from the detection engine with polling.
 */
export function useRecentAlerts(size = 50, severity = null, pollMs = 10_000) {
  const [alerts, setAlerts]   = useState([]);
  const [loading, setLoading] = useState(true);

  const fetch = useCallback(async () => {
    try {
      const data = await AlertsAPI.recent(size, severity);
      setAlerts(Array.isArray(data) ? data : []);
    } catch {}
    setLoading(false);
  }, [size, severity]);

  useEffect(() => {
    fetch();
    const id = setInterval(fetch, pollMs);
    return () => clearInterval(id);
  }, [fetch, pollMs]);

  return { alerts, loading, refetch: fetch };
}

// ─── useAgentStatus ──────────────────────────────────────────
/**
 * Polls multi-agent orchestrator for agent status every 10s.
 */
export function useAgentStatus() {
  const [agents, setAgents]   = useState({});
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const data = await AgentsAPI.status();
        setAgents(data);
      } catch {}
      setLoading(false);
    };
    fetch();
    const id = setInterval(fetch, 10_000);
    return () => clearInterval(id);
  }, []);

  return { agents, loading };
}

// ─── useAlertTimeline ────────────────────────────────────────
/**
 * Builds a 24-hour timeline of alert counts bucketed by hour.
 */
export function useAlertTimeline(alerts = []) {
  return Array.from({ length: 24 }, (_, hour) => {
    const label   = `${String(hour).padStart(2, "0")}:00`;
    const inHour  = alerts.filter(a => {
      try {
        return new Date(a.timestamp).getHours() === hour;
      } catch { return false; }
    });
    return {
      hour:     label,
      critical: inHour.filter(a => a.severity === "critical").length,
      high:     inHour.filter(a => a.severity === "high").length,
      medium:   inHour.filter(a => a.severity === "medium").length,
      low:      inHour.filter(a => a.severity === "low").length,
      total:    inHour.length,
    };
  });
}

// ─── useSOARTickets ──────────────────────────────────────────
export function useSOARTickets(pollMs = 15_000) {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const resp = await window.fetch(`${API_BASE}/soar/tickets`, {
          headers: { Authorization: `Bearer ${localStorage.getItem("sentinelai_token") || ""}` }
        });
        if (resp.ok) setTickets(await resp.json());
      } catch {}
      setLoading(false);
    };
    fetch();
    const id = setInterval(fetch, pollMs);
    return () => clearInterval(id);
  }, [pollMs]);

  return { tickets, loading };
}

// ─── useDebounce ─────────────────────────────────────────────
export function useDebounce(value, delay = 300) {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(id);
  }, [value, delay]);
  return debounced;
}

// ─── useLocalStorage ─────────────────────────────────────────
export function useLocalStorage(key, initialValue) {
  const [value, setValue] = useState(() => {
    if (typeof window === "undefined") return initialValue;
    try {
      const item = localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch { return initialValue; }
  });

  const set = useCallback((val) => {
    setValue(val);
    if (typeof window !== "undefined") {
      localStorage.setItem(key, JSON.stringify(val));
    }
  }, [key]);

  return [value, set];
}
