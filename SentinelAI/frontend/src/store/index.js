/**
 * SentinelAI — Global State Store
 * Uses React Context + useReducer (no external deps needed)
 * Manages: alerts, auth, platform stats, agent status
 */
import { createContext, useContext, useReducer, useEffect, useCallback } from "react";

// ─── Initial State ────────────────────────────────────────────
const initialState = {
  // Auth
  user:           null,
  token:          typeof window !== "undefined" ? localStorage.getItem("sentinelai_token") : null,
  isAuthenticated:false,

  // Alerts
  alerts:         [],
  alertCount:     { critical: 0, high: 0, medium: 0, low: 0, total: 0 },
  liveAlerts:     [],
  wsConnected:    false,

  // Platform
  stats: {
    totalAlerts:    0,
    criticalAlerts: 0,
    highAlerts:     0,
    logsIngested:   0,
    soarExecutions: 0,
    attackChains:   0,
    vpnConnections: 0,
    honeypotHits:   0,
  },

  // Agents
  agentStatus:    {},

  // UI
  activePage:     "dashboard",
  sidebarCollapsed: false,
  theme:          "dark",
  notifications:  [],
};

// ─── Actions ──────────────────────────────────────────────────
export const ACTIONS = {
  // Auth
  SET_USER:          "SET_USER",
  SET_TOKEN:         "SET_TOKEN",
  LOGOUT:            "LOGOUT",
  // Alerts
  SET_ALERTS:        "SET_ALERTS",
  ADD_LIVE_ALERT:    "ADD_LIVE_ALERT",
  UPDATE_ALERT_COUNT:"UPDATE_ALERT_COUNT",
  SET_WS_CONNECTED:  "SET_WS_CONNECTED",
  // Platform
  UPDATE_STATS:      "UPDATE_STATS",
  SET_AGENT_STATUS:  "SET_AGENT_STATUS",
  // UI
  SET_PAGE:          "SET_PAGE",
  TOGGLE_SIDEBAR:    "TOGGLE_SIDEBAR",
  ADD_NOTIFICATION:  "ADD_NOTIFICATION",
  REMOVE_NOTIFICATION:"REMOVE_NOTIFICATION",
};

// ─── Reducer ──────────────────────────────────────────────────
function reducer(state, action) {
  switch (action.type) {
    case ACTIONS.SET_USER:
      return { ...state, user: action.payload, isAuthenticated: !!action.payload };

    case ACTIONS.SET_TOKEN:
      if (typeof window !== "undefined" && action.payload) {
        localStorage.setItem("sentinelai_token", action.payload);
      }
      return { ...state, token: action.payload };

    case ACTIONS.LOGOUT:
      if (typeof window !== "undefined") {
        localStorage.removeItem("sentinelai_token");
        localStorage.removeItem("sentinelai_refresh");
      }
      return { ...initialState, token: null, isAuthenticated: false, user: null };

    case ACTIONS.SET_ALERTS:
      return { ...state, alerts: action.payload };

    case ACTIONS.ADD_LIVE_ALERT: {
      const alert     = action.payload;
      const liveAlerts = [alert, ...state.liveAlerts].slice(0, 100);
      const sev        = alert.severity || "low";
      const count      = {
        ...state.alertCount,
        [sev]:  (state.alertCount[sev] || 0) + 1,
        total:  state.alertCount.total + 1,
      };
      return { ...state, liveAlerts, alertCount: count };
    }

    case ACTIONS.UPDATE_ALERT_COUNT:
      return { ...state, alertCount: { ...state.alertCount, ...action.payload } };

    case ACTIONS.SET_WS_CONNECTED:
      return { ...state, wsConnected: action.payload };

    case ACTIONS.UPDATE_STATS:
      return { ...state, stats: { ...state.stats, ...action.payload } };

    case ACTIONS.SET_AGENT_STATUS:
      return { ...state, agentStatus: action.payload };

    case ACTIONS.SET_PAGE:
      return { ...state, activePage: action.payload };

    case ACTIONS.TOGGLE_SIDEBAR:
      return { ...state, sidebarCollapsed: !state.sidebarCollapsed };

    case ACTIONS.ADD_NOTIFICATION: {
      const notif = { id: Date.now(), ...action.payload };
      return { ...state, notifications: [notif, ...state.notifications].slice(0, 10) };
    }

    case ACTIONS.REMOVE_NOTIFICATION:
      return { ...state, notifications: state.notifications.filter(n => n.id !== action.payload) };

    default:
      return state;
  }
}

// ─── Context ──────────────────────────────────────────────────
const StoreContext = createContext(null);

export function StoreProvider({ children }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Action creators
  const actions = {
    login:   (user, token, refresh) => {
      dispatch({ type: ACTIONS.SET_USER,  payload: user });
      dispatch({ type: ACTIONS.SET_TOKEN, payload: token });
      if (typeof window !== "undefined" && refresh) {
        localStorage.setItem("sentinelai_refresh", refresh);
      }
    },
    logout:  () => dispatch({ type: ACTIONS.LOGOUT }),
    setAlerts: (alerts) => dispatch({ type: ACTIONS.SET_ALERTS, payload: alerts }),
    addLiveAlert: (alert) => {
      dispatch({ type: ACTIONS.ADD_LIVE_ALERT, payload: alert });
      // Auto-notification for critical
      if (alert.severity === "critical") {
        dispatch({
          type: ACTIONS.ADD_NOTIFICATION,
          payload: {
            type:    "critical",
            title:   `🚨 ${alert.rule_name}`,
            message: `${alert.source_ip} → ${alert.hostname}`,
            alert,
          }
        });
      }
    },
    setWsConnected: (v) => dispatch({ type: ACTIONS.SET_WS_CONNECTED, payload: v }),
    updateStats:    (s) => dispatch({ type: ACTIONS.UPDATE_STATS,    payload: s }),
    setAgentStatus: (s) => dispatch({ type: ACTIONS.SET_AGENT_STATUS, payload: s }),
    setPage:        (p) => dispatch({ type: ACTIONS.SET_PAGE,         payload: p }),
    toggleSidebar:  ()  => dispatch({ type: ACTIONS.TOGGLE_SIDEBAR }),
    addNotification:(n) => dispatch({ type: ACTIONS.ADD_NOTIFICATION, payload: n }),
    removeNotification:(id) => dispatch({ type: ACTIONS.REMOVE_NOTIFICATION, payload: id }),
  };

  return (
    <StoreContext.Provider value={{ state, dispatch, actions }}>
      {children}
    </StoreContext.Provider>
  );
}

export function useStore() {
  const ctx = useContext(StoreContext);
  if (!ctx) throw new Error("useStore must be used inside <StoreProvider>");
  return ctx;
}

// ─── Typed selectors ──────────────────────────────────────────
export const useAlerts      = () => useStore().state.alerts;
export const useLiveAlerts  = () => useStore().state.liveAlerts;
export const useAlertCount  = () => useStore().state.alertCount;
export const useAuth        = () => ({ user: useStore().state.user, token: useStore().state.token, isAuthenticated: useStore().state.isAuthenticated });
export const useStats       = () => useStore().state.stats;
export const useAgentStatus = () => useStore().state.agentStatus;
export const useWsConnected = () => useStore().state.wsConnected;
export const useNotifications = () => useStore().state.notifications;
export const useActions     = () => useStore().actions;
