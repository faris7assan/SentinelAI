// ============================================================
// SentinelAI — TypeScript Type Definitions
// ============================================================

// ─── Severity ─────────────────────────────────────────────────
export type Severity = "critical" | "high" | "medium" | "low" | "info";

// ─── Alert ────────────────────────────────────────────────────
export interface Alert {
  alert_id:         string;
  rule_id:          string;
  rule_name:        string;
  severity:         Severity;
  detection_type:   string;
  source_ip:        string;
  hostname:         string;
  description:      string;
  mitre_tactic:     string;
  mitre_technique:  string;
  raw_log:          string;
  timestamp:        string;
  correlated:       boolean;
  attack_chain:     string[];
  ai_analysis?:     string;
  ai_enriched_at?:  string;
  log_source?:      string;
  agent_id?:        string;
  extra?:           Record<string, unknown>;
}

// ─── Log Event ────────────────────────────────────────────────
export interface LogEvent {
  source_ip:   string;
  hostname:    string;
  log_source:  "syslog" | "sysmon" | "zeek" | "suricata" | "auditd" | "winevent" | "cloud" | "osquery";
  event_type:  string;
  severity:    Severity | "info";
  raw_log:     string;
  parsed:      Record<string, unknown>;
  agent_id?:   string;
  os_type:     "linux" | "windows" | "network" | "cloud";
  timestamp?:  string;
}

// ─── User ─────────────────────────────────────────────────────
export type Role = "admin" | "analyst" | "viewer" | "soar_bot";

export interface User {
  id:          string;
  username:    string;
  email:       string;
  role:        Role;
  full_name:   string;
  mfa_enabled: boolean;
  last_login?: string;
  created_at:  string;
  permissions: string[];
}

export interface TokenResponse {
  access_token:  string;
  refresh_token: string;
  token_type:    string;
  expires_in:    number;
  user:          User;
}

// ─── Threat Intelligence ──────────────────────────────────────
export interface ThreatScore {
  score:   number;
  verdict: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "CLEAN" | "UNKNOWN";
  reasons: string[];
}

export interface VirusTotalResult {
  source:       "virustotal";
  ip?:          string;
  hash?:        string;
  domain?:      string;
  malicious:    number;
  suspicious:   number;
  harmless:     number;
  country?:     string;
  as_owner?:    string;
  reputation?:  number;
  tags?:        string[];
  threat_label?:string;
}

export interface AbuseIPDBResult {
  source:           "abuseipdb";
  ip:               string;
  abuse_confidence: number;
  total_reports:    number;
  country_code:     string;
  isp:              string;
  domain:           string;
  is_whitelisted:   boolean;
  usage_type:       string;
  last_reported:    string;
}

export interface ShodanResult {
  source:       "shodan";
  ip:           string;
  org:          string;
  isp:          string;
  country_code: string;
  city:         string;
  os?:          string;
  open_ports:   number[];
  hostnames:    string[];
  vulns:        string[];
  tags:         string[];
  last_update:  string;
  services:     Array<{ port: number; transport: string; product: string }>;
}

export interface MISPResult {
  source:      "misp";
  ioc:         string;
  ioc_type:    string;
  found:       boolean;
  hit_count:   number;
  events:      string[];
  tags:        string[];
  threat_level:number;
}

export interface FullIPResult {
  ip:           string;
  threat_score: ThreatScore;
  virustotal:   VirusTotalResult;
  abuseipdb:    AbuseIPDBResult;
  otx:          Record<string, unknown>;
  shodan:       ShodanResult;
  misp:         MISPResult;
  opencti:      Record<string, unknown>;
  queried_at:   string;
}

// ─── SOAR ────────────────────────────────────────────────────
export type PlaybookName =
  | "brute_force"
  | "malware_execution"
  | "phishing"
  | "ddos"
  | "data_exfiltration"
  | "privilege_escalation"
  | "default";

export interface PlaybookStep {
  action:      string;
  status:      "executed" | "simulated" | "failed" | "skipped";
  status_icon: "✅" | "❌";
  note?:       string;
  ip?:         string;
  hostname?:   string;
  [key: string]: unknown;
}

export interface SOARExecution {
  playbook_name:  PlaybookName;
  alert_id:       string;
  status:         "completed" | "failed" | "running";
  steps_executed: PlaybookStep[];
  total_time_ms:  number;
  timestamp:      string;
}

export interface Ticket {
  ticket_id:  string;
  alert_id:   string;
  severity:   Severity;
  status:     "open" | "in_progress" | "resolved" | "closed";
  created_at: string;
  rule_name:  string;
}

// ─── AI ──────────────────────────────────────────────────────
export interface AnomalyResult {
  is_anomaly:    boolean;
  anomaly_score: number;
  risk_level:    "critical" | "high" | "medium" | "low";
  source_ip:     string;
}

export interface EnsembleAnomalyResult {
  is_anomaly:  boolean;
  confidence:  number;
  votes: {
    isolation_forest: boolean;
    autoencoder:      boolean;
    ocsvm:            boolean;
  };
  scores: {
    if_score:    number;
    ae_error:    number;
    ocsvm_score: number;
  };
  risk_level:  string;
}

export interface ClassificationResult {
  attack_class:  string;
  confidence:    number;
  probabilities: Record<string, number>;
  model:         string;
  source_ip:     string;
}

export interface GeneratedRule {
  status:       "generated" | "invalid" | "error" | "llm_unavailable";
  rule_type:    "sigma" | "yara";
  rule_text?:   string;
  model?:       string;
  technique?:   string;
  malware?:     string;
  generated_at?:string;
  error?:       string;
}

// ─── Multi-Agent ─────────────────────────────────────────────
export type AgentName =
  | "detection_agent"
  | "threat_intel_agent"
  | "malware_agent"
  | "incident_report_agent"
  | "response_agent"
  | "hunting_agent";

export type AgentStatus = "idle" | "running" | "completed" | "failed";

export interface AgentState {
  name:         string;
  status:       AgentStatus;
  last_run:     string | null;
  tasks_done:   number;
  tasks_failed: number;
  current_task: string | null;
}

export interface OrchestrationResult {
  session_id:       string;
  alert_id:         string;
  orchestrated_at:  string;
  agents_run:       AgentName[];
  agent_results:    Record<AgentName, Record<string, unknown>>;
  risk_score:       number;
  auto_response:    string;
  attack_class:     string;
  ip_verdict:       string;
}

// ─── Reports ─────────────────────────────────────────────────
export interface ReportStats {
  period_hours:  number;
  total_alerts:  number;
  by_severity:   Record<Severity, number>;
  by_type:       Record<string, number>;
  by_technique:  Record<string, number>;
  attack_chains: number;
}

// ─── VPN ─────────────────────────────────────────────────────
export interface VPNSession {
  username:       string;
  peer_ip:        string;
  vpn_ip:         string;
  protocol:       "wireguard" | "openvpn";
  event:          "connect" | "disconnect" | "handshake";
  bytes_sent?:    number;
  bytes_received?:number;
  timestamp?:     string;
  geo?: {
    country:   string;
    city:      string;
    latitude:  number;
    longitude: number;
    isp:       string;
    is_proxy:  boolean;
  };
}

// ─── Cloud Security ───────────────────────────────────────────
export interface CloudCheckResult {
  check_id:    string;
  title:       string;
  status:      "PASS" | "FAIL" | "WARNING" | "UNKNOWN";
  severity:    Severity | "info";
  category:    string;
  nist_ref:    string;
  description: string;
  details:     string;
  remediation: string;
}

export interface CloudScanResult {
  provider:      "aws" | "azure" | "gcp";
  account_id?:   string;
  region?:       string;
  scanned_at:    string;
  posture_score: number;
  grade:         "A" | "B" | "C" | "D" | "F";
  summary: {
    total:   number;
    passing: number;
    failing: number;
    unknown: number;
  };
  checks:    CloudCheckResult[];
  framework: string;
}

// ─── Sandbox ─────────────────────────────────────────────────
export interface SandboxResult {
  file_hash_md5:    string;
  file_hash_sha256: string;
  file_size:        number;
  file_name:        string;
  file_type:        string;
  file_extension:   string;
  is_malicious:     boolean;
  verdict:          "MALICIOUS" | "SUSPICIOUS" | "CLEAN";
  threat_score:     number;
  static_analysis: {
    entropy:           number;
    entropy_note:      string;
    suspicious_strings:string[];
    pe_info:           Record<string, unknown>;
    dangerous_ext:     boolean;
  };
  yara_matches: string[];
  vt_result?:   VirusTotalResult | null;
  timestamp:    string;
}

// ─── Metrics (Go service) ─────────────────────────────────────
export interface PlatformMetrics {
  total_alerts:         number;
  critical_alerts:      number;
  high_alerts:          number;
  medium_alerts:        number;
  low_alerts:           number;
  logs_ingested:        number;
  soar_executions:      number;
  soar_failures:        number;
  honeypot_hits:        number;
  vpn_connections:      number;
  sandbox_analyzed:     number;
  malicious_files:      number;
  attack_chains:        number;
  threat_intel_queries: number;
  impossible_travel:    number;
  sampled_at:           string;
}

// ─── Honeypot ─────────────────────────────────────────────────
export interface HoneypotHit {
  attacker_ip:   string;
  attacker_port: number;
  honeypot_type: "ssh" | "ftp" | "http" | "smtp" | "web_admin";
  event_type:    "connect" | "auth_attempt" | "command" | "scan" | "web_scan" | "credential_stuffing";
  payload:       string;
  credentials?:  Record<string, string>;
  timestamp:     string;
  alert_id?:     string;
  count?:        number;
}

// ─── Red Team ─────────────────────────────────────────────────
export interface SimulationScenario {
  id:          string;
  name:        string;
  description: string;
  mitre:       string;
}

export interface SimulationResult {
  sim_id:          string;
  scenario:        string;
  scenario_name:   string;
  attacker_ip:     string;
  target_host:     string;
  mitre:           string;
  events_total:    number;
  events_shipped:  number;
  dry_run:         boolean;
  status:          "completed" | "failed";
  timestamp:       string;
}

// ─── WebSocket messages ───────────────────────────────────────
export interface WSMessage {
  type: "alert" | "history" | "ping" | "ack" | "orchestration_complete" | "status_update";
  data?: Alert | Record<string, unknown>;
  alert_id?: string;
  analyst?:  string;
  ts?:       string;
}

// ─── Sigma/YARA generation ────────────────────────────────────
export interface SigmaGenRequest {
  threat_description: string;
  mitre_technique:    string;
  log_source:         "linux" | "windows" | "network" | "cloud";
}

export interface YaraGenRequest {
  threat_description: string;
  malware_family:     string;
  platform:           "windows" | "linux" | "macos";
}
