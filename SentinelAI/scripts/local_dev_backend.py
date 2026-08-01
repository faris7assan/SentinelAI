from __future__ import annotations

import base64
import hashlib
import io
import json
import math
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional
from email import policy
from email.parser import BytesParser
from urllib.parse import parse_qs, urlparse

ROOT_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT_DIR / "data" / "local-dev"
DATA_DIR.mkdir(parents=True, exist_ok=True)

APP_NAME = "SentinelAI Local Dev Backend"
APP_VERSION = "1.0.0"
LOCAL_HOST = os.getenv("SENTINELAI_LOCAL_HOST", "127.0.0.1")
LOCAL_PORT = int(os.getenv("SENTINELAI_LOCAL_PORT", "8000"))

DEFAULT_USER = {
    "id": "local-admin",
    "username": "admin",
    "email": "admin@localhost",
    "password": "admin",
    "role": "admin",
    "full_name": "Local Administrator",
    "mfa_enabled": False,
    "is_active": True,
}

DEFAULT_PLAYBOOKS = [
    {"name": "default", "description": "Generic containment workflow"},
    {"name": "brute_force", "description": "Block source and notify admin"},
    {"name": "malware_isolation", "description": "Isolate affected host"},
    {"name": "phishing", "description": "Quarantine message and reset credentials"},
]

DEFAULT_SCENARIOS = [
    {"id": "port_scan", "name": "Port Scan", "description": "Simulated discovery traffic"},
    {"id": "brute_force_ssh", "name": "Brute Force SSH", "description": "Repeated failed logins"},
    {"id": "ransomware_chain", "name": "Ransomware Chain", "description": "File encryption and exfiltration"},
    {"id": "full_attack_chain", "name": "Full APT Chain", "description": "Multi-stage attack simulation"},
]

DEFAULT_TICKETS = [
    {"id": "TCK-1001", "title": "Review suspicious login activity", "status": "open", "priority": "high"},
    {"id": "TCK-1002", "title": "Validate endpoint isolation workflow", "status": "in_progress", "priority": "medium"},
]

DEFAULT_VPN_SESSIONS = [
    {"user": "analyst", "ip": "10.8.0.23", "country": "US", "anomaly": False, "connected_at": "2026-07-03T08:15:00Z"},
    {"user": "admin", "ip": "10.8.0.24", "country": "GB", "anomaly": True, "connected_at": "2026-07-03T08:18:00Z"},
]

DEFAULT_HONEYPOT_LOG = [
    {"source_ip": "185.220.101.45", "attempts": 11, "service": "ssh", "last_seen": "2026-07-03T08:00:00Z"},
    {"source_ip": "45.155.205.233", "attempts": 8, "service": "rdp", "last_seen": "2026-07-03T08:04:00Z"},
]

DEFAULT_AGENTS = [
    {"agent_id": "agent-ws01", "hostname": "workstation-01", "os_type": "windows", "status": "online"},
    {"agent_id": "agent-srv01", "hostname": "server-01", "os_type": "linux", "status": "online"},
]

SIGMA_RULES = [
    {
        "id": "SIG-001",
        "name": "SSH Brute Force",
        "severity": "high",
        "detection_type": "brute_force",
        "conditions": [
            {"field": "event_type", "op": "contains", "value": "failed_login"},
            {"field": "log_source", "op": "eq", "value": "syslog"},
        ],
        "threshold": {"count": 5, "window_seconds": 60},
        "description": "Multiple failed SSH login attempts from same IP",
    },
    {
        "id": "SIG-002",
        "name": "Reverse Shell via Bash",
        "severity": "critical",
        "detection_type": "reverse_shell",
        "conditions": [
            {"field": "raw_log", "op": "regex", "value": r"bash\s+-i.*>&.*\/dev\/tcp"},
        ],
        "description": "Bash reverse shell pattern detected",
    },
    {
        "id": "SIG-003",
        "name": "Suspicious PowerShell Execution",
        "severity": "high",
        "detection_type": "malware_execution",
        "conditions": [
            {"field": "raw_log", "op": "regex", "value": r"(?i)powershell.*(-enc|-encodedcommand|-nop|-bypass|-exec\s+bypass)"},
        ],
        "description": "Suspicious PowerShell flags indicating obfuscation or bypass",
    },
    {
        "id": "SIG-004",
        "name": "Port Scan Detected",
        "severity": "medium",
        "detection_type": "port_scan",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "suricata"},
            {"field": "raw_log", "op": "contains", "value": "ET SCAN"},
        ],
        "description": "Network port scanning activity",
    },
    {
        "id": "SIG-005",
        "name": "DNS Tunneling Activity",
        "severity": "high",
        "detection_type": "dns_tunneling",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "dns_query"},
            {"field": "raw_log", "op": "regex", "value": r"[a-zA-Z0-9]{30,}\."},
        ],
        "description": "Long subdomain suggests DNS tunneling/C2 beaconing",
    },
    {
        "id": "SIG-006",
        "name": "Ransomware File Extension Change",
        "severity": "critical",
        "detection_type": "ransomware",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "file_modification"},
            {"field": "raw_log", "op": "regex", "value": r"\.(locked|encrypted|enc|crypto|crypt|ransom)$"},
        ],
        "description": "File extension change matching ransomware patterns",
    },
    {
        "id": "SIG-007",
        "name": "Privilege Escalation via SUID",
        "severity": "high",
        "detection_type": "privilege_escalation",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "auditd"},
            {"field": "raw_log", "op": "regex", "value": r"chmod\s+[u+]*s|setuid"},
        ],
        "description": "SUID bit manipulation — possible privilege escalation",
    },
]

MITRE_MAP = {
    "brute_force": {"tactic": "Credential Access", "technique": "T1110"},
    "privilege_escalation": {"tactic": "Privilege Escalation", "technique": "T1068"},
    "reverse_shell": {"tactic": "Execution", "technique": "T1059"},
    "lateral_movement": {"tactic": "Lateral Movement", "technique": "T1021"},
    "data_exfiltration": {"tactic": "Exfiltration", "technique": "T1041"},
    "dns_tunneling": {"tactic": "Command and Control", "technique": "T1071"},
    "port_scan": {"tactic": "Discovery", "technique": "T1046"},
    "ransomware": {"tactic": "Impact", "technique": "T1486"},
    "credential_dumping": {"tactic": "Credential Access", "technique": "T1003"},
    "phishing": {"tactic": "Initial Access", "technique": "T1566"},
    "ddos": {"tactic": "Impact", "technique": "T1498"},
    "malware_execution": {"tactic": "Execution", "technique": "T1204"},
    "impossible_travel": {"tactic": "Initial Access", "technique": "T1078"},
    "c2_beacon": {"tactic": "Command and Control", "technique": "T1071"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-") or "item"


def parse_json(body: bytes) -> Any:
    if not body:
        return None
    return json.loads(body.decode("utf-8"))


def json_bytes(data: Any) -> bytes:
    return json.dumps(data, indent=2, sort_keys=True, default=str).encode("utf-8")


def normalize_query_text(value: str) -> str:
    return (value or "").strip().lower()


class LocalStore:
    def __init__(self):
        self._lock = threading.RLock()
        self.users = self._load("users.json", [DEFAULT_USER])
        self.logs = self._load("logs.json", self._seed_logs())
        self.alerts = self._load("alerts.json", self._seed_alerts())
        self.executions = self._load("executions.json", [])
        self.redteam_history = self._load("redteam_history.json", [])
        self.tickets = self._load("tickets.json", DEFAULT_TICKETS)
        self.reports = self._load("reports.json", [])
        self.vpn_sessions = self._load("vpn_sessions.json", DEFAULT_VPN_SESSIONS)
        self.honeypot_log = self._load("honeypot_log.json", DEFAULT_HONEYPOT_LOG)
        self.cloud_scans = self._load("cloud_scans.json", [])
        self.sandbox_results = self._load("sandbox_results.json", [])
        self.agents = self._load("agents.json", DEFAULT_AGENTS)
        self.threat_cache = self._load("threat_cache.json", {})

    def _load(self, name: str, default: Any) -> Any:
        path = DATA_DIR / name
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                return default
        self._save(name, default)
        return default

    def _save(self, name: str, value: Any) -> None:
        path = DATA_DIR / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")

    def save_all(self) -> None:
        with self._lock:
            self._save("users.json", self.users)
            self._save("logs.json", self.logs)
            self._save("alerts.json", self.alerts)
            self._save("executions.json", self.executions)
            self._save("redteam_history.json", self.redteam_history)
            self._save("tickets.json", self.tickets)
            self._save("reports.json", self.reports)
            self._save("vpn_sessions.json", self.vpn_sessions)
            self._save("honeypot_log.json", self.honeypot_log)
            self._save("cloud_scans.json", self.cloud_scans)
            self._save("sandbox_results.json", self.sandbox_results)
            self._save("agents.json", self.agents)
            self._save("threat_cache.json", self.threat_cache)

    def _seed_logs(self) -> List[Dict[str, Any]]:
        return [
            {
                "source_ip": "10.0.2.15",
                "hostname": "workstation-01",
                "log_source": "syslog",
                "event_type": "failed_login",
                "severity": "high",
                "raw_log": "Failed password for root from 10.0.2.15 port 44444 ssh2",
                "parsed": {"username": "root"},
                "agent_id": "agent-ws01",
                "os_type": "linux",
                "timestamp": now_iso(),
                "ingested_at": now_iso(),
                "event_hash": hashlib.sha256(b"seed-log-1").hexdigest(),
            },
            {
                "source_ip": "10.0.1.50",
                "hostname": "server-01",
                "log_source": "auditd",
                "event_type": "file_modification",
                "severity": "critical",
                "raw_log": 'auditd: type=PATH name="/home/user/docs/report.docx.encrypted" nametype=CREATE',
                "parsed": {},
                "agent_id": "agent-srv01",
                "os_type": "linux",
                "timestamp": now_iso(),
                "ingested_at": now_iso(),
                "event_hash": hashlib.sha256(b"seed-log-2").hexdigest(),
            },
        ]

    def _seed_alerts(self) -> List[Dict[str, Any]]:
        return [
            {
                "alert_id": "seed-alert-1",
                "rule_id": "SIG-001",
                "rule_name": "SSH Brute Force",
                "severity": "high",
                "detection_type": "brute_force",
                "source_ip": "10.0.2.15",
                "hostname": "workstation-01",
                "description": "Multiple failed SSH login attempts from same IP",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "T1110",
                "raw_log": "Failed password for root from 10.0.2.15 port 44444 ssh2",
                "timestamp": now_iso(),
                "correlated": False,
                "attack_chain": [],
            }
        ]

    def _dedupe_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event = dict(event)
        event.setdefault("timestamp", now_iso())
        event.setdefault("ingested_at", now_iso())
        event_hash = event.get("event_hash") or hashlib.sha256(
            f"{event.get('source_ip','')}{event.get('raw_log','')}{event.get('timestamp','')}".encode("utf-8")
        ).hexdigest()
        event["event_hash"] = event_hash
        return event

    def add_log(self, event: Dict[str, Any]) -> Dict[str, Any]:
        event = self._dedupe_event(event)
        self.logs.insert(0, event)
        self.logs = self.logs[:5000]
        self.save_all()
        return event

    def add_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        alert = dict(alert)
        alert.setdefault("timestamp", now_iso())
        alert.setdefault("attack_chain", [])
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:5000]
        self.save_all()
        return alert

    def add_execution(self, execution: Dict[str, Any]) -> Dict[str, Any]:
        self.executions.insert(0, execution)
        self.executions = self.executions[:2000]
        self.save_all()
        return execution

    def add_redteam_history(self, simulation: Dict[str, Any]) -> Dict[str, Any]:
        self.redteam_history.insert(0, simulation)
        self.redteam_history = self.redteam_history[:1000]
        self.save_all()
        return simulation

    def add_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        self.reports.insert(0, report)
        self.reports = self.reports[:1000]
        self.save_all()
        return report


STORE = LocalStore()


def condition_matches(event: Dict[str, Any], cond: Dict[str, Any]) -> bool:
    value = str(event.get(cond["field"], ""))
    op = cond["op"]
    target = cond["value"]
    if op == "eq":
        return value == target
    if op == "contains":
        return target.lower() in value.lower()
    if op == "regex":
        return bool(re.search(target, value, re.IGNORECASE))
    if op == "gt":
        try:
            return float(value or 0) > float(target)
        except Exception:
            return False
    return False


def detect_alerts(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    matched_alerts: List[Dict[str, Any]] = []
    for rule in SIGMA_RULES:
        if all(condition_matches(event, cond) for cond in rule.get("conditions", [])):
            mitre = MITRE_MAP.get(rule["detection_type"], {"tactic": "Unknown", "technique": "T0000"})
            alert = {
                "alert_id": f"alert-{slug(rule['name'])}-{secrets.token_hex(4)}",
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "detection_type": rule["detection_type"],
                "source_ip": event.get("source_ip", "0.0.0.0"),
                "hostname": event.get("hostname", "unknown"),
                "description": rule.get("description", "Suspicious activity detected"),
                "mitre_tactic": mitre["tactic"],
                "mitre_technique": mitre["technique"],
                "raw_log": event.get("raw_log", ""),
                "timestamp": now_iso(),
                "correlated": False,
                "attack_chain": [],
            }
            matched_alerts.append(alert)
    return matched_alerts


def summarize_alert(alert: Dict[str, Any]) -> str:
    return (
        f"{alert.get('rule_name', 'Unknown')} ({alert.get('severity', 'info')}) detected on "
        f"{alert.get('hostname', 'unknown')} from {alert.get('source_ip', '0.0.0.0')}"
    )


def severity_counts(items: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in items:
        sev = str(item.get("severity", "info")).lower()
        counts[sev if sev in counts else "info"] += 1
    return counts


def json_response(handler: BaseHTTPRequestHandler, code: int, payload: Any) -> None:
    data = json_bytes(payload)
    handler.send_response(code)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
    handler.end_headers()
    handler.wfile.write(data)


def bytes_response(handler: BaseHTTPRequestHandler, code: int, content_type: str, data: bytes) -> None:
    handler.send_response(code)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(data)))
    handler.send_header("Access-Control-Allow-Origin", "*")
    handler.send_header("Access-Control-Allow-Headers", "*")
    handler.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
    handler.end_headers()
    handler.wfile.write(data)


def parse_body(handler: BaseHTTPRequestHandler) -> Any:
    length = int(handler.headers.get("Content-Length", "0") or 0)
    raw = handler.rfile.read(length) if length else b""
    content_type = handler.headers.get("Content-Type", "")
    if "multipart/form-data" in content_type:
        return parse_multipart_form(content_type, raw)
    if raw:
        return parse_json(raw)
    return None


def parse_multipart_form(content_type: str, raw: bytes) -> Dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(
        f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + raw
    )
    data: Dict[str, Any] = {}
    if not message.is_multipart():
        return data
    for part in message.iter_parts():
        disposition = part.get("Content-Disposition", "")
        name = part.get_param("name", header="Content-Disposition")
        if not name:
            continue
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename:
            data[name] = {"filename": filename, "content": payload}
        else:
            data[name] = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
    return data


def parse_query(path: str) -> tuple[str, Dict[str, List[str]]]:
    parsed = urlparse(path)
    return parsed.path, parse_qs(parsed.query)


def simple_pdf_bytes(title: str, lines: List[str]) -> bytes:
    text_lines = [title] + lines
    stream_parts = ["BT /F1 12 Tf 50 770 Td"]
    for i, line in enumerate(text_lines):
        escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        if i == 0:
            stream_parts.append(f"({escaped}) Tj")
        else:
            stream_parts.append("T*")
            stream_parts.append(f"({escaped}) Tj")
    stream_parts.append("ET")
    stream = "\n".join(stream_parts).encode("latin-1")

    objects = []
    objects.append(b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n")
    objects.append(b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n")
    objects.append(
        b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>endobj\n"
    )
    objects.append(b"4 0 obj<< /Length " + str(len(stream)).encode("ascii") + b" >>stream\n" + stream + b"\nendstream endobj\n")
    objects.append(b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n")

    buffer = io.BytesIO()
    buffer.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(buffer.tell())
        buffer.write(obj)
    xref_pos = buffer.tell()
    buffer.write(f"xref\n0 {len(objects)+1}\n".encode("ascii"))
    buffer.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        buffer.write(f"{offset:010d} 00000 n \n".encode("ascii"))
    buffer.write(b"trailer<< /Size " + str(len(objects) + 1).encode("ascii") + b" /Root 1 0 R >>\n")
    buffer.write(b"startxref\n")
    buffer.write(str(xref_pos).encode("ascii") + b"\n%%EOF")
    return buffer.getvalue()


class LocalDevHandler(BaseHTTPRequestHandler):
    server_version = f"{APP_NAME}/{APP_VERSION}"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,OPTIONS")
        self.end_headers()

    def do_GET(self) -> None:
        path, query = parse_query(self.path)
        if path == "/health":
            return json_response(self, 200, {"status": "healthy", "service": "local-dev-gateway", "version": APP_VERSION})
        if path == "/metrics":
            return json_response(self, 200, metrics_payload())
        if path == "/logs/recent":
            size = int(query.get("size", ["50"])[0])
            severity = query.get("severity", [None])[0]
            return json_response(self, 200, recent_logs(size=size, severity=severity))
        if path == "/logs/stats":
            return json_response(self, 200, logs_stats())
        if path == "/alerts/recent":
            size = int(query.get("size", ["50"])[0])
            severity = query.get("severity", [None])[0]
            return json_response(self, 200, recent_alerts(size=size, severity=severity))
        if path == "/alerts/stats":
            return json_response(self, 200, alerts_stats())
        if path == "/rules":
            return json_response(self, 200, SIGMA_RULES)
        if path == "/soar/playbooks":
            return json_response(self, 200, {"playbooks": DEFAULT_PLAYBOOKS})
        if path == "/soar/executions":
            limit = int(query.get("limit", ["50"])[0])
            return json_response(self, 200, {"executions": STORE.executions[:limit]})
        if path == "/soar/tickets":
            return json_response(self, 200, {"tickets": STORE.tickets})
        if path == "/cloud/scan/history":
            return json_response(self, 200, {"history": STORE.cloud_scans})
        if path == "/vpn/sessions":
            limit = int(query.get("limit", ["100"])[0])
            return json_response(self, 200, {"sessions": STORE.vpn_sessions[:limit]})
        if path == "/vpn/stats":
            return json_response(self, 200, vpn_stats())
        if path == "/agents/status":
            return json_response(self, 200, {"agents": STORE.agents})
        if path == "/honeypot/log":
            limit = int(query.get("limit", ["100"])[0])
            return json_response(self, 200, {"logs": STORE.honeypot_log[:limit]})
        if path == "/honeypot/top-attackers":
            return json_response(self, 200, {"attackers": STORE.honeypot_log[:10]})
        if path == "/sandbox/results":
            limit = int(query.get("limit", ["50"])[0])
            return json_response(self, 200, {"results": STORE.sandbox_results[:limit]})
        if path.startswith("/intel/ip/full/"):
            value = path.split("/", 4)[-1]
            return json_response(self, 200, threat_intel_ip(value, full=True))
        if path.startswith("/intel/ip/"):
            value = path.split("/", 3)[-1]
            return json_response(self, 200, threat_intel_ip(value, full=False))
        if path.startswith("/intel/hash/"):
            value = path.split("/", 3)[-1]
            return json_response(self, 200, threat_intel_hash(value))
        if path.startswith("/intel/domain/"):
            value = path.split("/", 3)[-1]
            return json_response(self, 200, threat_intel_domain(value))
        if path.startswith("/intel/cve/"):
            value = path.split("/", 3)[-1]
            return json_response(self, 200, threat_intel_cve(value))
        if path == "/redteam/scenarios":
            return json_response(self, 200, {"scenarios": DEFAULT_SCENARIOS})
        if path == "/redteam/history":
            return json_response(self, 200, STORE.redteam_history)
        if path == "/reports/json":
            return json_response(self, 200, build_report_json("executive", 24))
        return json_response(self, 404, {"detail": f"Unknown route: {path}"})

    def do_POST(self) -> None:
        path, _ = parse_query(self.path)
        body = parse_body(self)
        if path == "/auth/login":
            return json_response(self, 200, auth_login(body or {}))
        if path == "/auth/register":
            return json_response(self, 200, auth_register(body or {}))
        if path == "/logs/ingest":
            return json_response(self, 202, ingest_log(body or {}))
        if path == "/logs/bulk":
            return json_response(self, 202, ingest_bulk(body or {}))
        if path == "/logs/search":
            return json_response(self, 200, search_logs(body or {}))
        if path == "/detect":
            return json_response(self, 200, manual_detect(body or {}))
        if path == "/ai/analyze-alert":
            return json_response(self, 200, ai_analyze_alert(body or {}))
        if path == "/ai/threat-hunt":
            return json_response(self, 200, ai_threat_hunt(body or {}))
        if path == "/ai/generate/sigma-rule":
            return json_response(self, 200, ai_generate_rule(body or {}, kind="sigma"))
        if path == "/ai/generate/yara-rule":
            return json_response(self, 200, ai_generate_rule(body or {}, kind="yara"))
        if path == "/cloud/scan":
            return json_response(self, 200, cloud_scan(body or {}))
        if path == "/sandbox/analyze":
            return json_response(self, 200, sandbox_analyze(body))
        if path.startswith("/soar/execute/"):
            name = path.split("/", 3)[-1]
            return json_response(self, 200, soar_execute(name, body or {}))
        if path == "/reports/json":
            report_type = (body or {}).get("report_type", "executive")
            time_range_h = int((body or {}).get("time_range_h", 24))
            return json_response(self, 200, build_report_json(report_type, time_range_h))
        if path == "/reports/pdf":
            report_type = (body or {}).get("report_type", "executive")
            time_range_h = int((body or {}).get("time_range_h", 24))
            pdf = build_report_pdf(report_type, time_range_h)
            return bytes_response(self, 200, "application/pdf", pdf)
        if path == "/redteam/phishing":
            return json_response(self, 200, redteam_phishing(body or {}))
        if path == "/redteam/simulate":
            return json_response(self, 200, redteam_simulate(body or {}))
        if path == "/logs/search":
            return json_response(self, 200, search_logs(body or {}))
        return json_response(self, 404, {"detail": f"Unknown route: {path}"})

    def do_PUT(self) -> None:
        path, query = parse_query(self.path)
        body = parse_body(self)
        if path.startswith("/soar/tickets/") and path.endswith("/status"):
            ticket_id = path.split("/")[3]
            status_value = (query.get("status", [None])[0] or (body or {}).get("status") or "open")
            return json_response(self, 200, update_ticket(ticket_id, status_value))
        return json_response(self, 404, {"detail": f"Unknown route: {path}"})


def auth_login(payload: Dict[str, Any]) -> Dict[str, Any]:
    username = str(payload.get("username", "")).strip() or "admin"
    password = str(payload.get("password", "")).strip()
    mfa_token = payload.get("mfa_token")
    user = next((item for item in STORE.users if item["username"] == username), None)
    if not user or (password and user.get("password") != password):
        raise_http(401, "Invalid credentials")
    if user.get("mfa_enabled") and not mfa_token:
        raise_http(200, "MFA_REQUIRED")
    token = f"local-{username}-{secrets.token_hex(12)}"
    return {
        "access_token": token,
        "refresh_token": f"refresh-{secrets.token_hex(12)}",
        "token_type": "bearer",
        "expires_in": 1800,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
            "full_name": user["full_name"],
            "mfa_enabled": user["mfa_enabled"],
        },
    }


def auth_register(payload: Dict[str, Any]) -> Dict[str, Any]:
    username = str(payload.get("username", "")).strip() or f"user-{len(STORE.users)+1}"
    if any(user["username"] == username for user in STORE.users):
        raise_http(409, "Username already exists")
    user = {
        "id": secrets.token_hex(8),
        "username": username,
        "email": payload.get("email") or f"{username}@localhost",
        "password": payload.get("password") or "changeme",
        "role": payload.get("role") or "analyst",
        "full_name": payload.get("full_name") or username,
        "mfa_enabled": False,
        "is_active": True,
    }
    STORE.users.append(user)
    STORE.save_all()
    return {"message": "User created successfully", "user_id": user["id"]}


def event_to_alert(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = detect_alerts(event)
    for alert in alerts:
        STORE.add_alert(alert)
    return alerts


def ingest_log(payload: Dict[str, Any]) -> Dict[str, Any]:
    event = dict(payload)
    event.setdefault("timestamp", now_iso())
    event.setdefault("ingested_at", now_iso())
    event.setdefault("severity", "info")
    event.setdefault("log_source", "syslog")
    event.setdefault("event_type", "event")
    event.setdefault("source_ip", "127.0.0.1")
    event.setdefault("hostname", "local-dev")
    event["event_hash"] = hashlib.sha256(
        f"{event.get('source_ip','')}{event.get('raw_log','')}{event.get('timestamp','')}".encode("utf-8")
    ).hexdigest()
    STORE.add_log(event)
    matched = event_to_alert(event)
    return {"status": "accepted", "event_hash": event["event_hash"], "alerts_created": len(matched)}


def ingest_bulk(payload: Dict[str, Any]) -> Dict[str, Any]:
    events = payload.get("events") or []
    if len(events) > 10000:
        raise_http(400, "Max 10,000 events per bulk request")
    count = 0
    for event in events:
        ingest_log(event)
        count += 1
    return {"status": "accepted", "count": count}


def recent_logs(size: int, severity: Optional[str]) -> List[Dict[str, Any]]:
    logs = STORE.logs
    if severity:
        logs = [item for item in logs if str(item.get("severity", "")).lower() == severity.lower()]
    return logs[:size]


def logs_stats() -> Dict[str, Any]:
    logs = STORE.logs
    by_source: Dict[str, int] = {}
    for item in logs:
        by_source[item.get("log_source", "unknown")] = by_source.get(item.get("log_source", "unknown"), 0) + 1
    return {
        "total": len(logs),
        "by_severity": severity_counts(logs),
        "by_source": by_source,
    }


def search_logs(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = normalize_query_text(payload.get("query", ""))
    size = int(payload.get("size", 50))
    results = []
    for item in STORE.logs:
        haystack = " ".join(str(item.get(key, "")) for key in ("raw_log", "hostname", "source_ip", "event_type", "log_source"))
        if not query or query in haystack.lower():
            results.append(item)
    return {"total": len(results), "results": results[:size]}


def manual_detect(payload: Dict[str, Any]) -> Dict[str, Any]:
    event = payload.get("log_event") or {}
    alerts = event_to_alert(event)
    return {
        "status": "ok",
        "alerts": alerts,
        "matched": len(alerts),
    }


def recent_alerts(size: int, severity: Optional[str]) -> List[Dict[str, Any]]:
    alerts = STORE.alerts
    if severity:
        alerts = [item for item in alerts if str(item.get("severity", "")).lower() == severity.lower()]
    return alerts[:size]


def alerts_stats() -> Dict[str, Any]:
    alerts = STORE.alerts
    return {
        "total": len(alerts),
        "by_severity": severity_counts(alerts),
        "by_rule": {item["rule_name"]: sum(1 for alert in alerts if alert["rule_name"] == item["rule_name"]) for item in alerts[:10]},
    }


def ai_analyze_alert(payload: Dict[str, Any]) -> Dict[str, Any]:
    alert = payload.get("alert") or {}
    rule_name = alert.get("rule_name", "Unknown")
    severity = alert.get("severity", "info")
    analysis = (
        f"{rule_name} observed with severity {severity}. "
        f"Recommended actions: validate source host, isolate if malicious, and review related logs."
    )
    return {
        "analysis": analysis,
        "summary": summarize_alert(alert),
        "recommendations": [
            "Inspect the source host",
            "Check related logs and alerts",
            "Contain or isolate if confirmed malicious",
        ],
        "confidence": 0.86,
    }


def ai_threat_hunt(payload: Dict[str, Any]) -> Dict[str, Any]:
    query = normalize_query_text(payload.get("query", ""))
    time_range_hours = int(payload.get("time_range_hours", 24))
    findings = []
    for alert in STORE.alerts:
        if query and query not in json.dumps(alert).lower():
            continue
        findings.append(alert)
    return {
        "query": query,
        "time_range_hours": time_range_hours,
        "findings": findings[:50],
        "count": len(findings),
    }


def ai_generate_rule(payload: Dict[str, Any], kind: str) -> Dict[str, Any]:
    desc = str(payload.get("threat_description", "suspicious activity")).strip()
    if kind == "sigma":
        return {
            "rule_type": "sigma",
            "rule_name": f"Local Dev {desc[:48] or 'Suspicious Activity'}",
            "content": {
                "title": f"Local Dev {desc[:48] or 'Suspicious Activity'}",
                "logsource": {"product": "windows"},
                "detection": {"selection": {"EventID|contains": "4688"}},
                "condition": "selection",
                "fields": ["EventID", "Image", "CommandLine"],
                "level": "medium",
            },
        }
    return {
        "rule_type": "yara",
        "rule_name": f"Local Dev {desc[:48] or 'Suspicious Activity'}",
        "content": f"rule local_dev_rule {{\n  strings:\n    $a = \"{desc[:20]}\"\n  condition:\n    $a\n}}",
    }


def threat_intel_ip(value: str, full: bool) -> Dict[str, Any]:
    score = 80 if value.startswith(("185.", "45.", "91.")) else 10
    verdict = "malicious" if score >= 70 else "benign"
    result = {
        "source": "local-dev",
        "ioc": value,
        "ioc_type": "ip",
        "threat_score": {"score": score, "verdict": verdict},
    }
    if full:
        result["details"] = {
            "country": "Unknown",
            "asn": "AS0",
            "tags": ["local-dev", verdict],
            "last_seen": now_iso(),
        }
    return result


def threat_intel_hash(value: str) -> Dict[str, Any]:
    malicious = int(hashlib.sha256(value.encode("utf-8")).hexdigest(), 16) % 5 == 0
    return {
        "source": "local-dev",
        "ioc": value,
        "ioc_type": "hash",
        "threat_score": {"score": 90 if malicious else 12, "verdict": "malicious" if malicious else "benign"},
    }


def threat_intel_domain(value: str) -> Dict[str, Any]:
    malicious = any(token in value for token in ("login", "secure", "verify"))
    return {
        "source": "local-dev",
        "ioc": value,
        "ioc_type": "domain",
        "threat_score": {"score": 75 if malicious else 15, "verdict": "suspicious" if malicious else "benign"},
    }


def threat_intel_cve(value: str) -> Dict[str, Any]:
    severity = "high" if value.endswith(("0001", "0002", "0003")) else "medium"
    return {
        "source": "local-dev",
        "ioc": value,
        "ioc_type": "cve",
        "severity": severity,
        "summary": f"Local dev advisory for {value}",
    }


def soar_execute(name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    execution = {
        "execution_id": f"exe-{secrets.token_hex(6)}",
        "playbook": name,
        "status": "completed",
        "started_at": now_iso(),
        "finished_at": now_iso(),
        "details": payload,
    }
    STORE.add_execution(execution)
    return execution


def update_ticket(ticket_id: str, status_value: str) -> Dict[str, Any]:
    for ticket in STORE.tickets:
        if ticket["id"] == ticket_id:
            ticket["status"] = status_value
            STORE.save_all()
            return ticket
    ticket = {"id": ticket_id, "title": f"Ticket {ticket_id}", "status": status_value, "priority": "medium"}
    STORE.tickets.append(ticket)
    STORE.save_all()
    return ticket


def build_report_json(report_type: str, time_range_h: int) -> Dict[str, Any]:
    report = {
        "report_type": report_type,
        "time_range_h": time_range_h,
        "generated_at": now_iso(),
        "alerts": len(STORE.alerts),
        "logs": len(STORE.logs),
        "executions": len(STORE.executions),
        "tickets": len(STORE.tickets),
        "severity": severity_counts(STORE.alerts),
    }
    STORE.add_report(report)
    return report


def build_report_pdf(report_type: str, time_range_h: int) -> bytes:
    report = build_report_json(report_type, time_range_h)
    lines = [
        f"Type: {report['report_type']}",
        f"Window: {report['time_range_h']}h",
        f"Generated: {report['generated_at']}",
        f"Alerts: {report['alerts']}",
        f"Logs: {report['logs']}",
        f"Executions: {report['executions']}",
        f"Tickets: {report['tickets']}",
    ]
    return simple_pdf_bytes("SentinelAI Local Dev Report", lines)


def cloud_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
    scan = {
        "scan_id": f"scan-{secrets.token_hex(6)}",
        "provider": payload.get("provider", "aws"),
        "account_id": payload.get("account_id") or "local-dev",
        "region": payload.get("region") or "us-east-1",
        "status": "completed",
        "summary": "Local dev cloud posture scan completed",
        "findings": [
            {"check": "public_s3", "result": "pass"},
            {"check": "mfa_enabled", "result": "warn"},
            {"check": "security_groups", "result": "pass"},
        ],
        "scanned_at": now_iso(),
    }
    STORE.cloud_scans.insert(0, scan)
    STORE.save_all()
    return scan


def sandbox_analyze(body: Any) -> Dict[str, Any]:
    if not isinstance(body, dict) or "file" not in body:
        raise_http(400, "Multipart form-data required")
    file_value = body["file"]
    if isinstance(file_value, dict):
        filename = str(file_value.get("filename", "sample.bin"))
        content = file_value.get("content", b"")
    else:
        filename = "sample.bin"
        content = str(file_value).encode("utf-8")
    size = len(content)
    entropy = calculate_entropy(content)
    result = {
        "analysis_id": f"sbx-{secrets.token_hex(6)}",
        "filename": filename,
        "size": size,
        "entropy": round(entropy, 4),
        "verdict": "suspicious" if entropy > 7.2 or size > 1_000_000 else "benign",
        "matches": ["local-dev-yara" if entropy > 6.5 else "none"],
        "analyzed_at": now_iso(),
    }
    STORE.sandbox_results.insert(0, result)
    STORE.save_all()
    return result


def redteam_simulate(payload: Dict[str, Any]) -> Dict[str, Any]:
    scenario = payload.get("scenario", "port_scan")
    result = {
        "simulation_id": f"sim-{secrets.token_hex(6)}",
        "scenario": scenario,
        "status": "completed",
        "dry_run": bool(payload.get("dry_run", False)),
        "delay_ms": int(payload.get("delay_ms", 100)),
        "attacker_ip": payload.get("attacker_ip") or "10.0.9.99",
        "target_host": payload.get("target_host") or "local-target",
        "summary": f"Simulated {scenario} successfully in local dev mode",
        "generated_alerts": 1 if scenario != "port_scan" else 0,
        "executed_at": now_iso(),
    }
    if result["generated_alerts"]:
        STORE.add_alert(
            {
                "alert_id": f"redteam-{secrets.token_hex(4)}",
                "rule_id": "RED-001",
                "rule_name": f"Red Team {scenario}",
                "severity": "medium",
                "detection_type": scenario,
                "source_ip": result["attacker_ip"],
                "hostname": result["target_host"],
                "description": result["summary"],
                "mitre_tactic": "Discovery",
                "mitre_technique": "T1046",
                "raw_log": f"redteam scenario {scenario}",
                "timestamp": now_iso(),
                "correlated": False,
                "attack_chain": [],
            }
        )
    STORE.add_redteam_history(
        {
            "sim_id": result["simulation_id"],
            "scenario": scenario,
            "attacker_ip": result["attacker_ip"],
            "events": 1,
            "timestamp": result["executed_at"],
        }
    )
    return result


def redteam_phishing(payload: Dict[str, Any]) -> Dict[str, Any]:
    target_email = str(payload.get("target_email", "victim@company.com")).strip() or "victim@company.com"
    sender_domain = str(payload.get("sender_domain", "company-secure.net")).strip() or "company-secure.net"
    lure_type = str(payload.get("lure_type", "credential_reset")).strip() or "credential_reset"
    result = {
        "campaign_id": f"phish-{secrets.token_hex(6)}",
        "target_email": target_email,
        "sender_domain": sender_domain,
        "lure_type": lure_type,
        "status": "generated",
        "summary": f"Generated {lure_type} phishing training payload for {target_email}",
        "generated_at": now_iso(),
    }
    STORE.add_redteam_history(
        {
            "sim_id": result["campaign_id"],
            "scenario": "phishing",
            "attacker_ip": sender_domain,
            "events": 0,
            "timestamp": result["generated_at"],
        }
    )
    return result


def vpn_stats() -> Dict[str, Any]:
    sessions = STORE.vpn_sessions
    return {
        "total": len(sessions),
        "anomalies": sum(1 for item in sessions if item.get("anomaly")),
        "countries": {item.get("country", "unknown"): sum(1 for sess in sessions if sess.get("country") == item.get("country")) for item in sessions[:10]},
    }


def metrics_payload() -> Dict[str, Any]:
    return {
        "counters": {
            "total_alerts": len(STORE.alerts),
            "critical_alerts": sum(1 for item in STORE.alerts if item.get("severity") == "critical"),
            "high_alerts": sum(1 for item in STORE.alerts if item.get("severity") == "high"),
            "attack_chains": sum(1 for item in STORE.alerts if item.get("correlated")),
            "logs_ingested": len(STORE.logs),
            "soar_executions": len(STORE.executions),
        },
        "services": {name: True for name in ["auth", "logs", "detection", "ai", "soar", "threatintel", "alerts", "reports", "vpn", "honeypot", "sandbox", "cloud", "redteam", "agents", "metrics"]},
    }


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {byte: data.count(byte) for byte in set(data)}
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in freq.values())


def raise_http(code: int, detail: str):
    raise RuntimeError(f"HTTP {code}: {detail}")


class SimpleHTTPError(Exception):
    def __init__(self, code: int, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(detail)


class SafeHandler(LocalDevHandler):
    def handle_one_request(self):
        try:
            super().handle_one_request()
        except SimpleHTTPError as exc:
            json_response(self, exc.code, {"detail": exc.detail})
        except Exception as exc:
            json_response(self, 500, {"detail": str(exc)})


def serve() -> None:
    server = ThreadingHTTPServer((LOCAL_HOST, LOCAL_PORT), SafeHandler)
    print(f"{APP_NAME} listening on http://{LOCAL_HOST}:{LOCAL_PORT}")
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
