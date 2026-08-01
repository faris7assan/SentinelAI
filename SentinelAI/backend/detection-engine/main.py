"""
SentinelAI — Detection Engine
Sigma rules + YARA + Behavioral detection + Attack correlation
"""
import os, json, re, asyncio
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any
from collections import defaultdict, deque
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from opensearchpy import AsyncOpenSearch
import aioredis
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS      = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_LOG_TOPIC    = os.getenv("KAFKA_TOPIC_LOGS", "sentinelai.logs")
KAFKA_ALERT_TOPIC  = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
OS_HOST            = os.getenv("OPENSEARCH_HOST", "opensearch")
OS_PORT            = int(os.getenv("OPENSEARCH_PORT", 9200))
OS_USER            = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS            = os.getenv("OPENSEARCH_PASSWORD", "admin")
REDIS_URL          = os.getenv("REDIS_URL", "redis://redis:6379/0")
RULES_DIR          = os.getenv("RULES_DIR", "/app/detection-rules")
ALERT_INDEX        = "sentinelai-alerts"

app = FastAPI(title="SentinelAI Detection Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer: Optional[AIOKafkaProducer] = None
os_client: Optional[AsyncOpenSearch] = None
redis_client = None

# ─── MITRE ATT&CK Map ────────────────────────────────────────
MITRE_MAP = {
    "brute_force":          {"tactic": "Credential Access",       "technique": "T1110"},
    "privilege_escalation": {"tactic": "Privilege Escalation",    "technique": "T1068"},
    "reverse_shell":        {"tactic": "Execution",               "technique": "T1059"},
    "lateral_movement":     {"tactic": "Lateral Movement",        "technique": "T1021"},
    "data_exfiltration":    {"tactic": "Exfiltration",            "technique": "T1041"},
    "dns_tunneling":        {"tactic": "Command and Control",     "technique": "T1071"},
    "port_scan":            {"tactic": "Discovery",               "technique": "T1046"},
    "ransomware":           {"tactic": "Impact",                  "technique": "T1486"},
    "credential_dumping":   {"tactic": "Credential Access",       "technique": "T1003"},
    "phishing":             {"tactic": "Initial Access",          "technique": "T1566"},
    "ddos":                 {"tactic": "Impact",                  "technique": "T1498"},
    "malware_execution":    {"tactic": "Execution",               "technique": "T1204"},
    "impossible_travel":    {"tactic": "Initial Access",          "technique": "T1078"},
    "c2_beacon":            {"tactic": "Command and Control",     "technique": "T1071"},
}

# ─── Sigma Rules (inline for portability) ────────────────────
SIGMA_RULES: List[Dict] = [
    {
        "id": "SIG-001", "name": "SSH Brute Force", "severity": "high",
        "detection_type": "brute_force",
        "conditions": [
            {"field": "event_type", "op": "contains", "value": "failed_login"},
            {"field": "log_source", "op": "eq",       "value": "syslog"},
        ],
        "threshold": {"count": 5, "window_seconds": 60},
        "description": "Multiple failed SSH login attempts from same IP"
    },
    {
        "id": "SIG-002", "name": "Reverse Shell via Bash", "severity": "critical",
        "detection_type": "reverse_shell",
        "conditions": [
            {"field": "raw_log", "op": "regex", "value": r"bash\s+-i.*>&.*\/dev\/tcp"},
        ],
        "description": "Bash reverse shell pattern detected"
    },
    {
        "id": "SIG-003", "name": "Suspicious PowerShell Execution", "severity": "high",
        "detection_type": "malware_execution",
        "conditions": [
            {"field": "raw_log", "op": "regex", "value": r"(?i)powershell.*(-enc|-encodedcommand|-nop|-bypass|-exec\s+bypass)"},
        ],
        "description": "Suspicious PowerShell flags indicating obfuscation or bypass"
    },
    {
        "id": "SIG-004", "name": "Port Scan Detected", "severity": "medium",
        "detection_type": "port_scan",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "suricata"},
            {"field": "raw_log",    "op": "contains", "value": "ET SCAN"},
        ],
        "description": "Network port scanning activity from Suricata ET rules"
    },
    {
        "id": "SIG-005", "name": "DNS Tunneling Activity", "severity": "high",
        "detection_type": "dns_tunneling",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "dns_query"},
            {"field": "raw_log",    "op": "regex", "value": r"[a-zA-Z0-9]{30,}\."},
        ],
        "description": "Long subdomain suggests DNS tunneling/C2 beaconing"
    },
    {
        "id": "SIG-006", "name": "Ransomware File Extension Change", "severity": "critical",
        "detection_type": "ransomware",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "file_modification"},
            {"field": "raw_log",    "op": "regex", "value": r"\.(locked|encrypted|enc|crypto|crypt|ransom)$"},
        ],
        "description": "Mass file extension change matching ransomware patterns"
    },
    {
        "id": "SIG-007", "name": "Privilege Escalation via SUID", "severity": "high",
        "detection_type": "privilege_escalation",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "auditd"},
            {"field": "raw_log",    "op": "regex", "value": r"chmod\s+[u+]*s|setuid"},
        ],
        "description": "SUID bit manipulation — possible privilege escalation"
    },
    {
        "id": "SIG-008", "name": "Data Exfiltration — Large Outbound Transfer", "severity": "high",
        "detection_type": "data_exfiltration",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "zeek"},
            {"field": "event_type", "op": "eq", "value": "conn"},
            {"field": "raw_log",    "op": "regex", "value": r"orig_bytes.*[5-9]\d{6,}|[1-9]\d{7,}"},
        ],
        "description": "Large outbound data transfer detected via Zeek conn logs"
    },
    {
        "id": "SIG-009", "name": "Mimikatz / Credential Dump", "severity": "critical",
        "detection_type": "credential_dumping",
        "conditions": [
            {"field": "raw_log", "op": "regex", "value": r"(?i)(mimikatz|sekurlsa|lsadump|wce\.exe|pwdump)"},
        ],
        "description": "Known credential harvesting tool signature detected"
    },
    {
        "id": "SIG-010", "name": "DDoS Flood Pattern", "severity": "high",
        "detection_type": "ddos",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "suricata"},
            {"field": "raw_log",    "op": "regex", "value": r"(?i)(ET DOS|ET DROP|Flood)"},
        ],
        "description": "Suricata DDoS/flood signature triggered"
    },
    {
        "id": "SIG-011", "name": "New Admin Account Created", "severity": "high",
        "detection_type": "privilege_escalation",
        "conditions": [
            {"field": "event_type", "op": "eq", "value": "user_created"},
            {"field": "raw_log",    "op": "regex", "value": r"(wheel|sudo|admin|root)"},
        ],
        "description": "New privileged account added to sudoers/admin group"
    },
    {
        "id": "SIG-012", "name": "Lateral Movement — SMB Enumeration", "severity": "high",
        "detection_type": "lateral_movement",
        "conditions": [
            {"field": "log_source", "op": "eq", "value": "zeek"},
            {"field": "raw_log",    "op": "regex", "value": r"smb.*IPC\$|net\s+view|net\s+use"},
        ],
        "description": "SMB lateral movement patterns detected"
    },
]

# ─── Models ──────────────────────────────────────────────────
class ManualDetectRequest(BaseModel):
    log_event: Dict[str, Any]

class AlertModel(BaseModel):
    alert_id:       str
    rule_id:        str
    rule_name:      str
    severity:       str
    detection_type: str
    source_ip:      str
    hostname:       str
    description:    str
    mitre_tactic:   str
    mitre_technique:str
    raw_log:        str
    timestamp:      str
    correlated:     bool = False
    attack_chain:   List[str] = []

# ─── In-memory state for correlation ─────────────────────────
# source_ip -> deque of (timestamp, detection_type)
ip_event_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
# Attack chain patterns (ordered sequence of detection_types)
ATTACK_CHAINS = [
    ["brute_force", "privilege_escalation", "reverse_shell"],
    ["phishing", "malware_execution", "lateral_movement", "data_exfiltration"],
    ["port_scan", "lateral_movement", "credential_dumping"],
    ["brute_force", "lateral_movement", "ransomware"],
]

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, os_client, redis_client
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode(),
    )
    await producer.start()

    os_client = AsyncOpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=False, verify_certs=False,
    )

    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)

    # Start Kafka consumer in background
    asyncio.create_task(_consume_logs())
    logger.info("Detection engine started — consuming logs from Kafka")

@app.on_event("shutdown")
async def shutdown():
    if producer: await producer.stop()
    if os_client: await os_client.close()
    if redis_client: await redis_client.close()

# ─── Core Detection Logic ─────────────────────────────────────
def match_condition(event: dict, cond: dict) -> bool:
    val = str(event.get(cond["field"], ""))
    op, target = cond["op"], cond["value"]
    if op == "eq":       return val == target
    if op == "contains": return target.lower() in val.lower()
    if op == "regex":    return bool(re.search(target, val, re.IGNORECASE))
    if op == "gt":       return float(val or 0) > float(target)
    return False

def evaluate_sigma_rule(rule: dict, event: dict, ip_history: deque) -> bool:
    """Returns True if all rule conditions match."""
    for cond in rule.get("conditions", []):
        if not match_condition(event, cond):
            return False
    # Threshold check
    threshold = rule.get("threshold")
    if threshold:
        window = threshold["window_seconds"]
        count  = threshold["count"]
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=window)
        recent = [t for t, _ in ip_history if t > cutoff]
        if len(recent) < count:
            return False
    return True

def build_alert(rule: dict, event: dict) -> dict:
    import uuid
    mitre = MITRE_MAP.get(rule["detection_type"], {"tactic": "Unknown", "technique": "T0000"})
    return {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         rule["id"],
        "rule_name":       rule["name"],
        "severity":        rule["severity"],
        "detection_type":  rule["detection_type"],
        "source_ip":       event.get("source_ip", "unknown"),
        "hostname":        event.get("hostname", "unknown"),
        "description":     rule["description"],
        "mitre_tactic":    mitre["tactic"],
        "mitre_technique": mitre["technique"],
        "raw_log":         event.get("raw_log", ""),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "correlated":      False,
        "attack_chain":    [],
        "log_source":      event.get("log_source", ""),
        "agent_id":        event.get("agent_id", ""),
    }

def check_correlation(ip: str, new_type: str) -> Optional[List[str]]:
    """Check if events for an IP match a known attack chain."""
    history = ip_event_history[ip]
    history.append((datetime.now(timezone.utc), new_type))
    types_only = [t for _, t in history]
    for chain in ATTACK_CHAINS:
        if all(step in types_only for step in chain):
            # Verify approximate order
            idxs = []
            for step in chain:
                for i, t in enumerate(types_only):
                    if t == step and i not in idxs:
                        idxs.append(i)
                        break
            if idxs == sorted(idxs):
                return chain
    return None

async def process_event(event: dict):
    """Run all Sigma rules against a log event and emit alerts."""
    ip = event.get("source_ip", "unknown")
    ip_history = ip_event_history[ip]

    for rule in SIGMA_RULES:
        if evaluate_sigma_rule(rule, event, ip_history):
            alert = build_alert(rule, event)

            # Correlation check
            chain = check_correlation(ip, rule["detection_type"])
            if chain:
                alert["correlated"] = True
                alert["attack_chain"] = chain
                alert["severity"] = "critical"
                logger.warning(f"🔗 ATTACK CHAIN DETECTED: {' → '.join(chain)} from {ip}")

            # Publish to Kafka alerts topic
            await producer.send(KAFKA_ALERT_TOPIC, alert)

            # Index alert to OpenSearch
            await os_client.index(index=ALERT_INDEX, body=alert, id=alert["alert_id"])

            logger.warning(
                f"🚨 ALERT [{alert['severity'].upper()}] {alert['rule_name']} "
                f"src={ip} technique={alert['mitre_technique']}"
            )

            # Track in Redis for SOAR
            await redis_client.lpush(
                f"pending_alerts:{alert['severity']}",
                json.dumps(alert)
            )
            await redis_client.expire(f"pending_alerts:{alert['severity']}", 86400)

# ─── Kafka Consumer ──────────────────────────────────────────
async def _consume_logs():
    consumer = AIOKafkaConsumer(
        KAFKA_LOG_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id="detection-engine",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    await consumer.start()
    logger.info(f"Consuming from {KAFKA_LOG_TOPIC}")
    try:
        async for msg in consumer:
            await process_event(msg.value)
    finally:
        await consumer.stop()

# ─── API Routes ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "detection-engine", "rules_loaded": len(SIGMA_RULES)}

@app.post("/detect")
async def manual_detect(req: ManualDetectRequest):
    """Run detection rules on a single event (for testing)."""
    results = []
    for rule in SIGMA_RULES:
        if evaluate_sigma_rule(rule, req.log_event, deque()):
            results.append(build_alert(rule, req.log_event))
    return {"alerts": results, "count": len(results)}

@app.get("/alerts/recent")
async def recent_alerts(size: int = 50, severity: Optional[str] = None):
    query = {"match_all": {}}
    if severity:
        query = {"term": {"severity": severity}}
    body = {
        "query": query,
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": size,
    }
    resp = await os_client.search(index=ALERT_INDEX, body=body)
    return [h["_source"] for h in resp["hits"]["hits"]]

@app.get("/alerts/stats")
async def alert_stats():
    body = {
        "size": 0,
        "aggs": {
            "by_severity":    {"terms": {"field": "severity"}},
            "by_type":        {"terms": {"field": "detection_type"}},
            "by_technique":   {"terms": {"field": "mitre_technique"}},
            "correlated":     {"filter": {"term": {"correlated": True}}},
        }
    }
    resp = await os_client.search(index=ALERT_INDEX, body=body)
    return resp["aggregations"]

@app.get("/rules")
async def list_rules():
    return {"rules": SIGMA_RULES, "count": len(SIGMA_RULES)}

@app.get("/correlation/chains")
async def list_chains():
    return {"chains": ATTACK_CHAINS}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8003, reload=False)
