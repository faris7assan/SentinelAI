"""
SentinelAI — SOAR Service
Security Orchestration, Automation & Response
Playbooks: Phishing | BruteForce | Malware | DDoS | DataExfil
"""
import os, json, asyncio, smtplib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from enum import Enum

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
import aioredis
import httpx
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS     = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ALERT_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379/0")
FIREWALL_API      = os.getenv("FIREWALL_API_URL", "http://firewall-api:8099")
FIREWALL_KEY      = os.getenv("FIREWALL_API_KEY", "")
SLACK_WEBHOOK     = os.getenv("SLACK_WEBHOOK_URL", "")
SMTP_HOST         = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT         = int(os.getenv("SMTP_PORT", 587))
SMTP_USER         = os.getenv("SMTP_USER", "")
SMTP_PASS         = os.getenv("SMTP_PASSWORD", "")
SOC_EMAIL         = os.getenv("SOC_EMAIL", "soc@company.com")

app = FastAPI(title="SentinelAI SOAR Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer     = None
redis_client = None

# ─── Playbook Registry ───────────────────────────────────────
class PlaybookStep(BaseModel):
    step_id:     int
    name:        str
    action:      str
    params:      Dict[str, Any] = {}
    on_success:  str = "continue"
    on_failure:  str = "notify_analyst"

class PlaybookResult(BaseModel):
    playbook_name:   str
    alert_id:        str
    status:          str
    steps_executed:  List[Dict]
    total_time_ms:   float
    timestamp:       str

# ─── Action Implementations ──────────────────────────────────
async def action_block_ip(ip: str, reason: str) -> dict:
    """Block IP via firewall API."""
    logger.warning(f"🚫 BLOCKING IP: {ip} | Reason: {reason}")
    result = {"action": "block_ip", "ip": ip, "status": "simulated"}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{FIREWALL_API}/block",
                json={"ip": ip, "reason": reason, "duration": 3600},
                headers={"X-API-Key": FIREWALL_KEY},
                timeout=5.0,
            )
            result["status"] = "executed" if resp.status_code == 200 else "failed"
            result["firewall_response"] = resp.status_code
        except Exception as e:
            result["status"] = "simulated"
            result["note"] = f"Firewall API unavailable: {e}"
    return result

async def action_send_slack(message: str, severity: str) -> dict:
    """Send alert notification to Slack."""
    if not SLACK_WEBHOOK:
        return {"action": "slack_notify", "status": "skipped", "reason": "No webhook configured"}
    color = {"critical": "#FF0000", "high": "#FF6B00", "medium": "#FFD700", "low": "#00FF00"}.get(severity, "#808080")
    payload = {
        "attachments": [{
            "color": color,
            "title": f"🚨 SentinelAI Alert [{severity.upper()}]",
            "text": message,
            "footer": "SentinelAI SOC Platform",
            "ts": int(datetime.now(timezone.utc).timestamp()),
        }]
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(SLACK_WEBHOOK, json=payload, timeout=5.0)
            return {"action": "slack_notify", "status": "sent" if resp.status_code == 200 else "failed"}
        except Exception as e:
            return {"action": "slack_notify", "status": "failed", "error": str(e)}

async def action_send_email(subject: str, body: str, to: str) -> dict:
    """Send email alert via SMTP."""
    if not SMTP_USER:
        return {"action": "email_notify", "status": "skipped", "reason": "SMTP not configured"}
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = SMTP_USER
        msg["To"]      = to
        msg.attach(MIMEText(body, "html"))
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(SMTP_USER, to, msg.as_string())
        return {"action": "email_notify", "status": "sent"}
    except Exception as e:
        return {"action": "email_notify", "status": "failed", "error": str(e)}

async def action_isolate_endpoint(hostname: str) -> dict:
    """Isolate an endpoint (disable network, kill session)."""
    logger.critical(f"🔒 ISOLATING ENDPOINT: {hostname}")
    # In production: integrate with EDR API (CrowdStrike/Wazuh/etc.)
    return {"action": "isolate_endpoint", "hostname": hostname, "status": "simulated",
            "note": "In production: calls EDR API to isolate host from network"}

async def action_disable_account(username: str, reason: str) -> dict:
    """Disable compromised user account."""
    logger.warning(f"🔐 DISABLING ACCOUNT: {username} | {reason}")
    return {"action": "disable_account", "username": username, "status": "simulated",
            "note": "In production: calls AD/LDAP or IAM API to disable account"}

async def action_force_mfa(username: str) -> dict:
    """Force MFA re-enrollment for a user."""
    return {"action": "force_mfa", "username": username, "status": "simulated"}

async def action_quarantine_file(filepath: str, hostname: str) -> dict:
    """Quarantine a suspicious file."""
    logger.warning(f"🗑 QUARANTINE: {filepath} on {hostname}")
    return {"action": "quarantine_file", "filepath": filepath, "hostname": hostname, "status": "simulated"}

async def action_kill_process(process: str, hostname: str) -> dict:
    """Kill a malicious process."""
    return {"action": "kill_process", "process": process, "hostname": hostname, "status": "simulated"}

async def action_create_ticket(alert: dict) -> dict:
    """Create incident ticket in the ticketing system."""
    ticket_id = f"INC-{int(datetime.now(timezone.utc).timestamp())}"
    await redis_client.hset(f"ticket:{ticket_id}", mapping={
        "alert_id":   alert.get("alert_id", ""),
        "severity":   alert.get("severity", ""),
        "status":     "open",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rule_name":  alert.get("rule_name", ""),
    })
    return {"action": "create_ticket", "ticket_id": ticket_id, "status": "created"}

async def action_enrich_threat_intel(ip: str) -> dict:
    """Enrich IP with threat intelligence."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"http://threat-intel-service:8006/intel/ip/{ip}", timeout=5.0
            )
            return {"action": "enrich_intel", "ip": ip, "data": resp.json()}
        except Exception as e:
            return {"action": "enrich_intel", "ip": ip, "status": "unavailable"}

async def action_block_domain(domain: str) -> dict:
    """Block a malicious domain via DNS sinkhole."""
    return {"action": "block_domain", "domain": domain, "status": "simulated",
            "note": "In production: updates DNS blacklist / firewall rule"}

# ─── Playbook Executor ────────────────────────────────────────
async def execute_playbook(playbook_name: str, alert: dict) -> PlaybookResult:
    start = datetime.now(timezone.utc)
    steps_executed = []
    ip       = alert.get("source_ip", "unknown")
    hostname = alert.get("hostname", "unknown")
    severity = alert.get("severity", "low")
    alert_id = alert.get("alert_id", "unknown")
    det_type = alert.get("detection_type", "")

    msg = (
        f"*Alert:* {alert.get('rule_name')}\n"
        f"*Severity:* {severity.upper()}\n"
        f"*Source IP:* {ip}\n"
        f"*Host:* {hostname}\n"
        f"*MITRE:* {alert.get('mitre_technique')}\n"
        f"*Time:* {alert.get('timestamp')}"
    )

    if playbook_name == "brute_force":
        steps_executed += await _run_steps([
            action_enrich_threat_intel(ip),
            action_block_ip(ip, f"Brute force attack: {alert_id}"),
            action_disable_account(alert.get("parsed", {}).get("username", "unknown"), "Brute force detected"),
            action_force_mfa(alert.get("parsed", {}).get("username", "unknown")),
            action_send_slack(msg, severity),
            action_create_ticket(alert),
        ])

    elif playbook_name == "malware_execution":
        steps_executed += await _run_steps([
            action_isolate_endpoint(hostname),
            action_kill_process(alert.get("parsed", {}).get("process", "unknown"), hostname),
            action_quarantine_file(alert.get("parsed", {}).get("filepath", "unknown"), hostname),
            action_send_slack(msg, severity),
            action_send_email(
                subject=f"🚨 CRITICAL: Malware Detected on {hostname}",
                body=f"<h2>Malware Execution Alert</h2><pre>{json.dumps(alert, indent=2)}</pre>",
                to=SOC_EMAIL,
            ),
            action_create_ticket(alert),
        ])

    elif playbook_name == "phishing":
        urls  = alert.get("parsed", {}).get("urls", [])
        steps = [action_enrich_threat_intel(ip), action_send_slack(msg, severity)]
        for url in urls[:5]:
            domain = url.split("/")[2] if "/" in url else url
            steps.append(action_block_domain(domain))
        steps.append(action_create_ticket(alert))
        steps_executed += await _run_steps(steps)

    elif playbook_name == "ddos":
        steps_executed += await _run_steps([
            action_block_ip(ip, f"DDoS attack source: {alert_id}"),
            action_send_slack(msg, severity),
            action_create_ticket(alert),
        ])

    elif playbook_name == "data_exfiltration":
        steps_executed += await _run_steps([
            action_isolate_endpoint(hostname),
            action_block_ip(ip, f"Data exfiltration detected: {alert_id}"),
            action_send_slack(msg, severity),
            action_send_email(
                subject=f"🚨 DATA EXFILTRATION DETECTED — {hostname}",
                body=f"<h2>Data Exfiltration Alert</h2><pre>{json.dumps(alert, indent=2)}</pre>",
                to=SOC_EMAIL,
            ),
            action_create_ticket(alert),
        ])

    elif playbook_name == "privilege_escalation":
        steps_executed += await _run_steps([
            action_disable_account(alert.get("parsed", {}).get("username", "unknown"), "Privilege escalation"),
            action_isolate_endpoint(hostname),
            action_send_slack(msg, severity),
            action_create_ticket(alert),
        ])

    else:
        # Default playbook
        steps_executed += await _run_steps([
            action_send_slack(msg, severity),
            action_create_ticket(alert),
        ])

    elapsed = (datetime.now(timezone.utc) - start).total_seconds() * 1000
    result = {
        "playbook_name":  playbook_name,
        "alert_id":       alert_id,
        "status":         "completed",
        "steps_executed": steps_executed,
        "total_time_ms":  round(elapsed, 2),
        "timestamp":      datetime.now(timezone.utc).isoformat(),
    }

    # Store execution log
    await redis_client.lpush("soar:executions", json.dumps(result))
    await redis_client.ltrim("soar:executions", 0, 999)
    return result

async def _run_steps(coros) -> list:
    results = []
    for coro in coros:
        try:
            r = await coro
            r["status_icon"] = "✅"
            results.append(r)
        except Exception as e:
            results.append({"status": "error", "error": str(e), "status_icon": "❌"})
    return results

# ─── Playbook Auto-Router ────────────────────────────────────
DETECTION_TO_PLAYBOOK = {
    "brute_force":          "brute_force",
    "malware_execution":    "malware_execution",
    "ransomware":           "malware_execution",
    "phishing":             "phishing",
    "ddos":                 "ddos",
    "data_exfiltration":    "data_exfiltration",
    "privilege_escalation": "privilege_escalation",
    "lateral_movement":     "privilege_escalation",
    "credential_dumping":   "brute_force",
}

# ─── Kafka Consumer ──────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, redis_client
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode(),
    )
    await producer.start()
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    asyncio.create_task(_consume_alerts())
    logger.info("SOAR Service started")

@app.on_event("shutdown")
async def shutdown():
    if producer: await producer.stop()
    if redis_client: await redis_client.close()

async def _consume_alerts():
    consumer = AIOKafkaConsumer(
        KAFKA_ALERT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id="soar-service",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    await consumer.start()
    try:
        async for msg in consumer:
            alert = msg.value
            sev   = alert.get("severity", "low")
            det   = alert.get("detection_type", "")
            # Only auto-execute for high/critical
            if sev in ("high", "critical"):
                pb = DETECTION_TO_PLAYBOOK.get(det, "default")
                logger.info(f"Auto-executing playbook '{pb}' for alert {alert.get('alert_id')}")
                asyncio.create_task(execute_playbook(pb, alert))
    finally:
        await consumer.stop()

# ─── API Routes ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "soar-service"}

@app.post("/soar/execute/{playbook_name}")
async def run_playbook_manual(playbook_name: str, alert: dict, bg: BackgroundTasks):
    """Manually trigger a playbook for a given alert."""
    valid = list(DETECTION_TO_PLAYBOOK.values()) + ["default"]
    if playbook_name not in set(valid):
        raise HTTPException(400, f"Unknown playbook. Valid: {set(valid)}")
    bg.add_task(execute_playbook, playbook_name, alert)
    return {"status": "triggered", "playbook": playbook_name}

@app.get("/soar/executions")
async def get_executions(limit: int = 50):
    items = await redis_client.lrange("soar:executions", 0, limit - 1)
    return [json.loads(i) for i in items]

@app.get("/soar/tickets")
async def get_tickets():
    keys = await redis_client.keys("ticket:INC-*")
    tickets = []
    for k in keys:
        data = await redis_client.hgetall(k)
        data["ticket_id"] = k.split(":")[-1]
        tickets.append(data)
    return sorted(tickets, key=lambda x: x.get("created_at", ""), reverse=True)

@app.put("/soar/tickets/{ticket_id}/status")
async def update_ticket(ticket_id: str, status: str):
    valid_statuses = ["open", "in_progress", "resolved", "closed"]
    if status not in valid_statuses:
        raise HTTPException(400, f"Invalid status. Valid: {valid_statuses}")
    await redis_client.hset(f"ticket:{ticket_id}", "status", status)
    return {"ticket_id": ticket_id, "status": status}

@app.get("/soar/playbooks")
async def list_playbooks():
    return {
        "playbooks": [
            {"name": "brute_force",          "description": "Block IP, disable account, force MFA"},
            {"name": "malware_execution",     "description": "Isolate endpoint, kill process, quarantine file"},
            {"name": "phishing",             "description": "Extract URLs, check VirusTotal, block domain"},
            {"name": "ddos",                 "description": "Block attacking IPs, rate limit"},
            {"name": "data_exfiltration",    "description": "Isolate endpoint, block exfil destination"},
            {"name": "privilege_escalation", "description": "Disable account, isolate host"},
        ]
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8005, reload=False)
