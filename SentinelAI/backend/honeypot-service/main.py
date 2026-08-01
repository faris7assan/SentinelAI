"""
SentinelAI — Honeypot Service
Simulated SSH/HTTP/FTP/Telnet traps to lure and fingerprint attackers
Publishes real-time alerts when attacker interacts with honeypot
"""
import os, json, asyncio, socket, hashlib, re
from datetime import datetime, timezone
from typing import Optional, Dict, List
import asyncio.tasks

from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaProducer
import aioredis
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS     = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ALERT_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379/0")
ALERT_THRESHOLD   = int(os.getenv("HONEYPOT_ALERT_THRESHOLD", 3))
SSH_PORT          = int(os.getenv("HONEYPOT_SSH_PORT", 2222))
HTTP_PORT         = int(os.getenv("HONEYPOT_HTTP_PORT", 8888))
FTP_PORT          = int(os.getenv("HONEYPOT_FTP_PORT", 2121))

app = FastAPI(title="SentinelAI Honeypot Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer     = None
redis_client = None

# ─── Honeypot banners (realistic lures) ──────────────────────
BANNERS = {
    "ssh":  "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7\r\n",
    "ftp":  "220 ProFTPD 1.3.5 Server (SentinelLab FTP) [::ffff:10.0.0.1]\r\n",
    "smtp": "220 mail.corp-internal.com ESMTP Postfix (Ubuntu)\r\n",
    "http": (
        "HTTP/1.1 200 OK\r\n"
        "Server: Apache/2.4.18 (Ubuntu)\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body><h1>Internal Admin Portal</h1>"
        "<form><input name='user' placeholder='Username'>"
        "<input name='pass' type='password' placeholder='Password'>"
        "<button>Login</button></form></body></html>"
    ),
}

# ─── Common attacker credential attempts ─────────────────────
KNOWN_ATTACKER_CREDS = {
    ("admin", "admin"), ("root", "root"), ("admin", "password"),
    ("admin", "123456"), ("root", "toor"), ("admin", "admin123"),
    ("user", "user"), ("test", "test"), ("pi", "raspberry"),
    ("admin", "1234"), ("guest", "guest"), ("ubuntu", "ubuntu"),
}

# ─── Models ──────────────────────────────────────────────────
class HoneypotHit(BaseModel):
    attacker_ip:   str
    attacker_port: int
    honeypot_type: str   # ssh | http | ftp | smtp | web_admin
    event_type:    str   # connect | auth_attempt | command | scan
    payload:       str = ""
    credentials:   Optional[Dict[str, str]] = None
    timestamp:     Optional[str] = None

class CommandLog(BaseModel):
    attacker_ip: str
    command:     str
    honeypot:    str = "ssh"

# ─── Startup / Shutdown ──────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, redis_client
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode(),
    )
    await producer.start()
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)

    # Start low-interaction TCP honeypots
    asyncio.create_task(_run_ssh_honeypot())
    asyncio.create_task(_run_ftp_honeypot())
    logger.info("Honeypot service started — SSH trap on :2222, FTP on :2121")

@app.on_event("shutdown")
async def shutdown():
    if producer:     await producer.stop()
    if redis_client: await redis_client.close()

# ─── Alert Publisher ─────────────────────────────────────────
async def publish_honeypot_alert(hit: dict, severity: str = "high"):
    import uuid
    alert = {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         "HONEYPOT-001",
        "rule_name":       f"Honeypot Interaction — {hit['honeypot_type'].upper()}",
        "severity":        severity,
        "detection_type":  "honeypot_trigger",
        "source_ip":       hit["attacker_ip"],
        "hostname":        "honeypot-system",
        "description":     f"Attacker {hit['attacker_ip']} interacted with {hit['honeypot_type']} honeypot. Event: {hit['event_type']}",
        "mitre_tactic":    "Initial Access",
        "mitre_technique": "T1190",
        "raw_log":         json.dumps(hit),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "correlated":      False,
        "extra":           hit,
    }
    await producer.send(KAFKA_ALERT_TOPIC, alert)

    # Track in Redis — escalate after threshold
    key = f"honeypot:hits:{hit['attacker_ip']}"
    count = await redis_client.incr(key)
    await redis_client.expire(key, 3600)

    if count >= ALERT_THRESHOLD:
        alert["severity"] = "critical"
        alert["description"] += f" [{count} total interactions — escalated to CRITICAL]"
        await producer.send(KAFKA_ALERT_TOPIC, alert)
        logger.critical(f"🍯 HONEYPOT CRITICAL: {hit['attacker_ip']} — {count} interactions!")
    else:
        logger.warning(f"🍯 HONEYPOT HIT: {hit['attacker_ip']} via {hit['honeypot_type']} — {hit['event_type']}")

    # Log to Redis list
    await redis_client.lpush("honeypot:log", json.dumps({**hit, "alert_id": alert["alert_id"], "count": count}))
    await redis_client.ltrim("honeypot:log", 0, 9999)

# ─── SSH Honeypot (low-interaction) ──────────────────────────
async def _handle_ssh_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
    try:
        writer.write(BANNERS["ssh"].encode())
        await writer.drain()

        # Fake SSH handshake — capture whatever attacker sends
        data = await asyncio.wait_for(reader.read(2048), timeout=10.0)
        payload = data.decode(errors="replace")

        # Extract credential attempts
        creds = None
        # Simple heuristic for SSH auth payloads
        if "password" in payload.lower() or len(payload) > 10:
            creds = {"raw": payload[:200]}

        await publish_honeypot_alert({
            "attacker_ip":   ip,
            "attacker_port": port,
            "honeypot_type": "ssh",
            "event_type":    "auth_attempt",
            "payload":       payload[:500],
            "credentials":   creds,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }, severity="high")

        # Fake auth failure to keep attacker engaged
        writer.write(b"\xff\xfb\x01\xff\xfb\x03\xff\xfd\x27")
        await writer.drain()
        await asyncio.sleep(2)

    except asyncio.TimeoutError:
        pass
    except Exception as e:
        logger.debug(f"SSH honeypot: {e}")
    finally:
        writer.close()

async def _run_ssh_honeypot():
    try:
        server = await asyncio.start_server(_handle_ssh_client, "0.0.0.0", SSH_PORT)
        logger.info(f"SSH honeypot listening on port {SSH_PORT}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"SSH honeypot failed: {e}")

# ─── FTP Honeypot ────────────────────────────────────────────
async def _handle_ftp_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("unknown", 0)
    username = None
    try:
        writer.write(BANNERS["ftp"].encode())
        await writer.drain()

        while True:
            line = await asyncio.wait_for(reader.readline(), timeout=15.0)
            cmd = line.decode(errors="replace").strip()
            if not cmd:
                break

            cmd_upper = cmd.upper()
            if cmd_upper.startswith("USER"):
                username = cmd[5:].strip()
                writer.write(b"331 Password required for " + username.encode() + b"\r\n")
            elif cmd_upper.startswith("PASS"):
                password = cmd[5:].strip()
                await publish_honeypot_alert({
                    "attacker_ip":   ip,
                    "attacker_port": port,
                    "honeypot_type": "ftp",
                    "event_type":    "auth_attempt",
                    "payload":       cmd[:200],
                    "credentials":   {"username": username or "?", "password": password},
                    "timestamp":     datetime.now(timezone.utc).isoformat(),
                }, severity="medium")
                writer.write(b"530 Login incorrect.\r\n")
            elif cmd_upper == "QUIT":
                writer.write(b"221 Goodbye.\r\n")
                break
            else:
                writer.write(b"500 Unknown command.\r\n")
            await writer.drain()

    except (asyncio.TimeoutError, ConnectionResetError):
        pass
    except Exception as e:
        logger.debug(f"FTP honeypot: {e}")
    finally:
        writer.close()

async def _run_ftp_honeypot():
    try:
        server = await asyncio.start_server(_handle_ftp_client, "0.0.0.0", FTP_PORT)
        logger.info(f"FTP honeypot listening on port {FTP_PORT}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"FTP honeypot failed: {e}")

# ─── HTTP Honeypot Routes (fake admin portal) ─────────────────
@app.get("/admin")
@app.get("/admin/login")
@app.get("/wp-admin")
@app.get("/phpmyadmin")
@app.get("/.env")
@app.get("/config.php")
async def fake_admin(request: Request):
    """Fake admin portal — logs scanner hits."""
    ip = request.client.host if request.client else "unknown"
    path = request.url.path
    ua = request.headers.get("user-agent", "")

    await publish_honeypot_alert({
        "attacker_ip":   ip,
        "attacker_port": 80,
        "honeypot_type": "http",
        "event_type":    "web_scan",
        "payload":       f"GET {path} UA={ua[:100]}",
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }, severity="low")

    return {"status": "ok", "message": "Access logged"}

@app.post("/admin/login")
@app.post("/wp-login.php")
@app.post("/admin")
async def fake_login(request: Request):
    """Capture credential stuffing attempts."""
    ip = request.client.host if request.client else "unknown"
    try:
        body = await request.json()
    except Exception:
        body = {}

    username = body.get("username") or body.get("user") or body.get("email", "?")
    password = body.get("password") or body.get("pass", "?")
    cred_pair = (username, password)

    severity = "critical" if cred_pair in KNOWN_ATTACKER_CREDS else "high"
    await publish_honeypot_alert({
        "attacker_ip":   ip,
        "attacker_port": 80,
        "honeypot_type": "web_admin",
        "event_type":    "credential_stuffing",
        "payload":       f"username={username}",
        "credentials":   {"username": username, "password": "***REDACTED***"},
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }, severity=severity)

    # Delay to frustrate automated tools
    await asyncio.sleep(2)
    return {"error": "Invalid credentials", "code": 401}

# ─── API Routes ──────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "honeypot-service", "traps": ["ssh:2222", "ftp:2121", "http:web_admin"]}

@app.post("/honeypot/report")
async def report_hit(hit: HoneypotHit, bg_tasks=None):
    """Manually report a honeypot hit (from external Cowrie/Dionaea)."""
    await publish_honeypot_alert(hit.dict(), severity="high")
    return {"status": "reported"}

@app.get("/honeypot/log")
async def get_log(limit: int = 100):
    raw = await redis_client.lrange("honeypot:log", 0, limit - 1)
    return [json.loads(r) for r in raw]

@app.get("/honeypot/top-attackers")
async def top_attackers():
    keys = await redis_client.keys("honeypot:hits:*")
    attackers = []
    for k in keys:
        count = await redis_client.get(k)
        ip = k.split(":")[-1]
        attackers.append({"ip": ip, "hits": int(count or 0)})
    return sorted(attackers, key=lambda x: -x["hits"])[:20]

@app.post("/honeypot/command")
async def log_command(cmd: CommandLog):
    """Log attacker command from Cowrie/shell session."""
    dangerous = any(kw in cmd.command for kw in [
        "wget", "curl", "chmod", "python", "perl", "/dev/tcp",
        "uname", "whoami", "cat /etc/passwd", "id", "bash -i"
    ])
    severity = "critical" if dangerous else "medium"
    await publish_honeypot_alert({
        "attacker_ip":   cmd.attacker_ip,
        "attacker_port": 2222,
        "honeypot_type": cmd.honeypot,
        "event_type":    "command_execution",
        "payload":       cmd.command[:500],
        "timestamp":     datetime.now(timezone.utc).isoformat(),
    }, severity=severity)
    return {"status": "logged", "dangerous": dangerous}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8010, reload=False)
