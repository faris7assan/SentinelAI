"""
SentinelAI — VPN Monitor Service
WireGuard / OpenVPN session monitoring + geo-anomaly detection
Impossible travel detection + VPN abuse detection
"""
import os, json, asyncio, math
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaProducer
import aioredis
import httpx
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS     = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ALERT_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379/0")
# Max speed (km/h) a human can realistically travel between logins
IMPOSSIBLE_TRAVEL_KMH = 900  # Below commercial flight speed

app = FastAPI(title="SentinelAI VPN Monitor", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer     = None
redis_client = None

# ─── Models ──────────────────────────────────────────────────
class VPNSession(BaseModel):
    username:       str
    peer_ip:        str
    vpn_ip:         str
    protocol:       str = "wireguard"  # wireguard | openvpn
    event:          str = "connect"    # connect | disconnect | handshake
    bytes_sent:     int = 0
    bytes_received: int = 0
    timestamp:      Optional[str] = None

class GeoPoint(BaseModel):
    ip:        str
    latitude:  float
    longitude: float
    country:   str
    city:      str

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, redis_client
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode(),
    )
    await producer.start()
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("VPN Monitor Service started")

@app.on_event("shutdown")
async def shutdown():
    if producer:     await producer.stop()
    if redis_client: await redis_client.close()

# ─── Geo-IP Lookup ───────────────────────────────────────────
async def geo_lookup(ip: str) -> dict:
    """Use ip-api.com free tier for geo lookup."""
    cache_key = f"geo:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon,isp,org,as,mobile,proxy,hosting",
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "ip":       ip,
                        "country":  data.get("country", "Unknown"),
                        "city":     data.get("city", "Unknown"),
                        "latitude": data.get("lat", 0.0),
                        "longitude":data.get("lon", 0.0),
                        "isp":      data.get("isp", ""),
                        "is_proxy": data.get("proxy", False),
                        "is_hosting":data.get("hosting", False),
                        "is_mobile": data.get("mobile", False),
                    }
                    await redis_client.setex(cache_key, 86400, json.dumps(result))
                    return result
        except Exception as e:
            logger.error(f"Geo lookup failed for {ip}: {e}")

    return {"ip": ip, "country": "Unknown", "city": "Unknown",
            "latitude": 0.0, "longitude": 0.0}

# ─── Haversine Distance ──────────────────────────────────────
def haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlam = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlam / 2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

# ─── Impossible Travel Check ─────────────────────────────────
async def check_impossible_travel(username: str, new_geo: dict, now: datetime) -> Optional[dict]:
    last_key = f"vpn:last_session:{username}"
    last_raw = await redis_client.get(last_key)
    if not last_raw:
        return None

    last = json.loads(last_raw)
    last_time = datetime.fromisoformat(last["timestamp"])
    hours_elapsed = (now - last_time).total_seconds() / 3600.0

    if hours_elapsed < 0.01:  # < 36 seconds, ignore
        return None

    dist_km = haversine_km(
        last["latitude"], last["longitude"],
        new_geo["latitude"], new_geo["longitude"]
    )
    speed_kmh = dist_km / hours_elapsed if hours_elapsed > 0 else float("inf")

    if speed_kmh > IMPOSSIBLE_TRAVEL_KMH and dist_km > 100:
        return {
            "alert_type":      "impossible_travel",
            "username":        username,
            "last_location":   f"{last['city']}, {last['country']}",
            "new_location":    f"{new_geo['city']}, {new_geo['country']}",
            "distance_km":     round(dist_km, 1),
            "time_elapsed_h":  round(hours_elapsed, 2),
            "speed_kmh":       round(speed_kmh, 1),
            "last_ip":         last.get("ip"),
            "new_ip":          new_geo.get("ip"),
        }
    return None

# ─── VPN Abuse Detection ─────────────────────────────────────
async def check_vpn_abuse(username: str, geo: dict) -> List[dict]:
    alerts = []

    # Check if IP is a known proxy/hosting/datacenter
    if geo.get("is_proxy"):
        alerts.append({
            "alert_type": "vpn_via_proxy",
            "username":   username,
            "ip":         geo["ip"],
            "reason":     "VPN connection from a known proxy/anonymizer",
        })

    if geo.get("is_hosting"):
        alerts.append({
            "alert_type": "vpn_from_datacenter",
            "username":   username,
            "ip":         geo["ip"],
            "reason":     "VPN connection from a hosting/datacenter IP",
        })

    # Check concurrent sessions (same user, multiple IPs)
    session_key = f"vpn:active:{username}"
    active_ips  = await redis_client.smembers(session_key)
    if len(active_ips) > 2:
        alerts.append({
            "alert_type": "concurrent_vpn_sessions",
            "username":   username,
            "session_count": len(active_ips),
            "ips":        list(active_ips),
            "reason":     f"User has {len(active_ips)} concurrent VPN sessions",
        })

    # Check brute force / rapid reconnect
    attempts_key = f"vpn:attempts:{username}"
    attempts = await redis_client.incr(attempts_key)
    await redis_client.expire(attempts_key, 300)  # 5-min window
    if attempts > 10:
        alerts.append({
            "alert_type": "vpn_rapid_reconnect",
            "username":   username,
            "attempts":   attempts,
            "reason":     "Rapid VPN reconnect attempts — possible credential stuffing",
        })

    return alerts

# ─── Alert Publisher ─────────────────────────────────────────
async def publish_vpn_alert(alert_data: dict, severity: str = "high"):
    import uuid
    alert = {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         "VPN-AUTO",
        "rule_name":       f"VPN: {alert_data['alert_type'].replace('_', ' ').title()}",
        "severity":        severity,
        "detection_type":  "impossible_travel",
        "source_ip":       alert_data.get("new_ip") or alert_data.get("ip", "unknown"),
        "hostname":        "vpn-gateway",
        "description":     alert_data.get("reason", "VPN security event"),
        "mitre_tactic":    "Initial Access",
        "mitre_technique": "T1078",
        "raw_log":         json.dumps(alert_data),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "extra":           alert_data,
    }
    await producer.send(KAFKA_ALERT_TOPIC, alert)
    logger.warning(f"VPN Alert: {alert_data['alert_type']} for user {alert_data.get('username')}")

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "vpn-monitor-service"}

@app.post("/vpn/session")
async def report_session(session: VPNSession):
    """Report a VPN connect/disconnect event."""
    now      = datetime.now(timezone.utc)
    ts_str   = session.timestamp or now.isoformat()
    geo      = await geo_lookup(session.peer_ip)

    if session.event == "connect":
        # Impossible travel check
        travel_alert = await check_impossible_travel(session.username, geo, now)
        if travel_alert:
            await publish_vpn_alert(travel_alert, severity="critical")

        # VPN abuse checks
        abuse_alerts = await check_vpn_abuse(session.username, geo)
        for ab in abuse_alerts:
            await publish_vpn_alert(ab, severity="high")

        # Store last session
        session_data = {
            "ip":        session.peer_ip,
            "country":   geo.get("country", ""),
            "city":      geo.get("city", ""),
            "latitude":  geo.get("latitude", 0.0),
            "longitude": geo.get("longitude", 0.0),
            "timestamp": ts_str,
        }
        await redis_client.setex(
            f"vpn:last_session:{session.username}",
            86400,
            json.dumps(session_data)
        )
        await redis_client.sadd(f"vpn:active:{session.username}", session.peer_ip)
        await redis_client.expire(f"vpn:active:{session.username}", 86400)

    elif session.event == "disconnect":
        await redis_client.srem(f"vpn:active:{session.username}", session.peer_ip)

    # Store session event in Redis
    event_data = {
        **session.dict(),
        "geo": geo,
        "timestamp": ts_str,
    }
    await redis_client.lpush("vpn:sessions", json.dumps(event_data))
    await redis_client.ltrim("vpn:sessions", 0, 9999)

    return {
        "status":  "processed",
        "geo":     geo,
        "event":   session.event,
        "alerts_generated": (1 if 'travel_alert' in dir() and travel_alert else 0)
    }

@app.get("/vpn/sessions")
async def get_sessions(limit: int = 100):
    """Get recent VPN sessions."""
    items = await redis_client.lrange("vpn:sessions", 0, limit - 1)
    return [json.loads(i) for i in items]

@app.get("/vpn/active")
async def get_active_users():
    """Get all currently active VPN users."""
    pattern = "vpn:active:*"
    keys = await redis_client.keys(pattern)
    active = {}
    for key in keys:
        username = key.split(":")[-1]
        ips = await redis_client.smembers(key)
        active[username] = list(ips)
    return {"active_users": active, "count": len(active)}

@app.get("/vpn/geo/{username}")
async def user_geo_history(username: str):
    """Get geo location history for a user."""
    last_raw = await redis_client.get(f"vpn:last_session:{username}")
    last = json.loads(last_raw) if last_raw else None
    return {"username": username, "last_session": last}

@app.get("/vpn/stats")
async def vpn_stats():
    """VPN usage statistics."""
    total_sessions  = await redis_client.llen("vpn:sessions")
    active_keys     = await redis_client.keys("vpn:active:*")
    recent_raw      = await redis_client.lrange("vpn:sessions", 0, 99)
    recent          = [json.loads(r) for r in recent_raw]
    countries       = {}
    for s in recent:
        c = s.get("geo", {}).get("country", "Unknown")
        countries[c] = countries.get(c, 0) + 1

    return {
        "total_sessions":  total_sessions,
        "active_users":    len(active_keys),
        "countries":       countries,
        "recent_count":    len(recent),
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8009, reload=False)
