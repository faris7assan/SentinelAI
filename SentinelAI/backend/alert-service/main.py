"""
SentinelAI — Alert Service
Real-time alert delivery via WebSockets + notification routing
"""
import os, json, asyncio
from datetime import datetime, timezone
from typing import Optional, List, Set
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaConsumer
import aioredis
from loguru import logger
import uvicorn

KAFKA_SERVERS     = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ALERT_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379/0")

app = FastAPI(title="SentinelAI Alert Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

redis_client = None

# ─── WebSocket Manager ────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)
        logger.info(f"WS client connected. Total: {len(self.active)}")

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)
        logger.info(f"WS client disconnected. Total: {len(self.active)}")

    async def broadcast(self, message: dict):
        dead = set()
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self.active.discard(ws)

manager = ConnectionManager()

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    asyncio.create_task(_consume_and_broadcast())
    logger.info("Alert Service started")

@app.on_event("shutdown")
async def shutdown():
    if redis_client: await redis_client.close()

async def _consume_and_broadcast():
    """Consume alerts from Kafka and push to all WebSocket clients."""
    consumer = AIOKafkaConsumer(
        KAFKA_ALERT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id="alert-service-ws",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    await consumer.start()
    try:
        async for msg in consumer:
            alert = msg.value
            # Store in Redis sorted set (score = timestamp)
            score = datetime.now(timezone.utc).timestamp()
            await redis_client.zadd("alerts:timeline", {json.dumps(alert): score})
            await redis_client.zremrangebyrank("alerts:timeline", 0, -10001)

            # Broadcast to WS clients
            await manager.broadcast({"type": "alert", "data": alert})
            logger.info(f"Broadcasted alert: {alert.get('rule_name')} to {len(manager.active)} clients")
    finally:
        await consumer.stop()

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "alert-service", "ws_clients": len(manager.active)}

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    """WebSocket endpoint for real-time alerts."""
    await manager.connect(websocket)
    try:
        # Send last 20 alerts on connect
        recent_raw = await redis_client.zrevrange("alerts:timeline", 0, 19)
        for raw in recent_raw:
            await websocket.send_json({"type": "history", "data": json.loads(raw)})
        # Keep alive
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({"type": "ping", "ts": datetime.now(timezone.utc).isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        manager.disconnect(websocket)
        logger.error(f"WS error: {e}")

@app.get("/alerts/timeline")
async def get_timeline(limit: int = 100, offset: int = 0):
    """Get alert timeline."""
    raw = await redis_client.zrevrange("alerts:timeline", offset, offset + limit - 1, withscores=True)
    return [{"alert": json.loads(r[0]), "score": r[1]} for r in raw]

@app.get("/alerts/count-by-severity")
async def count_by_severity():
    all_raw = await redis_client.zrevrange("alerts:timeline", 0, 999)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for raw in all_raw:
        sev = json.loads(raw).get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1
    return counts

@app.get("/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: str, analyst: str):
    """Mark alert as acknowledged."""
    await redis_client.hset(f"alert:ack:{alert_id}", mapping={
        "analyst": analyst,
        "acked_at": datetime.now(timezone.utc).isoformat(),
    })
    await manager.broadcast({"type": "ack", "alert_id": alert_id, "analyst": analyst})
    return {"status": "acknowledged", "alert_id": alert_id}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8007, reload=False)
