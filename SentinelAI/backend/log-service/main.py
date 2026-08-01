"""
SentinelAI — Log Service
Ingests logs from agents, publishes to Kafka, indexes to OpenSearch
"""
import os, json, asyncio, hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from aiokafka import AIOKafkaProducer
from opensearchpy import AsyncOpenSearch
from loguru import logger
import aioredis
import uvicorn

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS   = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC     = os.getenv("KAFKA_TOPIC_LOGS", "sentinelai.logs")
OS_HOST         = os.getenv("OPENSEARCH_HOST", "opensearch")
OS_PORT         = int(os.getenv("OPENSEARCH_PORT", 9200))
OS_USER         = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS         = os.getenv("OPENSEARCH_PASSWORD", "admin")
REDIS_URL       = os.getenv("REDIS_URL", "redis://redis:6379/0")
LOG_INDEX       = "sentinelai-logs"
EVENT_INDEX     = "sentinelai-events"

app = FastAPI(title="SentinelAI Log Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── Global clients ──────────────────────────────────────────
producer: Optional[AIOKafkaProducer] = None
os_client: Optional[AsyncOpenSearch] = None

# ─── Models ──────────────────────────────────────────────────
class LogEvent(BaseModel):
    source_ip:    str
    hostname:     str
    log_source:   str   # syslog | sysmon | zeek | suricata | auditd | winevent | cloud
    event_type:   str
    severity:     str = "info"   # info | low | medium | high | critical
    raw_log:      str
    parsed:       Dict[str, Any] = {}
    agent_id:     Optional[str] = None
    os_type:      str = "linux"  # linux | windows | network | cloud
    timestamp:    Optional[str] = None

class BulkLogRequest(BaseModel):
    events: List[LogEvent]

class QueryRequest(BaseModel):
    query:      str
    index:      str = LOG_INDEX
    size:       int = 100
    from_:      int = Field(0, alias="from")
    time_from:  Optional[str] = None
    time_to:    Optional[str] = None

# ─── Startup / Shutdown ──────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, os_client
    producer = AIOKafkaProducer(
        bootstrap_servers=KAFKA_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode(),
        compression_type="gzip",
        max_batch_size=1048576,
        linger_ms=10,
    )
    await producer.start()
    logger.info("Kafka producer started")

    os_client = AsyncOpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=False,
        verify_certs=False,
    )
    await _ensure_indices()
    logger.info("OpenSearch client ready")

@app.on_event("shutdown")
async def shutdown():
    if producer:
        await producer.stop()
    if os_client:
        await os_client.close()

async def _ensure_indices():
    """Create OpenSearch indices with proper mappings if they don't exist."""
    log_mapping = {
        "mappings": {
            "properties": {
                "timestamp":   {"type": "date"},
                "source_ip":   {"type": "ip"},
                "hostname":    {"type": "keyword"},
                "log_source":  {"type": "keyword"},
                "event_type":  {"type": "keyword"},
                "severity":    {"type": "keyword"},
                "raw_log":     {"type": "text"},
                "agent_id":    {"type": "keyword"},
                "os_type":     {"type": "keyword"},
                "parsed":      {"type": "object", "dynamic": True},
            }
        },
        "settings": {"number_of_shards": 1, "number_of_replicas": 0}
    }
    for idx, mapping in [(LOG_INDEX, log_mapping), (EVENT_INDEX, log_mapping)]:
        exists = await os_client.indices.exists(index=idx)
        if not exists:
            await os_client.indices.create(index=idx, body=mapping)
            logger.info(f"Created index: {idx}")

# ─── Helpers ─────────────────────────────────────────────────
def enrich_event(event: LogEvent) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    d = event.dict()
    d["timestamp"] = d.get("timestamp") or now
    d["ingested_at"] = now
    # Dedup hash
    d["event_hash"] = hashlib.sha256(
        f"{event.source_ip}{event.raw_log}{event.timestamp}".encode()
    ).hexdigest()
    # Severity numeric for sorting
    d["severity_num"] = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(event.severity, 0)
    return d

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "log-service"}

@app.post("/logs/ingest", status_code=202)
async def ingest_log(event: LogEvent, bg: BackgroundTasks):
    """Ingest a single log event — non-blocking."""
    enriched = enrich_event(event)
    bg.add_task(_publish_and_index, enriched)
    return {"status": "accepted", "event_hash": enriched["event_hash"]}

@app.post("/logs/bulk", status_code=202)
async def ingest_bulk(req: BulkLogRequest, bg: BackgroundTasks):
    """Bulk ingest up to 10k log events."""
    if len(req.events) > 10_000:
        raise HTTPException(400, "Max 10,000 events per bulk request")
    enriched = [enrich_event(e) for e in req.events]
    bg.add_task(_bulk_index, enriched)
    return {"status": "accepted", "count": len(enriched)}

@app.post("/logs/search")
async def search_logs(req: QueryRequest):
    """Full-text + structured search over logs."""
    must_clauses = [{"query_string": {"query": req.query, "default_field": "raw_log"}}]
    if req.time_from or req.time_to:
        rng = {}
        if req.time_from: rng["gte"] = req.time_from
        if req.time_to:   rng["lte"] = req.time_to
        must_clauses.append({"range": {"timestamp": rng}})

    body = {
        "query": {"bool": {"must": must_clauses}},
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": req.size,
        "from": req.from_,
    }
    resp = await os_client.search(index=req.index, body=body)
    hits = resp["hits"]["hits"]
    return {
        "total": resp["hits"]["total"]["value"],
        "results": [h["_source"] for h in hits],
    }

@app.get("/logs/stats")
async def log_stats():
    """Get log volume stats by severity and source."""
    aggs = {
        "by_severity": {"terms": {"field": "severity", "size": 10}},
        "by_source":   {"terms": {"field": "log_source", "size": 20}},
        "by_hour": {
            "date_histogram": {
                "field": "timestamp",
                "calendar_interval": "hour",
                "min_doc_count": 1,
            }
        },
    }
    body = {"size": 0, "aggs": aggs}
    resp = await os_client.search(index=LOG_INDEX, body=body)
    return resp["aggregations"]

@app.get("/logs/recent")
async def recent_logs(size: int = 50, severity: Optional[str] = None):
    """Get most recent log events."""
    query = {"match_all": {}}
    if severity:
        query = {"term": {"severity": severity}}
    body = {
        "query": query,
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": size,
    }
    resp = await os_client.search(index=LOG_INDEX, body=body)
    return [h["_source"] for h in resp["hits"]["hits"]]

# ─── Background tasks ────────────────────────────────────────
async def _publish_and_index(event: dict):
    try:
        # Kafka
        await producer.send(KAFKA_TOPIC, event)
        # OpenSearch
        await os_client.index(index=LOG_INDEX, body=event, id=event["event_hash"])
    except Exception as e:
        logger.error(f"Failed to publish/index event: {e}")

async def _bulk_index(events: list):
    try:
        # Kafka bulk send
        for e in events:
            await producer.send(KAFKA_TOPIC, e)

        # OpenSearch bulk
        body = []
        for e in events:
            body.append({"index": {"_index": LOG_INDEX, "_id": e["event_hash"]}})
            body.append(e)
        if body:
            await os_client.bulk(body=body)
        logger.info(f"Bulk indexed {len(events)} events")
    except Exception as ex:
        logger.error(f"Bulk index error: {ex}")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=False)
