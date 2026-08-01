"""
SentinelAI — Multi-Agent AI Architecture
Separate specialized AI agents coordinated via a central orchestrator:
  DetectionAgent     → Runs ML anomaly/classification
  ThreatIntelAgent   → Enriches IOCs from external feeds
  MalwareAnalysisAgent → Analyzes file behavior
  IncidentReportAgent  → Generates structured reports
  ResponseAgent       → Recommends / executes SOAR actions
  HuntingAgent        → Autonomous threat hunting
"""
import os, json, asyncio, uuid
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from enum import Enum
from dataclasses import dataclass, field, asdict

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import aioredis
import httpx
from loguru import logger
import uvicorn

# ─── Service URLs ────────────────────────────────────────────
AI_SVC         = os.getenv("AI_SERVICE_URL",         "http://ai-service:8004")
THREAT_SVC     = os.getenv("THREAT_INTEL_URL",        "http://threat-intel-service:8006")
SOAR_SVC       = os.getenv("SOAR_SERVICE_URL",        "http://soar-service:8005")
REPORT_SVC     = os.getenv("REPORT_SERVICE_URL",      "http://report-service:8008")
DETECTION_SVC  = os.getenv("DETECTION_ENGINE_URL",    "http://detection-engine:8003")
REDIS_URL      = os.getenv("REDIS_URL",               "redis://redis:6379/0")

app = FastAPI(title="SentinelAI Multi-Agent Orchestrator", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

redis_client = None
ws_clients   = set()

# ─── Agent Status ─────────────────────────────────────────────
class AgentStatus(str, Enum):
    IDLE      = "idle"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"

@dataclass
class AgentState:
    name:        str
    status:      AgentStatus = AgentStatus.IDLE
    last_run:    Optional[str] = None
    tasks_done:  int = 0
    tasks_failed:int = 0
    current_task:Optional[str] = None

# ─── Global Agent Registry ───────────────────────────────────
AGENTS: Dict[str, AgentState] = {
    "detection_agent":      AgentState("Detection Agent"),
    "threat_intel_agent":   AgentState("Threat Intel Agent"),
    "malware_agent":        AgentState("Malware Analysis Agent"),
    "incident_report_agent":AgentState("Incident Report Agent"),
    "response_agent":       AgentState("Response Agent"),
    "hunting_agent":        AgentState("Threat Hunting Agent"),
}

# ─── Task / Message Bus ──────────────────────────────────────
@dataclass
class AgentTask:
    task_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    agent:     str = ""
    task_type: str = ""
    payload:   Dict[str, Any] = field(default_factory=dict)
    priority:  int = 5          # 1=highest, 10=lowest
    created_at:str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    result:    Optional[Dict] = None
    status:    str = "pending"

# ─── Models ──────────────────────────────────────────────────
class OrchestrateRequest(BaseModel):
    alert:       Dict[str, Any]
    agents:      Optional[List[str]] = None   # None = all relevant agents
    async_mode:  bool = True

class HuntRequest(BaseModel):
    hypothesis:  str
    time_range_h:int = 24

class AgentTaskRequest(BaseModel):
    agent:     str
    task_type: str
    payload:   Dict[str, Any] = {}
    priority:  int = 5

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    asyncio.create_task(_background_agent_loop())
    logger.info("Multi-Agent Orchestrator started — 6 agents registered")

@app.on_event("shutdown")
async def shutdown():
    if redis_client: await redis_client.close()

# ─── Agent Implementations ────────────────────────────────────

async def detection_agent_run(task: AgentTask) -> dict:
    """Runs anomaly detection + attack classification on an event."""
    alert   = task.payload.get("alert", {})
    src_ip  = alert.get("source_ip", "unknown")
    raw_log = alert.get("raw_log", "")

    features = [
        len(raw_log),
        raw_log.count(" "),
        0,  # hour placeholder
        1 if "failed" in raw_log.lower() else 0,
        1 if "sudo"   in raw_log.lower() else 0,
        1 if "root"   in raw_log.lower() else 0,
        1, 0, 0, 0,
    ]

    async with httpx.AsyncClient() as client:
        try:
            anomaly_resp = await client.post(
                f"{AI_SVC}/ai/anomaly-detect",
                json={"features": features, "source_ip": src_ip},
                timeout=10.0,
            )
            classify_resp = await client.post(
                f"{AI_SVC}/ai/classify-attack",
                json={"features": features, "source_ip": src_ip, "raw_log": raw_log},
                timeout=10.0,
            )
            return {
                "agent":      "detection_agent",
                "anomaly":    anomaly_resp.json() if anomaly_resp.status_code == 200 else {},
                "classified": classify_resp.json() if classify_resp.status_code == 200 else {},
                "status":     "completed",
            }
        except Exception as e:
            return {"agent": "detection_agent", "error": str(e), "status": "failed"}


async def threat_intel_agent_run(task: AgentTask) -> dict:
    """Enriches source IP with multi-source threat intelligence."""
    alert  = task.payload.get("alert", {})
    src_ip = alert.get("source_ip", "")
    if not src_ip or src_ip in ("unknown", "file-upload", "cloud-scanner"):
        return {"agent": "threat_intel_agent", "status": "skipped", "reason": "no valid IP"}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{THREAT_SVC}/intel/ip/{src_ip}",
                timeout=15.0,
            )
            data = resp.json() if resp.status_code == 200 else {}
            verdict = data.get("threat_score", {}).get("verdict", "UNKNOWN")
            score   = data.get("threat_score", {}).get("score", 0)
            return {
                "agent":         "threat_intel_agent",
                "ip":            src_ip,
                "verdict":       verdict,
                "score":         score,
                "intel":         data,
                "action_needed": score > 60,
                "status":        "completed",
            }
        except Exception as e:
            return {"agent": "threat_intel_agent", "error": str(e), "status": "failed"}


async def malware_agent_run(task: AgentTask) -> dict:
    """Checks file hashes against sandbox/VirusTotal."""
    alert = task.payload.get("alert", {})
    raw   = alert.get("raw_log", "")

    import re
    sha256_match = re.search(r"\b[a-fA-F0-9]{64}\b", raw)
    md5_match    = re.search(r"\b[a-fA-F0-9]{32}\b", raw)
    file_hash    = sha256_match.group(0) if sha256_match else (md5_match.group(0) if md5_match else None)

    if not file_hash:
        return {"agent": "malware_agent", "status": "skipped", "reason": "no file hash in alert"}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                "http://sandbox-service:8011/sandbox/hash",
                json={"file_hash": file_hash},
                timeout=20.0,
            )
            data = resp.json() if resp.status_code == 200 else {}
            return {
                "agent":       "malware_agent",
                "file_hash":   file_hash,
                "is_malicious":data.get("is_malicious", False),
                "verdict":     data.get("verdict", "UNKNOWN"),
                "result":      data,
                "status":      "completed",
            }
        except Exception as e:
            return {"agent": "malware_agent", "error": str(e), "status": "failed"}


async def incident_report_agent_run(task: AgentTask) -> dict:
    """Auto-generates AI incident report for the alert."""
    alert = task.payload.get("alert", {})
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{AI_SVC}/ai/analyze-alert",
                json={"alert": alert},
                timeout=60.0,
            )
            data = resp.json() if resp.status_code == 200 else {}
            return {
                "agent":    "incident_report_agent",
                "analysis": data.get("analysis", ""),
                "model":    data.get("model", ""),
                "status":   "completed",
            }
        except Exception as e:
            return {"agent": "incident_report_agent", "error": str(e), "status": "failed"}


async def response_agent_run(task: AgentTask) -> dict:
    """Decides and triggers appropriate SOAR playbook."""
    alert      = task.payload.get("alert", {})
    intel      = task.payload.get("intel_result", {})
    detection  = task.payload.get("detection_result", {})

    severity   = alert.get("severity", "low")
    det_type   = alert.get("detection_type", "")
    ip_score   = intel.get("score", 0)
    is_anomaly = detection.get("anomaly", {}).get("is_anomaly", False)

    # Decision logic
    should_auto_respond = (
        severity in ("critical", "high") and
        (ip_score > 50 or is_anomaly or det_type in (
            "brute_force", "ransomware", "reverse_shell",
            "malware_execution", "data_exfiltration"
        ))
    )

    action_taken = "none"
    if should_auto_respond:
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{SOAR_SVC}/soar/execute/{det_type}",
                    json=alert,
                    timeout=10.0,
                )
                action_taken = "playbook_triggered"
            except Exception as e:
                action_taken = f"failed: {e}"

    return {
        "agent":               "response_agent",
        "should_auto_respond": should_auto_respond,
        "action_taken":        action_taken,
        "reasoning": {
            "severity":    severity,
            "ip_score":    ip_score,
            "is_anomaly":  is_anomaly,
            "det_type":    det_type,
        },
        "status": "completed",
    }


async def hunting_agent_run(task: AgentTask) -> dict:
    """Autonomous threat hunt based on recent alert patterns."""
    hypothesis = task.payload.get("hypothesis", "")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{AI_SVC}/ai/threat-hunt",
                json={"query": hypothesis, "time_range_hours": 24},
                timeout=90.0,
            )
            data = resp.json() if resp.status_code == 200 else {}
            return {
                "agent":           "hunting_agent",
                "hypothesis":      hypothesis,
                "hunt_result":     data.get("result", ""),
                "context_events":  data.get("context_events", 0),
                "status":          "completed",
            }
        except Exception as e:
            return {"agent": "hunting_agent", "error": str(e), "status": "failed"}


# ─── Agent Dispatcher ────────────────────────────────────────
AGENT_RUNNERS = {
    "detection_agent":       detection_agent_run,
    "threat_intel_agent":    threat_intel_agent_run,
    "malware_agent":         malware_agent_run,
    "incident_report_agent": incident_report_agent_run,
    "response_agent":        response_agent_run,
    "hunting_agent":         hunting_agent_run,
}

async def dispatch_agent(task: AgentTask) -> dict:
    """Run a single agent task and update its state."""
    runner = AGENT_RUNNERS.get(task.agent)
    if not runner:
        return {"error": f"Unknown agent: {task.agent}"}

    state = AGENTS.get(task.agent)
    if state:
        state.status       = AgentStatus.RUNNING
        state.current_task = task.task_id

    try:
        result = await runner(task)
        if state:
            state.status       = AgentStatus.COMPLETED
            state.tasks_done  += 1
            state.last_run     = datetime.now(timezone.utc).isoformat()
            state.current_task = None
        return result
    except Exception as e:
        if state:
            state.status        = AgentStatus.FAILED
            state.tasks_failed += 1
            state.current_task  = None
        return {"agent": task.agent, "error": str(e), "status": "failed"}


# ─── Orchestration Pipeline ──────────────────────────────────
async def orchestrate_alert(alert: dict, selected_agents: Optional[List[str]] = None) -> dict:
    """
    Full orchestration pipeline for an alert:
    Phase 1: Detection + Threat Intel (parallel)
    Phase 2: Response Agent (uses Phase 1 results)
    Phase 3: Report Generation (background)
    """
    session_id = str(uuid.uuid4())[:8]
    results    = {}

    # Phase 1: Run Detection + ThreatIntel + Malware in parallel
    phase1_agents = ["detection_agent", "threat_intel_agent", "malware_agent"]
    if selected_agents:
        phase1_agents = [a for a in phase1_agents if a in selected_agents]

    phase1_tasks = [
        AgentTask(agent=a, task_type="analyze", payload={"alert": alert})
        for a in phase1_agents
    ]

    phase1_results = await asyncio.gather(*[dispatch_agent(t) for t in phase1_tasks])
    for r in phase1_results:
        results[r.get("agent", "unknown")] = r

    # Phase 2: Response Agent (needs intel + detection results)
    if not selected_agents or "response_agent" in selected_agents:
        intel_result     = results.get("threat_intel_agent", {})
        detection_result = results.get("detection_agent", {})
        resp_task = AgentTask(
            agent="response_agent",
            task_type="respond",
            payload={
                "alert":            alert,
                "intel_result":     intel_result,
                "detection_result": detection_result,
            }
        )
        response_result = await dispatch_agent(resp_task)
        results["response_agent"] = response_result

    # Phase 3: Incident Report (background, non-blocking)
    if not selected_agents or "incident_report_agent" in selected_agents:
        report_task = AgentTask(
            agent="incident_report_agent",
            task_type="report",
            payload={"alert": alert}
        )
        asyncio.create_task(_run_report_agent(report_task, session_id))

    # Compute overall risk
    ip_score    = results.get("threat_intel_agent", {}).get("score", 0)
    is_anomaly  = results.get("detection_agent", {}).get("anomaly", {}).get("is_anomaly", False)
    attack_class= results.get("detection_agent", {}).get("classified", {}).get("attack_class", "normal")
    auto_resp   = results.get("response_agent", {}).get("action_taken", "none")

    risk_score = min(
        (ip_score * 0.4) +
        (30 if is_anomaly else 0) +
        (30 if attack_class != "normal" else 0) +
        ({"critical": 40, "high": 25, "medium": 10, "low": 5}.get(alert.get("severity","low"), 0)),
        100
    )

    session_result = {
        "session_id":     session_id,
        "alert_id":       alert.get("alert_id", "unknown"),
        "orchestrated_at":datetime.now(timezone.utc).isoformat(),
        "agents_run":     list(results.keys()),
        "agent_results":  results,
        "risk_score":     round(risk_score, 1),
        "auto_response":  auto_resp,
        "attack_class":   attack_class,
        "ip_verdict":     results.get("threat_intel_agent", {}).get("verdict", "UNKNOWN"),
    }

    # Cache result
    await redis_client.setex(
        f"orchestration:{session_id}",
        3600,
        json.dumps(session_result, default=str)
    )

    # Broadcast to WebSocket clients
    await _broadcast_ws({"type": "orchestration_complete", "data": session_result})

    return session_result


async def _run_report_agent(task: AgentTask, session_id: str):
    result = await dispatch_agent(task)
    await redis_client.hset(f"report:{session_id}", mapping={
        "analysis":   result.get("analysis", ""),
        "created_at": datetime.now(timezone.utc).isoformat(),
    })


async def _broadcast_ws(message: dict):
    dead = set()
    for ws in ws_clients:
        try:
            await ws.send_json(message)
        except Exception:
            dead.add(ws)
    for ws in dead:
        ws_clients.discard(ws)


# ─── Background Agent Loop ───────────────────────────────────
async def _background_agent_loop():
    """Process queued tasks from Redis every 5 seconds."""
    while True:
        try:
            raw = await redis_client.rpop("agent:task_queue")
            if raw:
                task_data = json.loads(raw)
                task = AgentTask(**task_data)
                result = await dispatch_agent(task)
                await redis_client.setex(
                    f"agent:result:{task.task_id}",
                    3600,
                    json.dumps(result, default=str)
                )
                logger.debug(f"Agent task {task.task_id} completed: {result.get('status')}")
        except Exception as e:
            logger.error(f"Agent loop error: {e}")
        await asyncio.sleep(5)

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status":  "healthy",
        "service": "multi-agent-orchestrator",
        "agents":  {name: asdict(state) for name, state in AGENTS.items()},
    }

@app.post("/orchestrate")
async def orchestrate(req: OrchestrateRequest, bg: BackgroundTasks):
    """Orchestrate all AI agents against an alert."""
    if req.async_mode:
        session_id = str(uuid.uuid4())[:8]
        bg.add_task(orchestrate_alert, req.alert, req.agents)
        return {"status": "queued", "session_id": session_id, "message": "Agents dispatched — check /orchestrate/result/{session_id}"}
    else:
        result = await orchestrate_alert(req.alert, req.agents)
        return result

@app.get("/orchestrate/result/{session_id}")
async def get_result(session_id: str):
    raw = await redis_client.get(f"orchestration:{session_id}")
    if not raw:
        raise HTTPException(404, "Session not found or expired")
    return json.loads(raw)

@app.post("/agents/{agent_name}/run")
async def run_agent(agent_name: str, req: AgentTaskRequest):
    """Run a single agent directly."""
    if agent_name not in AGENTS:
        raise HTTPException(400, f"Unknown agent. Valid: {list(AGENTS.keys())}")
    task   = AgentTask(agent=agent_name, task_type=req.task_type, payload=req.payload, priority=req.priority)
    result = await dispatch_agent(task)
    return result

@app.get("/agents/status")
async def agents_status():
    """Get status of all agents."""
    return {name: asdict(state) for name, state in AGENTS.items()}

@app.post("/agents/hunt")
async def autonomous_hunt(req: HuntRequest, bg: BackgroundTasks):
    """Launch an autonomous threat hunt."""
    task = AgentTask(
        agent="hunting_agent",
        task_type="hunt",
        payload={"hypothesis": req.hypothesis, "time_range_h": req.time_range_h}
    )
    result = await dispatch_agent(task)
    return result

@app.post("/agents/queue")
async def queue_task(req: AgentTaskRequest):
    """Queue an async agent task."""
    task = AgentTask(agent=req.agent, task_type=req.task_type, payload=req.payload, priority=req.priority)
    await redis_client.lpush("agent:task_queue", json.dumps(asdict(task)))
    return {"status": "queued", "task_id": task.task_id}

@app.get("/agents/queue/size")
async def queue_size():
    size = await redis_client.llen("agent:task_queue")
    return {"queue_size": size}

@app.websocket("/ws/agents")
async def ws_agent_updates(websocket: WebSocket):
    """WebSocket for real-time agent status updates."""
    await websocket.accept()
    ws_clients.add(websocket)
    try:
        await websocket.send_json({"type": "connected", "agents": list(AGENTS.keys())})
        while True:
            status = {name: asdict(state) for name, state in AGENTS.items()}
            await websocket.send_json({"type": "status_update", "data": status})
            await asyncio.sleep(10)
    except WebSocketDisconnect:
        ws_clients.discard(websocket)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8014, reload=False)
