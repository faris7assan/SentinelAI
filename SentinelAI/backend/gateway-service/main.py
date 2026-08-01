import os
import json
import asyncio
from typing import Dict, Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import httpx
import uvicorn
from loguru import logger

app = FastAPI(title="SentinelAI API Gateway", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Service mapping (internal Docker network or localhost)
SERVICES = {
    "auth": os.getenv("AUTH_SERVICE_URL", "http://localhost:8001"),
    "logs": os.getenv("LOGS_SERVICE_URL", "http://localhost:8002"),
    "detection": os.getenv("DETECTION_SERVICE_URL", "http://localhost:8003"),
    "ai": os.getenv("AI_SERVICE_URL", "http://localhost:8004"),
    "soar": os.getenv("SOAR_SERVICE_URL", "http://localhost:8005"),
    "threatintel": os.getenv("THREATINTEL_SERVICE_URL", "http://localhost:8006"),
    "alerts": os.getenv("ALERTS_SERVICE_URL", "http://localhost:8007"),
    "reports": os.getenv("REPORTS_SERVICE_URL", "http://localhost:8008"),
    "vpn": os.getenv("VPN_SERVICE_URL", "http://localhost:8009"),
    "honeypot": os.getenv("HONEYPOT_SERVICE_URL", "http://localhost:8010"),
    "sandbox": os.getenv("SANDBOX_SERVICE_URL", "http://localhost:8011"),
    "cloud": os.getenv("CLOUD_SERVICE_URL", "http://localhost:8012"),
    "redteam": os.getenv("REDTEAM_SERVICE_URL", "http://localhost:8013"),
    "agents": os.getenv("AGENTS_SERVICE_URL", "http://localhost:8014"),
    "metrics": os.getenv("METRICS_SERVICE_URL", "http://localhost:8015"),
}

client = httpx.AsyncClient()

@app.on_event("shutdown")
async def shutdown_event():
    await client.aclose()

# ── WebSocket Manager ──────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

@app.websocket("/ws/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle incoming client messages if any
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# A background task to simulate or aggregate real-time pushes
async def push_metrics():
    while True:
        try:
            if manager.active_connections:
                # Fetch metrics or health and push
                # For demonstration, we push a ping
                await manager.broadcast(json.dumps({"type": "ping", "timestamp": str(asyncio.get_event_loop().time())}))
        except Exception:
            pass
        await asyncio.sleep(5)

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(push_metrics())


# ── Routing Logic ──────────────────────────────────────────
@app.api_route("/{service_name}/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
async def gateway(service_name: str, path: str, request: Request):
    if service_name not in SERVICES:
        return JSONResponse(status_code=404, content={"error": f"Service '{service_name}' not found"})
    
    target_url = f"{SERVICES[service_name]}/{service_name}/{path}"
    
    # Read body
    body = await request.body()
    
    # Exclude headers that can cause issues
    excluded_headers = {"host", "content-length"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in excluded_headers}

    try:
        req = client.build_request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
            params=request.query_params
        )
        response = await client.send(req, stream=True)
        
        async def stream_response():
            async for chunk in response.aiter_bytes():
                yield chunk
                
        return StreamingResponse(
            stream_response(),
            status_code=response.status_code,
            headers={k: v for k, v in response.headers.items() if k.lower() not in ["content-encoding", "transfer-encoding"]}
        )
    except httpx.RequestError as e:
        logger.error(f"Gateway error connecting to {target_url}: {e}")
        return JSONResponse(status_code=502, content={"error": "Bad Gateway", "details": str(e)})

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
