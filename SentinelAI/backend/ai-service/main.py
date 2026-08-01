"""
SentinelAI — AI Engine Service
Anomaly Detection + Attack Classification + LangChain Security Copilot
"""
import os, json, asyncio, pickle, numpy as np
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from opensearchpy import AsyncOpenSearch
import aioredis
from loguru import logger
import uvicorn
import httpx

# ML
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import xgboost as xgb

# LangChain / Ollama
from langchain_community.llms import Ollama
from langchain.prompts import PromptTemplate
from langchain.chains import LLMChain

# ─── Config ──────────────────────────────────────────────────
KAFKA_SERVERS     = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_ALERT_TOPIC = os.getenv("KAFKA_TOPIC_ALERTS", "sentinelai.alerts")
OS_HOST           = os.getenv("OPENSEARCH_HOST", "opensearch")
OS_PORT           = int(os.getenv("OPENSEARCH_PORT", 9200))
OS_USER           = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS           = os.getenv("OPENSEARCH_PASSWORD", "admin")
REDIS_URL         = os.getenv("REDIS_URL", "redis://redis:6379/0")
OLLAMA_URL        = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
OLLAMA_MODEL      = os.getenv("OLLAMA_MODEL", "llama3.2")
MODELS_DIR        = os.getenv("MODELS_DIR", "/app/models")

app = FastAPI(title="SentinelAI AI Engine", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer    = None
os_client   = None
redis_client= None
llm         = None

# ─── ML Models (initialized at startup) ──────────────────────
isolation_forest = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
scaler           = StandardScaler()
rf_classifier    = RandomForestClassifier(n_estimators=100, random_state=42)
xgb_classifier   = xgb.XGBClassifier(n_estimators=100, random_state=42, eval_metric="logloss")
models_trained   = False

ATTACK_CLASSES = [
    "normal", "brute_force", "port_scan", "ddos", "data_exfiltration",
    "lateral_movement", "ransomware", "malware_execution", "c2_beacon"
]

# ─── LangChain Prompt Templates ──────────────────────────────
ANALYST_PROMPT = PromptTemplate(
    input_variables=["alert"],
    template="""You are an elite SOC analyst at a top-tier cybersecurity operations center.
Analyze the following security alert and provide a professional assessment.

ALERT DETAILS:
{alert}

Provide your analysis in this exact format:
## Threat Assessment
[2-3 sentence summary of what happened]

## Attack Vector
[How the attacker likely gained access or executed this]

## MITRE ATT&CK Mapping
[Tactic and Technique with explanation]

## Immediate Actions Required
1. [Action 1]
2. [Action 2]
3. [Action 3]

## Containment Strategy
[How to contain this threat]

## Investigation Steps
[What logs/artifacts to examine next]

## Risk Level
[Critical / High / Medium / Low — with reasoning]
"""
)

THREAT_HUNT_PROMPT = PromptTemplate(
    input_variables=["query", "context"],
    template="""You are a threat hunter with deep expertise in MITRE ATT&CK and network forensics.

Threat Hunt Query: {query}

Available Context from SIEM:
{context}

Provide a structured threat hunting response:
## Hypothesis
[What threat actor behavior are we hunting for]

## IOCs to Search
- [List specific IOCs, file hashes, IPs, domains]

## Hunt Queries
[Specific searches/queries to run in the SIEM]

## Expected Evidence
[What artifacts we expect to find if hypothesis is correct]

## Verdict
[Found / Not Found / Inconclusive — with explanation]
"""
)

REPORT_PROMPT = PromptTemplate(
    input_variables=["incident_data"],
    template="""You are a cybersecurity incident response manager writing an executive report.

INCIDENT DATA:
{incident_data}

Generate a professional incident report with:
## Executive Summary
[3-4 sentences for non-technical leadership]

## Incident Timeline
[Chronological sequence of events]

## Technical Details
[What happened technically]

## Business Impact
[What assets/data were at risk or compromised]

## Response Actions Taken
[What was done to contain/remediate]

## Recommendations
[Security improvements to prevent recurrence]

## Lessons Learned
[Key takeaways for the security program]
"""
)

# ─── Models ──────────────────────────────────────────────────
class AnalyzeAlertRequest(BaseModel):
    alert: Dict[str, Any]

class AnomalyRequest(BaseModel):
    features: List[float]  # [bytes_sent, bytes_recv, duration, port, protocol_num, hour]
    source_ip: str

class ClassifyRequest(BaseModel):
    features: List[float]
    source_ip: str
    raw_log: str

class ThreatHuntRequest(BaseModel):
    query: str
    time_range_hours: int = 24

class ReportRequest(BaseModel):
    incident_ids: List[str]
    report_type: str = "executive"  # executive | technical | summary

class PredictionRequest(BaseModel):
    ip: str
    recent_events: List[Dict]

# ─── Feature Extraction ──────────────────────────────────────
def extract_features(event: dict) -> np.ndarray:
    """Extract numerical features from a log/alert event."""
    raw = event.get("raw_log", "")
    ts  = event.get("timestamp", datetime.now(timezone.utc).isoformat())
    try:
        hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
    except Exception:
        hour = 0

    features = [
        len(raw),                                          # log length
        raw.count(" "),                                    # word count proxy
        hour,                                              # hour of day
        1 if "failed" in raw.lower() else 0,              # failure flag
        1 if "sudo" in raw.lower() else 0,                # priv flag
        1 if "root" in raw.lower() else 0,                # root flag
        1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', raw) else 0,  # IP present
        len(re.findall(r'[A-Z]', raw)),                    # uppercase count
        1 if "powershell" in raw.lower() else 0,          # PS flag
        1 if any(x in raw.lower() for x in ["bash", "sh", "cmd"]) else 0,    # shell
    ]
    return np.array(features, dtype=float)

import re

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global producer, os_client, redis_client, llm, models_trained

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

    # Try to init LLM (non-blocking — Ollama may not be ready)
    try:
        llm = Ollama(base_url=OLLAMA_URL, model=OLLAMA_MODEL, timeout=30)
        logger.info(f"LLM initialized: {OLLAMA_MODEL}")
    except Exception as e:
        logger.warning(f"LLM not available: {e}")

    # Train models on synthetic baseline data
    _train_models()

    # Start background alert consumer
    asyncio.create_task(_consume_alerts())
    logger.info("AI Engine started")

def _train_models():
    """Train anomaly + classification models on synthetic baseline."""
    global models_trained
    import numpy as np
    rng = np.random.default_rng(42)
    # Generate synthetic normal data
    X_normal = rng.normal(loc=50, scale=15, size=(500, 10)).clip(0, 200)
    # Generate synthetic anomalies
    X_anomaly = rng.normal(loc=150, scale=30, size=(50, 10)).clip(0, 500)
    X_all = np.vstack([X_normal, X_anomaly])

    scaler.fit(X_all)
    X_scaled = scaler.transform(X_all)
    isolation_forest.fit(X_scaled)

    # Classification labels
    y = np.zeros(len(X_all), dtype=int)
    y[-50:] = rng.integers(1, len(ATTACK_CLASSES), size=50)
    rf_classifier.fit(X_scaled, y)
    xgb_classifier.fit(X_scaled, y)
    models_trained = True
    logger.info("ML models trained on baseline data")

@app.on_event("shutdown")
async def shutdown():
    if producer:    await producer.stop()
    if os_client:   await os_client.close()
    if redis_client:await redis_client.close()

# ─── Background Alert Consumer ───────────────────────────────
async def _consume_alerts():
    consumer = AIOKafkaConsumer(
        KAFKA_ALERT_TOPIC,
        bootstrap_servers=KAFKA_SERVERS,
        group_id="ai-engine",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    await consumer.start()
    try:
        async for msg in consumer:
            await _ai_enrich_alert(msg.value)
    finally:
        await consumer.stop()

async def _ai_enrich_alert(alert: dict):
    """Auto-enrich every alert with AI analysis and store back."""
    if not llm:
        return
    try:
        chain = LLMChain(llm=llm, prompt=ANALYST_PROMPT)
        analysis = await asyncio.get_event_loop().run_in_executor(
            None, lambda: chain.run(alert=json.dumps(alert, indent=2))
        )
        alert["ai_analysis"] = analysis
        alert["ai_enriched_at"] = datetime.now(timezone.utc).isoformat()
        await os_client.index(
            index="sentinelai-alerts",
            body=alert,
            id=alert.get("alert_id"),
        )
    except Exception as e:
        logger.error(f"AI enrichment failed: {e}")

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ai-service",
        "models_trained": models_trained,
        "llm_available": llm is not None,
    }

@app.post("/ai/analyze-alert")
async def analyze_alert(req: AnalyzeAlertRequest):
    """AI security analyst explanation of an alert."""
    if not llm:
        return {"error": "LLM not available", "analysis": _rule_based_analysis(req.alert)}
    try:
        chain = LLMChain(llm=llm, prompt=ANALYST_PROMPT)
        analysis = chain.run(alert=json.dumps(req.alert, indent=2))
        return {"analysis": analysis, "model": OLLAMA_MODEL}
    except Exception as e:
        logger.error(f"Alert analysis failed: {e}")
        return {"error": str(e), "analysis": _rule_based_analysis(req.alert)}

@app.post("/ai/anomaly-detect")
async def detect_anomaly(req: AnomalyRequest):
    """Run Isolation Forest anomaly detection on event features."""
    if not models_trained:
        raise HTTPException(503, "Models not yet trained")
    X = np.array(req.features).reshape(1, -1)
    X_scaled = scaler.transform(X)
    prediction = isolation_forest.predict(X_scaled)[0]
    score = isolation_forest.score_samples(X_scaled)[0]
    is_anomaly = prediction == -1
    return {
        "is_anomaly":    is_anomaly,
        "anomaly_score": float(score),
        "risk_level":    "high" if score < -0.5 else "medium" if score < -0.2 else "low",
        "source_ip":     req.source_ip,
    }

@app.post("/ai/classify-attack")
async def classify_attack(req: ClassifyRequest):
    """Multi-class attack classification using XGBoost + RandomForest."""
    if not models_trained:
        raise HTTPException(503, "Models not yet trained")
    X = np.array(req.features).reshape(1, -1)
    X_scaled = scaler.transform(X)

    rf_proba  = rf_classifier.predict_proba(X_scaled)[0]
    xgb_proba = xgb_classifier.predict_proba(X_scaled)[0]
    # Ensemble: average probabilities
    avg_proba = (rf_proba + xgb_proba) / 2
    predicted_class = int(np.argmax(avg_proba))
    confidence = float(avg_proba[predicted_class])

    return {
        "attack_class":  ATTACK_CLASSES[predicted_class],
        "confidence":    round(confidence, 4),
        "probabilities": {
            cls: round(float(p), 4)
            for cls, p in zip(ATTACK_CLASSES, avg_proba)
        },
        "source_ip": req.source_ip,
    }

@app.post("/ai/threat-hunt")
async def threat_hunt(req: ThreatHuntRequest):
    """AI-powered threat hunting assistant."""
    # Pull recent alerts as context
    body = {
        "query": {"range": {"timestamp": {"gte": f"now-{req.time_range_hours}h"}}},
        "sort":  [{"timestamp": {"order": "desc"}}],
        "size":  20,
    }
    resp = await os_client.search(index="sentinelai-alerts", body=body)
    context = json.dumps([h["_source"] for h in resp["hits"]["hits"]], indent=2)

    if not llm:
        return {"result": "LLM unavailable — install Ollama and pull llama3.2", "context_events": len(resp["hits"]["hits"])}

    chain = LLMChain(llm=llm, prompt=THREAT_HUNT_PROMPT)
    result = chain.run(query=req.query, context=context[:3000])
    return {"result": result, "context_events": len(resp["hits"]["hits"])}

@app.post("/ai/generate-report")
async def generate_report(req: ReportRequest):
    """Generate an AI incident report."""
    # Fetch incident details
    incidents = []
    for iid in req.incident_ids:
        try:
            r = await os_client.get(index="sentinelai-alerts", id=iid)
            incidents.append(r["_source"])
        except Exception:
            pass

    incident_data = json.dumps(incidents, indent=2)

    if not llm:
        return {"report": _static_report(incidents), "type": req.report_type}

    chain = LLMChain(llm=llm, prompt=REPORT_PROMPT)
    report = chain.run(incident_data=incident_data[:4000])
    return {"report": report, "type": req.report_type, "incident_count": len(incidents)}

@app.post("/ai/predict-threat")
async def predict_threat(req: PredictionRequest):
    """Predict likelihood of future attack based on recent events."""
    types = [e.get("detection_type", "") for e in req.recent_events]
    attack_indicators = {
        "recon":    ["port_scan", "dns_tunneling"],
        "initial":  ["brute_force", "phishing"],
        "escalate": ["privilege_escalation", "credential_dumping"],
        "exfil":    ["data_exfiltration", "lateral_movement"],
    }
    predictions = {}
    for stage, indicators in attack_indicators.items():
        matches = sum(1 for t in types if t in indicators)
        predictions[stage] = min(matches / len(indicators), 1.0)

    overall_risk = max(predictions.values()) if predictions else 0
    return {
        "ip": req.ip,
        "stage_probabilities": predictions,
        "overall_risk_score": round(overall_risk, 2),
        "risk_level": "critical" if overall_risk > 0.7 else "high" if overall_risk > 0.4 else "medium" if overall_risk > 0.2 else "low",
        "recommendation": _risk_recommendation(overall_risk),
    }

@app.get("/ai/stats")
async def ai_stats():
    return {
        "models": {
            "isolation_forest": {"trained": models_trained, "algorithm": "IsolationForest"},
            "random_forest":    {"trained": models_trained, "algorithm": "RandomForest"},
            "xgboost":          {"trained": models_trained, "algorithm": "XGBoost"},
        },
        "llm": {"available": llm is not None, "model": OLLAMA_MODEL},
        "attack_classes": ATTACK_CLASSES,
    }

# ─── Helpers ─────────────────────────────────────────────────
def _rule_based_analysis(alert: dict) -> str:
    sev  = alert.get("severity", "unknown").upper()
    name = alert.get("rule_name", "Unknown Rule")
    tech = alert.get("mitre_technique", "T0000")
    ip   = alert.get("source_ip", "unknown")
    return (
        f"## Threat Assessment\n"
        f"Detected {name} (Severity: {sev}) from {ip}. "
        f"MITRE ATT&CK: {tech}.\n\n"
        f"## Immediate Actions\n"
        f"1. Investigate source IP {ip}\n"
        f"2. Review associated logs\n"
        f"3. Consider blocking IP if malicious"
    )

def _static_report(incidents: list) -> str:
    return (
        f"## Incident Report\n"
        f"Total incidents analyzed: {len(incidents)}\n"
        f"Severities: {', '.join(set(i.get('severity','?') for i in incidents))}\n"
        f"Sources: {', '.join(set(i.get('source_ip','?') for i in incidents))}"
    )

def _risk_recommendation(score: float) -> str:
    if score > 0.7: return "IMMEDIATE ACTION: Isolate affected systems, engage IR team"
    if score > 0.4: return "HIGH PRIORITY: Block suspicious IPs, increase monitoring"
    if score > 0.2: return "MONITOR: Watch for escalation, review logs"
    return "LOW RISK: Continue standard monitoring"

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8004, reload=False)

# ─── Extended models (Autoencoder + OCSVM + DNN) ─────────────
try:
    from models_extended import EnsembleAnomalyDetector, DeepNeuralNetwork
    ensemble_detector = EnsembleAnomalyDetector()
    dnn_classifier    = DeepNeuralNetwork(input_dim=10, n_classes=9)
    EXTENDED_MODELS_AVAILABLE = True
except Exception as _e:
    EXTENDED_MODELS_AVAILABLE = False
    logger.warning(f"Extended models not loaded: {_e}")

def _train_extended_models(X_all, y):
    global EXTENDED_MODELS_AVAILABLE
    try:
        ensemble_detector.fit(X_all)
        dnn_classifier.fit(X_all, y, epochs=50)
        EXTENDED_MODELS_AVAILABLE = True
        logger.info("Extended models (Autoencoder + OCSVM + DNN) trained")
    except Exception as e:
        logger.warning(f"Extended model training failed: {e}")

@app.post("/ai/ensemble-anomaly")
async def ensemble_anomaly(req: AnomalyRequest):
    """Ensemble anomaly detection: IsolationForest + Autoencoder + One-Class SVM."""
    if not EXTENDED_MODELS_AVAILABLE or not models_trained:
        raise HTTPException(503, "Extended models not ready — use /ai/anomaly-detect instead")
    X = np.array(req.features).reshape(1, -1)
    result = ensemble_detector.predict(X)
    result["source_ip"] = req.source_ip
    return result

@app.post("/ai/dnn-classify")
async def dnn_classify(req: ClassifyRequest):
    """Deep Neural Network attack classification."""
    if not EXTENDED_MODELS_AVAILABLE or not models_trained:
        raise HTTPException(503, "DNN not ready — use /ai/classify-attack instead")
    X = np.array(req.features).reshape(1, -1)
    X_scaled = scaler.transform(X)
    pred  = dnn_classifier.predict(X_scaled)[0]
    proba = dnn_classifier.predict_proba(X_scaled)[0]
    return {
        "attack_class":  ATTACK_CLASSES[int(pred)],
        "confidence":    round(float(proba[int(pred)]), 4),
        "probabilities": {c: round(float(p), 4) for c, p in zip(ATTACK_CLASSES, proba)},
        "model":         "DeepNeuralNetwork",
        "source_ip":     req.source_ip,
    }

# Wire AI rule generation routes
try:
    from missing_features import register_rule_generation_routes
    register_rule_generation_routes(app, OLLAMA_URL, OLLAMA_MODEL)
    logger.info("AI rule generation routes registered")
except Exception as _e:
    logger.warning(f"Rule generation routes not loaded: {_e}")
