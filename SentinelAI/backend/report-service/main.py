"""
SentinelAI — Report Service
PDF + HTML incident report generation with statistics
"""
import os, json, io
from datetime import datetime, timezone, timedelta
from typing import Optional, List

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from opensearchpy import AsyncOpenSearch
import asyncpg
import aioredis
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor, black, white
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib import colors
from loguru import logger
import uvicorn

OS_HOST      = os.getenv("OPENSEARCH_HOST", "opensearch")
OS_PORT      = int(os.getenv("OPENSEARCH_PORT", 9200))
OS_USER      = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS      = os.getenv("OPENSEARCH_PASSWORD", "admin")
DATABASE_URL = os.getenv("DATABASE_URL", "")
REDIS_URL    = os.getenv("REDIS_URL", "redis://redis:6379/0")

# SentinelAI brand colors
SENTINEL_DARK  = HexColor("#0A0E1A")
SENTINEL_BLUE  = HexColor("#00D4FF")
SENTINEL_RED   = HexColor("#FF3B3B")
SENTINEL_GREEN = HexColor("#00FF88")
SENTINEL_GREY  = HexColor("#1A2035")

app = FastAPI(title="SentinelAI Report Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

os_client    = None
redis_client = None

class ReportRequest(BaseModel):
    report_type:    str = "executive"  # executive | technical | summary | compliance
    time_range_h:   int = 24
    include_alerts: bool = True
    include_stats:  bool = True
    title:          Optional[str] = None
    prepared_by:    str = "SentinelAI Auto-Reporter"

@app.on_event("startup")
async def startup():
    global os_client, redis_client
    os_client = AsyncOpenSearch(
        hosts=[{"host": OS_HOST, "port": OS_PORT}],
        http_auth=(OS_USER, OS_PASS),
        use_ssl=False, verify_certs=False,
    )
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)

@app.on_event("shutdown")
async def shutdown():
    if os_client:    await os_client.close()
    if redis_client: await redis_client.close()

async def _fetch_report_data(time_range_h: int) -> dict:
    """Fetch alerts and stats for the report period."""
    body = {
        "query":  {"range": {"timestamp": {"gte": f"now-{time_range_h}h"}}},
        "sort":   [{"timestamp": {"order": "desc"}}],
        "size":   500,
        "aggs": {
            "by_severity":  {"terms": {"field": "severity"}},
            "by_type":      {"terms": {"field": "detection_type"}},
            "by_technique": {"terms": {"field": "mitre_technique"}},
            "by_host":      {"terms": {"field": "hostname", "size": 10}},
            "correlated":   {"filter": {"term": {"correlated": True}}},
        }
    }
    try:
        resp = await os_client.search(index="sentinelai-alerts", body=body)
        alerts = [h["_source"] for h in resp["hits"]["hits"]]
        aggs   = resp.get("aggregations", {})
    except Exception as e:
        logger.error(f"OpenSearch query failed: {e}")
        alerts, aggs = [], {}

    sev_counts = {b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])}
    type_counts = {b["key"]: b["doc_count"] for b in aggs.get("by_type", {}).get("buckets", [])}
    tech_counts = {b["key"]: b["doc_count"] for b in aggs.get("by_technique", {}).get("buckets", [])}

    return {
        "alerts":        alerts,
        "total":         len(alerts),
        "sev_counts":    sev_counts,
        "type_counts":   type_counts,
        "tech_counts":   tech_counts,
        "critical":      sev_counts.get("critical", 0),
        "high":          sev_counts.get("high", 0),
        "medium":        sev_counts.get("medium", 0),
        "low":           sev_counts.get("low", 0),
        "correlated":    aggs.get("correlated", {}).get("doc_count", 0),
    }

def _build_pdf(data: dict, req: ReportRequest) -> bytes:
    """Generate a professional PDF report."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle",
        fontSize=22, textColor=SENTINEL_BLUE,
        spaceAfter=6, fontName="Helvetica-Bold",
    )
    h2_style = ParagraphStyle(
        "SentinelH2",
        fontSize=14, textColor=SENTINEL_BLUE,
        spaceAfter=4, fontName="Helvetica-Bold",
    )
    body_style = ParagraphStyle(
        "SentinelBody",
        fontSize=10, textColor=HexColor("#333333"),
        spaceAfter=4, fontName="Helvetica",
    )
    stat_style = ParagraphStyle(
        "SentinelStat",
        fontSize=24, textColor=SENTINEL_RED,
        fontName="Helvetica-Bold", alignment=1,
    )

    story = []
    now   = datetime.now(timezone.utc)
    title = req.title or f"SentinelAI Security Report — {now.strftime('%Y-%m-%d')}"

    story.append(Paragraph("🛡️ SENTINELAI", title_style))
    story.append(Paragraph(title, h2_style))
    story.append(HRFlowable(width="100%", thickness=1, color=SENTINEL_BLUE))
    story.append(Spacer(1, 0.3*cm))
    story.append(Paragraph(f"Report Type: {req.report_type.upper()} | Period: Last {req.time_range_h}h | Generated: {now.strftime('%Y-%m-%d %H:%M UTC')} | Prepared by: {req.prepared_by}", body_style))
    story.append(Spacer(1, 0.5*cm))

    # ── Executive Summary ───────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_style))
    crit = data["critical"]; high = data["high"]
    risk = "CRITICAL" if crit > 5 else "HIGH" if high > 10 else "MEDIUM" if data["total"] > 20 else "LOW"
    summary = (
        f"During the past {req.time_range_h} hours, SentinelAI detected a total of <b>{data['total']} security alerts</b>. "
        f"Of these, <b>{crit} were Critical</b> and <b>{high} were High severity</b>. "
        f"<b>{data['correlated']}</b> alerts were part of correlated attack chains, indicating coordinated threat activity. "
        f"Overall risk posture is assessed as: <b>{risk}</b>."
    )
    story.append(Paragraph(summary, body_style))
    story.append(Spacer(1, 0.4*cm))

    # ── Key Metrics Table ───────────────────────────────────
    story.append(Paragraph("Alert Summary", h2_style))
    metrics_data = [
        ["Metric", "Count", "Status"],
        ["Total Alerts",   str(data["total"]),    "—"],
        ["Critical",       str(data["critical"]), "🔴 CRITICAL"],
        ["High",           str(data["high"]),     "🟠 HIGH"],
        ["Medium",         str(data["medium"]),   "🟡 MEDIUM"],
        ["Low",            str(data["low"]),      "🟢 LOW"],
        ["Attack Chains",  str(data["correlated"]),"⛓️ CORRELATED"],
    ]
    t = Table(metrics_data, colWidths=[8*cm, 3*cm, 5*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  SENTINEL_GREY),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  SENTINEL_BLUE),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#F9F9F9"), white]),
        ("GRID",         (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
        ("ALIGN",        (1, 0), (1, -1),  "CENTER"),
        ("TOPPADDING",   (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4*cm))

    # ── Top Attack Types ────────────────────────────────────
    if data["type_counts"]:
        story.append(Paragraph("Top Attack Types", h2_style))
        type_data = [["Attack Type", "Count"]] + [
            [k.replace("_", " ").title(), str(v)]
            for k, v in sorted(data["type_counts"].items(), key=lambda x: -x[1])[:10]
        ]
        t2 = Table(type_data, colWidths=[11*cm, 5*cm])
        t2.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SENTINEL_GREY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  SENTINEL_BLUE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 10),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [HexColor("#F9F9F9"), white]),
            ("GRID",          (0, 0), (-1, -1), 0.5, HexColor("#CCCCCC")),
            ("TOPPADDING",    (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t2)
        story.append(Spacer(1, 0.4*cm))

    # ── Recent Critical Alerts ──────────────────────────────
    critical_alerts = [a for a in data["alerts"] if a.get("severity") in ("critical", "high")][:15]
    if critical_alerts:
        story.append(Paragraph("Recent High/Critical Alerts", h2_style))
        alert_rows = [["Timestamp", "Rule", "Source IP", "Technique", "Severity"]]
        for a in critical_alerts:
            ts  = a.get("timestamp", "")[:19].replace("T", " ")
            alert_rows.append([
                ts,
                a.get("rule_name", "")[:30],
                a.get("source_ip", ""),
                a.get("mitre_technique", ""),
                a.get("severity", "").upper(),
            ])
        t3 = Table(alert_rows, colWidths=[3.5*cm, 5.5*cm, 3*cm, 2*cm, 2.5*cm])
        t3.setStyle(TableStyle([
            ("BACKGROUND",    (0, 0), (-1, 0),  SENTINEL_GREY),
            ("TEXTCOLOR",     (0, 0), (-1, 0),  SENTINEL_BLUE),
            ("FONTNAME",      (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",      (0, 0), (-1, -1), 8),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [HexColor("#FFF8F8"), white]),
            ("GRID",          (0, 0), (-1, -1), 0.4, HexColor("#DDDDDD")),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("WORDWRAP",      (0, 0), (-1, -1), True),
        ]))
        story.append(t3)
        story.append(Spacer(1, 0.4*cm))

    # ── Recommendations ─────────────────────────────────────
    story.append(Paragraph("Security Recommendations", h2_style))
    recs = _generate_recommendations(data)
    for i, rec in enumerate(recs, 1):
        story.append(Paragraph(f"{i}. {rec}", body_style))

    story.append(Spacer(1, 0.5*cm))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#CCCCCC")))
    story.append(Paragraph(f"Generated by SentinelAI Platform v1.0 | {now.strftime('%Y-%m-%d %H:%M UTC')} | CONFIDENTIAL", body_style))

    doc.build(story)
    return buf.getvalue()

def _generate_recommendations(data: dict) -> list:
    recs = []
    if data["critical"] > 0:
        recs.append("IMMEDIATE: Investigate and remediate all Critical alerts — engage IR team if attack chains detected.")
    if data["correlated"] > 0:
        recs.append("HIGH PRIORITY: Correlated attack chains indicate active adversary — consider network isolation of affected hosts.")
    if data.get("type_counts", {}).get("brute_force", 0) > 5:
        recs.append("Enable account lockout policies and enforce MFA on all remote access systems.")
    if data.get("type_counts", {}).get("lateral_movement", 0) > 0:
        recs.append("Review network segmentation and implement micro-segmentation to limit lateral movement.")
    if data.get("type_counts", {}).get("data_exfiltration", 0) > 0:
        recs.append("CRITICAL: Potential data breach — activate DLP controls and notify stakeholders per IR plan.")
    if data["total"] == 0:
        recs.append("No alerts detected in the review period. Verify that log collection agents are active and healthy.")
    recs.append("Review and update detection rules to address any gaps in coverage.")
    recs.append("Conduct tabletop exercise simulating top attack types detected this period.")
    return recs

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "report-service"}

@app.post("/reports/pdf")
async def generate_pdf_report(req: ReportRequest):
    """Generate and download a PDF security report."""
    data = await _fetch_report_data(req.time_range_h)
    pdf_bytes = _build_pdf(data, req)
    filename  = f"SentinelAI_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )

@app.post("/reports/json")
async def generate_json_report(req: ReportRequest):
    """Generate a structured JSON report for programmatic consumption."""
    data = await _fetch_report_data(req.time_range_h)
    recommendations = _generate_recommendations(data)
    return {
        "report_type":    req.report_type,
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "period_hours":   req.time_range_h,
        "summary":        {k: v for k, v in data.items() if k != "alerts"},
        "alerts":         data["alerts"][:50],
        "recommendations":recommendations,
    }

@app.get("/reports/stats")
async def get_stats(hours: int = 24):
    """Get platform-wide statistics."""
    data = await _fetch_report_data(hours)
    return {
        "period_hours":  hours,
        "total_alerts":  data["total"],
        "by_severity":   data["sev_counts"],
        "by_type":       data["type_counts"],
        "by_technique":  data["tech_counts"],
        "attack_chains": data["correlated"],
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8008, reload=False)
