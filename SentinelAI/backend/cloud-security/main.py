"""
SentinelAI — Cloud Security Module
AWS / Azure / GCP security posture monitoring
Detects: IAM misuse, exposed buckets, suspicious API activity, privilege escalation
NIST 800-53 / CIS Benchmark checks
"""
import os, json, asyncio
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
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

# AWS
AWS_ACCESS_KEY  = os.getenv("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY  = os.getenv("AWS_SECRET_ACCESS_KEY", "")
AWS_REGION      = os.getenv("AWS_DEFAULT_REGION", "us-east-1")

# Azure
AZURE_TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
AZURE_CLIENT_ID = os.getenv("AZURE_CLIENT_ID", "")
AZURE_CLIENT_SECRET = os.getenv("AZURE_CLIENT_SECRET", "")
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")

app = FastAPI(title="SentinelAI Cloud Security", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer     = None
redis_client = None

# ─── CIS Benchmark Checks ─────────────────────────────────────
CIS_CHECKS_AWS = [
    {
        "check_id":   "CIS-AWS-1.1",
        "title":      "Root account MFA enabled",
        "severity":   "critical",
        "category":   "IAM",
        "nist_ref":   "AC-2",
        "description":"Root account should have MFA enabled to prevent unauthorized access",
    },
    {
        "check_id":   "CIS-AWS-1.4",
        "title":      "Access keys rotated every 90 days",
        "severity":   "high",
        "category":   "IAM",
        "nist_ref":   "AC-2",
        "description":"IAM access keys must be rotated regularly to minimize breach risk",
    },
    {
        "check_id":   "CIS-AWS-2.1",
        "title":      "CloudTrail enabled in all regions",
        "severity":   "high",
        "category":   "Logging",
        "nist_ref":   "AU-2",
        "description":"CloudTrail must log all regions for complete audit coverage",
    },
    {
        "check_id":   "CIS-AWS-2.3",
        "title":      "CloudTrail logs encrypted with KMS",
        "severity":   "medium",
        "category":   "Logging",
        "nist_ref":   "SC-28",
        "description":"CloudTrail log files should be encrypted using SSE-KMS",
    },
    {
        "check_id":   "CIS-AWS-2.6",
        "title":      "S3 bucket access logging enabled",
        "severity":   "medium",
        "category":   "Logging",
        "nist_ref":   "AU-2",
        "description":"Server access logging should be enabled for all S3 buckets",
    },
    {
        "check_id":   "CIS-AWS-4.1",
        "title":      "No security groups allow ingress 0.0.0.0/0 to port 22",
        "severity":   "critical",
        "category":   "Network",
        "nist_ref":   "SC-7",
        "description":"SSH access (port 22) must not be open to the world",
    },
    {
        "check_id":   "CIS-AWS-4.2",
        "title":      "No security groups allow ingress 0.0.0.0/0 to port 3389",
        "severity":   "critical",
        "category":   "Network",
        "nist_ref":   "SC-7",
        "description":"RDP access (port 3389) must not be open to the world",
    },
    {
        "check_id":   "CIS-AWS-3.1",
        "title":      "S3 buckets are not publicly accessible",
        "severity":   "critical",
        "category":   "Storage",
        "nist_ref":   "AC-3",
        "description":"S3 buckets must not allow public read/write access",
    },
    {
        "check_id":   "CIS-AWS-3.3",
        "title":      "IAM policies not attached directly to users",
        "severity":   "medium",
        "category":   "IAM",
        "nist_ref":   "AC-6",
        "description":"IAM permissions should be assigned via groups/roles, not directly to users",
    },
    {
        "check_id":   "CIS-AWS-5.1",
        "title":      "GuardDuty enabled",
        "severity":   "high",
        "category":   "Detection",
        "nist_ref":   "SI-3",
        "description":"AWS GuardDuty must be enabled for threat detection",
    },
]

# ─── Models ──────────────────────────────────────────────────
class CloudScanRequest(BaseModel):
    provider:    str    # aws | azure | gcp
    account_id:  Optional[str] = None
    region:      Optional[str] = None
    checks:      Optional[List[str]] = None  # specific check IDs, or None for all

class CloudEvent(BaseModel):
    provider:    str
    event_type:  str
    account_id:  str
    region:      str
    user:        Optional[str] = None
    resource:    Optional[str] = None
    action:      str
    source_ip:   Optional[str] = None
    raw_event:   Dict[str, Any] = {}
    timestamp:   Optional[str] = None

class CheckResult(BaseModel):
    check_id:    str
    title:       str
    status:      str    # PASS | FAIL | WARNING | UNKNOWN
    severity:    str
    category:    str
    nist_ref:    str
    description: str
    details:     str = ""
    remediation: str = ""

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
    logger.info("Cloud Security Module started")

@app.on_event("shutdown")
async def shutdown():
    if producer:     await producer.stop()
    if redis_client: await redis_client.close()

# ─── AWS Scanner ─────────────────────────────────────────────
async def scan_aws(region: str = "us-east-1") -> List[dict]:
    """
    Run CIS AWS Benchmark checks.
    Requires: boto3 + valid AWS credentials in environment.
    """
    results = []
    try:
        import boto3

        session = boto3.Session(
            aws_access_key_id=AWS_ACCESS_KEY or None,
            aws_secret_access_key=AWS_SECRET_KEY or None,
            region_name=region,
        )

        # ── IAM checks ──────────────────────────────────────
        iam = session.client("iam")

        try:
            summary = iam.get_account_summary()["SummaryMap"]
            root_mfa = summary.get("AccountMFAEnabled", 0)
            results.append({
                **CIS_CHECKS_AWS[0],
                "status":     "PASS" if root_mfa else "FAIL",
                "details":    f"Root MFA enabled: {bool(root_mfa)}",
                "remediation": "Enable MFA for root account via IAM console → Security credentials",
            })
        except Exception as e:
            results.append({**CIS_CHECKS_AWS[0], "status": "UNKNOWN", "details": str(e)})

        # ── S3 public access check ───────────────────────────
        try:
            s3 = session.client("s3")
            buckets = s3.list_buckets().get("Buckets", [])
            public_buckets = []
            for bucket in buckets[:20]:  # limit to 20
                name = bucket["Name"]
                try:
                    acl = s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            public_buckets.append(name)
                except Exception:
                    pass

            results.append({
                **CIS_CHECKS_AWS[7],
                "status":      "FAIL" if public_buckets else "PASS",
                "details":     f"Public buckets: {public_buckets}" if public_buckets else "No public buckets found",
                "remediation": "Apply S3 Block Public Access at the account level",
            })
        except Exception as e:
            results.append({**CIS_CHECKS_AWS[7], "status": "UNKNOWN", "details": str(e)})

        # ── Security Group checks ────────────────────────────
        try:
            ec2    = session.client("ec2", region_name=region)
            groups = ec2.describe_security_groups()["SecurityGroups"]
            open_ssh = [g["GroupId"] for g in groups
                for p in g.get("IpPermissions", [])
                if p.get("FromPort") == 22
                for r in p.get("IpRanges", [])
                if r.get("CidrIp") == "0.0.0.0/0"
            ]
            results.append({
                **CIS_CHECKS_AWS[5],
                "status":      "FAIL" if open_ssh else "PASS",
                "details":     f"Security groups with open SSH: {open_ssh}" if open_ssh else "No open SSH security groups",
                "remediation": "Restrict port 22 to specific trusted CIDR ranges",
            })
        except Exception as e:
            results.append({**CIS_CHECKS_AWS[5], "status": "UNKNOWN", "details": str(e)})

        # ── GuardDuty check ──────────────────────────────────
        try:
            gd = session.client("guardduty", region_name=region)
            detectors = gd.list_detectors()["DetectorIds"]
            gd_enabled = len(detectors) > 0
            results.append({
                **CIS_CHECKS_AWS[9],
                "status":     "PASS" if gd_enabled else "FAIL",
                "details":    f"GuardDuty detectors: {detectors}",
                "remediation": "Enable GuardDuty in all regions via Security Hub",
            })
        except Exception as e:
            results.append({**CIS_CHECKS_AWS[9], "status": "UNKNOWN", "details": str(e)})

    except ImportError:
        # boto3 not installed — return simulated results
        for check in CIS_CHECKS_AWS:
            results.append({
                **check,
                "status":      "UNKNOWN",
                "details":     "boto3 not installed — install with: pip install boto3",
                "remediation": check.get("description", ""),
            })

    return results

# ─── Cloud Event Analyzer ─────────────────────────────────────
SUSPICIOUS_CLOUD_ACTIONS = {
    # AWS CloudTrail events to watch
    "ConsoleLogin":              ("Initial Access",       "T1078"),
    "AssumeRole":                ("Privilege Escalation", "T1548"),
    "CreateUser":                ("Persistence",          "T1136"),
    "AttachUserPolicy":          ("Privilege Escalation", "T1548"),
    "CreateAccessKey":           ("Credential Access",    "T1528"),
    "DeleteTrail":               ("Defense Evasion",      "T1070"),
    "PutBucketAcl":              ("Exfiltration",         "T1537"),
    "GetSecretValue":            ("Credential Access",    "T1552"),
    "RunInstances":              ("Execution",            "T1204"),
    "ModifyInstanceAttribute":   ("Defense Evasion",      "T1578"),
    "AuthorizeSecurityGroupIngress": ("Initial Access",   "T1190"),
}

async def analyze_cloud_event(event: CloudEvent) -> Optional[dict]:
    action = event.action
    if action not in SUSPICIOUS_CLOUD_ACTIONS:
        return None

    tactic, technique = SUSPICIOUS_CLOUD_ACTIONS[action]
    import uuid
    alert = {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         f"CLOUD-{technique}",
        "rule_name":       f"Suspicious Cloud API: {action}",
        "severity":        "high" if technique.startswith("T1548") or action == "DeleteTrail" else "medium",
        "detection_type":  "cloud_api_abuse",
        "source_ip":       event.source_ip or "unknown",
        "hostname":        f"{event.provider}:{event.account_id}",
        "description":     (
            f"Suspicious {event.provider.upper()} API call: {action} "
            f"by {event.user or 'unknown'} in {event.region} on {event.resource or 'unknown'}"
        ),
        "mitre_tactic":    tactic,
        "mitre_technique": technique,
        "raw_log":         json.dumps(event.raw_event),
        "timestamp":       event.timestamp or datetime.now(timezone.utc).isoformat(),
        "extra": {
            "provider":   event.provider,
            "account_id": event.account_id,
            "region":     event.region,
            "user":       event.user,
            "action":     action,
            "resource":   event.resource,
        }
    }
    return alert

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "cloud-security"}

@app.post("/cloud/scan")
async def run_cloud_scan(req: CloudScanRequest, bg: BackgroundTasks):
    """Run CIS/NIST security posture scan against cloud account."""
    if req.provider == "aws":
        results = await scan_aws(req.region or AWS_REGION)
    else:
        results = [{
            "check_id":    f"{req.provider.upper()}-NOT-IMPL",
            "title":       f"{req.provider.upper()} scanning",
            "status":      "UNKNOWN",
            "severity":    "info",
            "category":    "General",
            "nist_ref":    "N/A",
            "description": f"{req.provider.upper()} scanning requires provider-specific SDK configuration",
            "details":     "See docs/ARCHITECTURE.md for setup instructions",
        }]

    # Calculate score
    total = len(results)
    passing = sum(1 for r in results if r["status"] == "PASS")
    failing = sum(1 for r in results if r["status"] == "FAIL")
    score = int((passing / total) * 100) if total else 0

    # Publish alerts for failures
    for r in results:
        if r["status"] == "FAIL" and r["severity"] in ("critical", "high"):
            bg.add_task(_publish_posture_alert, r, req.provider, req.account_id or "unknown")

    scan_result = {
        "provider":    req.provider,
        "account_id":  req.account_id,
        "region":      req.region,
        "scanned_at":  datetime.now(timezone.utc).isoformat(),
        "posture_score": score,
        "grade":       "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F",
        "summary": {
            "total": total, "passing": passing,
            "failing": failing, "unknown": total - passing - failing,
        },
        "checks":  results,
        "framework": "CIS Benchmark + NIST 800-53",
    }

    # Cache scan result
    await redis_client.setex(
        f"cloud:scan:{req.provider}:{req.account_id or 'default'}",
        3600,
        json.dumps(scan_result)
    )
    return scan_result

@app.post("/cloud/event")
async def ingest_cloud_event(event: CloudEvent, bg: BackgroundTasks):
    """Ingest and analyze a cloud API event (CloudTrail / Azure Monitor / GCP Audit)."""
    alert = await analyze_cloud_event(event)
    if alert:
        bg.add_task(producer.send, KAFKA_ALERT_TOPIC, alert)
        return {"status": "alert_generated", "alert_id": alert["alert_id"], "severity": alert["severity"]}
    return {"status": "benign", "action": event.action}

@app.get("/cloud/events/suspicious")
async def get_suspicious_events():
    """List monitored suspicious cloud API actions."""
    return [
        {"action": k, "tactic": v[0], "technique": v[1]}
        for k, v in SUSPICIOUS_CLOUD_ACTIONS.items()
    ]

@app.get("/cloud/scan/history")
async def scan_history():
    keys = await redis_client.keys("cloud:scan:*")
    results = []
    for k in keys:
        raw = await redis_client.get(k)
        if raw:
            d = json.loads(raw)
            results.append({
                "provider":      d.get("provider"),
                "account_id":    d.get("account_id"),
                "posture_score": d.get("posture_score"),
                "grade":         d.get("grade"),
                "scanned_at":    d.get("scanned_at"),
            })
    return sorted(results, key=lambda x: x.get("scanned_at",""), reverse=True)

async def _publish_posture_alert(check: dict, provider: str, account_id: str):
    import uuid
    alert = {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         check["check_id"],
        "rule_name":       f"Cloud Posture Failure: {check['title']}",
        "severity":        check["severity"],
        "detection_type":  "cloud_misconfiguration",
        "source_ip":       "cloud-scanner",
        "hostname":        f"{provider}:{account_id}",
        "description":     check["description"],
        "mitre_tactic":    "Defense Evasion",
        "mitre_technique": "T1562",
        "raw_log":         json.dumps(check),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }
    await producer.send(KAFKA_ALERT_TOPIC, alert)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8012, reload=False)
