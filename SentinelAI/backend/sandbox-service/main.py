"""
SentinelAI — Malware Sandbox Service
File static analysis + behavioral analysis in local dev mode
YARA scanning + hash lookup + behavioral analysis
"""
import os, json, asyncio, hashlib, tempfile, subprocess, shutil
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path
import magic  # python-magic for MIME type detection

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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
VT_API_KEY        = os.getenv("VIRUSTOTAL_API_KEY", "")
CUCKOO_URL        = os.getenv("CUCKOO_API_URL", "http://cuckoo:8090")
SANDBOX_DIR       = Path("/tmp/sentinelai-sandbox")
YARA_RULES_DIR    = Path("/app/detection-rules/yara")
MAX_FILE_SIZE     = 50 * 1024 * 1024  # 50 MB

app = FastAPI(title="SentinelAI Sandbox Service", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

producer     = None
redis_client = None

# ─── Dangerous file indicators ───────────────────────────────
DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".jar",
    ".scr", ".pif", ".com", ".msi", ".hta", ".lnk", ".wsf", ".reg",
    ".sh", ".elf", ".deb", ".rpm", ".py", ".rb", ".php",
}

SUSPICIOUS_STRINGS = [
    b"MZ",          # Windows PE header
    b"\x7fELF",     # ELF header
    b"powershell",  # PowerShell
    b"cmd.exe",
    b"WScript",
    b"HKEY_",       # Registry access
    b"/dev/tcp",    # Reverse shell
    b"base64",
    b"eval(",
    b"exec(",
    b"socket.connect",
    b"CreateRemoteThread",
    b"VirtualAlloc",
    b"WriteProcessMemory",
]

# ─── YARA Rules (inline) ─────────────────────────────────────
INLINE_YARA_RULES = """
rule MaliciousPE {
    meta: description = "Detects PE files with suspicious imports"
    strings:
        $s1 = "VirtualAlloc" nocase
        $s2 = "WriteProcessMemory" nocase
        $s3 = "CreateRemoteThread" nocase
        $s4 = "NtUnmapViewOfSection" nocase
    condition: uint16(0) == 0x5A4D and 2 of them
}

rule SuspiciousScript {
    meta: description = "Suspicious scripting patterns"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "exec(base64_decode" nocase
        $s3 = "powershell -enc" nocase
        $s4 = "/dev/tcp" nocase
        $s5 = "IEX(New-Object" nocase
    condition: any of them
}

rule RansomwareIndicator {
    meta: description = "Generic ransomware strings"
    strings:
        $s1 = "bitcoin" nocase
        $s2 = "decrypt your files" nocase
        $s3 = "all your files have been" nocase
        $s4 = ".locked" nocase
    condition: 2 of them
}
"""

# ─── Models ──────────────────────────────────────────────────
class AnalysisResult(BaseModel):
    file_hash_md5:    str
    file_hash_sha256: str
    file_size:        int
    file_type:        str
    file_extension:   str
    is_malicious:     bool
    verdict:          str
    threat_score:     int
    static_analysis:  Dict[str, Any]
    yara_matches:     List[str]
    vt_result:        Optional[Dict] = None
    behavioral:       Optional[Dict] = None
    timestamp:        str

class HashLookupRequest(BaseModel):
    file_hash: str  # MD5, SHA1, or SHA256

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
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)
    logger.info("Sandbox service started")

@app.on_event("shutdown")
async def shutdown():
    if producer:     await producer.stop()
    if redis_client: await redis_client.close()
    # Clean up temp files
    if SANDBOX_DIR.exists():
        shutil.rmtree(SANDBOX_DIR, ignore_errors=True)

# ─── Static Analysis ─────────────────────────────────────────
def compute_hashes(data: bytes) -> dict:
    return {
        "md5":    hashlib.md5(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

def detect_file_type(data: bytes) -> str:
    try:
        return magic.from_buffer(data, mime=True)
    except Exception:
        return "application/octet-stream"

def scan_suspicious_strings(data: bytes) -> List[str]:
    found = []
    for pattern in SUSPICIOUS_STRINGS:
        if pattern in data:
            found.append(pattern.decode(errors="replace"))
    return found

def analyze_pe_header(data: bytes) -> dict:
    """Basic PE (Windows executable) header analysis."""
    result = {"is_pe": False}
    if len(data) < 2 or data[:2] != b"MZ":
        return result
    result["is_pe"] = True
    try:
        pe_offset = int.from_bytes(data[0x3C:0x40], "little")
        if data[pe_offset:pe_offset+4] == b"PE\x00\x00":
            result["has_pe_signature"] = True
            machine = int.from_bytes(data[pe_offset+4:pe_offset+6], "little")
            result["arch"] = "x64" if machine == 0x8664 else "x86" if machine == 0x014c else f"unknown({machine:#x})"
    except Exception:
        pass
    return result

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy — high entropy (>7.0) may indicate packing/encryption."""
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    entropy = 0.0
    n = len(data)
    for f in freq:
        if f > 0:
            p = f / n
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def run_yara_scan(data: bytes, filename: str) -> List[str]:
    """Run YARA rules against file data."""
    matches = []
    try:
        import yara
        rules = yara.compile(source=INLINE_YARA_RULES)

        # Also load rules from disk if available
        if YARA_RULES_DIR.exists():
            for rule_file in YARA_RULES_DIR.glob("*.yar"):
                try:
                    file_rules = yara.compile(filepath=str(rule_file))
                    file_matches = file_rules.match(data=data)
                    matches.extend(m.rule for m in file_matches)
                except Exception:
                    pass

        inline_matches = rules.match(data=data)
        matches.extend(m.rule for m in inline_matches)
    except ImportError:
        # YARA not installed — do string-based scan
        for pattern in [b"mimikatz", b"meterpreter", b"cobalt", b"metasploit"]:
            if pattern in data.lower():
                matches.append(f"StringMatch:{pattern.decode()}")
    except Exception as e:
        logger.error(f"YARA scan error: {e}")
    return list(set(matches))

def compute_threat_score(
    yara_matches: list, suspicious_strings: list,
    entropy: float, is_pe: bool, file_type: str, extension: str
) -> int:
    score = 0
    score += len(yara_matches) * 25
    score += min(len(suspicious_strings) * 5, 30)
    if entropy > 7.5: score += 20
    elif entropy > 6.5: score += 10
    if extension in DANGEROUS_EXTENSIONS: score += 15
    if is_pe and entropy > 7.0: score += 15
    if "script" in file_type.lower(): score += 10
    return min(score, 100)

# ─── VirusTotal Integration ───────────────────────────────────
async def vt_hash_lookup(sha256: str) -> Optional[dict]:
    cache_key = f"sandbox:vt:{sha256}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not VT_API_KEY:
        return None

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}",
                headers={"x-apikey": VT_API_KEY},
                timeout=15.0,
            )
            if resp.status_code == 200:
                data  = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                result = {
                    "malicious":    attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious":   attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless":     attrs.get("last_analysis_stats", {}).get("harmless", 0),
                    "threat_label": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                    "tags":         attrs.get("tags", []),
                    "type":         attrs.get("type_description", ""),
                    "name":         attrs.get("meaningful_name", ""),
                }
                await redis_client.setex(cache_key, 86400, json.dumps(result))
                return result
            elif resp.status_code == 404:
                return {"status": "not_found", "message": "File not in VirusTotal database"}
        except Exception as e:
            logger.error(f"VT lookup error: {e}")
    return None

# ─── Alert Publisher ─────────────────────────────────────────
async def publish_malware_alert(result: dict, filename: str):
    import uuid
    if not result["is_malicious"]:
        return

    alert = {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         "SANDBOX-001",
        "rule_name":       f"Malware Detected — {filename}",
        "severity":        "critical" if result["threat_score"] > 70 else "high",
        "detection_type":  "malware_execution",
        "source_ip":       "file-upload",
        "hostname":        "sandbox",
        "description":     (
            f"Malicious file detected: {filename}. "
            f"YARA matches: {', '.join(result['yara_matches']) or 'none'}. "
            f"Threat score: {result['threat_score']}/100."
        ),
        "mitre_tactic":    "Execution",
        "mitre_technique": "T1204",
        "raw_log":         json.dumps({
            "file_hash":  result["file_hash_sha256"],
            "file_type":  result["file_type"],
            "yara_hits":  result["yara_matches"],
            "vt_malicious": result.get("vt_result", {}).get("malicious", 0) if result.get("vt_result") else 0,
        }),
        "timestamp":       datetime.now(timezone.utc).isoformat(),
    }
    await producer.send(KAFKA_ALERT_TOPIC, alert)
    logger.critical(f"🦠 MALWARE DETECTED: {filename} — score={result['threat_score']}")

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "sandbox-service", "max_file_size_mb": MAX_FILE_SIZE // 1048576}

@app.post("/sandbox/analyze")
async def analyze_file(bg: BackgroundTasks, file: UploadFile = File(...)):
    """Upload and analyze a suspicious file."""
    if file.size and file.size > MAX_FILE_SIZE:
        raise HTTPException(413, "File too large — max 50MB")

    data     = await file.read()
    filename = file.filename or "unknown"
    ext      = Path(filename).suffix.lower()

    # Static analysis
    hashes   = compute_hashes(data)
    filetype = detect_file_type(data)
    entropy  = calculate_entropy(data)
    susp_str = scan_suspicious_strings(data)
    pe_info  = analyze_pe_header(data)
    yara_hits= run_yara_scan(data, filename)
    threat   = compute_threat_score(yara_hits, susp_str, entropy, pe_info.get("is_pe", False), filetype, ext)

    # VirusTotal lookup
    vt_result = await vt_hash_lookup(hashes["sha256"])

    # Adjust threat score from VT
    if vt_result and vt_result.get("malicious", 0) > 0:
        threat = min(threat + vt_result["malicious"] * 5, 100)

    verdict     = "MALICIOUS" if threat >= 50 else "SUSPICIOUS" if threat >= 25 else "CLEAN"
    is_malicious = threat >= 50

    result = {
        "file_hash_md5":    hashes["md5"],
        "file_hash_sha256": hashes["sha256"],
        "file_hash_sha1":   hashes["sha1"],
        "file_size":        len(data),
        "file_name":        filename,
        "file_type":        filetype,
        "file_extension":   ext,
        "is_malicious":     is_malicious,
        "verdict":          verdict,
        "threat_score":     threat,
        "static_analysis": {
            "entropy":           entropy,
            "entropy_note":      "High (>7.5) suggests packed/encrypted" if entropy > 7.5 else "Normal",
            "suspicious_strings":susp_str,
            "pe_info":           pe_info,
            "dangerous_ext":     ext in DANGEROUS_EXTENSIONS,
        },
        "yara_matches":     yara_hits,
        "vt_result":        vt_result,
        "behavioral":       None,  # Requires Cuckoo integration
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }

    # Cache result
    await redis_client.setex(
        f"sandbox:result:{hashes['sha256']}",
        86400,
        json.dumps(result)
    )

    # Publish alert if malicious
    if is_malicious:
        bg.add_task(publish_malware_alert, result, filename)

    return result

@app.post("/sandbox/hash")
async def lookup_by_hash(req: HashLookupRequest):
    """Look up a known hash in our cache + VirusTotal."""
    cache_key = f"sandbox:result:{req.file_hash}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    # Try VT lookup
    vt = await vt_hash_lookup(req.file_hash)
    if vt:
        is_malicious = vt.get("malicious", 0) > 0
        return {
            "file_hash_sha256": req.file_hash,
            "is_malicious":     is_malicious,
            "verdict":          "MALICIOUS" if is_malicious else "CLEAN",
            "threat_score":     min(vt.get("malicious", 0) * 10, 100),
            "vt_result":        vt,
            "source":           "virustotal",
        }
    return {"file_hash_sha256": req.file_hash, "verdict": "UNKNOWN", "source": "not_found"}

@app.get("/sandbox/results")
async def list_results(limit: int = 50):
    """List recent sandbox analysis results."""
    keys = await redis_client.keys("sandbox:result:*")
    results = []
    for key in keys[:limit]:
        raw = await redis_client.get(key)
        if raw:
            d = json.loads(raw)
            results.append({k: d[k] for k in ["file_name","file_hash_sha256","verdict","threat_score","timestamp"] if k in d})
    return sorted(results, key=lambda x: x.get("timestamp",""), reverse=True)

@app.get("/sandbox/stats")
async def sandbox_stats():
    keys = await redis_client.keys("sandbox:result:*")
    total = len(keys)
    malicious = 0
    for k in keys:
        raw = await redis_client.get(k)
        if raw and json.loads(raw).get("is_malicious"):
            malicious += 1
    return {
        "total_analyzed": total,
        "malicious":      malicious,
        "clean":          total - malicious,
        "detection_rate": f"{(malicious/total*100):.1f}%" if total else "0%",
    }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8011, reload=False)
