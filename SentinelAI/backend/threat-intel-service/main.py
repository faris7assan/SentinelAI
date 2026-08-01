"""
SentinelAI — Threat Intelligence Service
VirusTotal + AbuseIPDB + AlienVault OTX + Shodan integration
"""
import os, json, asyncio, hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import aioredis
import httpx
import asyncpg
from loguru import logger
import uvicorn

# ─── Config ──────────────────────────────────────────────────
VT_API_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSE_API_KEY    = os.getenv("ABUSEIPDB_API_KEY", "")
OTX_API_KEY      = os.getenv("ALIENVAULT_OTX_KEY", "")
SHODAN_API_KEY   = os.getenv("SHODAN_API_KEY", "")
REDIS_URL        = os.getenv("REDIS_URL", "redis://redis:6379/0")
DATABASE_URL     = os.getenv("DATABASE_URL", "")
CACHE_TTL        = 3600  # 1 hour cache

app = FastAPI(title="SentinelAI Threat Intel", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

redis_client = None

# ─── Models ──────────────────────────────────────────────────
class IOCLookupRequest(BaseModel):
    ioc:      str
    ioc_type: str  # ip | domain | hash | url

class BulkLookupRequest(BaseModel):
    iocs: List[Dict[str, str]]  # [{"ioc": "1.2.3.4", "type": "ip"}]

class ThreatFeedRequest(BaseModel):
    feed_name: str
    iocs:      List[str]

# ─── Startup ─────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global redis_client
    redis_client = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Threat Intel Service started")

@app.on_event("shutdown")
async def shutdown():
    if redis_client: await redis_client.close()

# ─── VirusTotal ──────────────────────────────────────────────
async def vt_lookup_ip(ip: str) -> dict:
    cache_key = f"vt:ip:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not VT_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "ip": ip}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                result = {
                    "source":          "virustotal",
                    "ip":              ip,
                    "malicious":       attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious":      attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "harmless":        attrs.get("last_analysis_stats", {}).get("harmless", 0),
                    "country":         attrs.get("country", ""),
                    "as_owner":        attrs.get("as_owner", ""),
                    "reputation":      attrs.get("reputation", 0),
                    "last_analysis":   attrs.get("last_analysis_date", ""),
                    "tags":            attrs.get("tags", []),
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"VirusTotal IP lookup failed: {e}")
    return {"source": "virustotal", "status": "error", "ip": ip}

async def vt_lookup_hash(file_hash: str) -> dict:
    cache_key = f"vt:hash:{file_hash}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not VT_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "hash": file_hash}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data  = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                result = {
                    "source":      "virustotal",
                    "hash":        file_hash,
                    "malicious":   attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious":  attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "name":        attrs.get("meaningful_name", ""),
                    "type":        attrs.get("type_description", ""),
                    "size":        attrs.get("size", 0),
                    "tags":        attrs.get("tags", []),
                    "threat_names":attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"VirusTotal hash lookup failed: {e}")
    return {"source": "virustotal", "status": "error", "hash": file_hash}

async def vt_lookup_domain(domain: str) -> dict:
    cache_key = f"vt:domain:{domain}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not VT_API_KEY:
        return {"source": "virustotal", "status": "no_api_key", "domain": domain}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": VT_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data  = resp.json()
                attrs = data.get("data", {}).get("attributes", {})
                result = {
                    "source":     "virustotal",
                    "domain":     domain,
                    "malicious":  attrs.get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": attrs.get("last_analysis_stats", {}).get("suspicious", 0),
                    "categories": attrs.get("categories", {}),
                    "reputation": attrs.get("reputation", 0),
                    "registrar":  attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"VirusTotal domain lookup failed: {e}")
    return {"source": "virustotal", "status": "error", "domain": domain}

# ─── AbuseIPDB ───────────────────────────────────────────────
async def abuseipdb_lookup(ip: str) -> dict:
    cache_key = f"abuse:ip:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not ABUSE_API_KEY:
        return {"source": "abuseipdb", "status": "no_api_key", "ip": ip}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "source":             "abuseipdb",
                    "ip":                 ip,
                    "abuse_confidence":   data.get("abuseConfidenceScore", 0),
                    "total_reports":      data.get("totalReports", 0),
                    "country_code":       data.get("countryCode", ""),
                    "isp":                data.get("isp", ""),
                    "domain":             data.get("domain", ""),
                    "is_whitelisted":     data.get("isWhitelisted", False),
                    "usage_type":         data.get("usageType", ""),
                    "last_reported":      data.get("lastReportedAt", ""),
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed: {e}")
    return {"source": "abuseipdb", "status": "error", "ip": ip}

# ─── AlienVault OTX ──────────────────────────────────────────
async def otx_lookup_ip(ip: str) -> dict:
    cache_key = f"otx:ip:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    if not OTX_API_KEY:
        return {"source": "alienvault_otx", "status": "no_api_key", "ip": ip}

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                headers={"X-OTX-API-KEY": OTX_API_KEY},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "source":        "alienvault_otx",
                    "ip":            ip,
                    "pulse_count":   data.get("pulse_info", {}).get("count", 0),
                    "reputation":    data.get("reputation", 0),
                    "country_name":  data.get("country_name", ""),
                    "asn":           data.get("asn", ""),
                    "malware_families": [
                        p.get("name") for p in
                        data.get("pulse_info", {}).get("pulses", [])[:5]
                    ],
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"OTX lookup failed: {e}")
    return {"source": "alienvault_otx", "status": "error", "ip": ip}

# ─── Threat Score Calculator ─────────────────────────────────
def calculate_threat_score(vt: dict, abuse: dict, otx: dict) -> dict:
    score = 0
    reasons = []

    vt_mal = vt.get("malicious", 0)
    if vt_mal > 0:
        score += min(vt_mal * 5, 40)
        reasons.append(f"VirusTotal: {vt_mal} malicious detections")

    abuse_conf = abuse.get("abuse_confidence", 0)
    if abuse_conf > 0:
        score += int(abuse_conf * 0.4)
        reasons.append(f"AbuseIPDB confidence: {abuse_conf}%")

    pulse_count = otx.get("pulse_count", 0)
    if pulse_count > 0:
        score += min(pulse_count * 2, 20)
        reasons.append(f"OTX pulses: {pulse_count}")

    score = min(score, 100)
    verdict = (
        "CRITICAL" if score >= 80 else
        "HIGH"     if score >= 60 else
        "MEDIUM"   if score >= 30 else
        "LOW"      if score >= 10 else
        "CLEAN"
    )
    return {"score": score, "verdict": verdict, "reasons": reasons}

# ─── Routes ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "threat-intel-service"}

@app.get("/intel/ip/{ip}")
async def lookup_ip(ip: str):
    """Full IP enrichment from all threat intel sources."""
    vt, abuse, otx = await asyncio.gather(
        vt_lookup_ip(ip),
        abuseipdb_lookup(ip),
        otx_lookup_ip(ip),
    )
    threat_score = calculate_threat_score(vt, abuse, otx)
    return {
        "ip":           ip,
        "threat_score": threat_score,
        "virustotal":   vt,
        "abuseipdb":    abuse,
        "otx":          otx,
        "queried_at":   datetime.now(timezone.utc).isoformat(),
    }

@app.get("/intel/hash/{file_hash}")
async def lookup_hash(file_hash: str):
    """File hash malware lookup via VirusTotal."""
    result = await vt_lookup_hash(file_hash)
    is_malicious = result.get("malicious", 0) > 0
    return {
        "hash":         file_hash,
        "is_malicious": is_malicious,
        "verdict":      "MALICIOUS" if is_malicious else "CLEAN",
        "virustotal":   result,
        "queried_at":   datetime.now(timezone.utc).isoformat(),
    }

@app.get("/intel/domain/{domain}")
async def lookup_domain(domain: str):
    """Domain reputation lookup."""
    vt = await vt_lookup_domain(domain)
    otx_result = {"source": "otx", "status": "domain lookup not implemented"}
    return {
        "domain":     domain,
        "virustotal": vt,
        "otx":        otx_result,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/intel/bulk")
async def bulk_lookup(req: BulkLookupRequest):
    """Bulk IOC enrichment."""
    results = []
    for item in req.iocs[:50]:  # Max 50 per request
        ioc, ioc_type = item["ioc"], item["ioc_type"]
        if ioc_type == "ip":
            r = await lookup_ip(ioc)
        elif ioc_type == "hash":
            r = await lookup_hash(ioc)
        elif ioc_type == "domain":
            r = await lookup_domain(ioc)
        else:
            r = {"ioc": ioc, "error": "unsupported type"}
        results.append(r)
    return {"results": results, "count": len(results)}

@app.get("/intel/feed/malicious-ips")
async def get_malicious_ip_feed():
    """Return known malicious IPs from our cache."""
    keys = await redis_client.keys("vt:ip:*")
    malicious = []
    for key in keys[:100]:
        data = await redis_client.get(key)
        if data:
            d = json.loads(data)
            if d.get("malicious", 0) > 2:
                malicious.append(d)
    return {"malicious_ips": malicious, "count": len(malicious)}

@app.get("/intel/cve/{cve_id}")
async def lookup_cve(cve_id: str):
    """Look up CVE details from NVD."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {}) if metrics.get("cvssMetricV31") else {}
                    return {
                        "cve_id":       cve_id,
                        "description":  cve.get("descriptions", [{}])[0].get("value", ""),
                        "cvss_score":   cvss_v3.get("baseScore", "N/A"),
                        "severity":     cvss_v3.get("baseSeverity", "N/A"),
                        "published":    cve.get("published", ""),
                        "modified":     cve.get("lastModified", ""),
                    }
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
    raise HTTPException(404, f"CVE {cve_id} not found")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8006, reload=False)


# ─── MISP Integration ────────────────────────────────────────
async def misp_search_ioc(ioc: str, ioc_type: str) -> dict:
    """Search for an IOC in MISP threat sharing platform."""
    MISP_URL = os.getenv("MISP_URL", "")
    MISP_KEY = os.getenv("MISP_API_KEY", "")
    cache_key = f"misp:{ioc_type}:{ioc}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    if not MISP_URL or not MISP_KEY:
        return {"source": "misp", "status": "not_configured", "ioc": ioc}
    async with httpx.AsyncClient(verify=False) as client:
        try:
            resp = await client.post(
                f"{MISP_URL}/attributes/restSearch",
                headers={"Authorization": MISP_KEY, "Accept": "application/json", "Content-Type": "application/json"},
                json={"returnFormat": "json", "value": ioc, "type": ioc_type, "limit": 10},
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                attrs = data.get("response", {}).get("Attribute", [])
                result = {
                    "source":    "misp",
                    "ioc":       ioc,
                    "ioc_type":  ioc_type,
                    "found":     len(attrs) > 0,
                    "hit_count": len(attrs),
                    "events":    [a.get("Event", {}).get("info", "") for a in attrs[:5]],
                    "tags":      list({t["name"] for a in attrs for t in a.get("Tag", [])})[:10],
                    "threat_level": attrs[0].get("Event", {}).get("threat_level_id", 0) if attrs else 0,
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"MISP lookup failed: {e}")
    return {"source": "misp", "status": "error", "ioc": ioc}


# ─── OpenCTI Integration ─────────────────────────────────────
async def opencti_search_indicator(value: str) -> dict:
    """Search OpenCTI for threat indicators via GraphQL API."""
    OPENCTI_URL = os.getenv("OPENCTI_URL", "")
    OPENCTI_KEY = os.getenv("OPENCTI_API_KEY", "")
    cache_key = f"opencti:{value}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    if not OPENCTI_URL or not OPENCTI_KEY:
        return {"source": "opencti", "status": "not_configured", "value": value}
    query = """
    query SearchIndicators($value: String!) {
      indicators(filters: {key: "value", values: [$value]}, first: 5) {
        edges {
          node {
            id
            name
            pattern
            indicator_types
            confidence
            valid_from
            valid_until
            x_opencti_score
            created_by { name }
            objectLabel { value }
          }
        }
      }
    }
    """
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{OPENCTI_URL}/graphql",
                headers={"Authorization": f"Bearer {OPENCTI_KEY}", "Content-Type": "application/json"},
                json={"query": query, "variables": {"value": value}},
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                edges = data.get("data", {}).get("indicators", {}).get("edges", [])
                result = {
                    "source":    "opencti",
                    "value":     value,
                    "found":     len(edges) > 0,
                    "count":     len(edges),
                    "indicators": [
                        {
                            "name":            e["node"].get("name"),
                            "types":           e["node"].get("indicator_types", []),
                            "confidence":      e["node"].get("confidence", 0),
                            "score":           e["node"].get("x_opencti_score", 0),
                            "labels":          [l["value"] for l in e["node"].get("objectLabel", [])],
                        }
                        for e in edges
                    ],
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
        except Exception as e:
            logger.error(f"OpenCTI search failed: {e}")
    return {"source": "opencti", "status": "error", "value": value}


# ─── Shodan Integration ───────────────────────────────────────
async def shodan_lookup_ip(ip: str) -> dict:
    """Get Shodan host intelligence for an IP address."""
    SHODAN_KEY = os.getenv("SHODAN_API_KEY", "")
    cache_key  = f"shodan:ip:{ip}"
    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)
    if not SHODAN_KEY:
        return {"source": "shodan", "status": "not_configured", "ip": ip}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_KEY}",
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "source":        "shodan",
                    "ip":            ip,
                    "org":           data.get("org", ""),
                    "isp":           data.get("isp", ""),
                    "country_code":  data.get("country_code", ""),
                    "city":          data.get("city", ""),
                    "os":            data.get("os", ""),
                    "open_ports":    data.get("ports", []),
                    "hostnames":     data.get("hostnames", []),
                    "vulns":         list(data.get("vulns", {}).keys())[:10],
                    "tags":          data.get("tags", []),
                    "last_update":   data.get("last_update", ""),
                    "services":      [
                        {"port": s.get("port"), "transport": s.get("transport"), "product": s.get("product", "")}
                        for s in data.get("data", [])[:10]
                    ],
                }
                await redis_client.setex(cache_key, CACHE_TTL, json.dumps(result))
                return result
            elif resp.status_code == 404:
                return {"source": "shodan", "status": "not_found", "ip": ip}
        except Exception as e:
            logger.error(f"Shodan lookup failed: {e}")
    return {"source": "shodan", "status": "error", "ip": ip}


# ─── Enhanced IP lookup with all 5 sources ──────────────────
@app.get("/intel/ip/full/{ip}")
async def full_ip_lookup(ip: str):
    """Full IP enrichment: VirusTotal + AbuseIPDB + OTX + Shodan + MISP + OpenCTI."""
    vt, abuse, otx, shodan_data, misp_data, opencti_data = await asyncio.gather(
        vt_lookup_ip(ip),
        abuseipdb_lookup(ip),
        otx_lookup_ip(ip),
        shodan_lookup_ip(ip),
        misp_search_ioc(ip, "ip-dst"),
        opencti_search_indicator(ip),
    )
    threat_score = calculate_threat_score(vt, abuse, otx)
    # Boost score for Shodan vulns
    vuln_count = len(shodan_data.get("vulns", []))
    if vuln_count > 0:
        threat_score["score"] = min(threat_score["score"] + vuln_count * 5, 100)
        threat_score["reasons"].append(f"Shodan: {vuln_count} known CVEs on open ports")
    # Boost for MISP hits
    if misp_data.get("found"):
        threat_score["score"] = min(threat_score["score"] + 15, 100)
        threat_score["reasons"].append(f"MISP: matched {misp_data['hit_count']} threat events")
    return {
        "ip":          ip,
        "threat_score":threat_score,
        "virustotal":  vt,
        "abuseipdb":   abuse,
        "otx":         otx,
        "shodan":      shodan_data,
        "misp":        misp_data,
        "opencti":     opencti_data,
        "queried_at":  datetime.now(timezone.utc).isoformat(),
    }

@app.get("/intel/misp/search")
async def misp_search(ioc: str, ioc_type: str = "ip-dst"):
    return await misp_search_ioc(ioc, ioc_type)

@app.get("/intel/opencti/search")
async def opencti_search(value: str):
    return await opencti_search_indicator(value)

@app.get("/intel/shodan/{ip}")
async def shodan_ip(ip: str):
    return await shodan_lookup_ip(ip)
