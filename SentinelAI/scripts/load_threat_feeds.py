"""
SentinelAI — Threat Feed Loader
Fetches IOC feeds from public sources and loads into Redis/OpenSearch
Run daily via cron: 0 3 * * * python3 scripts/load_threat_feeds.py
"""
import os, json, asyncio, hashlib
from datetime import datetime, timezone
from pathlib import Path
import aioredis
import httpx
from loguru import logger

REDIS_URL   = os.getenv("REDIS_URL", "redis://localhost:6379/0")
API_URL     = os.getenv("SENTINELAI_API", "http://localhost:8000")
FEEDS_DIR   = Path(__file__).parent.parent / "threat-intel" / "feeds"

# ─── Public feed sources ─────────────────────────────────────
FEED_SOURCES = {
    "feodo_ips": {
        "url":  "https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt",
        "type": "ip",
        "desc": "Feodo Tracker botnet C2 IPs",
    },
    "emerging_threats_compromised": {
        "url":  "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "type": "ip",
        "desc": "Emerging Threats compromised hosts",
    },
    "tor_exit_nodes": {
        "url":  "https://check.torproject.org/torbulkexitlist",
        "type": "ip",
        "desc": "TOR exit node list",
    },
}

async def fetch_feed(name: str, config: dict) -> list:
    """Fetch a text-based IP feed and return list of IOCs."""
    iocs = []
    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            resp = await client.get(config["url"])
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and not line.startswith(";"):
                        # Basic IP validation
                        parts = line.split(".")
                        if len(parts) == 4:
                            iocs.append(line)
                logger.info(f"Feed '{name}': fetched {len(iocs)} IOCs")
    except Exception as e:
        logger.error(f"Feed '{name}' fetch failed: {e}")
    return iocs

async def load_local_feed(redis) -> int:
    """Load the curated local IOC feed into Redis."""
    feed_path = FEEDS_DIR / "ioc_feeds.json"
    if not feed_path.exists():
        logger.warning(f"Local feed not found: {feed_path}")
        return 0

    with open(feed_path) as f:
        data = json.load(f)

    count = 0
    # Load malicious IPs
    for entry in data.get("malicious_ips", []):
        ip = entry["ip"]
        await redis.hset(f"ioc:ip:{ip}", mapping={
            "ip":          ip,
            "threat_type": entry.get("threat_type", "malicious"),
            "confidence":  str(entry.get("confidence", 70)),
            "source":      entry.get("source", "sentinelai-feed"),
            "loaded_at":   datetime.now(timezone.utc).isoformat(),
        })
        await redis.sadd("ioc:malicious_ips", ip)
        count += 1

    # Load malicious domains
    for entry in data.get("malicious_domains", []):
        domain = entry["domain"]
        await redis.hset(f"ioc:domain:{domain}", mapping={
            "domain":      domain,
            "threat_type": entry.get("threat_type", "malicious"),
            "malware":     entry.get("malware", ""),
            "source":      "sentinelai-feed",
            "loaded_at":   datetime.now(timezone.utc).isoformat(),
        })
        await redis.sadd("ioc:malicious_domains", domain)
        count += 1

    # Load TOR exit nodes
    for ip in data.get("tor_exit_nodes", []):
        await redis.sadd("ioc:tor_exit_nodes", ip)
        count += 1

    # Load CVE watchlist
    for cve in data.get("cve_watchlist", []):
        await redis.hset(f"ioc:cve:{cve['cve']}", mapping={
            "cve":      cve["cve"],
            "name":     cve["name"],
            "cvss":     str(cve["cvss"]),
            "affected": cve["affected"],
        })
        count += 1

    logger.info(f"Local feed loaded: {count} IOCs into Redis")
    return count

async def check_ip_in_feeds(ip: str, redis) -> dict:
    """Check if an IP is in any threat feed."""
    result = {
        "ip":             ip,
        "is_malicious":   False,
        "is_tor_exit":    False,
        "threat_info":    None,
        "checked_at":     datetime.now(timezone.utc).isoformat(),
    }

    # Check malicious IPs set
    if await redis.sismember("ioc:malicious_ips", ip):
        result["is_malicious"] = True
        info = await redis.hgetall(f"ioc:ip:{ip}")
        result["threat_info"] = info

    # Check TOR exit nodes
    if await redis.sismember("ioc:tor_exit_nodes", ip):
        result["is_tor_exit"] = True

    return result

async def check_domain_in_feeds(domain: str, redis) -> dict:
    """Check if a domain is in any malicious domain feed."""
    if await redis.sismember("ioc:malicious_domains", domain):
        info = await redis.hgetall(f"ioc:domain:{domain}")
        return {"domain": domain, "is_malicious": True, "threat_info": info}
    return {"domain": domain, "is_malicious": False}

async def main():
    redis = await aioredis.from_url(REDIS_URL, decode_responses=True)
    logger.info("Starting threat feed loader...")

    # 1. Load local curated feed
    local_count = await load_local_feed(redis)

    # 2. Fetch public feeds
    total_remote = 0
    for name, config in FEED_SOURCES.items():
        iocs = await fetch_feed(name, config)
        for ip in iocs:
            await redis.sadd("ioc:malicious_ips", ip)
            await redis.hset(f"ioc:ip:{ip}", mapping={
                "ip":          ip,
                "threat_type": config["desc"],
                "confidence":  "75",
                "source":      name,
                "loaded_at":   datetime.now(timezone.utc).isoformat(),
            })
        total_remote += len(iocs)

    # 3. Set feed metadata
    await redis.hset("ioc:feed_meta", mapping={
        "last_updated":  datetime.now(timezone.utc).isoformat(),
        "local_iocs":    str(local_count),
        "remote_iocs":   str(total_remote),
        "total_sources": str(len(FEED_SOURCES) + 1),
    })

    total_ips = await redis.scard("ioc:malicious_ips")
    logger.info(f"✅ Feed load complete — {total_ips} malicious IPs in Redis")
    await redis.close()

if __name__ == "__main__":
    asyncio.run(main())
