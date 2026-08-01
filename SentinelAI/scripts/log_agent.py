#!/usr/bin/env python3
"""
SentinelAI — Linux Log Collection Agent
Collects auditd, syslog, auth logs and ships to SentinelAI Log Service
"""

import os, sys, re, time, json, hashlib, socket, platform
import asyncio, aiohttp, aiofiles
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from loguru import logger

# ─── Config ──────────────────────────────────────────────────
API_URL    = os.getenv("SENTINELAI_API", "http://localhost:8000")
AGENT_ID   = os.getenv("AGENT_ID", socket.gethostname())
AUTH_TOKEN = os.getenv("SENTINELAI_TOKEN", "")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", 50))
FLUSH_INTERVAL = int(os.getenv("FLUSH_INTERVAL", 5))

LOG_SOURCES = {
    "/var/log/auth.log":   "auth",
    "/var/log/syslog":     "syslog",
    "/var/log/kern.log":   "kernel",
    "/var/log/audit/audit.log": "auditd",
    "/var/log/nginx/access.log": "nginx",
    "/var/log/apache2/access.log": "apache",
}

# ─── Log Parser ──────────────────────────────────────────────
class LogParser:
    AUTH_PATTERNS = {
        "failed_login":  re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+) port \d+"),
        "success_login": re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+) port \d+"),
        "sudo_cmd":      re.compile(r"sudo:\s+(\S+)\s*:.*COMMAND=(.+)"),
        "user_created":  re.compile(r"useradd.*name=(\S+)"),
        "su_attempt":    re.compile(r"su\[.+\]: pam_unix\(su"),
    }

    AUDITD_PATTERNS = {
        "execve":        re.compile(r'type=EXECVE.*?a0="([^"]+)"'),
        "connect":       re.compile(r'type=SOCKADDR.*?addr=([0-9a-f]+)'),
        "file_modified": re.compile(r'type=PATH.*?name="([^"]+)"'),
        "priv_escalation": re.compile(r'type=USER_AUTH.*?res=success'),
    }

    @classmethod
    def parse(cls, line: str, source: str) -> dict:
        parsed = {}
        if source == "auth":
            for event_type, pattern in cls.AUTH_PATTERNS.items():
                m = pattern.search(line)
                if m:
                    parsed["event_type"] = event_type
                    groups = m.groups()
                    if len(groups) >= 2:
                        parsed["username"] = groups[0]
                        parsed["source_ip"] = groups[1]
                    elif len(groups) == 1:
                        parsed["username"] = groups[0]
                    break
        elif source == "auditd":
            for event_type, pattern in cls.AUDITD_PATTERNS.items():
                m = pattern.search(line)
                if m:
                    parsed["event_type"] = event_type
                    parsed["value"] = m.group(1)
                    break
        return parsed

    @classmethod
    def severity(cls, line: str, event_type: str) -> str:
        critical_keywords = ["exploit", "rootkit", "reverse shell", "/dev/tcp", "mimikatz"]
        high_keywords     = ["failed password", "su:", "sudo:", "adduser", "chmod 777"]
        medium_keywords   = ["connection refused", "invalid user", "segfault"]

        line_lower = line.lower()
        if any(kw in line_lower for kw in critical_keywords): return "critical"
        if event_type in ("failed_login", "priv_escalation", "sudo_cmd"): return "high"
        if any(kw in line_lower for kw in high_keywords): return "high"
        if any(kw in line_lower for kw in medium_keywords): return "medium"
        if event_type in ("success_login",): return "low"
        return "info"

# ─── File Tailer ─────────────────────────────────────────────
class FileTailer:
    def __init__(self, filepath: str, source_name: str):
        self.filepath    = filepath
        self.source_name = source_name
        self.position    = 0
        self._init_position()

    def _init_position(self):
        try:
            self.position = os.path.getsize(self.filepath)
        except FileNotFoundError:
            self.position = 0

    def read_new_lines(self) -> list:
        lines = []
        try:
            with open(self.filepath, "r", errors="replace") as f:
                f.seek(self.position)
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        lines.append(stripped)
                self.position = f.tell()
        except (FileNotFoundError, PermissionError):
            pass
        return lines

# ─── Agent ───────────────────────────────────────────────────
class SentinelAgent:
    def __init__(self):
        self.tailers = {}
        self.batch   = []
        self.session = None
        self.hostname = socket.gethostname()
        self.os_type  = "linux"

        for path, src in LOG_SOURCES.items():
            if os.path.exists(path):
                self.tailers[path] = FileTailer(path, src)
                logger.info(f"Monitoring: {path}")

    def build_event(self, raw: str, source: str) -> dict:
        parsed     = LogParser.parse(raw, source)
        event_type = parsed.get("event_type", "log_entry")
        severity   = LogParser.severity(raw, event_type)
        return {
            "source_ip":   parsed.get("source_ip", self._get_local_ip()),
            "hostname":    self.hostname,
            "log_source":  source,
            "event_type":  event_type,
            "severity":    severity,
            "raw_log":     raw[:2048],
            "parsed":      parsed,
            "agent_id":    AGENT_ID,
            "os_type":     self.os_type,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    async def _ship_batch(self):
        if not self.batch or not self.session:
            return
        payload = {"events": self.batch.copy()}
        self.batch.clear()
        headers = {"Content-Type": "application/json"}
        if AUTH_TOKEN:
            headers["Authorization"] = f"Bearer {AUTH_TOKEN}"
        try:
            async with self.session.post(
                f"{API_URL}/logs/bulk",
                json=payload,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 202:
                    logger.debug(f"Shipped {len(payload['events'])} events")
                else:
                    logger.warning(f"Ship failed: {resp.status}")
        except aiohttp.ClientConnectorError:
            logger.warning("Cannot connect to SentinelAI API — will retry")
        except Exception as e:
            logger.error(f"Ship error: {e}")

    async def run(self):
        connector    = aiohttp.TCPConnector(limit=10, ssl=False)
        self.session = aiohttp.ClientSession(connector=connector)
        logger.info(f"SentinelAI Agent started | host={self.hostname} | api={API_URL}")

        last_flush = time.time()
        try:
            while True:
                for path, tailer in self.tailers.items():
                    new_lines = tailer.read_new_lines()
                    for line in new_lines:
                        event = self.build_event(line, tailer.source_name)
                        self.batch.append(event)

                if len(self.batch) >= BATCH_SIZE or (self.batch and time.time() - last_flush >= FLUSH_INTERVAL):
                    await self._ship_batch()
                    last_flush = time.time()

                await asyncio.sleep(1)
        except KeyboardInterrupt:
            logger.info("Agent stopping...")
            if self.batch:
                await self._ship_batch()
        finally:
            await self.session.close()

# ─── Entry Point ─────────────────────────────────────────────
if __name__ == "__main__":
    logger.remove()
    logger.add(sys.stderr, format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}", level="INFO")
    agent = SentinelAgent()
    asyncio.run(agent.run())
