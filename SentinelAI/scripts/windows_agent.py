"""
SentinelAI — Windows Log Collection Agent
Parses Sysmon + Windows Event Logs and ships to SentinelAI
Runs on Windows with pywin32 OR cross-platform via log file tailing
"""
import os, sys, json, time, asyncio, socket, re, hashlib
import aiohttp
from datetime import datetime, timezone
from typing import Optional, List, Dict
from pathlib import Path
from loguru import logger

# ─── Config ──────────────────────────────────────────────────
API_URL        = os.getenv("SENTINELAI_API", "http://localhost:8000")
AGENT_ID       = os.getenv("AGENT_ID", socket.gethostname())
AUTH_TOKEN     = os.getenv("SENTINELAI_TOKEN", "")
BATCH_SIZE     = int(os.getenv("BATCH_SIZE", 30))
FLUSH_INTERVAL = int(os.getenv("FLUSH_INTERVAL", 5))
IS_WINDOWS     = sys.platform == "win32"

# ─── Sysmon Event IDs → Security relevance ───────────────────
SYSMON_EVENTS = {
    1:  ("process_create",      "medium"),  # Process creation
    2:  ("file_creation_time",  "low"),     # File creation time changed
    3:  ("network_connect",     "low"),     # Network connection
    5:  ("process_terminate",   "info"),    # Process terminated
    6:  ("driver_load",         "high"),    # Driver loaded
    7:  ("image_load",          "medium"),  # Image loaded
    8:  ("create_remote_thread","critical"),# CreateRemoteThread
    10: ("process_access",      "high"),    # Process accessed (LSASS dump)
    11: ("file_create",         "low"),     # File created
    12: ("registry_create",     "medium"),  # Registry event
    13: ("registry_value_set",  "medium"),  # Registry value set
    15: ("file_stream_create",  "high"),    # File stream created (ADS)
    17: ("pipe_created",        "medium"),  # Named pipe created
    22: ("dns_query",           "low"),     # DNS query
    23: ("file_delete",         "medium"),  # File deleted
    25: ("process_tamper",      "critical"),# Process tampered
    29: ("file_exe_detected",   "critical"),# Executable file detected
}

# ─── Windows Event Log IDs ────────────────────────────────────
WINEVENT_SECURITY = {
    4624: ("success_login",         "info"),
    4625: ("failed_login",          "medium"),
    4634: ("logoff",                "info"),
    4648: ("explicit_credentials",  "high"),
    4657: ("registry_modified",     "medium"),
    4688: ("process_created",       "medium"),
    4698: ("scheduled_task_created","high"),
    4720: ("user_account_created",  "high"),
    4722: ("user_account_enabled",  "medium"),
    4724: ("password_reset",        "high"),
    4728: ("group_member_added",    "high"),
    4732: ("local_group_member_added","high"),
    4756: ("universal_group_member_added","high"),
    4768: ("kerberos_ticket_request","low"),
    4769: ("kerberos_service_ticket","medium"),
    4776: ("ntlm_auth",             "medium"),
    4798: ("user_local_group_enum", "medium"),
    4799: ("security_group_enum",   "medium"),
    7045: ("service_installed",     "high"),
}

WINEVENT_SYSTEM = {
    7030: ("service_interactive",   "high"),
    7040: ("service_start_type_changed","medium"),
    7045: ("service_installed",     "high"),
}

POWERSHELL_EVENTS = {
    4103: ("ps_module_logging",     "medium"),
    4104: ("ps_script_block",       "high"),
    4105: ("ps_start",              "info"),
    4106: ("ps_stop",               "info"),
}

# ─── Sysmon XML Parser ───────────────────────────────────────
class SysmonParser:
    @staticmethod
    def parse_xml_event(xml_str: str) -> dict:
        """Parse Sysmon XML event to dict."""
        parsed = {}
        patterns = {
            "EventID":    r"<EventID>(\d+)</EventID>",
            "Image":      r"<Data Name='Image'>([^<]+)</Data>",
            "CommandLine":r"<Data Name='CommandLine'>([^<]+)</Data>",
            "ParentImage":r"<Data Name='ParentImage'>([^<]+)</Data>",
            "TargetImage":r"<Data Name='TargetImage'>([^<]+)</Data>",
            "Hashes":     r"<Data Name='Hashes'>([^<]+)</Data>",
            "DestinationIp":   r"<Data Name='DestinationIp'>([^<]+)</Data>",
            "DestinationPort": r"<Data Name='DestinationPort'>([^<]+)</Data>",
            "SourceIp":   r"<Data Name='SourceIp'>([^<]+)</Data>",
            "User":       r"<Data Name='User'>([^<]+)</Data>",
            "UtcTime":    r"<Data Name='UtcTime'>([^<]+)</Data>",
            "QueryName":  r"<Data Name='QueryName'>([^<]+)</Data>",
            "TargetFilename": r"<Data Name='TargetFilename'>([^<]+)</Data>",
        }
        for key, pattern in patterns.items():
            m = re.search(pattern, xml_str)
            if m:
                parsed[key] = m.group(1).strip()
        return parsed

    @staticmethod
    def is_suspicious(event_id: int, parsed: dict) -> bool:
        cmd = parsed.get("CommandLine", "").lower()
        image = parsed.get("Image", "").lower()
        target = parsed.get("TargetImage", "").lower()

        if event_id == 1:  # Process create
            suspicious_procs = ["cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe",
                                "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe"]
            if any(p in image for p in suspicious_procs):
                if "-enc" in cmd or "-nop" in cmd or "-bypass" in cmd or "/dev/tcp" in cmd:
                    return True

        if event_id == 10:  # Process access
            if "lsass.exe" in target:
                return True  # LSASS access = credential dump attempt

        if event_id == 8:  # CreateRemoteThread
            return True  # Always suspicious

        return False


class WindowsEventParser:
    @staticmethod
    def build_event(event_id: int, data: dict, hostname: str, log_source: str = "winevent") -> dict:
        event_map = {**WINEVENT_SECURITY, **WINEVENT_SYSTEM, **POWERSHELL_EVENTS}
        event_type, base_severity = event_map.get(event_id, ("unknown_event", "info"))

        # Escalate severity for suspicious combos
        username = data.get("SubjectUserName", data.get("TargetUserName", ""))
        logon_type = data.get("LogonType", "")

        severity = base_severity
        if event_id == 4625 and logon_type == "3":
            severity = "high"  # Network logon failure
        if event_id == 4688 and "powershell" in data.get("NewProcessName", "").lower():
            severity = "high"

        raw = f"EventID={event_id} {' '.join(f'{k}={v}' for k,v in data.items())}"
        return {
            "source_ip":   data.get("IpAddress", "127.0.0.1"),
            "hostname":    hostname,
            "log_source":  log_source,
            "event_type":  event_type,
            "severity":    severity,
            "raw_log":     raw[:2048],
            "parsed":      {"event_id": event_id, **data},
            "agent_id":    AGENT_ID,
            "os_type":     "windows",
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }


# ─── Windows Event Log Reader ────────────────────────────────
class WindowsEventLogReader:
    """Reads Windows Event Logs using pywin32 (Windows-only)."""

    def __init__(self):
        self.last_records = {}  # log_name -> last record number

    def read_new_events(self, log_name: str, event_ids: dict) -> List[dict]:
        events = []
        if not IS_WINDOWS:
            return events
        try:
            import win32evtlog
            import win32evtlogutil
            import pywintypes

            handle = win32evtlog.OpenEventLog(None, log_name)
            flags  = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            records = win32evtlog.ReadEventLog(handle, flags, 0)

            for record in records[:100]:  # Max 100 per poll
                event_id = record.EventID & 0xFFFF
                if event_id not in event_ids:
                    continue

                try:
                    msg = win32evtlogutil.SafeFormatMessage(record, log_name)
                except Exception:
                    msg = str(record.StringInserts or "")

                events.append(WindowsEventParser.build_event(
                    event_id,
                    {"message": msg[:500], "time_generated": str(record.TimeGenerated)},
                    socket.gethostname(),
                    f"winevent_{log_name.lower()}",
                ))

            win32evtlog.CloseEventLog(handle)
        except ImportError:
            pass  # pywin32 not available
        except Exception as e:
            logger.debug(f"Event log read error ({log_name}): {e}")

        return events


# ─── PowerShell Script Block Log Tailing ─────────────────────
class PSScriptBlockTailer:
    """Tails PowerShell Operational log from evtx file or text export."""

    SUSPICIOUS_PS_PATTERNS = [
        r"-[Ee]nc(?:oded[Cc]ommand)?\s+[A-Za-z0-9+/]{20,}",
        r"[Ii]nvoke-[Ee]xpression",
        r"IEX\(",
        r"\[System\.Reflection\.Assembly\]::Load",
        r"Net\.WebClient.*Download",
        r"Start-Process.*-WindowStyle\s+[Hh]idden",
        r"powershell.*bypass",
    ]

    def check_ps_block(self, script_block: str) -> bool:
        for pattern in self.SUSPICIOUS_PS_PATTERNS:
            if re.search(pattern, script_block, re.IGNORECASE):
                return True
        return False


# ─── Main Agent ──────────────────────────────────────────────
class WindowsSentinelAgent:
    def __init__(self):
        self.hostname    = socket.gethostname()
        self.batch       = []
        self.session     = None
        self.event_reader = WindowsEventLogReader()
        self.ps_tailer   = PSScriptBlockTailer()
        logger.info(f"Windows Agent initialized: {self.hostname}")

    async def collect_events(self) -> List[dict]:
        events = []

        if IS_WINDOWS:
            # Security events
            events += self.event_reader.read_new_events("Security", WINEVENT_SECURITY)
            # System events
            events += self.event_reader.read_new_events("System", WINEVENT_SYSTEM)
            # PowerShell operational
            events += self.event_reader.read_new_events("Microsoft-Windows-PowerShell/Operational", POWERSHELL_EVENTS)
            # Sysmon
            events += self.event_reader.read_new_events("Microsoft-Windows-Sysmon/Operational",
                                                         {k: v for k, v in SYSMON_EVENTS.items()})
        else:
            # Cross-platform: tail exported evtx/log files
            evtx_dir = Path(os.getenv("WINDOWS_LOG_EXPORT_DIR", "/mnt/windows-logs"))
            if evtx_dir.exists():
                for log_file in evtx_dir.glob("*.log"):
                    events += await self._tail_log_file(log_file)

        return events

    async def _tail_log_file(self, path: Path) -> List[dict]:
        """Tail an exported Windows log text file."""
        events = []
        key = f"tail_pos:{path.name}"
        pos = int(await self._get_cache(key) or 0)
        try:
            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Simple EventID extraction
                    m = re.search(r"EventID[=:\s]+(\d+)", line)
                    if m:
                        eid = int(m.group(1))
                        all_events = {**WINEVENT_SECURITY, **WINEVENT_SYSTEM, **POWERSHELL_EVENTS}
                        if eid in all_events:
                            events.append(WindowsEventParser.build_event(eid, {"raw": line[:500]}, self.hostname))
                pos = f.tell()
            await self._set_cache(key, str(pos))
        except Exception as e:
            logger.debug(f"Log file tail error: {e}")
        return events

    async def _get_cache(self, key: str) -> Optional[str]:
        cache_file = Path(f"/tmp/sentinelai_agent_cache_{hashlib.md5(key.encode()).hexdigest()[:8]}.txt")
        return cache_file.read_text() if cache_file.exists() else None

    async def _set_cache(self, key: str, value: str):
        cache_file = Path(f"/tmp/sentinelai_agent_cache_{hashlib.md5(key.encode()).hexdigest()[:8]}.txt")
        cache_file.write_text(value)

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
                    logger.debug(f"Shipped {len(payload['events'])} Windows events")
        except Exception as e:
            logger.warning(f"Failed to ship events: {e}")

    async def run(self):
        self.session = aiohttp.ClientSession()
        logger.info(f"🪟 Windows SentinelAI Agent | host={self.hostname} | api={API_URL}")
        last_flush = time.time()
        try:
            while True:
                new_events = await self.collect_events()
                self.batch.extend(new_events)

                if len(self.batch) >= BATCH_SIZE or (self.batch and time.time() - last_flush >= FLUSH_INTERVAL):
                    await self._ship_batch()
                    last_flush = time.time()

                await asyncio.sleep(2)
        except KeyboardInterrupt:
            logger.info("Agent stopping...")
            if self.batch:
                await self._ship_batch()
        finally:
            await self.session.close()


if __name__ == "__main__":
    logger.remove()
    logger.add(
        sys.stderr,
        format="<green>{time:HH:mm:ss}</green> | <level>{level}</level> | {message}",
        level="INFO"
    )
    agent = WindowsSentinelAgent()
    asyncio.run(agent.run())
