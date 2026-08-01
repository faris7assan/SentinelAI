"""
SentinelAI — Missing Spec Items
OAuth2 social login + Osquery integration + AI-generated Sigma/YARA rules
Append these to the appropriate services or use as standalone modules.
"""

# ══════════════════════════════════════════════════════════════
# 1. OAuth2 — Add to auth-service/main.py
# ══════════════════════════════════════════════════════════════
OAUTH2_PROVIDERS = {
    "google": {
        "auth_url":  "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo":  "https://openidconnect.googleapis.com/v1/userinfo",
        "scope":     "openid email profile",
    },
    "github": {
        "auth_url":  "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo":  "https://api.github.com/user",
        "scope":     "user:email",
    },
    "microsoft": {
        "auth_url":  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo":  "https://graph.microsoft.com/v1.0/me",
        "scope":     "openid email profile",
    },
}


def build_oauth2_routes(app, redis_client, create_access_token, create_refresh_token):
    """
    Call this from auth-service/main.py startup to register OAuth2 routes.
    Usage: build_oauth2_routes(app, redis_client, create_access_token, create_refresh_token)
    """
    import os, secrets, httpx
    from fastapi import HTTPException
    from fastapi.responses import RedirectResponse

    def normalize_asyncpg_dsn(dsn: str) -> str:
        if not dsn:
            raise RuntimeError("DATABASE_URL is not configured")
        if dsn.startswith("postgresql+asyncpg://"):
            return "postgresql://" + dsn.removeprefix("postgresql+asyncpg://")
        return dsn

    GOOGLE_CLIENT_ID     = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GITHUB_CLIENT_ID     = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET", "")
    FRONTEND_URL         = os.getenv("FRONTEND_URL", "http://localhost:3000")

    @app.get("/auth/oauth2/{provider}/login")
    async def oauth2_login(provider: str):
        """Redirect user to OAuth2 provider for authentication."""
        if provider not in OAUTH2_PROVIDERS:
            raise HTTPException(400, f"Unknown provider: {provider}. Supported: {list(OAUTH2_PROVIDERS)}")
        cfg   = OAUTH2_PROVIDERS[provider]
        state = secrets.token_hex(16)
        await redis_client.setex(f"oauth2:state:{state}", 300, provider)
        client_id = GOOGLE_CLIENT_ID if provider == "google" else GITHUB_CLIENT_ID
        redirect_uri = f"{os.getenv('API_URL', 'http://localhost:8000')}/auth/oauth2/{provider}/callback"
        url = (
            f"{cfg['auth_url']}?"
            f"client_id={client_id}&"
            f"redirect_uri={redirect_uri}&"
            f"response_type=code&"
            f"scope={cfg['scope'].replace(' ', '%20')}&"
            f"state={state}"
        )
        return RedirectResponse(url=url)

    @app.get("/auth/oauth2/{provider}/callback")
    async def oauth2_callback(provider: str, code: str, state: str):
        """Handle OAuth2 callback, exchange code for token, return JWT."""
        stored_provider = await redis_client.get(f"oauth2:state:{state}")
        if not stored_provider or stored_provider != provider:
            raise HTTPException(400, "Invalid OAuth2 state — CSRF protection triggered")
        await redis_client.delete(f"oauth2:state:{state}")

        cfg = OAUTH2_PROVIDERS[provider]
        client_id     = GOOGLE_CLIENT_ID if provider == "google" else GITHUB_CLIENT_ID
        client_secret = GOOGLE_CLIENT_SECRET if provider == "google" else GITHUB_CLIENT_SECRET
        redirect_uri  = f"{os.getenv('API_URL', 'http://localhost:8000')}/auth/oauth2/{provider}/callback"

        async with httpx.AsyncClient() as client:
            # Exchange code for access token
            token_resp = await client.post(
                cfg["token_url"],
                data={
                    "grant_type":    "authorization_code",
                    "code":          code,
                    "redirect_uri":  redirect_uri,
                    "client_id":     client_id,
                    "client_secret": client_secret,
                },
                headers={"Accept": "application/json"},
                timeout=10.0,
            )
            token_data   = token_resp.json()
            access_token = token_data.get("access_token", "")
            # Get user info
            user_resp = await client.get(
                cfg["userinfo"],
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10.0,
            )
            user_info = user_resp.json()

        # Extract user details
        email    = user_info.get("email") or user_info.get("login", "") + "@github.com"
        username = user_info.get("login") or email.split("@")[0]
        name     = user_info.get("name") or username

        # Create/update user in our system
        import asyncpg, os
        conn = await asyncpg.connect(normalize_asyncpg_dsn(os.getenv("DATABASE_URL")))
        try:
            existing = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
            if existing:
                user_id = existing["id"]
            else:
                import secrets as s
                user_id = s.token_hex(16)
                await conn.execute(
                    """INSERT INTO users (id, username, email, password_hash, role, full_name, mfa_enabled, is_active, created_at)
                       VALUES ($1,$2,$3,$4,$5,$6,false,true,NOW())""",
                    user_id, username, email, f"oauth2:{provider}", "analyst", name,
                )
        finally:
            await conn.close()

        # Issue JWT
        jwt_token     = create_access_token({"sub": user_id, "username": username, "role": "analyst", "email": email})
        refresh_token = create_refresh_token({"sub": user_id, "username": username, "role": "analyst", "email": email})
        await redis_client.setex(f"refresh:{user_id}", 7 * 86400, refresh_token)

        # Redirect frontend with token
        return RedirectResponse(url=f"{FRONTEND_URL}/auth/callback?token={jwt_token}&refresh={refresh_token}")

    @app.get("/auth/oauth2/providers")
    async def list_oauth2_providers():
        """List available OAuth2 providers."""
        return {
            "providers": [
                {"id": k, "name": k.title(), "auth_url": v["auth_url"]}
                for k, v in OAUTH2_PROVIDERS.items()
            ]
        }


# ══════════════════════════════════════════════════════════════
# 2. Osquery Integration — log collection via osquery REST API
# ══════════════════════════════════════════════════════════════
import asyncio, json, os
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
import httpx

OSQUERY_QUERIES = {
    "running_processes":   "SELECT pid, name, path, cmdline, uid FROM processes ORDER BY start_time DESC LIMIT 50;",
    "network_connections": "SELECT pid, local_address, local_port, remote_address, remote_port, state FROM process_open_sockets WHERE state='ESTABLISHED' LIMIT 50;",
    "logged_in_users":     "SELECT username, host, time, tty FROM logged_in_users;",
    "startup_items":       "SELECT name, path, source FROM startup_items;",
    "crontab_entries":     "SELECT event, minute, hour, day_of_month, month, day_of_week, command, path FROM crontab;",
    "suid_binaries":       "SELECT path, username, permissions FROM file WHERE (permissions LIKE '%s%') AND path LIKE '/usr/%';",
    "open_files_network":  "SELECT DISTINCT process.name, process.pid, socket.local_address, socket.remote_address FROM process_open_sockets AS socket JOIN processes AS process USING (pid) WHERE socket.remote_port > 0;",
    "installed_packages":  "SELECT name, version, arch FROM deb_packages LIMIT 100;",
    "usb_devices":         "SELECT vendor, model, serial, class FROM usb_devices;",
    "recent_shell_history":"SELECT username, command, time FROM shell_history ORDER BY time DESC LIMIT 100;",
}

class OsqueryCollector:
    """Collects security-relevant data via osquery fleet manager or local daemon."""

    def __init__(self, osquery_socket: str = "/run/osquery/osquery.em",
                 fleet_url: Optional[str] = None, fleet_token: Optional[str] = None):
        self.socket      = osquery_socket
        self.fleet_url   = fleet_url or os.getenv("OSQUERY_FLEET_URL", "")
        self.fleet_token = fleet_token or os.getenv("OSQUERY_FLEET_TOKEN", "")

    async def run_query(self, sql: str) -> List[Dict]:
        """Run an osquery SQL query via local socket or fleet API."""
        if self.fleet_url:
            return await self._run_fleet_query(sql)
        return await self._run_local_query(sql)

    async def _run_local_query(self, sql: str) -> List[Dict]:
        """Run query against local osquery daemon via Unix socket."""
        try:
            import asyncio
            reader, writer = await asyncio.open_unix_connection(self.socket)
            query_msg = json.dumps({"type": "distributed/read", "data": {"queries": {"q1": sql}}}) + "\n"
            writer.write(query_msg.encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=10.0)
            writer.close()
            data = json.loads(resp)
            return data.get("data", {}).get("queries", {}).get("q1", [])
        except Exception as e:
            return [{"error": str(e), "note": "osquery daemon not running or socket unavailable"}]

    async def _run_fleet_query(self, sql: str) -> List[Dict]:
        """Run query via osquery Fleet manager API (fleetdm.com)."""
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(
                    f"{self.fleet_url}/api/v1/fleet/queries/run",
                    headers={"Authorization": f"Bearer {self.fleet_token}"},
                    json={"query": sql, "selected": {"labels": ["All Hosts"]}},
                    timeout=30.0,
                )
                data = resp.json()
                return data.get("results", [])
            except Exception as e:
                return [{"error": str(e)}]

    async def collect_security_snapshot(self) -> Dict[str, Any]:
        """Collect a full security snapshot from osquery."""
        snapshot = {"collected_at": datetime.now(timezone.utc).isoformat(), "results": {}}
        for query_name, sql in OSQUERY_QUERIES.items():
            result = await self.run_query(sql)
            snapshot["results"][query_name] = result
        return snapshot

    def detect_anomalies(self, snapshot: Dict) -> List[Dict]:
        """Run simple anomaly detection on osquery results."""
        anomalies = []
        # Check for SUID binaries in unexpected paths
        for row in snapshot["results"].get("suid_binaries", []):
            if "/tmp/" in row.get("path","") or "/var/" in row.get("path",""):
                anomalies.append({
                    "type":     "suspicious_suid",
                    "severity": "critical",
                    "detail":   f"SUID binary in suspicious path: {row.get('path')}",
                    "mitre":    "T1548.001",
                })
        # Check for processes with network connections to unusual ports
        for row in snapshot["results"].get("open_files_network", []):
            remote = row.get("remote_address","")
            if remote and not remote.startswith(("10.","192.168.","172.","127.","0.")):
                anomalies.append({
                    "type":     "external_connection",
                    "severity": "medium",
                    "detail":   f"Process {row.get('name')} (PID {row.get('pid')}) connected to {remote}",
                    "mitre":    "T1071",
                })
        # Check startup items for suspicious entries
        for row in snapshot["results"].get("startup_items", []):
            if "/tmp/" in row.get("path","") or "/dev/shm/" in row.get("path",""):
                anomalies.append({
                    "type":     "suspicious_startup",
                    "severity": "high",
                    "detail":   f"Startup item from suspicious path: {row.get('path')}",
                    "mitre":    "T1547.001",
                })
        return anomalies


# ══════════════════════════════════════════════════════════════
# 3. AI-Generated Sigma & YARA Rules — Add to ai-service
# ══════════════════════════════════════════════════════════════
SIGMA_GENERATION_PROMPT = """You are an expert detection engineer. Generate a valid Sigma rule in YAML format for the following threat:

Threat description: {threat_description}
Attack technique: {mitre_technique}
Log source: {log_source}

Requirements:
- Valid Sigma YAML format
- Include: title, id, status, description, author, date, tags, logsource, detection, falsepositives, level
- Use realistic field names for the log source
- Include at least 2-3 detection conditions
- Set appropriate level (critical/high/medium/low)
- Add MITRE ATT&CK tags

Output ONLY the YAML rule, no explanation."""

YARA_GENERATION_PROMPT = """You are an expert malware analyst. Generate a valid YARA rule for the following:

Threat description: {threat_description}
Malware family: {malware_family}
Target platform: {platform}

Requirements:
- Valid YARA syntax
- Include: rule name, meta section (description, author, severity, mitre), strings section, condition
- Use realistic string patterns (hex, strings, regex)
- Condition should be specific enough to avoid false positives
- Include at least 3-5 string indicators

Output ONLY the YARA rule, no explanation."""


async def generate_sigma_rule(
    threat_description: str,
    mitre_technique: str,
    log_source: str,
    llm_url: str = "http://ollama:11434",
    model: str   = "llama3.2",
) -> Dict[str, Any]:
    """Use LLM to generate a Sigma detection rule from a threat description."""
    prompt = SIGMA_GENERATION_PROMPT.format(
        threat_description=threat_description,
        mitre_technique=mitre_technique,
        log_source=log_source,
    )
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{llm_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60.0,
            )
            if resp.status_code == 200:
                rule_text = resp.json().get("response", "").strip()
                # Validate it looks like YAML
                if "title:" in rule_text and "detection:" in rule_text:
                    return {
                        "status":      "generated",
                        "rule_type":   "sigma",
                        "rule_text":   rule_text,
                        "model":       model,
                        "technique":   mitre_technique,
                        "generated_at":datetime.now(timezone.utc).isoformat(),
                    }
                return {"status": "invalid", "raw_output": rule_text[:500]}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    return {"status": "llm_unavailable"}


async def generate_yara_rule(
    threat_description: str,
    malware_family: str,
    platform: str     = "windows",
    llm_url: str      = "http://ollama:11434",
    model: str        = "llama3.2",
) -> Dict[str, Any]:
    """Use LLM to generate a YARA malware detection rule."""
    prompt = YARA_GENERATION_PROMPT.format(
        threat_description=threat_description,
        malware_family=malware_family,
        platform=platform,
    )
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{llm_url}/api/generate",
                json={"model": model, "prompt": prompt, "stream": False},
                timeout=60.0,
            )
            if resp.status_code == 200:
                rule_text = resp.json().get("response", "").strip()
                if "rule " in rule_text and "strings:" in rule_text and "condition:" in rule_text:
                    return {
                        "status":      "generated",
                        "rule_type":   "yara",
                        "rule_text":   rule_text,
                        "model":       model,
                        "malware":     malware_family,
                        "generated_at":datetime.now(timezone.utc).isoformat(),
                    }
                return {"status": "invalid", "raw_output": rule_text[:500]}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    return {"status": "llm_unavailable"}


# ─── FastAPI routes to add to ai-service ─────────────────────
def register_rule_generation_routes(app, ollama_url: str, model: str):
    """Register AI rule generation endpoints on the FastAPI app."""
    from fastapi import HTTPException
    from pydantic import BaseModel

    class SigmaGenRequest(BaseModel):
        threat_description: str
        mitre_technique:    str = "T1059"
        log_source:         str = "linux"  # linux | windows | network

    class YaraGenRequest(BaseModel):
        threat_description: str
        malware_family:     str
        platform:           str = "windows"

    @app.post("/ai/generate/sigma-rule")
    async def gen_sigma(req: SigmaGenRequest):
        """Generate a Sigma detection rule using AI."""
        return await generate_sigma_rule(
            req.threat_description, req.mitre_technique, req.log_source,
            ollama_url, model
        )

    @app.post("/ai/generate/yara-rule")
    async def gen_yara(req: YaraGenRequest):
        """Generate a YARA malware detection rule using AI."""
        return await generate_yara_rule(
            req.threat_description, req.malware_family, req.platform,
            ollama_url, model
        )

    @app.get("/ai/generate/examples")
    async def rule_gen_examples():
        return {
            "sigma_example": {
                "threat_description": "Attacker uses certutil.exe to download malware from C2 server",
                "mitre_technique":    "T1105",
                "log_source":         "windows",
            },
            "yara_example": {
                "threat_description": "Ransomware that enumerates files, deletes shadow copies, and encrypts documents",
                "malware_family":     "LockBit",
                "platform":           "windows",
            },
        }
