# SentinelAI — Full Technical Architecture Documentation

## 1. System Overview

SentinelAI is a production-grade, AI-powered Security Operations Center platform that autonomously monitors, detects, correlates, and responds to cybersecurity threats in real time.

### Design Principles
- **Zero-Trust**: Every service requires authentication; no implicit trust
- **Microservices**: Independently deployable, scalable services
- **Event-Driven**: Kafka-based async communication between components
- **AI-First**: ML models + LLM at the core of every detection decision
- **Cloud-Native**: Kubernetes-ready, infrastructure-as-code

---

## 2. Microservice Architecture

### Service Map

```
Internet / Endpoints
        │
   [Nginx Gateway :8000]
        │
   ┌────┴─────────────────────────────────────┐
   │                                          │
[Auth :8001]    [Log Ingestion :8002]         │
                        │                     │
                   [Kafka Queue]              │
                   /         \                │
      [Detection :8003]   [AI :8004]          │
             │                │               │
      [SOAR :8005]   [ThreatIntel :8006]      │
             │                │               │
      [Alert WS :8007]  [Reports :8008]       │
             │                                │
      [VPN Monitor :8009]                     │
             │                                │
      [Frontend :3000] ◄──────────────────────┘
```

### Inter-Service Communication
- **Sync**: REST APIs via Nginx reverse proxy
- **Async**: Apache Kafka topics (logs, alerts, events)
- **Real-time**: WebSocket for dashboard live updates
- **Cache**: Redis for sessions, rate limits, threat intel cache

---

## 3. Data Flow

### Log Ingestion Flow
```
Endpoint Agent
    → POST /logs/bulk (batch of events)
    → Log Service enriches + deduplicates
    → Publishes to Kafka: sentinelai.logs
    → OpenSearch indexes for search
```

### Detection Flow
```
Kafka: sentinelai.logs
    → Detection Engine consumes
    → Runs Sigma rules (12 rules)
    → Runs behavioral detection
    → Checks correlation engine
    → Publishes alert to Kafka: sentinelai.alerts
    → OpenSearch indexes alert
    → Redis stores pending alerts
```

### AI Enrichment Flow
```
Kafka: sentinelai.alerts
    → AI Service consumes
    → Isolation Forest anomaly check
    → XGBoost attack classification
    → LangChain/Ollama analyst explanation
    → Enriched alert stored back to OpenSearch
```

### SOAR Response Flow
```
Kafka: sentinelai.alerts (severity=high/critical)
    → SOAR Service consumes
    → Routes to playbook by detection_type
    → Executes automated response actions
    → Logs execution to Redis + PostgreSQL
```

### Real-time Dashboard Flow
```
Kafka: sentinelai.alerts
    → Alert Service consumes
    → Broadcasts to all WebSocket clients
    → Dashboard updates in real time
```

---

## 4. Detection Engine

### Sigma Rules (12 Built-in)
| Rule ID | Name | Severity | MITRE |
|---------|------|----------|-------|
| SIG-001 | SSH Brute Force | High | T1110 |
| SIG-002 | Reverse Shell via Bash | Critical | T1059 |
| SIG-003 | Suspicious PowerShell | High | T1059.001 |
| SIG-004 | Port Scan (Suricata) | Medium | T1046 |
| SIG-005 | DNS Tunneling | High | T1071.004 |
| SIG-006 | Ransomware File Extension | Critical | T1486 |
| SIG-007 | SUID Bit Manipulation | High | T1068 |
| SIG-008 | Large Outbound Transfer | High | T1041 |
| SIG-009 | Mimikatz/Credential Dump | Critical | T1003 |
| SIG-010 | DDoS Flood Pattern | High | T1498 |
| SIG-011 | New Privileged Account | High | T1068 |
| SIG-012 | SMB Lateral Movement | High | T1021 |

### Attack Chain Correlation
The correlation engine detects multi-stage attacks:
- Brute Force → Privilege Escalation → Reverse Shell
- Phishing → Malware Execution → Lateral Movement → Exfiltration
- Port Scan → Lateral Movement → Credential Dumping
- Brute Force → Lateral Movement → Ransomware

---

## 5. AI Engine

### Models
| Model | Algorithm | Purpose |
|-------|-----------|---------|
| Anomaly Detector | Isolation Forest | Detect unusual events |
| Attack Classifier | XGBoost + RandomForest (ensemble) | Classify attack type |
| LLM Analyst | LangChain + Ollama (llama3.2) | Natural language analysis |
| Report Generator | LangChain + Ollama | Auto-generate incident reports |

### Feature Vector (10 features)
1. Log message length
2. Word count proxy
3. Hour of day (temporal anomaly)
4. Failure flag
5. Sudo/privilege flag
6. Root access flag
7. External IP present flag
8. Uppercase character count
9. PowerShell flag
10. Shell command flag

---

## 6. SOAR Playbooks

### Brute Force Playbook
1. Enrich source IP (VirusTotal + AbuseIPDB)
2. Block IP via firewall API
3. Disable compromised account
4. Force MFA re-enrollment
5. Send Slack alert
6. Create incident ticket

### Malware Execution Playbook
1. Isolate endpoint via EDR API
2. Kill malicious process
3. Quarantine suspicious file
4. Send Slack alert
5. Send email to SOC team
6. Create incident ticket

### Phishing Playbook
1. Enrich sender IP
2. Extract URLs from email
3. Check URLs via VirusTotal
4. Block malicious domains
5. Create incident ticket

### Data Exfiltration Playbook
1. Isolate endpoint
2. Block exfiltration destination IP
3. Send critical Slack alert
4. Email SOC with breach notification
5. Create high-priority incident ticket

---

## 7. Threat Intelligence

### Integrated Sources
| Source | Data Type | Update |
|--------|-----------|--------|
| VirusTotal | IP/Hash/URL/Domain | Real-time |
| AbuseIPDB | IP reputation | Real-time |
| AlienVault OTX | IOC pulses | Real-time |
| Shodan | Network exposure | Real-time |
| NVD | CVE details | Real-time |

### Threat Score Formula
```
score = min(vt_malicious * 5, 40)
      + int(abuse_confidence * 0.4)
      + min(otx_pulses * 2, 20)
      = max 100

CRITICAL: >= 80
HIGH:     >= 60
MEDIUM:   >= 30
LOW:      >= 10
CLEAN:    < 10
```

---

## 8. Database Schema

### PostgreSQL Tables
- `users` — Platform accounts (RBAC: admin, analyst, viewer)
- `api_keys` — Service-to-service auth keys
- `incidents` — Security incidents with full lifecycle
- `audit_logs` — Immutable user action audit trail
- `detection_rules` — Persistent detection rule registry
- `threat_intel_cache` — Enriched IOC cache
- `soar_executions` — Playbook execution history
- `reports` — Generated report metadata

### OpenSearch Indices
- `sentinelai-logs` — Raw log events (time-series)
- `sentinelai-alerts` — Enriched security alerts
- `sentinelai-events` — Correlated security events

### Redis Keys
- `refresh:{user_id}` — JWT refresh tokens
- `vt:ip:{ip}` — VirusTotal cache (1h TTL)
- `abuse:ip:{ip}` — AbuseIPDB cache (1h TTL)
- `vpn:last_session:{username}` — VPN geo tracking
- `vpn:active:{username}` — Active VPN sessions
- `alerts:timeline` — Sorted set of recent alerts
- `pending_alerts:{severity}` — Queued SOAR alerts
- `soar:executions` — Playbook execution log

---

## 9. Security Architecture

### Authentication Stack
```
User → JWT Bearer Token (30min expiry)
     → Refresh Token via Redis (7 days)
     → TOTP MFA (pyotp, Google Authenticator)
     → RBAC (admin/analyst/viewer/soar_bot)
     → API Keys for service-to-service
```

### RBAC Permissions
| Role | Permissions |
|------|-------------|
| admin | read, write, delete, manage_users, view_reports, soar_execute |
| analyst | read, write, view_reports |
| viewer | read |
| soar_bot | soar_execute, read |

### Network Security
- All inter-service traffic via Nginx reverse proxy
- Rate limiting: 100 req/min general, 20 req/min auth
- Security headers: CSP, X-Frame-Options, HSTS
- TLS termination at Nginx (self-signed dev, Let's Encrypt prod)

---

## 10. Deployment Architecture

### Local Development
One local backend process provides the core service APIs for the desktop app and developer workflows.

### Kubernetes (Production)
- Namespace: `sentinelai`
- HPA: detection-engine scales 2→10 pods on CPU>70%
- Ingress: nginx-ingress with Let's Encrypt TLS
- Secrets: Kubernetes Secrets (use Sealed Secrets in prod)
- Storage: PVCs for postgres, opensearch, kafka

### Cloud Deployment (AWS)
```
EKS Cluster
├── detection-engine (3 pods)
├── ai-service (2 pods, GPU if available)
├── auth-service (2 pods)
├── soar-service (2 pods)
├── frontend (2 pods)
RDS PostgreSQL (Multi-AZ)
ElastiCache Redis (cluster mode)
MSK Kafka (3 brokers)
OpenSearch Service (3 nodes)
CloudFront → ALB → Nginx → Frontend
```

---

## 11. Performance Targets

| Metric | Target |
|--------|--------|
| Log ingestion throughput | 50,000 events/sec |
| Alert detection latency | < 500ms |
| AI enrichment latency | < 2s |
| SOAR response time | < 5s |
| Dashboard WebSocket latency | < 100ms |
| API response time (p99) | < 200ms |

---

## 12. Extending the Platform

### Add a New Detection Rule
```python
# In backend/detection-engine/main.py, add to SIGMA_RULES:
{
    "id": "SIG-013",
    "name": "My Custom Rule",
    "severity": "high",
    "detection_type": "custom_attack",
    "conditions": [
        {"field": "raw_log", "op": "regex", "value": r"your_pattern_here"},
    ],
    "description": "What this rule detects",
}
```

### Add a New SOAR Playbook
```python
# In backend/soar-service/main.py, add elif to execute_playbook():
elif playbook_name == "my_playbook":
    steps_executed += await _run_steps([
        action_block_ip(ip, "My reason"),
        action_send_slack(msg, severity),
        action_create_ticket(alert),
    ])

# Add to DETECTION_TO_PLAYBOOK:
DETECTION_TO_PLAYBOOK["my_detection_type"] = "my_playbook"
```

### Add a New Threat Intel Source
```python
# In backend/threat-intel-service/main.py, add a new async function:
async def my_source_lookup(ip: str) -> dict:
    # ... query your source
    return {"source": "my_source", "ip": ip, "score": 0}
```
