# SentinelAI — Incident Response Runbooks

## Severity Definitions

| Level | SLA (Detection→Response) | Definition |
|---|---|---|
| 🔴 CRITICAL | < 15 minutes | Active attack, confirmed breach, ransomware |
| 🟠 HIGH | < 1 hour | Probable attack, credential dump, lateral movement |
| 🟡 MEDIUM | < 4 hours | Suspicious activity, policy violation |
| 🟢 LOW | < 24 hours | Informational, low confidence |

---

## Playbook 1 — Brute Force / Credential Attack

**MITRE:** T1110 — Credential Access  
**Triggers:** `SIG-001` SSH Brute Force, high AbuseIPDB score

### SOAR Auto-Actions (HIGH/CRITICAL)
1. Block source IP at firewall
2. Disable compromised account
3. Force MFA re-enrollment
4. Slack notification to SOC channel
5. Create incident ticket

### Manual Investigation Steps
```bash
# 1. Identify scope of attempts
GET /logs/search {"query":"failed_login AND {attacker_ip}","time_from":"now-1h"}

# 2. Check for successful logins after brute force
GET /logs/search {"query":"success_login AND {attacker_ip}"}

# 3. Threat intel on source IP
GET /intel/ip/full/{attacker_ip}

# 4. Check for lateral movement if login succeeded
GET /alerts/recent?severity=high
```

### Containment
- [ ] Block IP at perimeter firewall (SOAR auto-executes)
- [ ] Reset all passwords for targeted accounts
- [ ] Review sudo/admin group membership
- [ ] Check for new cron jobs / startup items on targeted hosts
- [ ] Enable enhanced logging on affected systems

### Recovery
- [ ] Unlock accounts after IP is blocked
- [ ] Re-enable services if disabled
- [ ] Update firewall rules permanently
- [ ] Document IOCs in MISP

---

## Playbook 2 — Ransomware

**MITRE:** T1486 — Impact  
**Triggers:** `SIG-006` Ransomware File Extension, mass file modifications

### ⚠️ CRITICAL — Act in < 15 minutes

### SOAR Auto-Actions
1. **Isolate endpoint** (network quarantine via EDR)
2. Kill malicious process
3. Quarantine suspicious files
4. Critical Slack + Email alert to SOC + Management
5. Create P1 incident ticket

### Manual Steps
```bash
# 1. Identify affected hosts
GET /alerts/recent?severity=critical&detection_type=ransomware

# 2. Get file modification scope
GET /logs/search {"query":"file_modification AND .encrypted","time_from":"now-30m"}

# 3. Sandbox the ransomware binary
POST /sandbox/analyze (upload suspicious .exe)

# 4. Check for network C2 connection
GET /alerts/recent?detection_type=c2_beacon
```

### Containment
- [ ] Isolate ALL affected hosts from network immediately
- [ ] Shut down shared drives / NAS to prevent spread
- [ ] Block C2 domains at DNS level
- [ ] Preserve memory dump of infected hosts before shutdown
- [ ] Identify patient zero (first infected system)

### Evidence Collection
```bash
# Memory dump (if possible before isolation)
sudo dd if=/dev/mem of=/forensics/mem_dump_$(hostname)_$(date +%s).raw

# File system snapshot
sudo cp -a /home /forensics/home_backup_$(date +%s)/

# Network connections at time of infection
ss -tunap > /forensics/netstat_$(date +%s).txt
```

### Recovery
- [ ] Restore from last clean backup (verify backup integrity first)
- [ ] Do NOT pay ransom without legal/management approval
- [ ] Patch vector that allowed initial access
- [ ] Re-deploy from golden images if backup unavailable
- [ ] Test restored systems before reconnecting to network

---

## Playbook 3 — Data Exfiltration

**MITRE:** T1041 — Exfiltration Over C2 Channel  
**Triggers:** `SIG-008` Large Outbound Transfer

### SOAR Auto-Actions
1. Isolate source endpoint
2. Block exfiltration destination IP
3. Critical Slack alert
4. Email SOC + Legal + Management (potential breach notification)
5. Create P1 ticket

### Manual Investigation
```bash
# 1. Quantify data volume
GET /logs/search {"query":"data_exfiltration AND orig_bytes","time_from":"now-24h"}

# 2. Identify destination
GET /intel/ip/full/{destination_ip}
GET /intel/shodan/{destination_ip}

# 3. Identify what data was exfiltrated
GET /logs/search {"query":"hostname:{affected_host} AND file_access","time_from":"now-1h"}

# 4. Check for persistence mechanisms
GET /logs/search {"query":"hostname:{affected_host} AND (crontab OR startup OR service_install)"}
```

### Legal & Compliance
- [ ] Preserve all logs (litigation hold)
- [ ] Notify Legal department within 1 hour
- [ ] Assess if PII/PHI/PCI data was involved
- [ ] If regulatory breach: GDPR 72h notification window starts NOW
- [ ] Document chain of custody for evidence

---

## Playbook 4 — Lateral Movement

**MITRE:** T1021 — Remote Services  
**Triggers:** `SIG-012` SMB Enumeration, correlated attack chain

### SOAR Auto-Actions
1. Disable compromised account
2. Isolate source host
3. High severity Slack alert
4. Create incident ticket

### Investigation
```bash
# Map the movement chain
GET /alerts/recent?detection_type=lateral_movement
GET /correlation/chains

# Identify all compromised hosts
GET /logs/search {"query":"source_ip:{attacker} AND smb OR rdp OR ssh","time_from":"now-6h"}

# Check for persistence on each compromised host
GET /logs/search {"query":"hostname:{each_host} AND (scheduled_task OR service_install OR registry)"}
```

### Containment
- [ ] Block lateral movement traffic at firewall (port 445, 3389, 22)
- [ ] Implement micro-segmentation if not already in place
- [ ] Reset credentials for ALL compromised accounts
- [ ] Review network segmentation gaps

---

## Playbook 5 — Insider Threat / Privilege Abuse

**MITRE:** T1548, T1078  
**Triggers:** `SIG-007` SUID abuse, `SIG-011` New admin account, Impossible Travel

### Investigation
```bash
# Review user activity timeline
GET /logs/search {"query":"username:{suspect_user}","size":500,"time_from":"now-7d"}

# Check privilege escalation attempts
GET /alerts/search {"query":"privilege_escalation AND {suspect_user}"}

# VPN geo history
GET /vpn/geo/{username}

# Data access patterns
GET /logs/search {"query":"username:{suspect_user} AND (file_access OR database)"}
```

### Preservation
- [ ] Do NOT alert suspect — covert investigation first
- [ ] Capture full audit logs before account is touched
- [ ] Escalate to HR and Legal before taking action
- [ ] Preserve evidence to USB/offline storage

---

## Playbook 6 — Phishing

**MITRE:** T1566  
**Triggers:** `SIG-XXX` Phishing email detected

### SOAR Auto-Actions
1. Extract URLs from email
2. Check URLs via VirusTotal
3. Block malicious domains at DNS
4. Create ticket

### Response
```bash
# 1. Identify all recipients
GET /logs/search {"query":"phishing AND email","time_from":"now-2h"}

# 2. Check if any user clicked the link
GET /logs/search {"query":"url_access AND {malicious_domain}"}

# 3. Sandbox any attachments
POST /sandbox/analyze

# 4. Block domain
POST /soar/execute/phishing {alert}
```

---

## Playbook 7 — Cloud Security Incident

**MITRE:** T1078, T1537, T1562  
**Triggers:** Cloud Security Module detections

### High-Risk API Calls
| Action | Threat | Response |
|---|---|---|
| `DeleteTrail` | Defense evasion — hiding activity | Re-enable immediately + investigate |
| `CreateUser` + `AttachAdminPolicy` | Persistence backdoor | Delete user, revoke keys |
| `PutBucketAcl` public=true | Data exposure | Fix ACL + check data accessed |
| `GetSecretValue` unexpected | Credential theft | Rotate all secrets immediately |

### Investigation
```bash
# Review cloud scan results
GET /cloud/scan/history

# Get all suspicious cloud events (24h)
GET /cloud/events/suspicious

# Run fresh posture scan
POST /cloud/scan {"provider":"aws","region":"us-east-1"}
```

---

## Post-Incident Template

```markdown
## Incident Report — INC-YYYYMMDD-XXX

**Date:** YYYY-MM-DD
**Severity:** CRITICAL / HIGH / MEDIUM
**Type:** [ransomware / breach / lateral_movement / etc]
**Affected Systems:** [list]
**Duration:** Detection: HH:MM — Containment: HH:MM

### Timeline
- HH:MM — Initial detection by SentinelAI (rule: SIG-XXX)
- HH:MM — SOAR auto-response triggered
- HH:MM — Analyst acknowledged
- HH:MM — Containment complete
- HH:MM — Recovery complete

### Root Cause
[What vulnerability/gap allowed this]

### Impact
[Data, systems, business operations affected]

### Actions Taken
1. [SOAR: IP blocked]
2. [Manual: Account disabled]
3. [Manual: Endpoint isolated]

### Lessons Learned
[What detection/response can be improved]

### Recommendations
1. [Patch/config change]
2. [New detection rule needed]
3. [Training needed]
```

---

## Emergency Contacts

| Role | Contact | When to call |
|---|---|---|
| SOC Manager | Pager / Slack | Any CRITICAL |
| CISO | Phone | Confirmed breach, ransomware |
| Legal | Email | PII breach, regulatory |
| IT Infrastructure | On-call rotation | Any system isolation needed |
| Cloud Team | Slack `#cloud-infra` | Cloud security incidents |
