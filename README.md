# 🛡️ SentinelAI — Autonomous AI-Powered SOC Platform

![Version](https://img.shields.io/badge/version-1.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110-teal)
![License](https://img.shields.io/badge/license-MIT-purple)

> Enterprise-grade, AI-powered Security Operations Center platform capable of autonomous threat detection, correlation, and response.

---

## 🌐 Architecture Overview

```
Endpoints/Servers
       ↓
 Log Collectors (Zeek, Suricata, Sysmon, auditd)
       ↓
 Message Queue (Kafka)
       ↓
 Detection Engine (Sigma + YARA + Behavioral)
       ↓
 AI Analysis Engine (Isolation Forest + XGBoost + LangChain)
       ↓
 Correlation Engine (Attack Chain Builder)
       ↓
 SOAR Automation (Playbooks + Auto-Response)
       ↓
 Dashboard + Reports + Alerts (React + Next.js)
```

---

## 📦 Microservices

| Service | Port | Description |
|---|---|---|
| local-dev backend | 8000 | Unified local backend for auth, logs, detections, AI, reports, SOAR, threat intel, and more |
| frontend | 3000 | React/Next.js dashboard |
| desktop app | local | PyQt5 control panel |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 20+

### Launch Local Dev Mode
```bash
git clone https://github.com/faris7assan/SentinelAI
cd SentinelAI
python scripts/start_local_dev.py
```

### Access
- **Local backend**: http://127.0.0.1:8000
- **Desktop app**: starts automatically in local mode
- **Dashboard**: http://localhost:3000 if you still run the frontend separately

---

## 🧩 Core Modules

### 1. Endpoint Monitoring
- Linux: `auditd`, `syslog`, `osquery`
- Windows: `Sysmon`, `Windows Event Logs`
- Network: `Zeek`, `Suricata`, `tcpdump`

### 2. Detection Engine
- **Signature**: Sigma Rules + YARA Rules + Suricata IDS
- **Behavioral**: Impossible travel, priv escalation, reverse shells
- **Correlation**: Multi-event attack chain detection

### 3. AI Engine
- **Anomaly Detection**: Isolation Forest + Autoencoders
- **Classification**: XGBoost + Random Forest + DNN
- **NLP Assistant**: LangChain + Ollama (local LLM)
- **Report Generation**: AI-powered incident summaries

### 4. SOAR Automation
- Phishing playbook
- Brute force response
- Malware isolation
- IP blocking automation

### 5. Threat Intelligence
- VirusTotal integration
- AbuseIPDB reputation
- AlienVault OTX feeds
- MISP/OpenCTI connectors

---

## 🔐 Security Architecture
- Zero-Trust design
- JWT + MFA + RBAC
- Secrets via environment variables
- OWASP Top 10 mitigations applied

---

## 📊 Supported Attack Detection
- DDoS, Brute Force, Ransomware
- Reverse Shells, DNS Tunneling
- Port Scanning, Malware Execution
- Data Exfiltration, Credential Stuffing
- Lateral Movement, Privilege Escalation

---

## 🗺️ MITRE ATT&CK Coverage
Dashboard maps all detections to ATT&CK tactics and techniques.

---

## 👨‍💻 Author
**Hassan Hamed Faris**  
Cybersecurity Engineering  
GitHub: [@faris7assan](https://github.com/faris7assan)
