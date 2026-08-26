# SentinelAI

## AI-Assisted SOC & Threat Detection Platform

SentinelAI is a cybersecurity project exploring how endpoint telemetry, network-security data, rule-based detection, machine learning, threat intelligence, and automated response can be combined into a SOC-style platform.

> **Project status:** Experimental / portfolio project. The architecture describes a broad security platform; individual integrations and capabilities should be verified against the current code before production use.

## Architecture

```text
Endpoints / Network Sources
          ↓
Log & Telemetry Collection
          ↓
Detection Layer
(Sigma / YARA / IDS / Behavioral)
          ↓
AI-Assisted Analysis
          ↓
Event Correlation
          ↓
Response / SOAR Workflows
          ↓
Dashboard / Reports / Alerts
```

## Core Areas

### Endpoint & Network Monitoring

The project is designed to work with security telemetry such as:

- Windows Event Logs / Sysmon
- Linux audit and system logs
- Zeek / Suricata network telemetry
- tcpdump/network traffic data

### Detection

- Sigma-style detection rules
- YARA-based analysis
- IDS/network detection signals
- Behavioral and anomaly detection
- Multi-event correlation

### AI / ML

The project explores:

- Isolation Forest anomaly detection
- Supervised classification models
- Local LLM-assisted analysis
- Automated incident summaries

### SOAR Concepts

Example response workflows include:

- Phishing investigation
- Brute-force response
- Suspicious-host isolation
- IP blocking

### Threat Intelligence

The architecture includes integrations for reputation and threat-intelligence sources such as VirusTotal, AbuseIPDB, AlienVault OTX, and MISP/OpenCTI.

## Local Development

### Requirements

- Python 3.11+
- Node.js 20+

```bash
git clone https://github.com/faris7assan/SentinelAI.git
cd SentinelAI
python scripts/start_local_dev.py
```

The local development setup exposes the backend on `127.0.0.1:8000`. A separate frontend can be run on port `3000` when required by the current project configuration.

## Security Architecture

The project explores:

- Zero-Trust security principles
- JWT authentication
- MFA
- RBAC
- Environment-based secret management
- OWASP-oriented application security
- MITRE ATT&CK mapping

## Example Detection Areas

The platform is designed to support investigation of security events including:

- Brute force
- DDoS
- Port scanning
- Suspicious process execution
- Reverse shells
- DNS tunneling
- Malware-related activity
- Privilege escalation
- Lateral movement

## Project Value

SentinelAI demonstrates how a SOC workflow can combine **telemetry → detection → correlation → investigation → response** rather than treating machine learning as a standalone classifier.

## Author

**Hassan Faris**  
Cybersecurity Graduate | SOC | Threat Detection | Network Security

- GitHub: https://github.com/faris7assan
- Portfolio: https://hassanhamedfaris69.base44.app/
- LinkedIn: https://www.linkedin.com/in/hassan-faris/

## Disclaimer

For educational, research, and authorized security-testing environments only. Do not deploy automated response actions against systems without explicit authorization.
