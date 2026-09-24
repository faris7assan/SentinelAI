# SentinelAI

## AI-Assisted SOC & Threat Detection Platform

SentinelAI explores endpoint telemetry, network-security data, rule-based detection, machine learning, threat intelligence, event correlation, and response workflows in a SOC-style platform.

> Status: Experimental / portfolio project. Integrations must be verified and hardened before production use.

## Security workflow

~~~text
Telemetry → Ingestion / Normalization → Detection + Threat Scoring
         → Correlation / Investigation → Analyst Dashboard
         → Response Workflow
~~~

## Detection areas

- Windows Event Logs / Sysmon
- Linux audit/system logs
- Zeek / Suricata telemetry
- Sigma-style rules
- YARA-oriented analysis
- Behavioral and anomaly detection
- Multi-event correlation
- Threat-intelligence enrichment

## AI / ML

- Isolation Forest anomaly detection
- Supervised classification
- Local LLM-assisted analysis
- Automated incident summaries

AI output is analyst assistance, not authoritative evidence.

## Response safety

High-impact actions such as endpoint isolation, process termination, firewall changes, and IP blocking should follow:

~~~text
DETECTED → TRIAGED → POLICY CHECK → APPROVED → EXECUTED → VERIFIED
~~~

Automated actions should be disabled by default, constrained to allowlisted assets, authorized explicitly, and audited.

See docs/RESPONSE_SAFETY.md.

## Security hardening

- Inject JWT secrets through deployment-time secret management.
- Restrict CORS to trusted origins.
- Enforce authorization on administrative/account-provisioning endpoints.
- Keep threat-intelligence credentials out of source control.
- Isolate high-impact response actions behind explicit policy gates.

See SECURITY.md.

## Author

Hassan Faris — Cybersecurity Engineer | SOC | Network Security

- GitHub: https://github.com/faris7assan
- LinkedIn: https://www.linkedin.com/in/hassan-faris
- Portfolio: https://hassanhamedfaris69.base44.app
