# SentinelAI — Desktop Control Panel

A native PyQt5 desktop application that gives full control over every SentinelAI
microservice from a single window — dashboard, alerts, AI copilot, threat intel,
SOAR, red-team simulation, cloud security, sandbox, honeypot, VPN monitor,
reports, raw logs, and settings.

---

## 1. Requirements

- Python 3.9 – 3.12
- The SentinelAI backend microservices running (see the main project
  the local launcher in the main SentinelAI repo.

## 2. Install

```bash
cd SentinelAI_Desktop_App/desktop-app
pip install -r requirements.txt
```

(Only two dependencies: `PyQt5` and `requests`.)

## 3. Run

**Linux / macOS**
```bash
bash run.sh
```

**Windows**
```cmd
run.bat
```

**Or directly**
```bash
python3 main.py
```

A splash screen appears for ~2 seconds, then a login dialog. In local mode, it
talks to the no-Docker backend on port 8000. You can also click **Skip (no
auth)** to browse the UI without a token.

## 4. First-Time Configuration

Go to **Settings → Connection** to point the app at your backend. In local
mode, all services route through the single backend on port 8000.

## 5. Feature Tour

| Tab | What it does |
|---|---|
| **Dashboard** | Live metric cards, service health grid, recent alert feed (auto-refreshes every 30s) |
| **Alerts** | Filter/search alerts, view full detail, trigger AI analysis, run SOAR playbook, or do an instant threat-intel lookup — all from the same row |
| **AI Copilot** | Chat with the AI analyst, run autonomous threat hunts, generate new Sigma/YARA rules from a plain-English description |
| **Threat Intel** | IP / Hash / Domain / CVE lookups via local-dev defaults plus bulk IOC checking |
| **SOAR** | Execute any playbook manually with a custom JSON alert, manage tickets, inspect execution history step-by-step |
| **Red Team** | Launch attack simulations (brute force, ransomware, full APT chain…), generate phishing emails for awareness training |
| **Cloud** | Run a CIS-benchmark posture scan against AWS/Azure/GCP and drill into each failed check with remediation guidance |
| **Sandbox** | Drop a suspicious file in, get YARA matches, entropy, and a verdict |
| **Honeypot** | See who's poking your traps and rank top attackers |
| **VPN** | Live VPN session table with GeoIP and proxy/anomaly flags |
| **Reports** | Generate an executive/technical/compliance PDF or JSON report with one click, auto-saved to your chosen folder |
| **Logs** | Full-text search across ingested logs, manually ingest a test event, or bulk-import a `.log`/`.txt` file |
| **Settings** | Endpoint config, dark/light theme, login, and an About page |

## 6. Keyboard Shortcuts

`Ctrl+1`…`Ctrl+8` jump directly to the first eight tabs.

## 7. Theme

Click **🌙 Dark / ☀️ Light** in the top header bar at any time — the choice is
saved to `~/.sentinelai/desktop_config.json` and restored next launch.

## 8. Architecture Notes

- **`api/client.py`** — one thin function per backend endpoint; nothing else
  in the UI talks to `requests` directly.
- **`utils/worker.py`** — every network call runs on a `QThread` so the UI
  never freezes, even on a slow AI/LLM call.
- **`ui/tabs/*`** — one file per feature area, fully self-contained.
- **`ui/main_window.py`** — assembles the tabs, header, status bar, and theme
  switcher.

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| All services show ❌ in the header | Backend isn't running — start it with `python ../SentinelAI/scripts/start_local_dev.py` from the project root, or fix the URLs in Settings → Connection |
| Login fails with "Login failed: ..." | Check `auth-service` is up on port 8001 and credentials are correct |
| PDF/JSON report saves to the wrong place | Set an explicit output folder in the Reports tab before generating |
| App looks unstyled / plain | Make sure `PyQt5` installed correctly (`pip show PyQt5`) |

---

Built by **Hassan Hamed Faris** — Cybersecurity Engineering
