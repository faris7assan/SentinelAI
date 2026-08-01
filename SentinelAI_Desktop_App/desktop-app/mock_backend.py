"""
SentinelAI — Lightweight Mock Backend
Serves realistic fake data for ALL desktop-app API endpoints.
Run:  python mock_backend.py
Then launch the desktop app with backend_mode = "local".
"""
import json, random, uuid, hashlib, os, time, sqlite3
from datetime import datetime, timezone, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

HOST, PORT = "127.0.0.1", 8000
DB_PATH = "sentinel.db"

# ── Reusable generators ────────────────────────────────────
def _ts(offset_min=0):
    return (datetime.now(timezone.utc) - timedelta(minutes=offset_min)).isoformat(timespec="seconds") + "Z"

def _ip():
    return f"{random.choice([185,203,45,91,104])}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

RULES = ["Brute Force SSH","Reverse Shell","Port Scan","DNS Tunneling","Privilege Escalation",
         "Lateral Movement SMB","Data Exfiltration","Ransomware Encryption","Phishing Email","Credential Dump"]
TACTICS = ["Initial Access","Execution","Persistence","Privilege Escalation","Defense Evasion",
           "Credential Access","Discovery","Lateral Movement","Collection","Exfiltration"]
TECHNIQUES = ["T1110.001","T1059.004","T1046","T1071.004","T1548.001","T1021.002","T1041","T1486","T1566.001","T1003.001"]
SEVS = ["critical","high","medium","low"]
HOSTS = [f"server-{c}-{i}" for c in "ABCDE" for i in range(1,4)]
LOG_SOURCES = ["syslog","auditd","zeek","suricata","winevent","osquery"]

def _alert(i=0):
    s = random.choice(SEVS)
    r = random.choice(RULES)
    return {"alert_id":f"ALR-{uuid.uuid4().hex[:8]}","severity":s,"rule_name":r,
            "source_ip":_ip(),"hostname":random.choice(HOSTS),
            "mitre_tactic":random.choice(TACTICS),"mitre_technique":random.choice(TECHNIQUES),
            "detection_type":r.lower().replace(" ","_"),
            "timestamp":_ts(random.randint(0,1440))}

def _log_event():
    return {"severity":random.choice(SEVS),"log_source":random.choice(LOG_SOURCES),
            "event_type":random.choice(["failed_login","command_execution","dns_query","conn","file_modification"]),
            "source_ip":_ip(),"hostname":random.choice(HOSTS),
            "raw_log":f"sample log line {uuid.uuid4().hex[:6]}",
            "timestamp":_ts(random.randint(0,1440))}

# ── Pre-generated data pools ───────────────────────────────
ALERTS_POOL = [_alert(i) for i in range(200)]

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
        alert_id TEXT PRIMARY KEY, severity TEXT, rule_name TEXT,
        source_ip TEXT, hostname TEXT, mitre_tactic TEXT,
        mitre_technique TEXT, timestamp TEXT, raw_json TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT,
        log_source TEXT, event_type TEXT, source_ip TEXT,
        hostname TEXT, timestamp TEXT, raw_json TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS system_metrics (
        id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
        cpu_percent REAL, mem_percent REAL, net_conns INTEGER)''')
    conn.commit()
    # Seed alerts if empty
    if c.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0:
        for a in ALERTS_POOL:
            c.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                      (a["alert_id"], a["severity"], a["rule_name"], a["source_ip"],
                       a["hostname"], a["mitre_tactic"], a["mitre_technique"], a["timestamp"], json.dumps(a)))
        conn.commit()
    conn.close()

init_db()

def get_db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
SCENARIOS = [
    {"id":"brute_force_ssh","name":"SSH Brute Force Campaign","description":"Dictionary-based SSH credential stuffing","mitre":"T1110.001"},
    {"id":"reverse_shell","name":"Bash Reverse Shell","description":"C2 via bash TCP socket","mitre":"T1059.004"},
    {"id":"port_scan","name":"Nmap SYN Port Scan","description":"Network recon via SYN scan","mitre":"T1046"},
    {"id":"dns_tunneling","name":"DNS Tunneling (dnscat2)","description":"C2 via encoded DNS queries","mitre":"T1071.004"},
    {"id":"privilege_escalation","name":"SUID Privilege Escalation","description":"SUID binary abuse for root","mitre":"T1548.001"},
    {"id":"lateral_movement","name":"SMB Lateral Movement","description":"Pivoting via SMB/WMI","mitre":"T1021.002"},
    {"id":"data_exfiltration","name":"Data Exfiltration via HTTPS","description":"Large data transfer to external IP","mitre":"T1041"},
    {"id":"ransomware","name":"Ransomware File Encryption","description":"File encryption across filesystem","mitre":"T1486"},
    {"id":"phishing_simulation","name":"Spear Phishing Email","description":"Phishing with malicious URL","mitre":"T1566.001"},
    {"id":"credential_dump","name":"LSASS Credential Dump","description":"Mimikatz credential extraction","mitre":"T1003.001"},
    {"id":"full_attack_chain","name":"Full APT Attack Chain","description":"Multi-stage APT simulation","mitre":"Multiple"},
]
PLAYBOOKS = [
    {"name":"block_ip","description":"Block malicious IP at firewall + EDR isolation"},
    {"name":"isolate_host","description":"Network-isolate compromised host via EDR"},
    {"name":"disable_user","description":"Disable AD account and revoke active sessions"},
    {"name":"quarantine_file","description":"Move suspicious file to sandbox quarantine"},
    {"name":"enrich_alert","description":"Auto-enrich alert with threat intelligence"},
]

SIM_HISTORY = []
SOAR_HISTORY = []
TICKETS = [{"ticket_id":f"TK-{uuid.uuid4().hex[:6]}","rule_name":random.choice(RULES),
            "severity":random.choice(SEVS),"status":random.choice(["open","in_progress","resolved"]),
            "created_at":_ts(random.randint(0,4320))} for _ in range(15)]


# ── Route handler ──────────────────────────────────────────
class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"  [{datetime.now().strftime('%H:%M:%S')}] {args[0]}")

    def _send(self, data, code=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length:
            return json.loads(self.rfile.read(length))
        return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type,Authorization")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")
        qs = parse_qs(urlparse(self.path).query)

        if path == "/health":
            return self._send({"status":"healthy","service":"mock-unified","version":"1.0.0"})

        if path == "/alerts/recent":
            size = int(qs.get("size",[50])[0])
            sev = qs.get("severity",[None])[0]
            with get_db_conn() as conn:
                if sev:
                    rows = conn.execute("SELECT raw_json FROM alerts WHERE severity=? ORDER BY timestamp DESC LIMIT ?", (sev, size)).fetchall()
                else:
                    rows = conn.execute("SELECT raw_json FROM alerts ORDER BY timestamp DESC LIMIT ?", (size,)).fetchall()
                return self._send([json.loads(r[0]) for r in rows])

        if path == "/alerts/stats":
            with get_db_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                sevs = {s: conn.execute("SELECT COUNT(*) FROM alerts WHERE severity=?", (s,)).fetchone()[0] for s in SEVS}
            return self._send({"total":total, "by_severity": sevs})

        if path == "/rules":
            return self._send([{"rule_id":f"R{i+1:03d}","name":r,"severity":SEVS[i%4],"enabled":True}
                               for i,r in enumerate(RULES)])

        if path == "/metrics":
            with get_db_conn() as conn:
                total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                crit = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical'").fetchone()[0]
                high = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='high'").fetchone()[0]
                logs_cnt = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
                
                # Fetch latest system metrics if available
                sys_m = conn.execute("SELECT cpu_percent, mem_percent, net_conns FROM system_metrics ORDER BY id DESC LIMIT 1").fetchone()
                cpu, mem, net = (sys_m[0], sys_m[1], sys_m[2]) if sys_m else (0, 0, 0)
                
            return self._send({"counters":{"total_alerts":total,
                "critical_alerts":crit,
                "high_alerts":high,
                "attack_chains":random.randint(2,8),
                "logs_ingested":logs_cnt + 80000,
                "soar_executions":len(SOAR_HISTORY)},
                "system": {"cpu": cpu, "mem": mem, "net": net}})

        if path == "/logs/stats":
            return self._send({"by_severity":{"buckets":[{"key":s,"doc_count":random.randint(100,5000)} for s in SEVS]},
                "by_source":{"buckets":[{"key":s,"doc_count":random.randint(200,8000)} for s in LOG_SOURCES]}})

        if path == "/redteam/scenarios":
            return self._send({"scenarios": SCENARIOS})

        if path == "/redteam/history":
            return self._send(SIM_HISTORY[-50:])

        if path == "/soar/playbooks":
            return self._send({"playbooks":PLAYBOOKS})

        if path == "/soar/executions":
            return self._send(SOAR_HISTORY[-50:])

        if path == "/soar/tickets":
            return self._send(TICKETS)

        if path == "/cloud/scan/history":
            return self._send([{"provider":p,"posture_score":random.randint(55,95),
                "grade":random.choice(["A","B","C"]),"scanned_at":_ts(random.randint(0,10080))}
                for p in ["aws","azure","gcp"]])

        if path == "/sandbox/results":
            return self._send([{"file_name":f"sample_{i}.exe","verdict":random.choice(["MALICIOUS","SUSPICIOUS","CLEAN"]),
                "threat_score":random.randint(0,90),"timestamp":_ts(random.randint(0,4320))} for i in range(8)])

        if path == "/honeypot/log":
            return self._send([{"attacker_ip":_ip(),"honeypot_type":random.choice(["ssh","http","smb","rdp"]),
                "event_type":random.choice(["login_attempt","scan","exploit"]),"timestamp":_ts(random.randint(0,1440))} for _ in range(30)])

        if path == "/honeypot/top-attackers":
            return self._send([{"ip":_ip(),"hits":random.randint(5,500)} for _ in range(10)])

        if path == "/vpn/sessions":
            users = ["h.faris","a.khan","m.omar","s.ali","n.hassan"]
            return self._send([{"username":random.choice(users),"peer_ip":_ip(),
                "geo":{"country":random.choice(["Egypt","UAE","US","UK","DE"]),"city":random.choice(["Cairo","Dubai","NYC","London","Berlin"]),"is_proxy":random.random()<0.15},
                "protocol":random.choice(["WireGuard","OpenVPN","IKEv2"]),"event":random.choice(["connect","disconnect"])}
                for _ in range(20)])

        if path == "/vpn/stats":
            return self._send({"active_users":random.randint(3,15),"total_sessions":random.randint(50,500)})

        if path == "/agents/status":
            return self._send([{"agent_id":f"agent-{i}","hostname":random.choice(HOSTS),
                "status":random.choice(["online","offline"]),"last_seen":_ts(random.randint(0,120))} for i in range(8)])

        # Threat intel GET routes
        if path.startswith("/intel/ip/full/"):
            ip = path.split("/")[-1]
            return self._send(self._intel_ip(ip, full=True))
        if path.startswith("/intel/ip/"):
            ip = path.split("/")[-1]
            return self._send(self._intel_ip(ip))
        if path.startswith("/intel/hash/"):
            h = path.split("/")[-1]
            mal = random.random() > 0.4
            return self._send({"hash":h,"is_malicious":mal,"verdict":"MALICIOUS" if mal else "CLEAN",
                "engines_detected":random.randint(5,40) if mal else 0,"engines_total":70,
                "file_type":"PE32 executable","first_seen":_ts(random.randint(1440,43200))})
        if path.startswith("/intel/domain/"):
            d = path.split("/")[-1]
            score = random.randint(10,95)
            return self._send({"domain":d,"threat_score":{"score":score,"verdict":"HIGH" if score>70 else "MEDIUM" if score>40 else "LOW"},
                "categories":["malware" if score>60 else "clean"],"registrar":"NameCheap","created":_ts(random.randint(10080,525600))})
        if path.startswith("/intel/cve/"):
            c = path.split("/")[-1]
            cvss = round(random.uniform(3.0,10.0),1)
            return self._send({"cve_id":c,"cvss_score":cvss,"severity":"CRITICAL" if cvss>=9 else "HIGH" if cvss>=7 else "MEDIUM",
                "description":f"Remote code execution vulnerability in {random.choice(['Apache','Nginx','OpenSSL','Log4j'])}",
                "affected_products":["Product A","Product B"],"published":_ts(random.randint(1440,525600)),
                "references":[f"https://nvd.nist.gov/vuln/detail/{c}"]})

        self._send({"error":"not found","path":path}, 404)

    def do_POST(self):
        path = urlparse(self.path).path.rstrip("/")
        body = self._body()

        if path == "/auth/login":
            token = f"eyJ_{uuid.uuid4().hex}"
            return self._send({"access_token":token,"user":{"username":body.get("username","admin"),"role":"soc_admin","mfa_enabled":True}})

        if path == "/detect":
            alert = {"alert_id":f"ALR-{uuid.uuid4().hex[:8]}","severity":"medium",
                     "rule_name":"manual_detect","source_ip":"127.0.0.1","hostname":"local",
                     "mitre_tactic":"Defense Evasion","mitre_technique":"T1562",
                     "detection_type":"manual","timestamp":_ts()}
            with get_db_conn() as conn:
                conn.execute("INSERT INTO alerts VALUES (?,?,?,?,?,?,?,?,?)",
                             (alert["alert_id"], alert["severity"], alert["rule_name"], alert["source_ip"],
                              alert["hostname"], alert["mitre_tactic"], alert["mitre_technique"], alert["timestamp"], json.dumps(alert)))
            return self._send({"detected":True,"rule":"manual_detect","severity":"medium","alert_id":alert["alert_id"]})

        if path == "/logs/ingest":
            event = body
            event["timestamp"] = _ts() if "timestamp" not in event else event["timestamp"]
            with get_db_conn() as conn:
                conn.execute("INSERT INTO logs (severity, log_source, event_type, source_ip, hostname, timestamp, raw_json) VALUES (?,?,?,?,?,?,?)",
                             (event.get("severity","info"), event.get("log_source","syslog"), event.get("event_type","unknown"),
                              event.get("source_ip",""), event.get("hostname",""), event.get("timestamp"), json.dumps(event)))
            return self._send({"status":"ingested","event_hash":hashlib.sha256(json.dumps(body).encode()).hexdigest()[:16]})

        if path == "/logs/bulk":
            events = body.get("events",[])
            with get_db_conn() as conn:
                for event in events:
                    event["timestamp"] = _ts() if "timestamp" not in event else event["timestamp"]
                    conn.execute("INSERT INTO logs (severity, log_source, event_type, source_ip, hostname, timestamp, raw_json) VALUES (?,?,?,?,?,?,?)",
                                 (event.get("severity","info"), event.get("log_source","syslog"), event.get("event_type","unknown"),
                                  event.get("source_ip",""), event.get("hostname",""), event.get("timestamp"), json.dumps(event)))
            return self._send({"status":"ingested","count":len(events)})

        if path == "/logs/search":
            size = min(body.get("size",20), 100)
            q = body.get("query", "").lower()
            with get_db_conn() as conn:
                if q:
                    rows = conn.execute("SELECT raw_json FROM logs WHERE raw_json LIKE ? ORDER BY id DESC LIMIT ?", (f"%{q}%", size)).fetchall()
                else:
                    rows = conn.execute("SELECT raw_json FROM logs ORDER BY id DESC LIMIT ?", (size,)).fetchall()
            res = [json.loads(r[0]) for r in rows]
            if not res and not q:
                res = [_log_event() for _ in range(size)]
            return self._send({"total":len(res),"results":res})
            
        if path == "/metrics/ingest":
            with get_db_conn() as conn:
                conn.execute("INSERT INTO system_metrics (timestamp, cpu_percent, mem_percent, net_conns) VALUES (?,?,?,?)",
                             (_ts(), body.get("cpu"), body.get("mem"), body.get("net_conns")))
            return self._send({"status":"saved"})

        if path == "/ai/analyze-alert":
            alert = body.get("alert",{})
            return self._send({"analysis":f"## AI Analysis\n\n**Alert:** {alert.get('rule_name','N/A')}\n"
                f"**Severity:** {alert.get('severity','N/A')}\n**Source:** {alert.get('source_ip','N/A')}\n\n"
                "### Assessment\nThis alert indicates potentially malicious activity. The source IP has been "
                "associated with known threat actors. Recommend immediate investigation and IP blocking.\n\n"
                "### Recommended Actions\n1. Block source IP at perimeter firewall\n"
                "2. Isolate affected host for forensic analysis\n3. Check for lateral movement indicators\n"
                "4. Review authentication logs for compromised credentials"})

        if path == "/ai/threat-hunt":
            return self._send({"result":f"## Threat Hunt Results\n\n**Query:** {body.get('query','')}\n"
                f"**Time Range:** {body.get('time_range_hours',24)}h\n\n"
                "### Findings\n- 3 suspicious PowerShell executions detected on server-A-2\n"
                "- Encoded command patterns match known C2 frameworks\n"
                "- Outbound connections to 185.x.x.x:4444 (known C2)\n\n"
                "### IOCs Found\n- `185.220.101.45` — Tor exit node\n"
                "- `evil-c2.com` — Known C2 domain\n- Process: `powershell -enc <base64>`\n\n"
                "### Risk: HIGH\nImmediate containment recommended.",
                "context_events":random.randint(5,50)})

        if path == "/ai/generate/sigma-rule":
            return self._send({"rule_text":f"""title: {body.get('threat_description','Custom Detection')[:60]}
id: {uuid.uuid4()}
status: experimental
level: high
description: |
    Auto-generated Sigma rule for: {body.get('threat_description','')}
logsource:
    category: process_creation
    product: {body.get('log_source','windows')}
detection:
    selection:
        CommandLine|contains:
            - 'certutil'
            - '-urlcache'
            - '-decode'
    condition: selection
tags:
    - attack.{body.get('mitre_technique','T1059').lower()}
falsepositives:
    - Legitimate admin activity
"""})

        if path == "/ai/generate/yara-rule":
            return self._send({"rule_text":f"""rule {body.get('malware_family','Generic').replace(' ','_')}_Detection {{
    meta:
        description = "{body.get('threat_description','Malware detection')}"
        author = "SentinelAI"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        platform = "{body.get('platform','windows')}"

    strings:
        $s1 = "CreateRemoteThread" ascii
        $s2 = "VirtualAllocEx" ascii
        $s3 = {{ 4D 5A 90 00 }}
        $ransom = "Your files have been encrypted" ascii nocase

    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $ransom)
}}"""})

        if path == "/redteam/simulate":
            sim_id = uuid.uuid4().hex[:8]
            scenario = body.get("scenario","unknown")
            n_events = random.randint(3,16)
            rec = {"sim_id":sim_id,"scenario":scenario,"scenario_name":next((s["name"] for s in SCENARIOS if s["id"]==scenario),scenario),
                   "attacker_ip":body.get("attacker_ip") or _ip(),
                   "target_host":body.get("target_host") or random.choice(HOSTS),
                   "mitre":next((s["mitre"] for s in SCENARIOS if s["id"]==scenario),"T1059"),
                   "events_total":n_events,"events_shipped":n_events if not body.get("dry_run") else 0,
                   "dry_run":body.get("dry_run",False),"status":"completed","timestamp":_ts(),
                   "events_preview":[]}
            SIM_HISTORY.insert(0, rec)
            return self._send(rec)

        if path == "/redteam/phishing":
            email = body.get("target_email","victim@company.com")
            domain = body.get("sender_domain","company-secure.net")
            return self._send({"from":f"noreply@{domain}","to":email,
                "subject":"⚠️ Action Required: Your VPN Access Expires in 24 Hours",
                "body":f"Dear {email.split('@')[0].title()},\n\nYour corporate VPN access will expire in 24 hours.\n"
                       f"Verify your credentials at:\nhttps://corp-vpn-secure.{domain}/renew?token={uuid.uuid4().hex[:16]}\n\n"
                       "IT Security Team",
                "malicious_urls":[f"https://corp-vpn-secure.{domain}/renew"],
                "headers":{"X-Mailer":"Microsoft Outlook 16.0","X-Originating-IP":_ip(),"Reply-To":f"helpdesk@{domain}"},
                "ioc_type":"phishing_email","generated_at":_ts(),
                "note":"⚠️ SIMULATION ONLY — For security awareness training"})

        if path.startswith("/soar/execute/"):
            pb_name = path.split("/")[-1]
            steps = [{"action":a,"status":"completed","status_icon":"✅"} for a in
                     ["Validate alert","Enrich with threat intel","Check reputation","Execute response","Update ticket"]]
            total_ms = random.uniform(200,1500)
            rec = {"playbook_name":pb_name,"status":"completed","total_time_ms":total_ms,
                   "steps_executed":steps,"timestamp":_ts()}
            SOAR_HISTORY.insert(0, rec)
            return self._send(rec)

        if path == "/cloud/scan":
            provider = body.get("provider","aws")
            score = random.randint(45,95)
            checks = [{"check_id":f"CIS-{provider.upper()}-{i+1:03d}",
                "title":t,"severity":random.choice(SEVS),"status":random.choice(["PASS","FAIL"]),
                "description":f"Ensure {t}","details":"Checked via API","remediation":"See CIS Benchmark",
                "nist_ref":f"AC-{random.randint(1,20)}"} for i,t in enumerate([
                    "Root account MFA enabled","CloudTrail logging enabled","S3 bucket encryption",
                    "Security groups restrict SSH","VPC flow logs enabled","IAM password policy",
                    "KMS key rotation enabled","RDS encryption at rest","WAF rules configured",
                    "GuardDuty enabled"])]
            passing = sum(1 for c in checks if c["status"]=="PASS")
            return self._send({"provider":provider,"posture_score":score,
                "grade":"A" if score>=80 else "B" if score>=60 else "C",
                "framework":"CIS Benchmark v1.4","checks":checks,
                "summary":{"passing":passing,"failing":len(checks)-passing}})

        if path == "/sandbox/analyze":
            return self._send({"file_name":"uploaded_file","file_type":"PE32 executable",
                "file_size":random.randint(10000,5000000),"file_hash_sha256":hashlib.sha256(os.urandom(32)).hexdigest(),
                "verdict":random.choice(["MALICIOUS","SUSPICIOUS","CLEAN"]),
                "threat_score":random.randint(0,90),
                "static_analysis":{"entropy":round(random.uniform(4.0,7.9),4),
                    "entropy_note":"High" if random.random()>0.5 else "Normal",
                    "dangerous_ext":random.random()>0.6,
                    "suspicious_strings":["cmd.exe /c","powershell -enc","CreateRemoteThread"][:random.randint(0,3)]},
                "yara_matches":["MALWARE_Generic","Ransomware_Note"][:random.randint(0,2)],
                "timestamp":_ts()})

        if path == "/intel/bulk":
            results = []
            for ioc in body.get("iocs",[]):
                score = random.randint(5,95)
                results.append({"ip":ioc.get("ioc"),"domain":ioc.get("ioc"),"hash":ioc.get("ioc"),
                    "threat_score":{"score":score,"verdict":"HIGH" if score>70 else "MEDIUM" if score>40 else "LOW"}})
            return self._send({"results":results})

        if path == "/reports/json":
            rt = body.get("report_type","executive")
            return self._send({"report_type":rt,"period_hours":body.get("time_range_h",24),
                "generated_at":_ts(),"summary":{"total_alerts":random.randint(50,300),
                    "by_severity":{"critical":random.randint(2,15),"high":random.randint(10,40),
                        "medium":random.randint(20,80),"low":random.randint(10,50)},
                    "attack_chains":random.randint(1,5),
                    "by_type":{"brute_force":random.randint(5,30),"port_scan":random.randint(3,20),
                        "phishing":random.randint(1,10),"malware":random.randint(2,15)}}})

        if path == "/reports/pdf":
            # Return a minimal valid PDF
            pdf = b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n190\n%%EOF"
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(pdf)))
            self.end_headers()
            self.wfile.write(pdf)
            return

        self._send({"error":"not found","path":path}, 404)

    def do_PUT(self):
        path = urlparse(self.path).path.rstrip("/")
        qs = parse_qs(urlparse(self.path).query)
        if "/soar/tickets/" in path and path.endswith("/status"):
            tid = path.split("/")[-2]
            status = qs.get("status",["resolved"])[0]
            for t in TICKETS:
                if t["ticket_id"] == tid:
                    t["status"] = status
            return self._send({"ticket_id":tid,"status":status,"updated":True})
        self._send({"error":"not found"}, 404)

    # ── Helper ─────────────────────────────────────────────
    def _intel_ip(self, ip, full=False):
        score = random.randint(10, 95)
        verdict = "CRITICAL" if score>80 else "HIGH" if score>60 else "MEDIUM" if score>30 else "LOW"
        data = {"ip":ip,"threat_score":{"score":score,"verdict":verdict},
            "virustotal":{"malicious":random.randint(0,15),"harmless":random.randint(40,70),"source":"VirusTotal"},
            "abuseipdb":{"abuse_confidence":score,"total_reports":random.randint(0,500),"country":"Unknown","source":"AbuseIPDB"},
            "otx":{"pulse_count":random.randint(0,20),"reputation":random.randint(0,5),"source":"OTX"}}
        if full:
            data["shodan"] = {"ports":[22,80,443,8080],"os":"Linux","org":"DigitalOcean","source":"Shodan"}
            data["misp"] = {"event_count":random.randint(0,10),"threat_level":"high","source":"MISP"}
            data["opencti"] = {"indicators":random.randint(0,5),"source":"OpenCTI"}
        return data


if __name__ == "__main__":
    print(f"""
======================================================
    SentinelAI Mock Backend                       
    Listening on http://{HOST}:{PORT}                  
    Press Ctrl+C to stop                               
======================================================
""")
    server = HTTPServer((HOST, PORT), MockHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nMock backend stopped.")
        server.server_close()
