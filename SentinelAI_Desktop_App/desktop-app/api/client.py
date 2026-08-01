import json
from datetime import datetime
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CONFIG_FILE = Path.home() / ".sentinelai" / "desktop_config.json"
DEFAULT_LOCAL_BACKEND_URL = "http://127.0.0.1:8000"

BASE_URLS = {
    "gateway":"http://localhost:8000","auth":"http://localhost:8001",
    "logs":"http://localhost:8002","detection":"http://localhost:8003",
    "ai":"http://localhost:8004","soar":"http://localhost:8005",
    "threatintel":"http://localhost:8006","alerts":"http://localhost:8007",
    "reports":"http://localhost:8008","vpn":"http://localhost:8009",
    "honeypot":"http://localhost:8010","sandbox":"http://localhost:8011",
    "cloud":"http://localhost:8012","redteam":"http://localhost:8013",
    "agents":"http://localhost:8014","metrics":"http://localhost:8015",
}
TIMEOUT = 8
_token  = ""
_session = requests.Session()
_retry = Retry(
    total=3,
    connect=3,
    read=3,
    backoff_factor=0.35,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset(["GET", "POST", "PUT", "PATCH", "DELETE"]),
)
_adapter = HTTPAdapter(max_retries=_retry, pool_connections=32, pool_maxsize=32)
_session.mount("http://", _adapter)
_session.mount("https://", _adapter)
_last_sync_at = None


def _load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


_cfg = _load_config()


def _normalize_url(url: str) -> str:
    return str(url or "").strip().rstrip("/")


def _apply_base_urls(base_urls: dict):
    for _name, _url in (base_urls or {}).items():
        if _name in BASE_URLS and _url:
            BASE_URLS[_name] = _normalize_url(_url)

_token = _cfg.get("token", "")

_backend_mode = _cfg.get("backend_mode", "distributed")
_backend_base_url = _normalize_url(_cfg.get("backend_base_url", DEFAULT_LOCAL_BACKEND_URL))

if _backend_mode == "local":
    for _name in BASE_URLS:
        BASE_URLS[_name] = _backend_base_url
else:
    _apply_base_urls(_cfg.get("base_urls", {}))

def set_token(t): 
    global _token
    _token = t


def set_backend_mode(mode: str, backend_base_url: str | None = None):
    global _backend_mode, _backend_base_url
    _backend_mode = mode or "distributed"
    if backend_base_url:
        _backend_base_url = _normalize_url(backend_base_url)
    if _backend_mode == "local":
        for _name in BASE_URLS:
            BASE_URLS[_name] = _backend_base_url
    else:
        _apply_base_urls(_cfg.get("base_urls", {}))


def apply_config(cfg):
    if not isinstance(cfg, dict):
        return
    set_backend_mode(cfg.get("backend_mode", _backend_mode), cfg.get("backend_base_url", _backend_base_url))
    if _backend_mode != "local":
        _apply_base_urls(cfg.get("base_urls", {}))
    token = cfg.get("token")
    if token:
        set_token(token)


def save_config(extra=None):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = _load_config()
    data["backend_mode"] = _backend_mode
    data["backend_base_url"] = _backend_base_url
    data["base_urls"] = {k: _normalize_url(v) for k, v in BASE_URLS.items()}
    data["token"] = _token
    if extra:
        data.update(extra)
    CONFIG_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")

def _h():
    return {"Content-Type":"application/json","Authorization":f"Bearer {_token}"} if _token else {"Content-Type":"application/json"}


def _request(method, url, *, params=None, json_body=None, files=None, timeout=TIMEOUT):
    global _last_sync_at
    headers = _h().copy()
    if files is not None:
        headers.pop("Content-Type", None)
    response = _session.request(
        method,
        _normalize_url(url),
        headers=headers,
        params=params,
        json=json_body,
        files=files,
        timeout=timeout,
    )
    response.raise_for_status()
    _last_sync_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
    return response


def get_last_sync_at():
    return _last_sync_at

def _get(svc,path):
    return _request("GET", BASE_URLS[svc] + path).json()

def _post(svc,path,data=None):
    return _request("POST", BASE_URLS[svc] + path, json_body=data or {}).json()

def health_all():
    out = {}
    for n,b in BASE_URLS.items():
        try:
            out[n] = _request("GET", b + "/health", timeout=3).status_code == 200
        except Exception:
            out[n] = False
    return out

def login(u,p,mfa=""):
    return _post("auth","/auth/login",{"username":u,"password":p,"mfa_token":mfa or None})

def get_recent_alerts(size=50,severity=None):
    p=f"/alerts/recent?size={size}"+(f"&severity={severity}" if severity else "")
    return _get("detection",p)

def get_alert_stats(): return _get("detection","/alerts/stats")
def get_rules(): return _get("detection","/rules")
def detect_manual(ev): return _post("detection","/detect",{"log_event":ev})
def ingest_log(ev): return _post("logs","/logs/ingest",ev)
def search_logs(q,size=50): return _post("logs","/logs/search",{"query":q,"size":size})
def get_log_stats(): return _get("logs","/logs/stats")
def get_metrics(): return _get("metrics","/metrics")
def analyze_alert_ai(alert): return _post("ai","/ai/analyze-alert",{"alert":alert})
def threat_hunt(q,hours=24): return _post("ai","/ai/threat-hunt",{"query":q,"time_range_hours":hours})

def generate_sigma_rule(d,t,s):
    return _post("ai","/ai/generate/sigma-rule",{"threat_description":d,"mitre_technique":t,"log_source":s})

def generate_yara_rule(d,f,p):
    return _post("ai","/ai/generate/yara-rule",{"threat_description":d,"malware_family":f,"platform":p})

def lookup_ip(ip): return _get("threatintel",f"/intel/ip/{ip}")
def lookup_ip_full(ip): return _get("threatintel",f"/intel/ip/full/{ip}")
def lookup_hash(h): return _get("threatintel",f"/intel/hash/{h}")
def lookup_domain(d): return _get("threatintel",f"/intel/domain/{d}")
def lookup_cve(c): return _get("threatintel",f"/intel/cve/{c}")
def get_soar_playbooks(): return _get("soar","/soar/playbooks")
def run_playbook(name,alert): return _post("soar",f"/soar/execute/{name}",alert)
def get_soar_executions(limit=50): return _get("soar",f"/soar/executions?limit={limit}")
def get_tickets(): return _get("soar","/soar/tickets")

def update_ticket(tid,status):
    return _request("PUT", BASE_URLS["soar"] + f"/soar/tickets/{tid}/status", params={"status": status}).json()

def get_redteam_scenarios(): return _get("redteam","/redteam/scenarios")

def run_simulation(scenario,attacker_ip="",target="",dry_run=False):
    return _post("redteam","/redteam/simulate",{"scenario":scenario,"attacker_ip":attacker_ip or None,
                 "target_host":target or None,"dry_run":dry_run,"delay_ms":100})

def cloud_scan(provider,account_id="",region="us-east-1"):
    return _post("cloud","/cloud/scan",{"provider":provider,"account_id":account_id or None,"region":region})

def get_cloud_scan_history(): return _get("cloud","/cloud/scan/history")

def analyze_file(path):
    with open(path,"rb") as f:
        response = _request("POST", BASE_URLS["sandbox"] + "/sandbox/analyze", files={"file": f}, timeout=60)
        return response.json()

def get_sandbox_results(limit=50): return _get("sandbox",f"/sandbox/results?limit={limit}")
def get_honeypot_log(limit=100): return _get("honeypot",f"/honeypot/log?limit={limit}")
def get_top_attackers(): return _get("honeypot","/honeypot/top-attackers")
def get_vpn_sessions(limit=100): return _get("vpn",f"/vpn/sessions?limit={limit}")
def get_vpn_stats(): return _get("vpn","/vpn/stats")
def get_agent_status(): return _get("agents","/agents/status")

def generate_report(report_type="executive",hours=24):
    return _post("reports","/reports/json",{"report_type":report_type,"time_range_h":hours})

def download_pdf_report(report_type="executive",hours=24,dest_path="report.pdf"):
    r = _request("POST", BASE_URLS["reports"]+"/reports/pdf",
        json_body={"report_type":report_type,"time_range_h":hours},timeout=60)
    with open(dest_path,"wb") as f:
        f.write(r.content)
    return dest_path
