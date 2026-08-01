import time
import json
import urllib.request
import psutil
import socket

METRICS_URL = "http://localhost:8015/metrics/ingest" # Default metrics endpoint, wait, we are using the unified mock backend on port 8000, but in desktop app it routes to 8015? No, the desktop app calls the gateway, but wait, mock backend serves ALL endpoints on 8000.
# Actually, let's just push to 8000 directly.
METRICS_URL = "http://localhost:8000/metrics/ingest"
LOGS_URL = "http://localhost:8000/logs/ingest"

def get_net_conns():
    try:
        return len(psutil.net_connections())
    except psutil.AccessDenied:
        return 0
    except Exception:
        return 0

def push_metrics():
    try:
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.virtual_memory().percent
        net_conns = get_net_conns()
        payload = json.dumps({"cpu": cpu, "mem": mem, "net_conns": net_conns}).encode('utf-8')
        req = urllib.request.Request(METRICS_URL, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
        with urllib.request.urlopen(req, timeout=3) as _:
            pass
        print(f"Pushed metrics: CPU={cpu}%, RAM={mem}%, Conns={net_conns}")
    except Exception as e:
        print(f"Error pushing metrics: {e}")

def push_log_if_anomaly():
    try:
        cpu = psutil.cpu_percent()
        mem = psutil.virtual_memory().percent
        
        events = []
        if cpu > 80:
            events.append(("high_cpu_usage", f"CPU usage exceeded threshold: {cpu}%", "high"))
        if mem > 90:
            events.append(("high_mem_usage", f"Memory usage critical: {mem}%", "critical"))
            
        for evt_type, raw, sev in events:
            payload = json.dumps({
                "severity": sev,
                "log_source": "sentinel_agent",
                "event_type": evt_type,
                "source_ip": socket.gethostbyname(socket.gethostname()),
                "hostname": socket.gethostname(),
                "raw_log": raw
            }).encode('utf-8')
            req = urllib.request.Request(LOGS_URL, data=payload, headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=3) as _:
                pass
            print(f"Anomaly logged: {evt_type}")
    except Exception as e:
        pass

if __name__ == "__main__":
    print("======================================================")
    print("    SentinelAI Live System Telemetry Agent")
    print("    Collecting and shipping metrics...")
    print("======================================================")
    while True:
        push_metrics()
        push_log_if_anomaly()
        time.sleep(5)
