"""
SentinelAI — Load Testing with Locust
Tests: log ingestion, alert API, threat intel lookup, SOAR triggers
Run: locust -f tests/locustfile.py --host=http://localhost:8000 --users=100 --spawn-rate=10
"""
import json, random, uuid
from locust import HttpUser, TaskSet, task, between, events

# ─── Sample data generators ──────────────────────────────────
def random_ip():
    return f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"

def random_log_event():
    sources    = ["syslog","auditd","zeek","suricata","winevent"]
    severities = ["info","low","medium","high"]
    events_    = ["failed_login","process_create","network_connect","file_modify","dns_query"]
    return {
        "source_ip":  random_ip(),
        "hostname":   f"host-{random.randint(1,50)}",
        "log_source": random.choice(sources),
        "event_type": random.choice(events_),
        "severity":   random.choice(severities),
        "raw_log":    f"[{random.choice(events_)}] user=test src={random_ip()} dst={random_ip()} port={random.randint(1,65535)}",
        "parsed":     {},
        "agent_id":   f"agent-{random.randint(1,20)}",
        "os_type":    "linux",
    }

def random_alert():
    types = ["brute_force","port_scan","reverse_shell","dns_tunneling","malware_execution"]
    sevs  = ["medium","high","critical"]
    return {
        "alert_id":        str(uuid.uuid4()),
        "rule_id":         f"SIG-{random.randint(1,12):03d}",
        "rule_name":       random.choice(["SSH Brute Force","Port Scan","Reverse Shell"]),
        "severity":        random.choice(sevs),
        "detection_type":  random.choice(types),
        "source_ip":       random_ip(),
        "hostname":        f"server-{random.randint(1,20)}",
        "description":     "Load test alert",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110",
        "raw_log":         "load test raw log entry",
        "timestamp":       "2024-06-01T00:00:00Z",
        "correlated":      False,
        "attack_chain":    [],
    }

# ─── Task Sets ───────────────────────────────────────────────
class LogIngestionTasks(TaskSet):
    @task(5)
    def ingest_single_log(self):
        self.client.post("/logs/ingest", json=random_log_event(),
                         headers={"Content-Type": "application/json"})

    @task(2)
    def ingest_bulk_logs(self):
        events = [random_log_event() for _ in range(random.randint(10,50))]
        self.client.post("/logs/bulk",
                         json={"events": events},
                         headers={"Content-Type": "application/json"})

    @task(1)
    def search_logs(self):
        self.client.post("/logs/search",
                         json={"query": "failed_login", "size": 20},
                         headers={"Content-Type": "application/json"})

    @task(1)
    def get_log_stats(self):
        self.client.get("/logs/stats")

    @task(1)
    def get_recent_logs(self):
        self.client.get("/logs/recent?size=20")


class AlertAPITasks(TaskSet):
    @task(3)
    def get_recent_alerts(self):
        severity = random.choice(["critical","high","medium","low",""])
        url = f"/alerts/recent?size=20{('&severity=' + severity) if severity else ''}"
        self.client.get(url)

    @task(2)
    def get_alert_stats(self):
        self.client.get("/alerts/stats")

    @task(1)
    def manual_detect(self):
        self.client.post("/detect",
                         json={"log_event": random_log_event()},
                         headers={"Content-Type": "application/json"})

    @task(1)
    def get_rules(self):
        self.client.get("/rules")


class ThreatIntelTasks(TaskSet):
    SAMPLE_IPS = ["8.8.8.8","1.1.1.1","185.220.101.45","45.33.32.156","94.102.49.190"]

    @task(4)
    def lookup_ip(self):
        ip = random.choice(self.SAMPLE_IPS)
        self.client.get(f"/intel/ip/{ip}")

    @task(1)
    def lookup_cve(self):
        cves = ["CVE-2021-44228","CVE-2021-34527","CVE-2022-30190"]
        self.client.get(f"/intel/cve/{random.choice(cves)}")


class AIMicrobenchTasks(TaskSet):
    @task(3)
    def anomaly_detect(self):
        features = [random.uniform(0,100) for _ in range(10)]
        self.client.post("/ai/anomaly-detect",
                         json={"features": features, "source_ip": random_ip()},
                         headers={"Content-Type": "application/json"})

    @task(2)
    def classify_attack(self):
        features = [random.uniform(0,100) for _ in range(10)]
        self.client.post("/ai/classify-attack",
                         json={"features": features, "source_ip": random_ip(), "raw_log": "test log"},
                         headers={"Content-Type": "application/json"})

    @task(1)
    def ai_stats(self):
        self.client.get("/ai/stats")


class MetricsTasks(TaskSet):
    @task(5)
    def get_metrics(self):
        self.client.get("/metrics", base_url="http://localhost:8015")

    @task(2)
    def get_prometheus(self):
        self.client.get("/metrics/prometheus", base_url="http://localhost:8015")

    @task(1)
    def ingest_metric(self):
        self.client.post("/metrics/ingest",
                         json={"event_type": "alert", "severity": "high", "count": 1},
                         base_url="http://localhost:8015")


# ─── User Classes ─────────────────────────────────────────────
class SOCAnalyst(HttpUser):
    """Simulates a SOC analyst monitoring dashboard + investigating alerts."""
    wait_time = between(1, 3)
    tasks     = {AlertAPITasks: 4, ThreatIntelTasks: 2, AIMicrobenchTasks: 1}

class LogAgent(HttpUser):
    """Simulates endpoint agents sending logs continuously."""
    wait_time = between(0.1, 0.5)
    tasks     = {LogIngestionTasks: 1}

class DashboardUser(HttpUser):
    """Simulates a user watching the live dashboard."""
    wait_time = between(5, 15)
    tasks     = {AlertAPITasks: 3, MetricsTasks: 2}


# ─── Event hooks ─────────────────────────────────────────────
@events.test_start.add_listener
def on_test_start(environment, **kwargs):
    print("\n🎯 SentinelAI Load Test Starting...")
    print("Endpoints under test: /logs/ingest, /detect, /intel/ip, /ai/anomaly-detect")

@events.test_stop.add_listener
def on_test_stop(environment, **kwargs):
    stats = environment.stats
    print(f"\n✅ Load Test Complete")
    print(f"   Total requests: {stats.total.num_requests}")
    print(f"   Failures:       {stats.total.num_failures}")
    print(f"   Avg response:   {stats.total.avg_response_time:.1f}ms")
    print(f"   p99 response:   {stats.total.get_response_time_percentile(0.99):.1f}ms")
    print(f"   RPS:            {stats.total.current_rps:.1f}")
