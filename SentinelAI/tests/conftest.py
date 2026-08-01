"""
SentinelAI — Pytest Configuration & Fixtures
"""
import os, sys, asyncio, pytest, json
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from typing import AsyncGenerator

# Add all backend services to path
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for svc in [
    "auth-service", "detection-engine", "ai-service",
    "log-service", "soar-service", "threat-intel-service",
    "alert-service", "report-service", "vpn-monitor-service",
]:
    sys.path.insert(0, os.path.join(BASE, "backend", svc.replace("-","_")))
    sys.path.insert(0, os.path.join(BASE, "backend", svc))

# ─── Event loop ──────────────────────────────────────────────
@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

# ─── Environment ─────────────────────────────────────────────
@pytest.fixture(autouse=True)
def set_test_env(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY",        "test_secret_key_sentinelai_2024")
    monkeypatch.setenv("JWT_ALGORITHM",         "HS256")
    monkeypatch.setenv("DATABASE_URL",          "postgresql://test:test@localhost/test")
    monkeypatch.setenv("REDIS_URL",             "redis://localhost:6379/0")
    monkeypatch.setenv("KAFKA_BOOTSTRAP_SERVERS","localhost:9092")
    monkeypatch.setenv("OPENSEARCH_HOST",       "localhost")
    monkeypatch.setenv("OLLAMA_BASE_URL",       "http://localhost:11434")

# ─── Sample alerts ───────────────────────────────────────────
@pytest.fixture
def sample_alert():
    return {
        "alert_id":        "test-alert-001",
        "rule_id":         "SIG-001",
        "rule_name":       "SSH Brute Force",
        "severity":        "high",
        "detection_type":  "brute_force",
        "source_ip":       "185.220.101.45",
        "hostname":        "server-A-1",
        "description":     "Multiple failed SSH login attempts",
        "mitre_tactic":    "Credential Access",
        "mitre_technique": "T1110",
        "raw_log":         "Failed password for root from 185.220.101.45 port 54321 ssh2",
        "timestamp":       datetime.now(timezone.utc).isoformat(),
        "correlated":      False,
        "attack_chain":    [],
    }

@pytest.fixture
def critical_alert(sample_alert):
    return {**sample_alert, "severity": "critical", "correlated": True, "attack_chain": ["brute_force","privilege_escalation","reverse_shell"]}

@pytest.fixture
def sample_log_event():
    return {
        "source_ip":  "10.0.2.15",
        "hostname":   "workstation-01",
        "log_source": "syslog",
        "event_type": "failed_login",
        "severity":   "medium",
        "raw_log":    "Failed password for invalid user root from 10.0.2.15 port 44444 ssh2",
        "parsed":     {"username": "root", "source_ip": "10.0.2.15"},
        "agent_id":   "agent-ws01",
        "os_type":    "linux",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }

@pytest.fixture
def ransomware_log():
    return {
        "source_ip":  "10.0.1.50",
        "hostname":   "server-B-2",
        "log_source": "auditd",
        "event_type": "file_modification",
        "severity":   "critical",
        "raw_log":    'auditd: type=PATH name="/home/user/docs/report.docx.encrypted" nametype=CREATE',
        "parsed":     {},
        "agent_id":   "agent-srv02",
        "os_type":    "linux",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }

@pytest.fixture
def mimikatz_log():
    return {
        "source_ip":  "10.0.2.20",
        "hostname":   "workstation-02",
        "log_source": "winevent",
        "event_type": "credential_dumping",
        "severity":   "critical",
        "raw_log":    "sekurlsa::logonpasswords mimikatz privilege::debug lsass.exe",
        "parsed":     {},
        "agent_id":   "agent-ws02",
        "os_type":    "windows",
        "timestamp":  datetime.now(timezone.utc).isoformat(),
    }

# ─── Mock clients ────────────────────────────────────────────
@pytest.fixture
def mock_redis():
    redis = AsyncMock()
    redis.get       = AsyncMock(return_value=None)
    redis.set       = AsyncMock(return_value=True)
    redis.setex     = AsyncMock(return_value=True)
    redis.delete    = AsyncMock(return_value=1)
    redis.incr      = AsyncMock(return_value=1)
    redis.expire    = AsyncMock(return_value=True)
    redis.lpush     = AsyncMock(return_value=1)
    redis.lrange    = AsyncMock(return_value=[])
    redis.ltrim     = AsyncMock(return_value=True)
    redis.keys      = AsyncMock(return_value=[])
    redis.hset      = AsyncMock(return_value=1)
    redis.hgetall   = AsyncMock(return_value={})
    redis.smembers  = AsyncMock(return_value=set())
    redis.sadd      = AsyncMock(return_value=1)
    redis.srem      = AsyncMock(return_value=1)
    redis.zadd      = AsyncMock(return_value=1)
    redis.zrevrange = AsyncMock(return_value=[])
    redis.close     = AsyncMock()
    return redis

@pytest.fixture
def mock_kafka_producer():
    producer = AsyncMock()
    producer.start  = AsyncMock()
    producer.stop   = AsyncMock()
    producer.send   = AsyncMock()
    return producer

@pytest.fixture
def mock_opensearch():
    client = AsyncMock()
    client.index   = AsyncMock(return_value={"result": "created"})
    client.search  = AsyncMock(return_value={"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}})
    client.get     = AsyncMock(return_value={"_source": {}})
    client.indices = AsyncMock()
    client.indices.exists = AsyncMock(return_value=False)
    client.indices.create = AsyncMock(return_value={"acknowledged": True})
    client.bulk    = AsyncMock(return_value={"errors": False, "items": []})
    client.close   = AsyncMock()
    return client

@pytest.fixture
def mock_db_conn():
    conn = AsyncMock()
    conn.fetchrow  = AsyncMock(return_value=None)
    conn.fetch     = AsyncMock(return_value=[])
    conn.execute   = AsyncMock(return_value="INSERT 0 1")
    conn.close     = AsyncMock()
    return conn

# ─── Feature vectors ─────────────────────────────────────────
@pytest.fixture
def normal_features():
    return [50.0, 10.0, 14.0, 0.0, 0.0, 0.0, 0.0, 2.0, 0.0, 0.0]

@pytest.fixture
def anomaly_features():
    return [5000.0, 200.0, 3.0, 1.0, 1.0, 1.0, 1.0, 150.0, 1.0, 1.0]

# ─── Pytest settings ─────────────────────────────────────────
def pytest_configure(config):
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests requiring services")
    config.addinivalue_line("markers", "slow: Slow tests (ML model training)")
    config.addinivalue_line("markers", "security: Security-specific tests")
