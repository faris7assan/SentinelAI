#!/usr/bin/env python3
"""
SentinelAI — OpenSearch Setup Script
Creates index templates, ILM policies, and aliases
Run once after OpenSearch is healthy: python3 scripts/setup_opensearch.py
"""
import os, json, sys
import requests
from requests.auth import HTTPBasicAuth

OS_HOST = os.getenv("OPENSEARCH_HOST", "localhost")
OS_PORT = os.getenv("OPENSEARCH_PORT", "9200")
OS_USER = os.getenv("OPENSEARCH_USER", "admin")
OS_PASS = os.getenv("OPENSEARCH_PASSWORD", "admin")
BASE    = f"http://{OS_HOST}:{OS_PORT}"
AUTH    = HTTPBasicAuth(OS_USER, OS_PASS)
HEADERS = {"Content-Type": "application/json"}

def os_put(path: str, body: dict, label: str):
    resp = requests.put(f"{BASE}{path}", json=body, auth=AUTH, headers=HEADERS, verify=False)
    status = "✅" if resp.status_code in (200, 201) else "⚠️"
    print(f"{status} {label}: {resp.status_code}")
    if resp.status_code not in (200, 201):
        print(f"   Error: {resp.text[:200]}")

def os_put_policy(name: str, body: dict):
    resp = requests.put(
        f"{BASE}/_plugins/_ism/policies/{name}",
        json=body, auth=AUTH, headers=HEADERS, verify=False
    )
    status = "✅" if resp.status_code in (200, 201) else "⚠️"
    print(f"{status} ILM policy '{name}': {resp.status_code}")

print("🔧 Setting up OpenSearch for SentinelAI...\n")

# ─── ILM Policy: Logs ─────────────────────────────────────────
logs_policy = {
    "policy": {
        "description": "SentinelAI log retention policy",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [
                    {"rollover": {"min_index_age": "1d", "min_size": "10gb"}}
                ],
                "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "2d"}}]
            },
            {
                "name": "warm",
                "actions": [{"replica_count": {"number_of_replicas": 0}}],
                "transitions": [{"state_name": "cold", "conditions": {"min_index_age": "7d"}}]
            },
            {
                "name": "cold",
                "actions": [],
                "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "30d"}}]
            },
            {
                "name": "delete",
                "actions": [{"delete": {}}],
                "transitions": []
            }
        ],
        "ism_template": [{"index_patterns": ["sentinelai-logs-*"], "priority": 100}]
    }
}
os_put_policy("sentinelai-logs-policy", logs_policy)

# ─── ILM Policy: Alerts (longer retention) ────────────────────
alerts_policy = {
    "policy": {
        "description": "SentinelAI alert retention — 90 days",
        "default_state": "hot",
        "states": [
            {
                "name": "hot",
                "actions": [],
                "transitions": [{"state_name": "warm", "conditions": {"min_index_age": "7d"}}]
            },
            {
                "name": "warm",
                "actions": [{"replica_count": {"number_of_replicas": 0}}],
                "transitions": [{"state_name": "delete", "conditions": {"min_index_age": "90d"}}]
            },
            {
                "name": "delete",
                "actions": [{"delete": {}}],
                "transitions": []
            }
        ],
        "ism_template": [{"index_patterns": ["sentinelai-alerts-*"], "priority": 100}]
    }
}
os_put_policy("sentinelai-alerts-policy", alerts_policy)

# ─── Index Template: Logs ─────────────────────────────────────
logs_template = {
    "index_patterns": ["sentinelai-logs*"],
    "template": {
        "settings": {
            "number_of_shards":   2,
            "number_of_replicas": 1,
            "refresh_interval":   "5s",
            "codec":              "best_compression",
        },
        "mappings": {
            "properties": {
                "@timestamp":  {"type": "date"},
                "timestamp":   {"type": "date"},
                "ingested_at": {"type": "date"},
                "source_ip":   {"type": "ip"},
                "hostname":    {"type": "keyword"},
                "log_source":  {"type": "keyword"},
                "event_type":  {"type": "keyword"},
                "severity":    {"type": "keyword"},
                "severity_num":{"type": "integer"},
                "agent_id":    {"type": "keyword"},
                "os_type":     {"type": "keyword"},
                "event_hash":  {"type": "keyword"},
                "raw_log":     {"type": "text",    "analyzer": "standard"},
                "parsed":      {"type": "object",  "dynamic": True},
            }
        }
    },
    "priority": 500,
    "_meta": {"description": "SentinelAI log events template"}
}
os_put("/_index_template/sentinelai-logs", logs_template, "Logs index template")

# ─── Index Template: Alerts ───────────────────────────────────
alerts_template = {
    "index_patterns": ["sentinelai-alerts*"],
    "template": {
        "settings": {
            "number_of_shards":   2,
            "number_of_replicas": 1,
            "refresh_interval":   "1s",
        },
        "mappings": {
            "properties": {
                "alert_id":        {"type": "keyword"},
                "rule_id":         {"type": "keyword"},
                "rule_name":       {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "severity":        {"type": "keyword"},
                "detection_type":  {"type": "keyword"},
                "source_ip":       {"type": "ip"},
                "hostname":        {"type": "keyword"},
                "description":     {"type": "text"},
                "mitre_tactic":    {"type": "keyword"},
                "mitre_technique": {"type": "keyword"},
                "raw_log":         {"type": "text"},
                "timestamp":       {"type": "date"},
                "correlated":      {"type": "boolean"},
                "attack_chain":    {"type": "keyword"},
                "ai_analysis":     {"type": "text"},
                "ai_enriched_at":  {"type": "date"},
                "extra":           {"type": "object", "dynamic": True},
            }
        }
    },
    "priority": 500,
    "_meta": {"description": "SentinelAI alert events template"}
}
os_put("/_index_template/sentinelai-alerts", alerts_template, "Alerts index template")

# ─── Create initial indices ───────────────────────────────────
for index in ["sentinelai-logs-000001", "sentinelai-alerts-000001"]:
    resp = requests.put(f"{BASE}/{index}", auth=AUTH, headers=HEADERS, verify=False)
    st = "✅" if resp.status_code in (200, 201) else "⚠️"
    print(f"{st} Index '{index}': {resp.status_code}")

# ─── Create aliases ───────────────────────────────────────────
aliases_body = {
    "actions": [
        {"add": {"index": "sentinelai-logs-000001",   "alias": "sentinelai-logs",   "is_write_index": True}},
        {"add": {"index": "sentinelai-alerts-000001", "alias": "sentinelai-alerts", "is_write_index": True}},
    ]
}
resp = requests.post(f"{BASE}/_aliases", json=aliases_body, auth=AUTH, headers=HEADERS, verify=False)
print(f"{'✅' if resp.status_code == 200 else '⚠️'} Aliases created: {resp.status_code}")

print("\n✅ OpenSearch setup complete!")
