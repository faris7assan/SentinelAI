import time
import statistics
import traceback
import sys
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, ".")
import api.client as api

# Ensure we are using local backend for the test
api.set_backend_mode("local", "http://127.0.0.1:8000")

def measure(fn, *args, **kwargs):
    t0 = time.perf_counter()
    res = fn(*args, **kwargs)
    t1 = time.perf_counter()
    return res, (t1 - t0) * 1000  # returns ms

def test_health():
    print("[*] Testing Service Health...")
    res, duration = measure(api.health_all)
    up = sum(1 for v in res.values() if v)
    total = len(res)
    print(f"    - {up}/{total} services online (Time: {duration:.2f}ms)")
    return up == total, duration

def test_metrics_telemetry():
    print("[*] Testing Metrics & Telemetry...")
    res, duration = measure(api.get_metrics)
    sys_metrics = res.get("system", {})
    counters = res.get("counters", {})
    print(f"    - Metrics retrieved (Time: {duration:.2f}ms)")
    print(f"    - System CPU: {sys_metrics.get('cpu')}%, RAM: {sys_metrics.get('mem')}%")
    print(f"    - Total Alerts: {counters.get('total_alerts')}")
    return bool(sys_metrics), duration

def test_log_ingestion_stress():
    print("[*] Testing Log Ingestion Stress (100 parallel inserts)...")
    def ingest_dummy(i):
        evt = {"source_ip": f"192.168.1.{i%255}", "hostname": f"host-{i}", "event_type": "stress_test"}
        return measure(api.ingest_log, evt)[1]
    
    with ThreadPoolExecutor(max_workers=10) as ex:
        times = list(ex.map(ingest_dummy, range(100)))
        
    avg = statistics.mean(times)
    p95 = statistics.quantiles(times, n=20)[18]
    print(f"    - 100 logs ingested. Avg time: {avg:.2f}ms, P95: {p95:.2f}ms")
    return avg < 100, avg

def test_alerts_read():
    print("[*] Testing Alerts Retrieval...")
    res, duration = measure(api.get_recent_alerts, 50, None)
    print(f"    - Retrieved {len(res)} alerts (Time: {duration:.2f}ms)")
    return len(res) > 0, duration

def test_soar_execution():
    print("[*] Testing SOAR Playbook Execution...")
    res, duration = measure(api.run_playbook, "isolate_host", {"alert_id": "test"})
    print(f"    - SOAR returned status: {res.get('status')} (Time: {duration:.2f}ms)")
    return res.get('status') == 'completed', duration

def run_all():
    print("========================================")
    print(" SentinelAI System Analysis & Test Run")
    print("========================================")
    results = {}
    try:
        ok, d = test_health()
        results["Health"] = {"pass": ok, "time": d}
        ok, d = test_metrics_telemetry()
        results["Telemetry"] = {"pass": ok, "time": d}
        ok, d = test_log_ingestion_stress()
        results["Log_Stress"] = {"pass": ok, "time": d}
        ok, d = test_alerts_read()
        results["Alerts_Read"] = {"pass": ok, "time": d}
        ok, d = test_soar_execution()
        results["SOAR"] = {"pass": ok, "time": d}
    except Exception as e:
        print(f"Test failed with error: {e}")
        traceback.print_exc()

    passed = sum(1 for r in results.values() if r["pass"])
    total = len(results)
    print("\n--- FINAL REPORT ---")
    print(f"Score: {passed}/{total} Tests Passed")
    for k, v in results.items():
        print(f"{k:15s}: {'PASS' if v['pass'] else 'FAIL'} ({v['time']:.2f}ms)")

if __name__ == "__main__":
    run_all()
