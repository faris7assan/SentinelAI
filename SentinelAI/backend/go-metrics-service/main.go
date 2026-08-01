// SentinelAI — Go Metrics & Streaming Service
// High-performance event counter, metrics aggregation, and Prometheus exporter
// Handles: real-time alert counters, log throughput metrics, SOAR execution stats
// Uses pure stdlib + goroutines for maximum performance
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// ─── Config ──────────────────────────────────────────────────
var (
	PORT         = getEnv("GO_METRICS_PORT", "8015")
	REDIS_URL    = getEnv("REDIS_URL", "redis://redis:6379/0")
	KAFKA_BROKERS= getEnv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

// ─── Atomic Counters ──────────────────────────────────────────
type Counters struct {
	TotalAlerts      int64
	CriticalAlerts   int64
	HighAlerts       int64
	MediumAlerts     int64
	LowAlerts        int64
	LogsIngested     int64
	SOARExecutions   int64
	SOARFailures     int64
	HoneypotHits     int64
	VPNConnections   int64
	SandboxAnalyzed  int64
	MaliciousFiles   int64
	AttackChains     int64
	ThreatIntelQueries int64
	ImpossibleTravel int64
	// Rate tracking
	AlertsLastMin    int64
	LogsLastMin      int64
}

var counters = &Counters{}
var mu sync.RWMutex

// ─── Time-series buffer (circular, last 60 minutes) ───────────
type DataPoint struct {
	Timestamp int64   `json:"ts"`
	Value     float64 `json:"v"`
}

type TimeSeries struct {
	mu     sync.Mutex
	points []DataPoint
	maxLen int
}

func NewTimeSeries(maxLen int) *TimeSeries {
	return &TimeSeries{points: make([]DataPoint, 0, maxLen), maxLen: maxLen}
}

func (ts *TimeSeries) Add(value float64) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.points = append(ts.points, DataPoint{
		Timestamp: time.Now().UnixMilli(),
		Value:     value,
	})
	if len(ts.points) > ts.maxLen {
		ts.points = ts.points[len(ts.points)-ts.maxLen:]
	}
}

func (ts *TimeSeries) Last(n int) []DataPoint {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.points) <= n {
		result := make([]DataPoint, len(ts.points))
		copy(result, ts.points)
		return result
	}
	result := make([]DataPoint, n)
	copy(result, ts.points[len(ts.points)-n:])
	return result
}

// Global time-series
var (
	alertRateSeries    = NewTimeSeries(720) // 12h at 1/min
	logRateSeries      = NewTimeSeries(720)
	cpuSeries          = NewTimeSeries(720)
	kafkaLagSeries     = NewTimeSeries(720)
)

// ─── Alert intake ─────────────────────────────────────────────
func recordAlert(severity string) {
	atomic.AddInt64(&counters.TotalAlerts, 1)
	atomic.AddInt64(&counters.AlertsLastMin, 1)
	switch severity {
	case "critical":
		atomic.AddInt64(&counters.CriticalAlerts, 1)
	case "high":
		atomic.AddInt64(&counters.HighAlerts, 1)
	case "medium":
		atomic.AddInt64(&counters.MediumAlerts, 1)
	default:
		atomic.AddInt64(&counters.LowAlerts, 1)
	}
}

// ─── Background workers ───────────────────────────────────────
func metricsSamplerWorker() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		// Sample current rates
		alerts := atomic.SwapInt64(&counters.AlertsLastMin, 0)
		logs   := atomic.SwapInt64(&counters.LogsLastMin, 0)
		alertRateSeries.Add(float64(alerts))
		logRateSeries.Add(float64(logs))
		// Simulate CPU (in prod: read from /proc/stat)
		cpuSeries.Add(rand.Float64()*30 + 10)
	}
}

// ─── HTTP Handlers ────────────────────────────────────────────
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  "healthy",
		"service": "go-metrics-service",
		"version": "1.0.0",
		"uptime":  time.Since(startTime).String(),
	})
}

func handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"counters": map[string]int64{
			"total_alerts":      atomic.LoadInt64(&counters.TotalAlerts),
			"critical_alerts":   atomic.LoadInt64(&counters.CriticalAlerts),
			"high_alerts":       atomic.LoadInt64(&counters.HighAlerts),
			"medium_alerts":     atomic.LoadInt64(&counters.MediumAlerts),
			"low_alerts":        atomic.LoadInt64(&counters.LowAlerts),
			"logs_ingested":     atomic.LoadInt64(&counters.LogsIngested),
			"soar_executions":   atomic.LoadInt64(&counters.SOARExecutions),
			"soar_failures":     atomic.LoadInt64(&counters.SOARFailures),
			"honeypot_hits":     atomic.LoadInt64(&counters.HoneypotHits),
			"vpn_connections":   atomic.LoadInt64(&counters.VPNConnections),
			"sandbox_analyzed":  atomic.LoadInt64(&counters.SandboxAnalyzed),
			"malicious_files":   atomic.LoadInt64(&counters.MaliciousFiles),
			"attack_chains":     atomic.LoadInt64(&counters.AttackChains),
			"threat_intel_queries": atomic.LoadInt64(&counters.ThreatIntelQueries),
			"impossible_travel": atomic.LoadInt64(&counters.ImpossibleTravel),
		},
		"sampled_at": time.Now().UTC().Format(time.RFC3339),
	})
}

func handlePrometheus(w http.ResponseWriter, r *http.Request) {
	// Prometheus text exposition format
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	metrics := []struct {
		Name  string
		Help  string
		Type  string
		Value int64
	}{
		{"sentinelai_alerts_total",          "Total security alerts detected", "counter", atomic.LoadInt64(&counters.TotalAlerts)},
		{"sentinelai_alerts_critical_total", "Critical alerts", "counter", atomic.LoadInt64(&counters.CriticalAlerts)},
		{"sentinelai_alerts_high_total",     "High severity alerts", "counter", atomic.LoadInt64(&counters.HighAlerts)},
		{"sentinelai_alerts_medium_total",   "Medium severity alerts", "counter", atomic.LoadInt64(&counters.MediumAlerts)},
		{"sentinelai_alerts_low_total",      "Low severity alerts", "counter", atomic.LoadInt64(&counters.LowAlerts)},
		{"sentinelai_logs_ingested_total",   "Total log events ingested", "counter", atomic.LoadInt64(&counters.LogsIngested)},
		{"sentinelai_soar_executions_total", "SOAR playbook executions", "counter", atomic.LoadInt64(&counters.SOARExecutions)},
		{"sentinelai_soar_failures_total",   "SOAR playbook failures", "counter", atomic.LoadInt64(&counters.SOARFailures)},
		{"sentinelai_honeypot_hits_total",   "Honeypot interactions", "counter", atomic.LoadInt64(&counters.HoneypotHits)},
		{"sentinelai_vpn_connections_total", "VPN connection events", "counter", atomic.LoadInt64(&counters.VPNConnections)},
		{"sentinelai_sandbox_analyzed_total","Files analyzed in sandbox", "counter", atomic.LoadInt64(&counters.SandboxAnalyzed)},
		{"sentinelai_malicious_files_total", "Malicious files detected", "counter", atomic.LoadInt64(&counters.MaliciousFiles)},
		{"sentinelai_correlated_alerts_total","Correlated attack chain alerts","counter", atomic.LoadInt64(&counters.AttackChains)},
		{"sentinelai_threat_intel_queries_total","Threat intel lookups performed","counter", atomic.LoadInt64(&counters.ThreatIntelQueries)},
		{"sentinelai_vpn_impossible_travel_total","Impossible travel detections","counter", atomic.LoadInt64(&counters.ImpossibleTravel)},
	}
	for _, m := range metrics {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n%s %d\n\n",
			m.Name, m.Help, m.Name, m.Type, m.Name, m.Value)
	}
}

func handleTimeSeries(w http.ResponseWriter, r *http.Request) {
	metric := r.URL.Query().Get("metric")
	n, _   := strconv.Atoi(r.URL.Query().Get("n"))
	if n == 0 {
		n = 60
	}
	w.Header().Set("Content-Type", "application/json")
	var points []DataPoint
	switch metric {
	case "alerts":
		points = alertRateSeries.Last(n)
	case "logs":
		points = logRateSeries.Last(n)
	case "cpu":
		points = cpuSeries.Last(n)
	default:
		points = alertRateSeries.Last(n)
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"metric": metric,
		"points": points,
		"count":  len(points),
	})
}

func handleIngestEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	var payload struct {
		EventType string `json:"event_type"`
		Severity  string `json:"severity"`
		Count     int    `json:"count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	count := payload.Count
	if count == 0 {
		count = 1
	}
	switch payload.EventType {
	case "alert":
		for i := 0; i < count; i++ {
			recordAlert(payload.Severity)
		}
	case "log":
		atomic.AddInt64(&counters.LogsIngested, int64(count))
		atomic.AddInt64(&counters.LogsLastMin, int64(count))
	case "soar_execute":
		atomic.AddInt64(&counters.SOARExecutions, int64(count))
	case "soar_fail":
		atomic.AddInt64(&counters.SOARFailures, int64(count))
	case "honeypot":
		atomic.AddInt64(&counters.HoneypotHits, int64(count))
	case "vpn_connect":
		atomic.AddInt64(&counters.VPNConnections, int64(count))
	case "sandbox_analyzed":
		atomic.AddInt64(&counters.SandboxAnalyzed, int64(count))
	case "malicious_file":
		atomic.AddInt64(&counters.MaliciousFiles, int64(count))
	case "attack_chain":
		atomic.AddInt64(&counters.AttackChains, int64(count))
	case "threat_intel":
		atomic.AddInt64(&counters.ThreatIntelQueries, int64(count))
	case "impossible_travel":
		atomic.AddInt64(&counters.ImpossibleTravel, int64(count))
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	// Reset all counters (used in testing)
	atomic.StoreInt64(&counters.TotalAlerts, 0)
	atomic.StoreInt64(&counters.CriticalAlerts, 0)
	atomic.StoreInt64(&counters.HighAlerts, 0)
	atomic.StoreInt64(&counters.MediumAlerts, 0)
	atomic.StoreInt64(&counters.LowAlerts, 0)
	atomic.StoreInt64(&counters.LogsIngested, 0)
	atomic.StoreInt64(&counters.SOARExecutions, 0)
	atomic.StoreInt64(&counters.SOARFailures, 0)
	atomic.StoreInt64(&counters.HoneypotHits, 0)
	atomic.StoreInt64(&counters.VPNConnections, 0)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "reset"})
}

// ─── SSE: Server-Sent Events for real-time dashboard ─────────
func handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type",                "text/event-stream")
	w.Header().Set("Cache-Control",               "no-cache")
	w.Header().Set("Connection",                  "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ctx := r.Context()
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, _ := json.Marshal(map[string]interface{}{
				"total_alerts":    atomic.LoadInt64(&counters.TotalAlerts),
				"critical":        atomic.LoadInt64(&counters.CriticalAlerts),
				"high":            atomic.LoadInt64(&counters.HighAlerts),
				"logs_ingested":   atomic.LoadInt64(&counters.LogsIngested),
				"soar_executions":atomic.LoadInt64(&counters.SOARExecutions),
				"attack_chains":   atomic.LoadInt64(&counters.AttackChains),
				"ts":              time.Now().UnixMilli(),
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

// ─── CORS middleware ──────────────────────────────────────────
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin",  "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next(w, r)
	}
}

var startTime = time.Now()

func main() {
	log.Printf("🚀 SentinelAI Go Metrics Service starting on :%s", PORT)

	// Start background workers
	go metricsSamplerWorker()

	// Seed some initial data for demo
	go func() {
		time.Sleep(2 * time.Second)
		atomic.StoreInt64(&counters.TotalAlerts, 247)
		atomic.StoreInt64(&counters.CriticalAlerts, 12)
		atomic.StoreInt64(&counters.HighAlerts, 58)
		atomic.StoreInt64(&counters.MediumAlerts, 103)
		atomic.StoreInt64(&counters.LowAlerts, 74)
		atomic.StoreInt64(&counters.LogsIngested, 1842651)
		atomic.StoreInt64(&counters.SOARExecutions, 43)
		atomic.StoreInt64(&counters.HoneypotHits, 127)
		atomic.StoreInt64(&counters.AttackChains, 5)
		log.Println("📊 Demo counters seeded")
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/health",          corsMiddleware(handleHealth))
	mux.HandleFunc("/metrics",         corsMiddleware(handleMetrics))
	mux.HandleFunc("/metrics/prometheus", corsMiddleware(handlePrometheus))
	mux.HandleFunc("/metrics/timeseries",corsMiddleware(handleTimeSeries))
	mux.HandleFunc("/metrics/ingest",  corsMiddleware(handleIngestEvent))
	mux.HandleFunc("/metrics/reset",   corsMiddleware(handleReset))
	mux.HandleFunc("/metrics/stream",  corsMiddleware(handleSSE))

	server := &http.Server{
		Addr:         ":" + PORT,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("✅ Go Metrics Service ready on :%s", PORT)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
