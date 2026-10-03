package shield

import (
	"bufio"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	g := askingGate(t)
	g.metrics = newGateMetrics()
	h := g.checkHandler()
	for _, hdr := range []map[string]string{
		{"X-Forwarded-For": "198.51.100.10", "X-Forwarded-Uri": "/"},
		{"X-Forwarded-For": "198.51.100.9"},
		{"X-Forwarded-For": "203.0.113.80", "X-Forwarded-Uri": "/.env"},
	} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9180/check", nil)
		r.RemoteAddr = "127.0.0.1:4000"
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), r)
	}
	g.metrics.banned("rule:MK-HTTP-PROBE")
	g.metrics.reloaded(nil)
	cfg := defaultConfig()
	w := httptest.NewRecorder()
	g.metricsHandler(func() *Config { return cfg }).ServeHTTP(w, httptest.NewRequest("GET", "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		`makit_shield_info{version="dev",mode="observe",ask="true",edge="false",kernel_block="false"} 1`,
		`makit_shield_decisions_total{site="global",verdict="allowed",rule="none"} 1`,
		`makit_shield_decisions_total{site="global",verdict="blocked",rule="manual"} 1`,
		`makit_shield_decisions_total{site="global",verdict="blocked",rule="rule:MK-HTTP-PROBE"} 1`,
		`makit_shield_decision_seconds_bucket{le="+Inf"} 3`,
		`makit_shield_decision_seconds_count 3`,
		`makit_shield_bans_total{source="rule"} 1`,
		`makit_shield_events_total{kind="blocked"} 2`,
		`makit_shield_entries{set="block"} 2`,
		`makit_shield_config_reloads_total{result="ok"} 1`,
		"# TYPE makit_shield_decision_seconds histogram",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in:\n%s", want, body)
		}
	}
	// Every line is a comment or "name{labels} value": what Prometheus parses.
	line := regexp.MustCompile(`^(# (HELP|TYPE) \S+ .+|[a-z_]+(\{([a-z_]+="[^"]*",?)+\})? [-+0-9.e]+|[a-z_]+(\{[^}]*\})? [-+0-9.eInf]+)$`)
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		if !line.MatchString(sc.Text()) {
			t.Errorf("not Prometheus text format: %q", sc.Text())
		}
	}
	// Buckets are cumulative.
	if !regexp.MustCompile(`makit_shield_decision_seconds_bucket\{le="0.005"\} 3`).MatchString(body) {
		t.Errorf("a decision takes far less than 5 ms:\n%s", body)
	}
}

func TestReady(t *testing.T) {
	g := &Gate{stats: map[string]int64{}}
	var cfg *Config
	edgeErr := ""
	h := g.readyHandler(func() string { return edgeErr }, func() *Config { return cfg })
	code := func() int {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", "/readyz", nil))
		return w.Code
	}
	if code() != 503 {
		t.Error("not ready before a policy is loaded")
	}
	g.policy.Store(&Policy{})
	cfg = &Config{Edge: true}
	if code() != 200 {
		t.Error("ready once loaded")
	}
	edgeErr = "listen tcp :443: address already in use"
	if code() != 503 {
		t.Error("not ready when the edge listeners failed")
	}
}

func BenchmarkMetricsObserve(b *testing.B) {
	m := newGateMetrics()
	d := Decision{Verdict: "allowed"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			m.observe("", d, 5*time.Microsecond)
		}
	})
}
