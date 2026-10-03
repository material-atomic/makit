package shield

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Metrics for Prometheus on the admin address (/metrics), and health for Kubernetes (/healthz, /readyz). The request
// path only adds to atomic counters: one read-locked map lookup for the decision counter, and a fixed histogram.

// decisionBuckets are upper bounds in seconds of the decision-latency histogram: a decision is microseconds.
var decisionBuckets = []float64{1e-6, 2.5e-6, 5e-6, 1e-5, 2.5e-5, 5e-5, 1e-4, 2.5e-4, 5e-4, 1e-3, 5e-3}

type decisionKey struct{ site, verdict, rule string }

// Counters every request adds to are striped: each core adds to one of several cache lines, picked at random, instead
// of all of them fighting over one. A scrape sums the stripes.
const stripes = 16

type paddedUint64 struct {
	atomic.Uint64
	_ [56]byte // one cache line each
}

type striped [stripes]paddedUint64

func (s *striped) total() uint64 {
	var t uint64
	for i := range s {
		t += s[i].Load()
	}
	return t
}

type histShard struct {
	buckets  [12]atomic.Uint64 // len(decisionBuckets) + the +Inf bucket
	sumNanos atomic.Uint64
	_        [24]byte
}

type gateMetrics struct {
	// decisions is copied on write: a new (site, verdict, rule) is rare, a lookup happens on every request and takes
	// no lock.
	mu        sync.Mutex
	decisions atomic.Pointer[map[decisionKey]*striped]
	hist      [stripes]histShard

	banMu sync.Mutex
	bans  map[string]uint64 // source kind (rule, score, bot, …) → automatic bans

	reloads      atomic.Uint64
	reloadErrors atomic.Uint64
	lastReload   atomic.Int64 // unix seconds of the last successful load
	started      time.Time
}

func newGateMetrics() *gateMetrics {
	m := &gateMetrics{bans: map[string]uint64{}, started: time.Now()}
	m.decisions.Store(&map[decisionKey]*striped{})
	return m
}

// ruleLabel keeps the metric's label set bounded: rule ids and bot ids come from the catalog, never from a request.
func ruleLabel(rule string) string {
	if rule == "" {
		return "none"
	}
	return rule
}

// observe counts one decision and how long it took.
func (m *gateMetrics) observe(site string, d Decision, took time.Duration) {
	if m == nil {
		return
	}
	k := decisionKey{site, d.Verdict, ruleLabel(d.Rule)}
	c := (*m.decisions.Load())[k]
	if c == nil {
		m.mu.Lock()
		cur := *m.decisions.Load()
		if c = cur[k]; c == nil {
			next := make(map[decisionKey]*striped, len(cur)+1)
			for kk, v := range cur {
				next[kk] = v
			}
			c = new(striped)
			next[k] = c
			m.decisions.Store(&next)
		}
		m.mu.Unlock()
	}
	stripe := rand.Uint32() % stripes
	c[stripe].Add(1)
	h := &m.hist[stripe]
	h.buckets[sort.SearchFloat64s(decisionBuckets, took.Seconds())].Add(1)
	h.sumNanos.Add(uint64(took.Nanoseconds()))
}

func (m *gateMetrics) banned(source string) {
	if m == nil {
		return
	}
	kind, _, _ := strings.Cut(source, ":")
	m.banMu.Lock()
	m.bans[kind]++
	m.banMu.Unlock()
}

func (m *gateMetrics) reloaded(err error) {
	if err != nil {
		m.reloadErrors.Add(1)
		return
	}
	m.reloads.Add(1)
	m.lastReload.Store(time.Now().Unix())
}

// promWriter writes the Prometheus text format (version 0.0.4).
type promWriter struct {
	w    io.Writer
	seen map[string]bool
}

func (p *promWriter) head(name, typ, help string) {
	if p.seen[name] {
		return
	}
	p.seen[name] = true
	fmt.Fprintf(p.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (p *promWriter) sample(name string, v float64, labels ...string) {
	fmt.Fprint(p.w, name)
	if len(labels) > 0 {
		fmt.Fprint(p.w, "{")
		for i := 0; i+1 < len(labels); i += 2 {
			if i > 0 {
				fmt.Fprint(p.w, ",")
			}
			fmt.Fprintf(p.w, "%s=%q", labels[i], labels[i+1])
		}
		fmt.Fprint(p.w, "}")
	}
	fmt.Fprintf(p.w, " %s\n", strconv.FormatFloat(v, 'g', -1, 64))
}

func b2f(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// metricsHandler serves /metrics. cfg returns the config in force.
func (g *Gate) metricsHandler(cfg func() *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		p := &promWriter{w: w, seen: map[string]bool{}}
		m := g.metrics
		c := cfg()
		pol := g.policy.Load()

		p.head("makit_shield_info", "gauge", "makit version and the shield's switches (1).")
		if c != nil {
			p.sample("makit_shield_info", 1, "version", Version, "mode", c.Mode, "ask", strconv.FormatBool(c.Ask),
				"edge", strconv.FormatBool(c.Edge), "kernel_block", strconv.FormatBool(c.KernelBlock))
		}
		p.head("makit_shield_decisions_total", "counter", "Requests decided, by site, verdict and the rule that decided (none when no rule did).")
		decisions := *m.decisions.Load()
		keys := make([]decisionKey, 0, len(decisions))
		for k := range decisions {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].site+keys[i].verdict+keys[i].rule < keys[j].site+keys[j].verdict+keys[j].rule
		})
		for _, k := range keys {
			v := decisions[k].total()
			p.sample("makit_shield_decisions_total", float64(v), "site", firstNonEmpty(k.site, "global"), "verdict", k.verdict, "rule", k.rule)
		}
		p.head("makit_shield_events_total", "counter", "Gate events by kind: verdicts, connections dropped at accept, tcp passes, PROXY header errors, ask switched off.")
		stats := g.Stats()
		ev := make([]string, 0, len(stats))
		for k := range stats {
			ev = append(ev, k)
		}
		sort.Strings(ev)
		for _, k := range ev {
			p.sample("makit_shield_events_total", float64(stats[k]), "kind", k)
		}
		p.head("makit_shield_decision_seconds", "histogram", "Time to decide one request (client IP, lists, bots, rules, scores).")
		var cum, sum uint64
		for i := 0; i <= len(decisionBuckets); i++ {
			for s := range m.hist {
				cum += m.hist[s].buckets[i].Load()
			}
			le := "+Inf"
			if i < len(decisionBuckets) {
				le = strconv.FormatFloat(decisionBuckets[i], 'g', -1, 64)
			}
			p.sample("makit_shield_decision_seconds_bucket", float64(cum), "le", le)
		}
		for s := range m.hist {
			sum += m.hist[s].sumNanos.Load()
		}
		p.sample("makit_shield_decision_seconds_sum", float64(sum)/1e9)
		p.sample("makit_shield_decision_seconds_count", float64(cum))

		p.head("makit_shield_bans_total", "counter", "Automatic bans, by what caused them (rule, score, bot, limit).")
		m.banMu.Lock()
		kinds := make([]string, 0, len(m.bans))
		for k := range m.bans {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			p.sample("makit_shield_bans_total", float64(m.bans[k]), "source", k)
		}
		m.banMu.Unlock()

		if pol != nil {
			p.head("makit_shield_entries", "gauge", "Entries in the shield's sets.")
			p.sample("makit_shield_entries", float64(pol.Block.Len()), "set", "block")
			p.sample("makit_shield_entries", float64(pol.Lists.Len()), "set", "lists")
			p.sample("makit_shield_entries", float64(pol.Allow.Len()), "set", "allow")
			p.head("makit_shield_rules", "gauge", "HTTP rules loaded from the catalog.")
			p.sample("makit_shield_rules", float64(len(pol.Rules)))
			p.head("makit_shield_trusted_proxy_ranges", "gauge", "Trusted proxy ranges (trusted_proxies expanded).")
			p.sample("makit_shield_trusted_proxy_ranges", float64(len(pol.Trusted)))
		}
		p.head("makit_shield_config_reloads_total", "counter", "Config and state loads, by result.")
		p.sample("makit_shield_config_reloads_total", float64(m.reloads.Load()), "result", "ok")
		p.sample("makit_shield_config_reloads_total", float64(m.reloadErrors.Load()), "result", "error")
		p.head("makit_shield_config_last_reload_timestamp_seconds", "gauge", "When the policy in force was loaded.")
		p.sample("makit_shield_config_last_reload_timestamp_seconds", float64(m.lastReload.Load()))
		p.head("makit_shield_start_time_seconds", "gauge", "When the gate started.")
		p.sample("makit_shield_start_time_seconds", float64(m.started.Unix()))

		samples := []metrics.Sample{{Name: "/sched/goroutines:goroutines"}, {Name: "/memory/classes/heap/objects:bytes"},
			{Name: "/memory/classes/total:bytes"}}
		metrics.Read(samples)
		p.head("go_goroutines", "gauge", "Goroutines.")
		p.sample("go_goroutines", float64(samples[0].Value.Uint64()))
		p.head("go_heap_objects_bytes", "gauge", "Bytes in live and unswept heap objects.")
		p.sample("go_heap_objects_bytes", float64(samples[1].Value.Uint64()))
		p.head("go_memory_total_bytes", "gauge", "All memory the Go runtime has mapped.")
		p.sample("go_memory_total_bytes", float64(samples[2].Value.Uint64()))
	})
}

// readyHandler: 200 once a policy is loaded and, with edge on, the listeners started; 503 before. A pod that fails it
// gets no traffic; /healthz only says the process answers.
func (g *Gate) readyHandler(edgeErr func() string, cfg func() *Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch c := cfg(); {
		case g.policy.Load() == nil || c == nil:
			http.Error(w, "no policy loaded yet", http.StatusServiceUnavailable)
		case c.Edge && edgeErr() != "":
			http.Error(w, "edge listeners: "+edgeErr(), http.StatusServiceUnavailable)
		default:
			_, _ = io.WriteString(w, "ready\n")
		}
	})
}
