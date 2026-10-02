package shield

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// Version is shown in /status.
var Version = "dev"

// buildPolicy loads config, state and rules into a policy.
func buildPolicy(cfg *Config, dirs []string) (*Policy, *State, error) {
	trusted, err := cfg.Trusted()
	if err != nil {
		return nil, nil, err
	}
	st, err := LoadState()
	if err != nil {
		return nil, nil, err
	}
	allow, block := st.Sets(cfg.Allow)
	p := &Policy{Observe: cfg.Mode == "observe", Pass: cfg.Mode == "pass", Trusted: trusted, Allow: allow, Block: block}
	if cfg.Rules {
		if p.Rules, err = LoadHTTPRules(dirs); err != nil {
			return nil, nil, err
		}
	}
	return p, st, nil
}

// checkHandler answers Caddy forward_auth / nginx auth_request: 2xx allow, 403 block.
func (g *Gate) checkHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Only proxies on this machine or its private networks may ask.
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || !(ap.Addr().IsLoopback() || ap.Addr().IsPrivate()) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		h := r.Header
		peer := h.Get("X-Makit-Peer")
		if peer == "" { // nginx without the header: fall back to the left-most X-Forwarded-For it set
			peer = strings.TrimSpace(strings.Split(h.Get("X-Forwarded-For"), ",")[0])
		}
		hdr := map[string]string{}
		for k, v := range h {
			if lk := strings.ToLower(k); lk != "cookie" && lk != "authorization" && lk != "proxy-authorization" {
				hdr[lk] = strings.Join(v, ", ")
			}
		}
		method := firstNonEmpty(h.Get("X-Forwarded-Method"), h.Get("X-Original-Method"), r.Method)
		uri := firstNonEmpty(h.Get("X-Forwarded-Uri"), h.Get("X-Original-URI"), r.RequestURI)
		host := firstNonEmpty(h.Get("X-Forwarded-Host"), r.Host)
		q := Request{Peer: peer, Client: firstNonEmpty(h.Get("X-Makit-Client"), h.Get(g.header)), Method: method, Host: host,
			URI: uri, UA: h.Get("User-Agent"), Referer: h.Get("Referer"), Country: h.Get("CF-IPCountry"), Ray: h.Get("CF-Ray"),
			Headers: hdr, Received: time.Now()}
		d := g.policy.Load().Decide(q)
		g.count(d.Verdict)
		snap := Snapshot{Time: q.Received, Listener: "check", Decision: d, Method: method, Host: host, URI: uri, UA: q.UA,
			Referer: q.Referer, Country: q.Country, Ray: q.Ray}
		w.Header().Set("X-Makit-Client", d.Client)
		w.Header().Set("X-Makit-Verdict", d.Verdict)
		if !d.Allow {
			snap.Status = http.StatusForbidden
			g.rec.Write(snap)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		snap.Status = http.StatusOK
		g.rec.Write(snap)
		w.WriteHeader(http.StatusOK)
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Serve runs the gate: /check + /status on the admin address, edge listeners from the config, kernel sync, reloads.
func Serve(cfgPath string, dirs []string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	rec, err := NewRecorder(cfg.Snapshot.Path, cfg.Snapshot.MaxMB, cfg.Snapshot.Keep)
	if err != nil {
		return err
	}
	g := &Gate{rec: rec, header: cfg.ClientHeader, stats: map[string]int64{}}
	load := func() error {
		c, err := LoadConfig(cfgPath)
		if err != nil {
			return err
		}
		p, st, err := buildPolicy(c, dirs)
		if err != nil {
			return err
		}
		p.Ban = func(a netip.Addr, rule HTTPRule) { g.autoBan(a, rule, c.KernelBlock) }
		cfg = c
		g.header = c.ClientHeader
		g.policy.Store(p)
		if c.KernelBlock && c.Mode == "block" {
			if err := ApplyKernel(st.Block); err != nil {
				log.Printf("shield: kernel set: %v", err)
			}
		} else {
			_ = RemoveKernel()
		}
		log.Printf("shield: mode=%s block=%d allow=%d rules=%d trusted=%d listeners=%d", c.Mode, len(st.Block), len(st.Allow)+len(c.Allow), len(p.Rules), len(p.Trusted), len(c.Listeners))
		return nil
	}
	if err := load(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	mux.Handle("/check", g.checkHandler())
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		p := g.policy.Load()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"version": Version, "mode": cfg.Mode, "stats": g.Stats(),
			"block": len(p.Block.Live(time.Now())), "allow": len(p.Allow.Live(time.Now())), "rules": len(p.Rules),
			"trusted": len(p.Trusted), "listeners": len(cfg.Listeners), "kernel_block": cfg.KernelBlock})
	})
	admin, err := net.Listen("tcp", cfg.Admin)
	if err != nil {
		return err
	}
	asrv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = asrv.Serve(admin) }()

	// Reload on SIGHUP and whenever the state file changes (makit shield ban/allow…); refresh Cloudflare ranges daily.
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		var last time.Time
		if st, err := os.Stat(statePath()); err == nil {
			last = st.ModTime()
		}
		tick, daily := time.NewTicker(2*time.Second), time.NewTicker(24*time.Hour)
		for {
			select {
			case <-ctx.Done():
				return
			case <-hup:
				if err := load(); err != nil {
					log.Printf("shield: reload: %v (kept the previous policy)", err)
				}
			case <-tick.C:
				if st, err := os.Stat(statePath()); err == nil && st.ModTime().After(last) {
					last = st.ModTime()
					_ = load()
				}
			case <-daily.C:
				if _, err := UpdateCloudflare(); err == nil {
					_ = load()
				}
			}
		}
	}()
	if containsStr(cfg.TrustedProxies, "cloudflare") {
		go func() {
			if _, err := UpdateCloudflare(); err == nil {
				_ = load()
			}
		}()
	}
	log.Printf("shield %s: /check on http://%s", Version, cfg.Admin)
	err = g.Serve(ctx, cfg.Listeners)
	sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = asrv.Shutdown(sh)
	return err
}

func (g *Gate) autoBan(a netip.Addr, rule HTTPRule, kernel bool) {
	p := netip.PrefixFrom(a, a.BitLen())
	until := time.Now().Add(rule.BanFor)
	e := Entry{Prefix: p, Until: until, Reason: rule.Title, Source: "rule:" + rule.ID, Added: time.Now()}
	if _, err := withState(func(st *State) error { st.Block = upsert(st.Block, e); return nil }); err != nil {
		log.Printf("shield: ban %s: %v", a, err)
		return
	}
	g.policy.Load().Block.Add(e)
	if kernel {
		_ = kernelAdd(p, until)
	}
	log.Printf("shield: banned %s for %s (%s)", a, rule.BanFor, rule.ID)
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
