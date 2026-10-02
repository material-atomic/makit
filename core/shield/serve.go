package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Version is shown in /status.
var Version = "dev"

// buildPolicy loads config, state, rules and (when lists is nil) the bulk lists into a policy.
func buildPolicy(cfg *Config, dirs []string, lists *Set) (*Policy, *State, error) {
	trusted, err := cfg.Trusted()
	if err != nil {
		return nil, nil, err
	}
	st, err := LoadState()
	if err != nil {
		return nil, nil, err
	}
	allow, block := st.Sets(cfg.Allow)
	if lists == nil {
		if lists, _, err = LoadLists(); err != nil {
			return nil, nil, err
		}
	}
	p := &Policy{Observe: cfg.Mode == "observe", Pass: cfg.Mode == "pass", Trusted: trusted, Allow: allow, Block: block, Lists: lists}
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
		if !g.ask.Load() {
			g.count("ask-off")
			w.WriteHeader(http.StatusOK) // ask switched off: proxies keep working, nothing is checked
			return
		}
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
	// Edge listeners start/stop with the "edge" switch and restart when their configuration changes.
	var edgeMu sync.Mutex
	var edgeStop context.CancelFunc
	var edgeKey string
	var edgeErr atomic.Value
	edgeErr.Store("")
	applyEdge := func(c *Config) {
		b, _ := json.Marshal(c.Listeners)
		key := fmt.Sprint(c.Edge, string(b))
		edgeMu.Lock()
		defer edgeMu.Unlock()
		if key == edgeKey {
			return
		}
		if edgeStop != nil {
			edgeStop()
			edgeStop = nil
			time.Sleep(300 * time.Millisecond) // let the old listeners release their ports
		}
		edgeKey = key
		edgeErr.Store("")
		if !c.Edge || len(c.Listeners) == 0 {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		edgeStop = cancel
		go func(ls []Listener) {
			if err := g.Serve(ctx, ls); err != nil {
				edgeErr.Store(err.Error())
				log.Printf("shield: edge: %v", err)
			}
		}(c.Listeners)
	}
	// Bulk lists are re-read only when their files change; bans and config reloads reuse them.
	var lists *Set
	var listsFP string
	kernelWasOn := false
	load := func() error {
		c, err := LoadConfig(cfgPath)
		if err != nil {
			return err
		}
		listsChanged := false
		if fp := listsFingerprint(); lists == nil || fp != listsFP {
			l, fp2, err := LoadLists()
			if err != nil {
				return err
			}
			lists, listsFP, listsChanged = l, fp2, true
		}
		p, st, err := buildPolicy(c, dirs, lists)
		if err != nil {
			return err
		}
		p.Ban = func(a netip.Addr, rule HTTPRule) { g.autoBan(a, rule, c.KernelBlock) }
		cfg = c
		g.header = c.ClientHeader
		g.policy.Store(p)
		g.ask.Store(c.Ask && c.Mode != "pass")
		applyEdge(c)
		if c.KernelBlock && c.Mode == "block" {
			if err := ApplyKernel(st.Block); err != nil {
				log.Printf("shield: kernel set: %v", err)
			}
			if listsChanged || !kernelWasOn {
				if err := ApplyKernelLists(lists); err != nil {
					log.Printf("shield: kernel lists: %v", err)
				}
			}
			kernelWasOn = true
		} else if kernelWasOn || !c.KernelBlock {
			_ = RemoveKernel()
			kernelWasOn = false
		}
		log.Printf("shield: mode=%s ask=%v edge=%v block=%d lists=%d allow=%d rules=%d trusted=%d listeners=%d", c.Mode, c.Ask, c.Edge, len(st.Block), lists.Len(), len(st.Allow)+len(c.Allow), len(p.Rules), len(p.Trusted), len(c.Listeners))
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
		_ = json.NewEncoder(w).Encode(map[string]any{"version": Version, "mode": cfg.Mode, "ask": cfg.Ask, "edge": cfg.Edge,
			"edge_error": edgeErr.Load(), "stats": g.Stats(),
			"block": p.Block.Len(), "lists": p.Lists.Len(), "allow": p.Allow.Len(), "rules": len(p.Rules),
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
		var last, lastCfg time.Time
		if st, err := os.Stat(statePath()); err == nil {
			last = st.ModTime()
		}
		if st, err := os.Stat(cfgPath); err == nil {
			lastCfg = st.ModTime()
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
				changed := false
				if st, err := os.Stat(statePath()); err == nil && st.ModTime().After(last) {
					last, changed = st.ModTime(), true
				}
				if st, err := os.Stat(cfgPath); err == nil && st.ModTime().After(lastCfg) {
					lastCfg, changed = st.ModTime(), true
				}
				if listsFingerprint() != listsFP {
					changed = true
				}
				if changed {
					if err := load(); err != nil {
						log.Printf("shield: reload: %v (kept the previous policy)", err)
					}
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
	<-ctx.Done()
	edgeMu.Lock()
	if edgeStop != nil {
		edgeStop()
	}
	edgeMu.Unlock()
	sh, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return asrv.Shutdown(sh)
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
