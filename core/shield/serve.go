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
	"path/filepath"
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
	if cfg.Scoring.Enabled == nil || *cfg.Scoring.Enabled {
		if p.Scoring, err = LoadScoring(dirs, cfg.Scoring.File, cfg.Scoring.ScoringOverrides); err != nil {
			return nil, nil, err
		}
	}
	if b := cfg.Bots; b.Enabled == nil || *b.Enabled {
		if p.Bots, err = LoadBotsConfig(dirs, b); err != nil {
			return nil, nil, err
		}
		if b.Score.Enabled == nil || *b.Score.Enabled {
			if p.BotScore, err = LoadScoringSet(dirs, "bots.yaml", b.ScoreFile, b.Score); err != nil {
				return nil, nil, err
			}
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
			// nginx auth_request only passes 401/403 through (anything else becomes 500): its snippet asks ?deny=403.
			code := http.StatusForbidden
			if d.Status == http.StatusTooManyRequests && r.URL.Query().Get("deny") != "403" {
				code = http.StatusTooManyRequests
				w.Header().Set("Retry-After", "60")
			}
			snap.Status = code
			g.rec.Write(snap)
			http.Error(w, http.StatusText(code), code)
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
	// Bulk lists are re-read only when their files change; bans and config reloads reuse them. The score tracker
	// survives reloads so per-IP history is not lost.
	var tracker, botTracker *Tracker
	verifier, limiter := NewVerifier(), NewLimiter()
	var lists *Set
	var listsFP string
	kernelWasOn := false
	var loadMu sync.Mutex // reloads come from the poller, SIGHUP and feed downloads
	load := func() error {
		loadMu.Lock()
		defer loadMu.Unlock()
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
		p.Ban = func(a netip.Addr, d time.Duration, src, why string) { g.autoBan(a, d, src, why, c.KernelBlock) }
		if p.Scoring != nil {
			if tracker == nil || tracker.sc.Window != p.Scoring.Window {
				tracker = NewTracker(p.Scoring, 200000)
			}
			tracker.sc = p.Scoring
			p.Tracker = tracker
		}
		if p.BotScore != nil {
			if botTracker == nil || botTracker.sc.Window != p.BotScore.Window {
				botTracker = NewTracker(p.BotScore, 200000)
			}
			botTracker.sc = p.BotScore
			p.BotTracker = botTracker
		}
		if p.Bots != nil {
			verifier.LoadRanges(p.Bots)
			if c.Bots.Verify == nil || *c.Bots.Verify {
				p.Verifier = verifier
			}
		}
		p.Limiter = limiter
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
	// Bot IP feeds (published ranges and your own URLs) are downloaded when due; the policy reloads when one changed.
	refreshFeeds := func() {
		p := g.policy.Load()
		if p == nil || p.Bots == nil {
			return
		}
		done, _ := RefreshBotRanges(p.Bots, false, "")
		changed := false
		for _, st := range done {
			if st.Error != "" {
				log.Printf("shield: bot feed %s %s: %s (kept the previous list)", st.Agent, st.URL, st.Error)
			} else {
				changed = true
			}
		}
		if changed {
			if err := load(); err != nil {
				log.Printf("shield: reload: %v", err)
			}
		}
	}
	feeds := time.NewTicker(5 * time.Minute)
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
		catFP := catalogFingerprint(dirs, cfg.Scoring.File, cfg.Bots.File, cfg.Bots.ScoreFile, filepath.Join(botsDir(), "status.json"))
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
				if fp := catalogFingerprint(dirs, cfg.Scoring.File, cfg.Bots.File, cfg.Bots.ScoreFile, filepath.Join(botsDir(), "status.json")); fp != catFP {
					catFP, changed = fp, true // a customized scoring/bots/rules file was edited
				}
				if changed {
					if err := load(); err != nil {
						log.Printf("shield: reload: %v (kept the previous policy)", err)
					}
				}
			case <-daily.C:
				_, _ = UpdateCloudflare()
				_ = load()
			case <-feeds.C:
				go refreshFeeds()
			}
		}
	}()
	go refreshFeeds() // missing or stale feeds at start
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

func (g *Gate) autoBan(a netip.Addr, d time.Duration, source, reason string, kernel bool) {
	if d <= 0 {
		return
	}
	p := netip.PrefixFrom(a, a.BitLen())
	until := time.Now().Add(d)
	e := Entry{Prefix: p, Until: until, Reason: reason, Source: source, Added: time.Now()}
	if _, err := withState(func(st *State) error { st.Block = upsert(st.Block, e); return nil }); err != nil {
		log.Printf("shield: ban %s: %v", a, err)
		return
	}
	g.policy.Load().Block.Add(e)
	if kernel {
		_ = kernelAdd(p, until)
	}
	log.Printf("shield: banned %s for %s (%s: %s)", a, d, source, reason)
	if g.notify != nil {
		g.notify(fmt.Sprintf("banned %s for %s — %s (%s)", a, d, reason, source))
	}
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// catalogFingerprint changes when any scoring, bots or HTTP rule file in the catalog directories changes, or one of
// the maintainer's own files named in shield.yaml.
func catalogFingerprint(dirs []string, files ...string) string {
	var b strings.Builder
	for _, f := range files {
		if info, err := os.Stat(f); f != "" && err == nil {
			fmt.Fprintf(&b, "%s:%d:%d;", f, info.Size(), info.ModTime().UnixNano())
		}
	}
	for _, d := range dirs {
		for _, sub := range []string{"scoring", "bots", "http"} {
			ents, _ := os.ReadDir(filepath.Join(d, sub))
			for _, e := range ents {
				if info, err := e.Info(); err == nil {
					fmt.Fprintf(&b, "%s/%s/%s:%d:%d;", d, sub, e.Name(), info.Size(), info.ModTime().UnixNano())
				}
			}
		}
	}
	return b.String()
}
