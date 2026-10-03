package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/material-atomic/makit/core/notify"
)

// Version is shown in /status.
var Version = "dev"

// buildPolicy loads config, state, rules and (when lists is nil) the bulk lists into a policy.
func buildPolicy(cfg *Config, dirs []string, lists *Set) (*Policy, *State, error) {
	st, err := LoadState()
	if err != nil {
		return nil, nil, err
	}
	if lists == nil {
		if lists, _, err = LoadLists(); err != nil {
			return nil, nil, err
		}
	}
	p, err := buildPolicyWith(cfg, dirs, st, lists)
	return p, st, err
}

// buildPolicyWith builds the policy from a config, the catalog directories, a state and the bulk lists, reading
// nothing else from disk.
func buildPolicyWith(cfg *Config, dirs []string, st *State, lists *Set) (*Policy, error) {
	trusted, err := cfg.Trusted()
	if err != nil {
		return nil, err
	}
	allow, block, siteAllow, siteBlock := st.SiteSets(cfg.Allow)
	p := &Policy{Observe: cfg.Mode == "observe", Pass: cfg.Mode == "pass", Trusted: trusted, Allow: allow, Block: block, Lists: lists}
	if cfg.Rules {
		if p.Rules, err = LoadHTTPRules(dirs); err != nil {
			return nil, err
		}
	}
	if cfg.Scoring.Enabled == nil || *cfg.Scoring.Enabled {
		if p.Scoring, err = LoadScoring(dirs, cfg.Scoring.File, cfg.Scoring.ScoringOverrides); err != nil {
			return nil, err
		}
	}
	if b := cfg.Bots; b.Enabled == nil || *b.Enabled {
		if p.Bots, err = LoadBotsConfig(dirs, b); err != nil {
			return nil, err
		}
		if b.Score.Enabled == nil || *b.Score.Enabled {
			if p.BotScore, err = LoadScoringSet(dirs, "bots.yaml", b.ScoreFile, b.Score); err != nil {
				return nil, err
			}
		}
	}
	if err := buildSites(p, cfg, dirs, siteAllow, siteBlock); err != nil {
		return nil, err
	}
	return p, nil
}

// buildSites derives one policy per site from the global one: what a site sets wins, the rest is inherited.
func buildSites(p *Policy, cfg *Config, dirs []string, siteAllow, siteBlock map[string]*Set) error {
	p.SiteScoped = cfg.BanScope == "site"
	if cfg.BanScope != "" && cfg.BanScope != "server" && cfg.BanScope != "site" {
		return fmt.Errorf("ban_scope: server or site")
	}
	p.exact, p.siteSets = map[string]*Policy{}, map[string]*Set{}
	seen := map[string]bool{}
	for i, sc := range cfg.Sites {
		id := sc.ID()
		where := fmt.Sprintf("sites[%d] (%s)", i, id)
		if id == "" || len(sc.Match) == 0 {
			return fmt.Errorf("sites[%d]: match is required", i)
		}
		if seen[id] {
			return fmt.Errorf("%s: two sites with the same name", where)
		}
		seen[id] = true
		sp := *p
		sp.sites, sp.exact, sp.wild, sp.siteSets = nil, nil, nil, nil
		sp.Site = id
		switch sc.Mode {
		case "":
		case "block", "observe", "pass":
			sp.Observe, sp.Pass = sc.Mode == "observe", sc.Mode == "pass"
		default:
			return fmt.Errorf("%s: mode block, observe or pass", where)
		}
		switch sc.BanScope {
		case "":
		case "server", "site":
			sp.SiteScoped = sc.BanScope == "site"
		default:
			return fmt.Errorf("%s: ban_scope server or site", where)
		}
		sp.SiteAllow = siteAllow[id]
		if sp.SiteAllow == nil {
			sp.SiteAllow = NewSet()
		}
		for _, a := range sc.Allow {
			pfx, err := ParsePrefix(a)
			if err != nil {
				return fmt.Errorf("%s allow: %w", where, err)
			}
			sp.SiteAllow.Add(Entry{Prefix: pfx, Source: "config", Reason: "site allow", Site: id})
		}
		sp.SiteBlock = siteBlock[id]
		if sp.SiteBlock == nil {
			sp.SiteBlock = NewSet()
		}
		p.siteSets[id] = sp.SiteBlock
		if sc.Rules.Enabled != nil && !*sc.Rules.Enabled {
			sp.Rules = nil
		} else if sc.Rules.Disable != nil {
			off := map[string]bool{}
			for _, x := range sc.Rules.Disable {
				off[x] = true
			}
			sp.Rules = nil
			for _, r := range p.Rules {
				if !off[r.ID] {
					sp.Rules = append(sp.Rules, r)
				}
			}
		}
		var err error
		if !sc.Scoring.empty() {
			o := mergeOverrides(cfg.Scoring.ScoringOverrides, sc.Scoring)
			sp.Scoring = nil
			if o.Enabled == nil || *o.Enabled {
				if sp.Scoring, err = LoadScoring(dirs, cfg.Scoring.File, o); err != nil {
					return fmt.Errorf("%s scoring: %w", where, err)
				}
			}
		}
		if p.Bots != nil && (len(sc.Bots.Policy) > 0 || !sc.Bots.Score.empty()) {
			b := cfg.Bots
			b.Policy = map[string]string{}
			for k, v := range cfg.Bots.Policy {
				b.Policy[k] = v
			}
			for k, v := range sc.Bots.Policy {
				b.Policy[k] = v
			}
			if sp.Bots, err = LoadBotsConfig(dirs, b); err != nil {
				return fmt.Errorf("%s bots: %w", where, err)
			}
			o := mergeOverrides(cfg.Bots.Score, sc.Bots.Score)
			sp.BotScore = nil
			if o.Enabled == nil || *o.Enabled {
				if sp.BotScore, err = LoadScoringSet(dirs, "bots.yaml", cfg.Bots.ScoreFile, o); err != nil {
					return fmt.Errorf("%s bot score: %w", where, err)
				}
			}
		}
		spp := &sp
		p.sites = append(p.sites, spp)
		for _, m := range sc.Match {
			m = strings.ToLower(strings.TrimSpace(m))
			if suf, ok := strings.CutPrefix(m, "*."); ok {
				p.wild = append(p.wild, wildSite{"." + suf, spp})
				continue
			}
			if p.exact[m] != nil {
				return fmt.Errorf("%s: %s is matched by two sites", where, m)
			}
			p.exact[m] = spp
		}
	}
	sort.SliceStable(p.wild, func(i, j int) bool { return len(p.wild[i].suffix) > len(p.wild[j].suffix) })
	// Bans of a site that is no longer configured stay in state.json but are not applied.
	return nil
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
		chain := headerChain(h, "X-Forwarded-For")
		if peer == "" {
			// A proxy without the header (Traefik forwardAuth, ingress-nginx auth-url): the right-most
			// X-Forwarded-For entry is the address the asking proxy itself received the request from. The left-most
			// is whatever the visitor typed.
			peer = chain
			if i := strings.LastIndexByte(chain, ','); i >= 0 {
				peer = chain[i+1:]
			}
			peer = strings.TrimSpace(peer)
		}
		hdr := map[string]string{}
		for k, v := range h {
			if lk := strings.ToLower(k); lk != "cookie" && lk != "authorization" && lk != "proxy-authorization" {
				hdr[lk] = strings.Join(v, ", ")
			}
		}
		method, uri, host := askedRequest(r)
		q := Request{Peer: peer, Client: firstNonEmpty(h.Get("X-Makit-Client"), headerChain(h, g.header)), Method: method, Host: host,
			URI: uri, UA: h.Get("User-Agent"), Referer: h.Get("Referer"), Country: h.Get("CF-IPCountry"), Ray: h.Get("CF-Ray"),
			Headers: hdr, Received: time.Now()}
		if !g.ask.Load() {
			g.count("ask-off")
			w.WriteHeader(http.StatusOK) // ask switched off: proxies keep working, nothing is checked
			return
		}
		d := g.policy.Load().Decide(q)
		g.metrics.observe(d.Site, d, time.Since(q.Received))
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
			g.record(snap)
			http.Error(w, http.StatusText(code), code)
			return
		}
		snap.Status = http.StatusOK
		g.record(snap)
		w.WriteHeader(http.StatusOK)
	})
}

// privateOnly answers only callers on this machine or its private networks (Prometheus, the CLI, a pod in the
// cluster): in Kubernetes the admin address listens on every interface of the pod.
func privateOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ap, err := netip.ParseAddrPort(r.RemoteAddr); err != nil || !(ap.Addr().Unmap().IsLoopback() || ap.Addr().Unmap().IsPrivate()) {
			// Name the caller: a refusal that does not say who was refused sends people looking in the wrong place.
			http.Error(w, "forbidden: makit-shield answers "+r.URL.Path+" only to this machine and private networks, not "+r.RemoteAddr, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// askedRequest is the request a proxy asks about. Caddy, nginx and Traefik send it in X-Forwarded-Method/-Uri/-Host;
// ingress-nginx in X-Original-Method/-URI and X-Original-URL (which also carries the host); Envoy ext_authz sends the
// original method and host as they are and the original path after /check (path_prefix /check, or path: /check in
// Envoy Gateway and Istio).
func askedRequest(r *http.Request) (method, uri, host string) {
	h := r.Header
	method = firstNonEmpty(h.Get("X-Forwarded-Method"), h.Get("X-Original-Method"), r.Method)
	uri = firstNonEmpty(h.Get("X-Forwarded-Uri"), h.Get("X-Original-URI"))
	host = h.Get("X-Forwarded-Host")
	if u := h.Get("X-Original-URL"); u != "" {
		if pu, err := url.Parse(u); err == nil {
			host = firstNonEmpty(host, pu.Host)
			uri = firstNonEmpty(uri, pu.RequestURI())
		}
	}
	if uri == "" {
		uri = r.URL.RequestURI()
		if rest, ok := strings.CutPrefix(uri, "/check"); ok && (strings.HasPrefix(rest, "/") || rest == "") {
			uri = firstNonEmpty(rest, "/") // Envoy: /check/<original path and query>
		}
	}
	return method, uri, firstNonEmpty(host, r.Host)
}

// headerChain joins every line of a header in order ("a, b" and a second line "c" → "a, b, c"): a forwarding chain
// read from the right must see the lines proxies appended, not only the first line a visitor may have sent.
func headerChain(h http.Header, name string) string {
	v := h.Values(name)
	switch len(v) {
	case 0:
		return ""
	case 1:
		return v[0]
	}
	return strings.Join(v, ", ")
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
	g := &Gate{rec: rec, header: cfg.ClientHeader, stats: map[string]int64{}, metrics: newGateMetrics()}
	// Batch reports go to every channel of `makit notify` whose min_level they reach (the channel file is read at
	// each send, so channels added later work without a restart).
	g.send = func(title, text, level string, channels []string) { go sendNotify(title, text, level, channels) }
	g.repFor("")
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
	var current atomic.Pointer[Config] // the config in force, for the report loop
	var loadMu sync.Mutex              // reloads come from the poller, SIGHUP and feed downloads
	var loadPolicy func() error
	load := func() error { // every load attempt is counted for /metrics
		err := loadPolicy()
		g.metrics.reloaded(err)
		return err
	}
	loadPolicy = func() error {
		loadMu.Lock()
		defer loadMu.Unlock()
		c, err := LoadConfig(cfgPath)
		if err != nil {
			return err
		}
		// What loads but probably does not do what was meant (a misspelt key is ignored): said in the log.
		if b, err := os.ReadFile(cfgPath); err == nil {
			for _, i := range CheckConfig(b, CheckOptions{InPod: os.Getenv("KUBERNETES_SERVICE_HOST") != ""}) {
				log.Printf("shield: config %s: %s (makit shield config check)", i.Level, i)
			}
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
		p.Ban = g.autoBan
		for _, e := range g.unsaved() { // bans still on their way to state.json
			if e.Site == "" {
				p.Block.Add(e)
			} else if s := p.SiteBlockSet(e.Site); s != nil {
				s.Add(e)
			}
		}
		g.kernel.Store(c.KernelBlock && c.Mode == "block")
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
		if g.cluster != nil { // counts are exchanged with the other replicas
			limiter.Share()
			if p.Tracker != nil {
				p.Tracker.Share()
			}
			if p.BotTracker != nil {
				p.BotTracker.Share()
			}
			g.cluster.StateLoaded(st)
		}
		p.Share() // sites use the same trackers, verifier, limiter and ban writer
		cfg = c
		current.Store(c)
		labels := map[string]string{}
		for _, sc := range []*Scoring{p.Scoring, p.BotScore} {
			if sc != nil {
				for k, v := range sc.Labels() {
					labels[k] = v
				}
			}
		}
		g.setLabels(labels)
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
	if cfg.Cluster.Enabled() {
		if g.cluster, err = NewCluster(g, cfg.Cluster); err != nil {
			return err
		}
	}
	if err := load(); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go g.banWriter(ctx)
	if cfg.AWSWAF.Enabled() { // aws_waf: is read at start, like cluster:
		if g.waf, err = NewWAFSync(ctx, cfg.AWSWAF); err != nil {
			return err
		}
		go g.wafLoop(ctx, g.waf)
	}
	if g.cluster != nil {
		go func() {
			if err := g.cluster.Run(ctx); err != nil {
				log.Printf("shield: %v", err)
				stop()
			}
		}()
	}
	go g.reportLoop(ctx, func() *Config { return current.Load() })

	mux := http.NewServeMux()
	mux.Handle("/check", g.checkHandler())
	mux.Handle("/check/", g.checkHandler()) // Envoy ext_authz appends the original path
	inForce := func() *Config { return current.Load() }
	mux.Handle("/metrics", privateOnly(g.metricsHandler(inForce)))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.Handle("/readyz", g.readyHandler(func() string { s, _ := edgeErr.Load().(string); return s }, inForce))
	mux.Handle("/status", privateOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := g.policy.Load()
		cfg := current.Load() // the config in force (reloads replace it)
		w.Header().Set("Content-Type", "application/json")
		out := map[string]any{"version": Version, "mode": cfg.Mode, "ask": cfg.Ask, "edge": cfg.Edge,
			"edge_error": edgeErr.Load(), "stats": g.Stats(),
			"block": p.Block.Len(), "lists": p.Lists.Len(), "allow": p.Allow.Len(), "rules": len(p.Rules),
			"trusted": len(p.Trusted), "listeners": len(cfg.Listeners), "kernel_block": cfg.KernelBlock}
		if g.cluster != nil {
			var peers []map[string]any
			for _, ps := range g.cluster.Peers() {
				peers = append(peers, map[string]any{"addr": ps.Addr, "last_ok": ps.LastOK, "error": ps.Err, "pending": ps.Pending})
			}
			out["cluster"] = map[string]any{"node": g.cluster.node, "peers": peers}
		}
		_ = json.NewEncoder(w).Encode(out)
	})))
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
	signal.Notify(hup, reloadSignal)
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
					last = st.ModTime()
					changed = changed || st.ModTime().UnixNano() != g.selfWrite.Load() // our own ban batch: no reload
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

func (g *Gate) autoBan(a netip.Addr, d time.Duration, source, reason, site string, scoped bool) {
	if d <= 0 {
		return
	}
	g.metrics.banned(source)
	now := time.Now()
	e := Entry{Prefix: netip.PrefixFrom(a, a.BitLen()), Until: now.Add(d), Reason: reason, Source: source, Added: now, origin: site}
	p := g.policy.Load()
	if scoped && site != "" {
		e.Site = site
		if s := p.SiteBlockSet(site); s != nil {
			s.Add(e) // this site only
		}
	} else {
		p.Block.Add(e) // every site; effective for the next request already
	}
	g.cluster.publish("ban", e) // the other replicas, with the next sync
	g.banMu.Lock()
	if len(g.pending) < 200000 {
		g.pending = append(g.pending, e)
	} else {
		g.banDrops++ // still banned in memory; only persistence is skipped under an extreme flood
	}
	g.banMu.Unlock()
}

// unsaved returns the bans not yet in state.json, so a reload in between keeps them.
func (g *Gate) unsaved() []Entry {
	g.banMu.Lock()
	defer g.banMu.Unlock()
	return append(append([]Entry(nil), g.inflight...), g.pending...)
}

// banWriter persists automatic bans once a second: one state.json write, one nft batch, one log line and one
// notification per batch — a botnet of 100,000 IPs costs a few writes, not 100,000 rewrites of a growing file.
func (g *Gate) banWriter(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.flushBans()
			g.flushRemote()
			return
		case <-t.C:
			g.flushBans()
			g.flushRemote()
		}
	}
}

func (g *Gate) flushBans() {
	g.banMu.Lock()
	batch, drops := g.pending, g.banDrops
	g.pending, g.inflight, g.banDrops = nil, batch, 0
	g.banMu.Unlock()
	if len(batch) == 0 && drops == 0 {
		return
	}
	defer func() {
		g.banMu.Lock()
		g.inflight = nil
		g.banMu.Unlock()
	}()
	if err := saveBans(batch); err != nil {
		log.Printf("shield: saving %d bans: %v (they stay active until restart)", len(batch), err)
		return
	}
	if info, err := os.Stat(statePath()); err == nil {
		g.selfWrite.Store(info.ModTime().UnixNano())
	}
	if g.kernel.Load() {
		var b strings.Builder
		now := time.Now()
		for _, e := range batch {
			if KernelSafe(e.Prefix) {
				set := "block4"
				if e.Prefix.Addr().Is6() {
					set = "block6"
				}
				fmt.Fprintf(&b, "add element inet %s %s { %s }\n", nftTable, set, element(e.Prefix, e.Until, now))
			}
		}
		if b.Len() > 0 {
			if err := nft(b.String()); err != nil {
				log.Printf("shield: kernel bans: %v", err)
			}
		}
	}
	by := map[string]int{}
	for _, e := range batch {
		by[e.Source]++
	}
	var parts []string
	for src, n := range by {
		parts = append(parts, fmt.Sprintf("%s %d", src, n))
	}
	sort.Strings(parts)
	msg := fmt.Sprintf("banned %d IPs (%s)", len(batch), strings.Join(parts, ", "))
	if len(batch) == 1 {
		e := batch[0]
		msg = fmt.Sprintf("banned %s until %s — %s (%s)", e.Prefix.Addr(), e.Until.UTC().Format("01-02 15:04 UTC"), e.Reason, e.Source)
	}
	if drops > 0 {
		msg += fmt.Sprintf("; %d more banned in memory only (queue full)", drops)
	}
	log.Printf("shield: %s", msg)
	for _, e := range batch {
		g.repFor(e.origin).Banned(e) // reported (and notified) with its site's batch report, not one message per ban
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

func notifyConfig() string {
	if p := os.Getenv("MAKIT_NOTIFY_CONFIG"); p != "" {
		return p
	}
	return notify.DefaultConfig
}

// reportLoop closes a batch report every report.every, saves it and sends it when it is worth it. It checks every
// few seconds, so a changed interval applies at once.
func (g *Gate) reportLoop(ctx context.Context, cfg func() *Config) {
	host, _ := os.Hostname()
	start := time.Now()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if _, on := cfg().Report.Window(); on {
				g.emitReport(cfg(), host)
			}
			return
		case <-t.C:
		}
		c := cfg()
		every, on := c.Report.Window()
		if !on {
			g.repMu.Lock()
			reps := make([]*Reporter, 0, len(g.reps))
			for _, r := range g.reps {
				reps = append(reps, r)
			}
			g.repMu.Unlock()
			for _, r := range reps {
				r.Flush(time.Now(), host) // reports off: keep the windows empty
			}
			start = time.Now()
			continue
		}
		if time.Since(start) < every {
			continue
		}
		start = time.Now()
		g.emitReport(c, host)
	}
}

func (g *Gate) emitReport(c *Config, host string) {
	g.repMu.Lock()
	sites := make([]string, 0, len(g.reps))
	for site := range g.reps {
		sites = append(sites, site)
	}
	g.repMu.Unlock()
	sort.Strings(sites)
	for _, site := range sites {
		b := g.repFor(site).Flush(time.Now(), host)
		if b == nil {
			continue
		}
		b.Site = site
		b.Text = b.render(g.labels)
		dir := c.Report.Directory()
		minLevel, channels := c.Report.MinLevel, []string(nil)
		if site != "" {
			dir = filepath.Join(dir, site)
			for _, sc := range c.Sites {
				if sc.ID() == site {
					minLevel, channels = firstNonEmpty(sc.Report.MinLevel, minLevel), sc.Report.Notify
				}
			}
		}
		if err := b.Save(dir, max(c.Report.KeepDays, 0)+30*boolInt(c.Report.KeepDays == 0)); err != nil {
			log.Printf("shield: report: %v", err)
		}
		if b.Worth(minLevel) && g.send != nil {
			title, level := b.notification()
			g.send(title, b.Text, level, channels)
		}
	}
}

func (b *BatchReport) notification() (title, level string) {
	level = map[string]string{"critical": "critical", "high": "high", "bot": "high", "medium": "medium", "likely": "medium"}[b.Level]
	if level == "" || (b.Banned > 0 && levelRank[level] < levelRank["high"]) {
		level = "high"
	}
	return fmt.Sprintf("%d suspicious IPs, %d banned", len(b.IPs)+b.MoreIPs, b.Banned), level
}

func sendReport(b *BatchReport, channels []string) {
	title, level := b.notification()
	sendNotify(title, b.Text, level, channels)
}

// sendNotify delivers through every makit notify channel whose min_level it reaches (the channel file is read at
// each send, so channels added later work without a restart).
func sendNotify(title, text, level string, channels []string) {
	c, err := notify.Load(notifyConfig())
	if err != nil || len(c.Channels) == 0 {
		return
	}
	for _, err := range c.SendTo(notify.Message{Title: title, Text: text, Level: level, Source: "shield"}, channels) {
		log.Printf("shield: notify: %v", err)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
