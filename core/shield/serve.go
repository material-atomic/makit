package shield

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/material-atomic/makit/core/notify"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
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
			g.record(snap)
			http.Error(w, http.StatusText(code), code)
			return
		}
		snap.Status = http.StatusOK
		g.record(snap)
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
	// Batch reports go to every channel of `makit notify` whose min_level they reach (the channel file is read at
	// each send, so channels added later work without a restart).
	g.send = func(title, text, level string) { go sendNotify(title, text, level) }
	g.rep = NewReporter(time.Now())
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
		p.Ban = g.autoBan
		for _, e := range g.unsaved() { // bans still on their way to state.json
			p.Block.Add(e)
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
		g.rep.SetLabels(labels)
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
	go g.banWriter(ctx)
	go g.reportLoop(ctx, func() *Config { return current.Load() })

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

func (g *Gate) autoBan(a netip.Addr, d time.Duration, source, reason string) {
	if d <= 0 {
		return
	}
	now := time.Now()
	e := Entry{Prefix: netip.PrefixFrom(a, a.BitLen()), Until: now.Add(d), Reason: reason, Source: source, Added: now}
	g.policy.Load().Block.Add(e) // effective for the next request already
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
			return
		case <-t.C:
			g.flushBans()
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
	_, err := withState(func(st *State) error {
		at := make(map[netip.Prefix]int, len(st.Block))
		for i, e := range st.Block {
			at[e.Prefix] = i
		}
		for _, e := range batch {
			if i, ok := at[e.Prefix]; ok {
				st.Block[i] = e
			} else {
				at[e.Prefix] = len(st.Block)
				st.Block = append(st.Block, e)
			}
		}
		return nil
	})
	if err != nil {
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
		g.rep.Banned(e) // reported (and notified) with the batch report, not one message per ban
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

// reportLoop closes a batch report every report.every, saves it and sends it when it is worth it.
func (g *Gate) reportLoop(ctx context.Context, cfg func() *Config) {
	host, _ := os.Hostname()
	for {
		c := cfg()
		every, on := c.Report.Window()
		if !on {
			every = time.Minute // reports off: check again later, keep the window empty
		}
		select {
		case <-ctx.Done():
			if on {
				g.emitReport(c, host)
			}
			return
		case <-time.After(every):
		}
		if !on {
			g.rep.Flush(time.Now(), host)
			continue
		}
		g.emitReport(cfg(), host)
	}
}

func (g *Gate) emitReport(c *Config, host string) {
	b := g.rep.Flush(time.Now(), host)
	if b == nil {
		return
	}
	if err := b.Save(c.Report.Directory(), max(c.Report.KeepDays, 0)+30*boolInt(c.Report.KeepDays == 0)); err != nil {
		log.Printf("shield: report: %v", err)
	}
	if !b.Worth(c.Report.MinLevel) || g.send == nil {
		return
	}
	title, level := b.notification()
	g.send(title, b.Text, level)
}

func (b *BatchReport) notification() (title, level string) {
	level = map[string]string{"critical": "critical", "high": "high", "bot": "high", "medium": "medium", "likely": "medium"}[b.Level]
	if level == "" || (b.Banned > 0 && levelRank[level] < levelRank["high"]) {
		level = "high"
	}
	return fmt.Sprintf("%d suspicious IPs, %d banned", len(b.IPs)+b.MoreIPs, b.Banned), level
}

func sendReport(b *BatchReport) {
	title, level := b.notification()
	sendNotify(title, b.Text, level)
}

// sendNotify delivers through every makit notify channel whose min_level it reaches (the channel file is read at
// each send, so channels added later work without a restart).
func sendNotify(title, text, level string) {
	c, err := notify.Load(notifyConfig())
	if err != nil || len(c.Channels) == 0 {
		return
	}
	for _, err := range c.Send(notify.Message{Title: title, Text: text, Level: level, Source: "shield"}, "") {
		log.Printf("shield: notify: %v", err)
	}
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
