package shield

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Agent is one known bot, crawler or AI agent (security/bots/agents.yaml).
type Agent struct {
	ID       string            `yaml:"id" json:"id"`
	Name     string            `yaml:"name" json:"name"`
	Operator string            `yaml:"operator" json:"operator,omitempty"`
	Category string            `yaml:"category" json:"category"`
	UA       string            `yaml:"ua" json:"-"`
	Header   map[string]string `yaml:"header" json:"-"` // lower-case header → regexp (e.g. signature-agent)
	Robots   string            `yaml:"robots" json:"robots,omitempty"`
	Action   string            `yaml:"action" json:"action,omitempty"` // the catalog's default for this agent (over its category's)
	URL      string            `yaml:"url" json:"url,omitempty"`
	Verify   struct {
		RDNS   []string `yaml:"rdns" json:"rdns,omitempty"`
		Ranges []string `yaml:"ranges" json:"ranges,omitempty"`
	} `yaml:"verify" json:"verify"`
	ByIP   bool `yaml:"-" json:"by_ip,omitempty"` // identified by IP alone (agents from your own sources)
	ua     *matcher
	hdr    map[string]*matcher
	feeds  []feed         // published or maintainer IP range URLs
	manual []netip.Prefix // IPs typed by the maintainer
}

// feed is one URL of IP ranges, cached in the state directory and refreshed every Every.
type feed struct {
	URL    string
	Every  time.Duration
	File   string
	Custom bool
}

func (a *Agent) Verifiable() bool {
	return len(a.Verify.RDNS) > 0 || len(a.feeds) > 0 || len(a.manual) > 0
}

type BotCategory struct {
	Label  string `yaml:"label" json:"label"`
	Action string `yaml:"action" json:"action"`
}

// BotCatalog is the agents file plus the maintainer's policy.
type BotCatalog struct {
	ID           string                 `yaml:"id"`
	Doc          string                 `yaml:"doc"`
	Categories   map[string]BotCategory `yaml:"categories"`
	Spoofed      string                 `yaml:"spoofed"`
	byID         map[string]*Agent
	uaMemo       *memo[int]          // per User-Agent: index of the first agent whose ua matches, -1 none
	RobotsTokens map[string][]string `yaml:"robots_tokens"`
	Agents       []*Agent            `yaml:"agents"`
	policy       map[string]Act      // effective: category ids, agent ids and "spoofed"
}

// BotsConfig is shield.yaml → bots:.
type BotsConfig struct {
	Enabled   *bool             `yaml:"enabled"`
	Policy    map[string]string `yaml:"policy"`     // category, agent id or "spoofed" → action
	Verify    *bool             `yaml:"verify"`     // reverse-DNS checks (default on)
	File      string            `yaml:"file"`       // your own agents file instead of the catalog's (same format)
	Score     ScoringOverrides  `yaml:"score"`      // bot score: enabled, actions per level, disable
	ScoreFile string            `yaml:"score_file"` // your own bot scoring file (same format as scoring/bots.yaml)
	Refresh   string            `yaml:"refresh"`    // how often published ranges are downloaded again (default 24h)
	Sources   []BotSource       `yaml:"sources"`    // your own IP ranges for bots: URLs refreshed on a schedule, or typed IPs
}

// BotSource adds IP ranges to an agent — one of the catalog's, or a new one (then category is required and the agent
// is recognised by IP alone: partners' crawlers, your monitoring).
type BotSource struct {
	Agent    string   `yaml:"agent"`
	Name     string   `yaml:"name,omitempty"`
	Category string   `yaml:"category,omitempty"`
	URL      string   `yaml:"url,omitempty"`   // JSON ({"prefixes":[…]} or any JSON with IPs/CIDRs), or text (one per line, comments ok)
	Every    string   `yaml:"every,omitempty"` // refresh interval for url (default: refresh)
	IPs      []string `yaml:"ips,omitempty"`   // typed by hand
	ByIP     *bool    `yaml:"by_ip,omitempty"` // recognise the agent by IP even without its User-Agent (default: only for new agents)
}

// LoadBots reads <dir>/bots/agents.yaml (the last one found wins, or file when set) and applies the policy.
func LoadBots(dirs []string, file string, policy map[string]string) (*BotCatalog, error) {
	return LoadBotsConfig(dirs, BotsConfig{File: file, Policy: policy})
}

// LoadBotsConfig loads the catalog, adds the maintainer's sources and applies the policy.
func LoadBotsConfig(dirs []string, cfg BotsConfig) (*BotCatalog, error) {
	paths := []string{}
	for _, d := range dirs {
		paths = append(paths, filepath.Join(d, "bots", "agents.yaml"))
	}
	if cfg.File != "" {
		if _, err := os.Stat(cfg.File); err != nil {
			return nil, fmt.Errorf("bots.file: %w", err)
		}
		paths = []string{cfg.File}
	}
	var bc *BotCatalog
	for _, f := range paths {
		b, err := readCatalog(f)
		if err != nil {
			continue
		}
		var x BotCatalog
		if err := yaml.Unmarshal(b, &x); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		bc = &x
	}
	if bc == nil {
		return nil, nil
	}
	refresh, err := parseDur(firstNonEmpty(cfg.Refresh, "24h"))
	if err != nil || refresh < time.Hour {
		return nil, fmt.Errorf("bots.refresh %q: a duration of 1h or more", cfg.Refresh)
	}
	bc.byID, bc.uaMemo = map[string]*Agent{}, newMemo[int]()
	for _, a := range bc.Agents {
		if a.ID == "" || bc.byID[a.ID] != nil {
			return nil, fmt.Errorf("agent %q: missing or duplicate id", a.ID)
		}
		bc.byID[a.ID] = a
		if _, ok := bc.Categories[a.Category]; !ok {
			return nil, fmt.Errorf("agent %s: unknown category %q", a.ID, a.Category)
		}
		if a.UA != "" {
			if a.ua, err = compileMatcher(a.UA); err != nil {
				return nil, fmt.Errorf("agent %s: %w", a.ID, err)
			}
		}
		for h, m := range a.Header {
			if a.hdr == nil {
				a.hdr = map[string]*matcher{}
			}
			if a.hdr[strings.ToLower(h)], err = compileMatcher(m); err != nil {
				return nil, fmt.Errorf("agent %s header %s: %w", a.ID, h, err)
			}
		}
		if a.ua == nil && a.hdr == nil {
			return nil, fmt.Errorf("agent %s: needs ua or header", a.ID)
		}
		for _, u := range a.Verify.Ranges {
			a.feeds = append(a.feeds, feed{URL: u, Every: refresh, File: feedFile(a.ID, u)})
		}
	}
	for i, src := range cfg.Sources {
		where := fmt.Sprintf("bots.sources[%d]", i)
		if !validName(src.Agent) {
			return nil, fmt.Errorf("%s: agent %q: letters, digits, - and _", where, src.Agent)
		}
		a := bc.byID[src.Agent]
		if a == nil {
			if _, ok := bc.Categories[src.Category]; !ok {
				return nil, fmt.Errorf("%s: %s is a new agent — give it a category (makit shield bots)", where, src.Agent)
			}
			a = &Agent{ID: src.Agent, Name: firstNonEmpty(src.Name, src.Agent), Category: src.Category, Operator: "your source", ByIP: true}
			bc.Agents = append(bc.Agents, a)
			bc.byID[a.ID] = a
		}
		if src.ByIP != nil {
			a.ByIP = *src.ByIP
		}
		if src.URL != "" {
			if !strings.HasPrefix(src.URL, "https://") && !strings.HasPrefix(src.URL, "http://") {
				return nil, fmt.Errorf("%s: url must be http(s)", where)
			}
			every := refresh
			if src.Every != "" {
				if every, err = parseDur(src.Every); err != nil || every < 5*time.Minute {
					return nil, fmt.Errorf("%s: every %q: a duration of 5m or more", where, src.Every)
				}
			}
			a.feeds = append(a.feeds, feed{URL: src.URL, Every: every, File: feedFile(a.ID, src.URL), Custom: true})
		}
		for _, ip := range src.IPs {
			p, err := ParsePrefix(ip)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			if !botRangeOK(p) {
				return nil, fmt.Errorf("%s: %s is too wide for a bot (narrower than /8 IPv4, /32 IPv6)", where, p)
			}
			a.manual = append(a.manual, p)
		}
	}
	bc.policy = map[string]Act{}
	set := func(k, v, from string) error {
		act, err := ParseAct(v)
		if err != nil {
			return fmt.Errorf("%s %s: %w", from, k, err)
		}
		bc.policy[k] = act
		return nil
	}
	for k, c := range bc.Categories {
		if err := set(k, firstNonEmpty(c.Action, "log"), "category"); err != nil {
			return nil, err
		}
	}
	if err := set("spoofed", firstNonEmpty(bc.Spoofed, "block"), "spoofed"); err != nil {
		return nil, err
	}
	for _, a := range bc.Agents {
		if a.Action != "" {
			if err := set(a.ID, a.Action, "agent"); err != nil {
				return nil, err
			}
		}
	}
	for k, v := range cfg.Policy {
		if _, isCat := bc.Categories[k]; !isCat && k != "spoofed" && bc.byID[k] == nil {
			return nil, fmt.Errorf("bots.policy: %q is not a category, an agent id or spoofed (makit shield bots)", k)
		}
		if err := set(k, v, "bots.policy"); err != nil {
			return nil, err
		}
	}
	return bc, nil
}

// Agent returns the agent with this id (nil if none).
func (bc *BotCatalog) Agent(id string) *Agent { return bc.byID[id] }

// feedFile is the cache file of one URL: bots/<agent>@<hash>.txt.
func feedFile(agent, url string) string {
	h := sha256.Sum256([]byte(url))
	return agent + "@" + hex.EncodeToString(h[:4]) + ".txt"
}

// botRangeOK refuses ranges so wide that a bad feed would turn a large part of the internet into a "verified" bot.
func botRangeOK(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() >= 8
	}
	return p.Bits() >= 32
}

// Identify returns the first agent whose User-Agent or header pattern matches.
func (bc *BotCatalog) Identify(r Request) *Agent {
	first := bc.uaMemo.get(r.UA, func() int {
		lower := strings.ToLower(r.UA)
		for i, a := range bc.Agents {
			if a.ua != nil && a.ua.matchLower(r.UA, lower) {
				return i
			}
		}
		return -1
	})
	if len(r.Headers) > 0 { // header-identified agents (signed AI agents) that come before the UA match
		end := len(bc.Agents)
		if first >= 0 {
			end = first
		}
		for _, a := range bc.Agents[:end] {
			for h, re := range a.hdr {
				if v, ok := r.Headers[h]; ok && re.MatchString(v) {
					return a
				}
			}
		}
	}
	if first >= 0 {
		return bc.Agents[first]
	}
	return nil
}

// PolicyFor is the agent's own policy, else its category's.
func (bc *BotCatalog) PolicyFor(a *Agent) Act {
	if act, ok := bc.policy[a.ID]; ok {
		return act
	}
	return bc.policy[a.Category]
}

func (bc *BotCatalog) Policy(key string) (Act, bool) {
	a, ok := bc.policy[key]
	return a, ok
}

// Bot is what a decision says about the client as a bot.
type Bot struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name,omitempty"`
	Category string   `json:"category,omitempty"`
	Status   string   `json:"status,omitempty"` // verified, claimed, pending, unknown, spoofed; "undeclared" for the bot score
	Action   string   `json:"action,omitempty"`
	Score    int      `json:"score,omitempty"`
	Level    string   `json:"level,omitempty"`
	Signals  []string `json:"signals,omitempty"` // bot score signals
}

// ── verification ──

type verdict struct {
	status  string
	at      time.Time
	recheck bool // DNS gave no answer: asked again after 10 minutes, not 24 hours
}

// Verifier checks claimed identities: published IP ranges first, then forward-confirmed reverse DNS. DNS runs in the
// background (Sync for log analysis) so a request never waits; until it finishes the identity is "pending".
type Verifier struct {
	mu         sync.Mutex
	cache      map[string]verdict
	ranges     map[string]*Set // agent id → published, maintainer and typed ranges
	byIP       *Set            // agents recognised by IP alone (Entry.Source = agent id)
	inflight   map[string]bool
	Sync       bool
	LookupAddr func(ctx context.Context, ip string) ([]string, error)
	LookupIP   func(ctx context.Context, host string) ([]net.IP, error)
}

func NewVerifier() *Verifier {
	return &Verifier{cache: map[string]verdict{}, inflight: map[string]bool{}, ranges: map[string]*Set{},
		LookupAddr: net.DefaultResolver.LookupAddr,
		LookupIP: func(ctx context.Context, h string) ([]net.IP, error) {
			return net.DefaultResolver.LookupIP(ctx, "ip", h)
		}}
}

func botsDir() string { return filepath.Join(StateDir, "bots") }

// LoadRanges reads every agent's cached feeds and typed IPs into one set per agent, plus one index of the agents
// recognised by IP alone. Both are hash-per-prefix-length sets: lookups stay fast with millions of entries.
func (v *Verifier) LoadRanges(bc *BotCatalog) {
	m, idx := map[string]*Set{}, NewSet()
	for _, a := range bc.Agents {
		ps := append([]netip.Prefix(nil), a.manual...)
		for _, f := range a.feeds {
			got, _ := ReadPrefixes(filepath.Join(botsDir(), f.File))
			for _, p := range got {
				if botRangeOK(p) {
					ps = append(ps, p)
				}
			}
		}
		if len(ps) == 0 {
			continue
		}
		s := NewSet()
		s.AddMany(ps, time.Time{}, "", "bot:"+a.ID)
		m[a.ID] = s
		if a.ByIP {
			idx.AddMany(ps, time.Time{}, "", a.ID)
		}
	}
	v.mu.Lock()
	v.ranges, v.byIP = m, idx
	v.mu.Unlock()
}

// ByIP returns the id of the agent (recognised by IP) that owns this address, or "".
func (v *Verifier) ByIP(ip netip.Addr, now time.Time) string {
	v.mu.Lock()
	idx := v.byIP
	v.mu.Unlock()
	if idx == nil {
		return ""
	}
	if e, ok := idx.Match(ip, now); ok {
		return e.Source
	}
	return ""
}

// RangeCount is the number of prefixes loaded for an agent.
func (v *Verifier) RangeCount(id string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	if s := v.ranges[id]; s != nil {
		return s.Len()
	}
	return 0
}

// Check returns verified, claimed, pending, unknown or spoofed.
func (v *Verifier) Check(a *Agent, ip netip.Addr, now time.Time) string {
	if !a.Verifiable() {
		return "claimed"
	}
	v.mu.Lock()
	rs := v.ranges[a.ID]
	v.mu.Unlock()
	if rs != nil {
		if _, ok := rs.Match(ip, now); ok {
			return "verified"
		}
		if len(a.Verify.RDNS) == 0 {
			return "spoofed" // ranges known, IP outside them
		}
	}
	if len(a.Verify.RDNS) == 0 {
		return "unknown" // ranges not downloaded yet (makit shield bots update)
	}
	key := a.ID + "|" + ip.String()
	v.mu.Lock()
	if c, ok := v.cache[key]; ok && (!c.recheck && now.Sub(c.at) < 24*time.Hour || now.Sub(c.at) < 10*time.Minute) {
		v.mu.Unlock()
		return c.status
	}
	ranged := rs != nil
	if v.Sync {
		v.mu.Unlock()
		st, recheck := v.settle(a, ip, ranged)
		v.store(key, verdict{st, now, recheck})
		return st
	}
	if !v.inflight[key] && len(v.inflight) < 256 {
		v.inflight[key] = true
		go func() {
			st, recheck := v.settle(a, ip, ranged)
			v.store(key, verdict{st, time.Now(), recheck})
			v.mu.Lock()
			delete(v.inflight, key)
			v.mu.Unlock()
		}()
	}
	v.mu.Unlock()
	return "pending"
}

// settle runs the DNS check. Reverse DNS only rescues an address outside the operator's published ranges (a list a
// day old may miss a new one); when DNS gives no answer — a timeout, SERVFAIL, the resolver down — nothing rescues
// it and the ranges' answer stands: spoofed. Otherwise a fake Googlebot whose own reverse zone never answers (its
// operator chooses that) would stay "unknown" and pass the spoofed policy. Either way it is asked again in 10 minutes.
func (v *Verifier) settle(a *Agent, ip netip.Addr, ranged bool) (string, bool) {
	st := v.rdns(a, ip)
	if st != "unknown" {
		return st, false
	}
	if ranged && v.LookupAddr != nil {
		return "spoofed", true
	}
	return st, true
}

func (v *Verifier) store(key string, vd verdict) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) > 100000 {
		for k, c := range v.cache {
			if vd.at.Sub(c.at) > time.Hour {
				delete(v.cache, k)
			}
		}
	}
	v.cache[key] = vd
}

// rdns: the PTR name must end in an operator domain and resolve back to the same IP.
func (v *Verifier) rdns(a *Agent, ip netip.Addr) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if v.LookupAddr == nil { // verification by DNS switched off
		return "unknown"
	}
	names, err := v.LookupAddr(ctx, ip.String())
	if err != nil {
		var de *net.DNSError
		if errors.As(err, &de) && de.IsNotFound {
			return "spoofed" // real crawlers of these operators always have PTR records
		}
		return "unknown"
	}
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(n), ".")
		for _, dom := range a.Verify.RDNS {
			if n != dom && !strings.HasSuffix(n, "."+dom) {
				continue
			}
			ips, err := v.LookupIP(ctx, n)
			if err != nil {
				return "unknown"
			}
			for _, x := range ips {
				if xa, ok := netip.AddrFromSlice(x); ok && xa.Unmap() == ip {
					return "verified"
				}
			}
		}
	}
	return "spoofed"
}

// ── rate limits ──

// Limiter counts requests per key in fixed windows (bounded).
type Limiter struct {
	mu sync.Mutex
	m  map[string]*window
	// With a cluster, the requests counted here since the last sync are kept for the other replicas (out), and
	// theirs are added to each window (remote): limit 60/1m holds across every replica, not per replica.
	share bool
	dirty []string // keys whose window has unsent counts
}

// window is a fixed window aligned on the clock (now / duration), so every replica counts into the same one.
type window struct {
	idx       int64
	end       time.Time
	dur       time.Duration
	n, remote int
	unsent    int // counted here, not sent to the other replicas yet
}

// LimitDelta is a count of requests in one window of one limit key, exchanged between replicas.
type LimitDelta struct {
	Key string        `json:"k"`
	Idx int64         `json:"w"`
	Dur time.Duration `json:"d"`
	N   int           `json:"n,omitempty"`
}

func NewLimiter() *Limiter { return &Limiter{m: map[string]*window{}} }

// Share starts keeping local counts for TakeDeltas.
func (l *Limiter) Share() {
	l.mu.Lock()
	l.share = true
	l.mu.Unlock()
}

func windowOf(now time.Time, dur time.Duration) (int64, time.Time) {
	if dur <= 0 {
		dur = time.Second
	}
	idx := now.UnixNano() / int64(dur)
	return idx, time.Unix(0, (idx+1)*int64(dur))
}

// cur returns key's window for idx, starting a new one when the old one is over. Call with mu held.
func (l *Limiter) cur(key string, idx int64, end, now time.Time, dur time.Duration) *window {
	w := l.m[key]
	if w == nil || w.idx < idx {
		if w == nil && len(l.m) >= 200000 {
			for k, x := range l.m {
				if now.After(x.end) {
					delete(l.m, k)
				}
			}
		}
		w = &window{idx: idx, end: end, dur: dur}
		l.m[key] = w
	}
	return w
}

// Allow counts one request and reports whether it is within the limit (counting the other replicas' requests too).
func (l *Limiter) Allow(key string, act Act, now time.Time) bool {
	idx, end := windowOf(now, act.Dur)
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.cur(key, idx, end, now, act.Dur)
	if w.idx > idx {
		return true // a request older than the window in force (clock skew between replicas): not counted
	}
	w.n++
	if l.share {
		if w.unsent == 0 {
			l.dirty = append(l.dirty, key)
		}
		w.unsent++
	}
	return w.n+w.remote <= act.N
}

// TakeDeltas returns the local counts since the last call and starts over.
func (l *Limiter) TakeDeltas() []LimitDelta {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LimitDelta, 0, len(l.dirty))
	for _, k := range l.dirty {
		if w := l.m[k]; w != nil && w.unsent > 0 {
			out = append(out, LimitDelta{Key: k, Idx: w.idx, Dur: w.dur, N: w.unsent})
			w.unsent = 0
		}
	}
	l.dirty = l.dirty[:0]
	return out
}

// Merge adds another replica's counts; counts for a window that is already over are dropped.
func (l *Limiter) Merge(ds []LimitDelta, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range ds {
		idx, end := windowOf(now, d.Dur)
		if d.Idx != idx || d.N <= 0 {
			continue
		}
		w := l.cur(d.Key, idx, end, now, d.Dur)
		if w.idx == idx {
			w.remote += d.N
		}
	}
}

// ── published ranges ──

// FeedStatus is the last download of one feed (bots/status.json).
type FeedStatus struct {
	Agent   string    `json:"agent"`
	URL     string    `json:"url"`
	Count   int       `json:"count"`
	Skipped int       `json:"skipped,omitempty"` // entries refused (too wide, unparsable)
	OK      time.Time `json:"ok,omitempty"`
	Tried   time.Time `json:"tried"`
	Error   string    `json:"error,omitempty"`
}

func readFeedStatus() map[string]FeedStatus {
	m := map[string]FeedStatus{}
	if b, err := os.ReadFile(filepath.Join(botsDir(), "status.json")); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

var refreshMu sync.Mutex

// RefreshBotRanges downloads the feeds that are due (all of them with force, or only one agent's with only) and
// reports what changed. A failed download keeps the previous file and is retried after an hour.
func RefreshBotRanges(bc *BotCatalog, force bool, only string) ([]FeedStatus, error) {
	refreshMu.Lock()
	defer refreshMu.Unlock()
	if err := os.MkdirAll(botsDir(), 0o755); err != nil {
		return nil, err
	}
	status := readFeedStatus()
	cl := &http.Client{Timeout: 60 * time.Second}
	now := time.Now()
	var done []FeedStatus
	for _, a := range bc.Agents {
		if only != "" && a.ID != only {
			continue
		}
		for _, f := range a.feeds {
			st := status[f.File]
			path := filepath.Join(botsDir(), f.File)
			if !force {
				info, err := os.Stat(path)
				if err == nil && now.Sub(info.ModTime()) < f.Every {
					continue // fresh
				}
				if st.Error != "" && now.Sub(st.Tried) < time.Hour {
					continue // failed recently
				}
			}
			st.Agent, st.URL, st.Tried, st.Error = a.ID, f.URL, now, ""
			ps, skipped, err := fetchRanges(cl, f.URL)
			if err == nil && len(ps) == 0 {
				err = fmt.Errorf("no IPs or ranges found")
			}
			if err == nil {
				err = writePrefixes(path, f.URL, ps)
			}
			if err != nil {
				st.Error = err.Error()
			} else {
				st.Count, st.Skipped, st.OK = len(ps), skipped, now
			}
			status[f.File] = st
			done = append(done, st)
		}
	}
	if len(done) > 0 {
		b, _ := json.MarshalIndent(status, "", "  ")
		_ = os.WriteFile(filepath.Join(botsDir(), "status.json"), b, 0o644)
	}
	return done, nil
}

// UpdateBotRanges downloads every feed now.
func UpdateBotRanges(bc *BotCatalog) (map[string]int, []error) {
	out, errs := map[string]int{}, []error(nil)
	done, err := RefreshBotRanges(bc, true, "")
	if err != nil {
		return out, []error{err}
	}
	for _, st := range done {
		if st.Error != "" {
			errs = append(errs, fmt.Errorf("%s %s: %s", st.Agent, st.URL, st.Error))
			continue
		}
		out[st.Agent] += st.Count
	}
	return out, errs
}

func writePrefixes(path, src string, ps []netip.Prefix) error {
	f, err := os.Create(path + ".tmp")
	if err != nil {
		return err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	fmt.Fprintf(w, "# %s — %s\n", src, time.Now().UTC().Format(time.RFC3339))
	for _, p := range ps {
		w.WriteString(p.String())
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func fetchRanges(cl *http.Client, u string) ([]netip.Prefix, int, error) {
	res, err := cl.Get(u)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, 0, fmt.Errorf("%s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 256<<20))
	if err != nil {
		return nil, 0, err
	}
	ps, skipped := parseRanges(b)
	return ps, skipped, nil
}

// parseRanges accepts the common JSON shape ({"prefixes":[{"ipv4Prefix":…}]}), any JSON holding IP/CIDR strings, or
// text with one or more IPs/CIDRs per line (comments after # or ; and CSV columns are fine). Ranges wider than /8
// (IPv4) or /32 (IPv6) are skipped and counted.
func parseRanges(b []byte) ([]netip.Prefix, int) {
	var out []netip.Prefix
	skipped := 0
	add := func(tok string) {
		p, err := ParsePrefix(tok)
		if err != nil {
			return
		}
		if !botRangeOK(p) {
			skipped++
			return
		}
		out = append(out, p)
	}
	var walk func(x any)
	walk = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, v := range t {
				walk(v)
			}
		case []any:
			for _, v := range t {
				walk(v)
			}
		case string:
			add(t)
		}
	}
	var j any
	if bytes.HasPrefix(bytes.TrimSpace(b), []byte("{")) || bytes.HasPrefix(bytes.TrimSpace(b), []byte("[")) {
		if json.Unmarshal(b, &j) == nil {
			walk(j)
			return dedupe(out), skipped
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		for _, tok := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\r' || r == '"' }) {
			add(tok)
		}
	}
	return dedupe(out), skipped
}

func dedupe(ps []netip.Prefix) []netip.Prefix {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
	out := ps[:0]
	for i, p := range ps {
		if i == 0 || p != ps[i-1] {
			out = append(out, p)
		}
	}
	return out
}

// Robots builds robots.txt groups that disallow every agent (and category token) whose policy blocks or bans it.
func (bc *BotCatalog) Robots() string {
	var b strings.Builder
	tokens := map[string]bool{}
	var order []string
	add := func(t string) {
		if t != "" && !tokens[t] {
			tokens[t] = true
			order = append(order, t)
		}
	}
	for _, a := range bc.Agents {
		if k := bc.PolicyFor(a).Kind; (k == "block" || k == "ban") && a.Robots != "" {
			add(a.Robots)
		}
	}
	cats := make([]string, 0, len(bc.RobotsTokens))
	for c := range bc.RobotsTokens {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		if k := bc.policy[c].Kind; k == "block" || k == "ban" {
			for _, t := range bc.RobotsTokens[c] {
				add(t)
			}
		}
	}
	if len(order) == 0 {
		return "# makit: no bot is blocked by policy — nothing to disallow\n"
	}
	b.WriteString("# Generated by `makit shield bots robots` from the bot policy. Polite crawlers stop here;\n# makit still blocks the ones that ignore robots.txt.\n")
	for _, t := range order {
		fmt.Fprintf(&b, "User-agent: %s\n", t)
	}
	b.WriteString("Disallow: /\n")
	return b.String()
}

// FeedStatuses is the last download of every bot IP feed, by cache file name (see FeedFile).
func FeedStatuses() map[string]FeedStatus { return readFeedStatus() }

// FeedFile is the cache file name of an agent's feed URL.
func FeedFile(agent, url string) string { return feedFile(agent, url) }
