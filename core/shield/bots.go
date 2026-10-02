package shield

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
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
	URL      string            `yaml:"url" json:"url,omitempty"`
	Verify   struct {
		RDNS   []string `yaml:"rdns" json:"rdns,omitempty"`
		Ranges []string `yaml:"ranges" json:"ranges,omitempty"`
	} `yaml:"verify" json:"verify"`
	ua  *regexp.Regexp
	hdr map[string]*regexp.Regexp
}

func (a *Agent) Verifiable() bool { return len(a.Verify.RDNS) > 0 || len(a.Verify.Ranges) > 0 }

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
	RobotsTokens map[string][]string    `yaml:"robots_tokens"`
	Agents       []*Agent               `yaml:"agents"`
	policy       map[string]Act         // effective: category ids, agent ids and "spoofed"
}

// BotsConfig is shield.yaml → bots:.
type BotsConfig struct {
	Enabled   *bool             `yaml:"enabled"`
	Policy    map[string]string `yaml:"policy"`     // category, agent id or "spoofed" → action
	Verify    *bool             `yaml:"verify"`     // reverse-DNS checks (default on)
	File      string            `yaml:"file"`       // your own agents file instead of the catalog's (same format)
	Score     ScoringOverrides  `yaml:"score"`      // bot score: enabled, actions per level, disable
	ScoreFile string            `yaml:"score_file"` // your own bot scoring file (same format as scoring/bots.yaml)
}

// LoadBots reads <dir>/bots/agents.yaml (the last one found wins, or file when set) and applies the policy.
func LoadBots(dirs []string, file string, policy map[string]string) (*BotCatalog, error) {
	paths := []string{}
	for _, d := range dirs {
		paths = append(paths, filepath.Join(d, "bots", "agents.yaml"))
	}
	if file != "" {
		if _, err := os.Stat(file); err != nil {
			return nil, fmt.Errorf("bots.file: %w", err)
		}
		paths = []string{file}
	}
	var bc *BotCatalog
	for _, f := range paths {
		b, err := os.ReadFile(f)
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
	seen := map[string]bool{}
	for _, a := range bc.Agents {
		if a.ID == "" || seen[a.ID] {
			return nil, fmt.Errorf("agent %q: missing or duplicate id", a.ID)
		}
		seen[a.ID] = true
		if _, ok := bc.Categories[a.Category]; !ok {
			return nil, fmt.Errorf("agent %s: unknown category %q", a.ID, a.Category)
		}
		var err error
		if a.UA != "" {
			if a.ua, err = regexp.Compile(a.UA); err != nil {
				return nil, fmt.Errorf("agent %s: %w", a.ID, err)
			}
		}
		for h, m := range a.Header {
			if a.hdr == nil {
				a.hdr = map[string]*regexp.Regexp{}
			}
			if a.hdr[strings.ToLower(h)], err = regexp.Compile(m); err != nil {
				return nil, fmt.Errorf("agent %s header %s: %w", a.ID, h, err)
			}
		}
		if a.ua == nil && a.hdr == nil {
			return nil, fmt.Errorf("agent %s: needs ua or header", a.ID)
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
	for k, v := range policy {
		if _, isCat := bc.Categories[k]; !isCat && k != "spoofed" && !seen[k] {
			return nil, fmt.Errorf("bots.policy: %q is not a category, an agent id or spoofed (makit shield bots)", k)
		}
		if err := set(k, v, "bots.policy"); err != nil {
			return nil, err
		}
	}
	return bc, nil
}

// Identify returns the first agent whose User-Agent or header pattern matches.
func (bc *BotCatalog) Identify(r Request) *Agent {
	for _, a := range bc.Agents {
		if a.ua != nil && a.ua.MatchString(r.UA) {
			return a
		}
		for h, re := range a.hdr {
			if v, ok := r.Headers[h]; ok && re.MatchString(v) {
				return a
			}
		}
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
	status string
	at     time.Time
}

// Verifier checks claimed identities: published IP ranges first, then forward-confirmed reverse DNS. DNS runs in the
// background (Sync for log analysis) so a request never waits; until it finishes the identity is "pending".
type Verifier struct {
	mu         sync.Mutex
	cache      map[string]verdict
	ranges     map[string]*Set // agent id → published ranges
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

// LoadRanges reads the cached ranges of every agent (bots/<id>.txt).
func (v *Verifier) LoadRanges(bc *BotCatalog) {
	m := map[string]*Set{}
	for _, a := range bc.Agents {
		if len(a.Verify.Ranges) == 0 {
			continue
		}
		ps, err := ReadPrefixes(filepath.Join(botsDir(), a.ID+".txt"))
		if err != nil || len(ps) == 0 {
			continue
		}
		s := NewSet()
		s.AddMany(ps, time.Time{}, "", "bot:"+a.ID)
		m[a.ID] = s
	}
	v.mu.Lock()
	v.ranges = m
	v.mu.Unlock()
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
	if c, ok := v.cache[key]; ok && (c.status != "unknown" && now.Sub(c.at) < 24*time.Hour || now.Sub(c.at) < 10*time.Minute) {
		v.mu.Unlock()
		return c.status
	}
	if v.Sync {
		v.mu.Unlock()
		st := v.rdns(a, ip)
		v.store(key, st, now)
		return st
	}
	if !v.inflight[key] && len(v.inflight) < 256 {
		v.inflight[key] = true
		go func() {
			st := v.rdns(a, ip)
			v.store(key, st, time.Now())
			v.mu.Lock()
			delete(v.inflight, key)
			v.mu.Unlock()
		}()
	}
	v.mu.Unlock()
	return "pending"
}

func (v *Verifier) store(key, st string, at time.Time) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.cache) > 100000 {
		for k, c := range v.cache {
			if at.Sub(c.at) > time.Hour {
				delete(v.cache, k)
			}
		}
	}
	v.cache[key] = verdict{st, at}
}

// rdns: the PTR name must end in an operator domain and resolve back to the same IP.
func (v *Verifier) rdns(a *Agent, ip netip.Addr) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
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
}

type window struct {
	start time.Time
	n     int
}

func NewLimiter() *Limiter { return &Limiter{m: map[string]*window{}} }

// Allow counts one request and reports whether it is within the limit.
func (l *Limiter) Allow(key string, act Act, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.m[key]
	if w == nil || now.Sub(w.start) >= act.Dur {
		if w == nil && len(l.m) >= 200000 {
			for k, x := range l.m {
				if now.Sub(x.start) > time.Hour {
					delete(l.m, k)
				}
			}
		}
		w = &window{start: now}
		l.m[key] = w
	}
	w.n++
	return w.n <= act.N
}

// ── published ranges ──

// UpdateBotRanges downloads every agent's published ranges into the state directory.
func UpdateBotRanges(bc *BotCatalog) (map[string]int, []error) {
	out, errs := map[string]int{}, []error(nil)
	if err := os.MkdirAll(botsDir(), 0o755); err != nil {
		return out, []error{err}
	}
	cl := &http.Client{Timeout: 20 * time.Second}
	for _, a := range bc.Agents {
		if len(a.Verify.Ranges) == 0 {
			continue
		}
		var lines []string
		var failed error
		for _, u := range a.Verify.Ranges {
			ps, err := fetchRanges(cl, u)
			if err != nil {
				failed = fmt.Errorf("%s: %w", a.ID, err)
				break
			}
			lines = append(lines, ps...)
		}
		if failed != nil || len(lines) == 0 {
			if failed == nil {
				failed = fmt.Errorf("%s: no ranges found", a.ID)
			}
			errs = append(errs, failed) // keep the previous file
			continue
		}
		path := filepath.Join(botsDir(), a.ID+".txt")
		body := "# " + strings.Join(a.Verify.Ranges, " ") + " — " + time.Now().UTC().Format(time.RFC3339) + "\n" + strings.Join(lines, "\n") + "\n"
		if err := os.WriteFile(path+".tmp", []byte(body), 0o644); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			errs = append(errs, err)
			continue
		}
		out[a.ID] = len(lines)
	}
	return out, errs
}

func fetchRanges(cl *http.Client, u string) ([]string, error) {
	res, err := cl.Get(u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", u, res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	return parseRanges(b), nil
}

// parseRanges accepts the common JSON shape ({"prefixes":[{"ipv4Prefix":…}]}), any JSON holding CIDR strings, or
// plain lines.
func parseRanges(b []byte) []string {
	var out []string
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
			if p, err := ParsePrefix(t); err == nil && strings.Contains(t, "/") {
				out = append(out, p.String())
			}
		}
	}
	var j any
	if json.Unmarshal(b, &j) == nil {
		walk(j)
	} else {
		for _, l := range strings.Fields(string(b)) {
			if p, err := ParsePrefix(l); err == nil {
				out = append(out, p.String())
			}
		}
	}
	sort.Strings(out)
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
