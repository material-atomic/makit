package shield

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// Request is what a reverse proxy tells the gate about one request.
type Request struct {
	Peer     string // the address the request reached the last proxy from (the asking proxy's own hop)
	Client   string // the forwarding chain before Peer (X-Forwarded-For, Forwarded), else X-Real-IP
	Method   string
	Host     string
	URI      string
	UA       string
	Referer  string
	Country  string            // CF-IPCountry
	Ray      string            // CF-Ray
	Headers  map[string]string // lower-cased request headers (for rules)
	Raw      string            // original request line when known (log analysis)
	Received time.Time
	Status   int // response status, known when analysing logs (0 live)
}

type Decision struct {
	Client  string   `json:"client"`
	Peer    string   `json:"peer"`
	Via     string   `json:"via,omitempty"` // trusted proxy that supplied the client IP
	Allow   bool     `json:"allow"`
	Verdict string   `json:"verdict"` // allowed, allowlisted, blocked, would-block (observe), invalid
	Rule    string   `json:"rule,omitempty"`
	Reason  string   `json:"reason,omitempty"`
	Score   int      `json:"score,omitempty"`   // request score; IP score when higher
	Level   string   `json:"level,omitempty"`   // normal, low, medium, high, critical
	Signals []string `json:"signals,omitempty"` // matched scoring signals
	Bot     *Bot     `json:"bot,omitempty"`     // known bot, or the bot score of an undeclared client
	Status  int      `json:"status,omitempty"`  // HTTP status for a denial when not 403 (429 for limits)
	Site    string   `json:"site,omitempty"`    // the site (sites: in shield.yaml) whose policy decided
}

// Policy holds everything a decision needs.
type Policy struct {
	Observe bool           // log what would be blocked, block nothing
	Pass    bool           // shield off: allow everything (keeps proxies working)
	Trusted []netip.Prefix // proxies whose client-IP header is believed (Cloudflare, your load balancer)
	Allow   *Set
	Block   *Set // manual and automatic bans (state.json)
	Lists   *Set // bulk lists (lists/*.txt), may hold millions
	Rules   []HTTPRule
	Scoring *Scoring
	Tracker *Tracker
	// Ban records an automatic ban (rules, scores, bots). site is where it happened; scoped makes it apply to that
	// site only (ban_scope: site) instead of the whole server.
	Ban func(addr netip.Addr, d time.Duration, source, reason, site string, scoped bool)

	Bots       *BotCatalog // known bots and the maintainer's policy for them
	BotScore   *Scoring    // bot score for undeclared clients
	BotTracker *Tracker
	Verifier   *Verifier
	Limiter    *Limiter

	// Sites: the global policy holds one policy per site, built at load time; a request is decided by the site its
	// Host matches, or by the global policy.
	Site       string // this policy's site ("" = global)
	SiteScoped bool   // ban_scope: site
	SiteAllow  *Set   // this site's own allowlist (on top of Allow)
	SiteBlock  *Set   // this site's own bans (on top of Block)
	sites      []*Policy
	exact      map[string]*Policy
	wild       []wildSite
	siteSets   map[string]*Set // site → its bans set (shared with the site policies, for automatic bans)
}

type wildSite struct {
	suffix string // ".example.com"
	p      *Policy
}

// ForHost returns the policy of the site that host belongs to (port and case ignored), or p itself.
func (p *Policy) ForHost(host string) *Policy {
	if len(p.sites) == 0 || host == "" {
		return p
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if sp := p.exact[host]; sp != nil {
		return sp
	}
	for _, w := range p.wild { // longest suffix first
		if strings.HasSuffix(host, w.suffix) {
			return w.p
		}
	}
	return p
}

// Sites lists the site policies.
func (p *Policy) Sites() []*Policy { return p.sites }

// SiteBlockSet is the set holding a site's own bans (nil for an unknown site).
func (p *Policy) SiteBlockSet(site string) *Set { return p.siteSets[site] }

// siteAllowSet is a site's own allowlist (nil for an unknown site).
func (p *Policy) siteAllowSet(site string) *Set {
	for _, sp := range p.sites {
		if sp.Site == site {
			return sp.SiteAllow
		}
	}
	return nil
}

// Share hands the global policy's per-process parts (trackers, verifier, limiter, ban function) to every site.
// Call it after setting them.
func (p *Policy) Share() {
	for _, sp := range p.sites {
		sp.Tracker, sp.BotTracker, sp.Verifier, sp.Limiter, sp.Ban = p.Tracker, p.BotTracker, p.Verifier, p.Limiter, p.Ban
		sp.Block, sp.Lists, sp.Trusted = p.Block, p.Lists, p.Trusted
	}
}

func (p *Policy) trusted(a netip.Addr) bool {
	for _, t := range p.Trusted {
		if t.Contains(a) {
			return true
		}
	}
	return false
}

// firstIP takes the left-most valid IP of a header value ("1.2.3.4, 5.6.7.8" or "[::1]:443").
func firstIP(v string) (netip.Addr, bool) {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return parseHop(v)
}

// parseHop parses one address of a forwarding chain: "1.2.3.4", "1.2.3.4:5678", "2001:db8::1" or "[2001:db8::1]:443".
// It picks the form before parsing, so the common case (a bare address) never builds an error value.
func parseHop(v string) (netip.Addr, bool) {
	v = strings.TrimSpace(v)
	withPort := false
	switch {
	case strings.HasPrefix(v, "["):
		withPort = strings.Contains(v, "]:")
		if !withPort {
			v = strings.TrimSuffix(v[1:], "]")
		}
	case strings.Count(v, ":") == 1:
		withPort = true // IPv4 with a port; a bare IPv6 address has at least two colons
	}
	if withPort {
		ap, err := netip.ParseAddrPort(v)
		return ap.Addr().Unmap(), err == nil
	}
	a, err := netip.ParseAddr(v)
	return a.Unmap(), err == nil
}

// maxHops bounds the walk through a forwarding chain: real chains are a handful of proxies long.
const maxHops = 16

// clientIP resolves the visitor behind a trusted proxy. Each proxy appends the address it received the request from,
// so a chain such as X-Forwarded-For is read from the right: trusted proxies are skipped and the first address that
// is not one is the visitor. Everything to its left was written by the visitor and is never believed — a client
// cannot pick its own IP by sending the header. A single address (X-Real-IP) is the same walk of one.
// The header counts only when the peer itself is a trusted proxy; from anyone else the peer is the client.
func (p *Policy) clientIP(peer netip.Addr, header string) (client netip.Addr, viaProxy bool) {
	if header == "" || !p.trusted(peer) {
		return peer, false
	}
	client = peer
	for hops, rest := 0, header; rest != "" && hops < maxHops; hops++ {
		hop := rest
		if i := strings.LastIndexByte(rest, ','); i >= 0 {
			hop, rest = rest[i+1:], rest[:i]
		} else {
			rest = ""
		}
		a, ok := parseHop(hop)
		if !ok {
			break // garbage written by a proxy we trust: stop at the last address it vouched for
		}
		client, viaProxy = a, true
		if !p.trusted(a) {
			break
		}
	}
	return client, viaProxy
}

// Decide picks the policy of the request's site, then applies, in order: client IP resolution (header only from
// trusted proxies) → allowlists → bans and lists → known bots (verified + allow skips the rest) → HTTP rules →
// attack score → bot score for undeclared clients.
func (p *Policy) Decide(r Request) Decision {
	sp := p.ForHost(r.Host)
	d := sp.decide(r)
	d.Site = sp.Site
	return d
}

func (p *Policy) decide(r Request) Decision {
	peer, ok := firstIP(r.Peer)
	if !ok {
		return Decision{Allow: true, Verdict: "invalid", Reason: "no peer address (check the proxy snippet)", Peer: r.Peer}
	}
	client, via := peer, ""
	if c, ok := p.clientIP(peer, r.Client); ok {
		client, via = c, peer.String()
	}
	d := Decision{Client: client.String(), Peer: peer.String(), Via: via, Allow: true, Verdict: "allowed"}
	if p.Pass {
		return d
	}
	now := r.Received
	if now.IsZero() {
		now = time.Now()
	}
	for _, al := range []*Set{p.Allow, p.SiteAllow} {
		if al == nil {
			continue
		}
		if e, ok := al.Match(client, now); ok {
			d.Verdict, d.Reason = "allowlisted", e.Prefix.String()
			return d
		}
	}
	block := func(rule, reason string) Decision {
		d.Rule, d.Reason = rule, reason
		if p.Observe {
			d.Verdict = "would-block"
			return d
		}
		d.Allow, d.Verdict = false, "blocked"
		return d
	}
	// apply enforces a policy action; it reports whether the request is denied.
	apply := func(act Act, rule, reason, limitKey string) (Decision, bool) {
		switch act.Kind {
		case "block":
			return block(rule, reason), true
		case "ban":
			// A trusted proxy is never banned: it carries every visitor behind it (only its own requests are blocked).
			if p.Ban != nil && !p.Observe && !p.trusted(client) {
				p.Ban(client, act.Dur, rule, reason, p.Site, p.SiteScoped)
			}
			return block(rule, reason), true
		case "limit":
			if p.Limiter == nil || p.Limiter.Allow(p.Site+"|"+limitKey, act, now) {
				return d, false
			}
			d.Rule, d.Reason = rule, fmt.Sprintf("over %s", act)
			if p.Observe {
				d.Verdict = "would-limit"
				return d, true
			}
			d.Allow, d.Verdict, d.Status = false, "limited", 429
			return d, true
		}
		return d, false
	}
	// The peer itself (a direct client, or a proxy you banned) is checked too.
	for _, a := range []netip.Addr{client, peer} {
		if e, ok := p.Block.Match(a, now); ok {
			return block(e.Source, e.Prefix.String()+" "+e.Reason)
		}
		if p.SiteBlock != nil {
			if e, ok := p.SiteBlock.Match(a, now); ok {
				return block(e.Source, e.Prefix.String()+" "+e.Reason+" (this site)")
			}
		}
		if p.Lists != nil {
			if e, ok := p.Lists.Match(a, now); ok {
				return block(e.Source, e.Prefix.String()+" "+e.Reason)
			}
		}
	}
	if p.Bots != nil {
		a, st := p.Bots.Identify(r), "claimed"
		if a == nil && p.Verifier != nil { // no bot User-Agent: maybe an IP from your own bot sources
			if id := p.Verifier.ByIP(client, now); id != "" {
				a, st = p.Bots.Agent(id), "verified"
			}
		}
		if a != nil {
			if st != "verified" && a.Verifiable() {
				st = "unknown"
				if p.Verifier != nil {
					st = p.Verifier.Check(a, client, now)
				}
			}
			act, rule, key := p.Bots.PolicyFor(a), "bot:"+a.ID, "agent:"+a.ID
			if st == "spoofed" {
				act, _ = p.Bots.Policy("spoofed")
				rule, key = "bot:spoofed", "spoofed:"+client.String()
			}
			d.Bot = &Bot{ID: a.ID, Name: a.Name, Category: a.Category, Status: st, Action: act.String()}
			if st == "verified" && act.Kind == "allow" {
				d.Verdict = "bot-verified" // the real crawler: no rules, no scores (it follows any link it finds)
				return d
			}
			reason := fmt.Sprintf("%s (%s, %s)", a.Name, a.Category, st)
			if res, done := apply(act, rule, reason, key); done {
				return res
			}
		}
	}
	lowerURI := ""
	if len(p.Rules) > 0 {
		lowerURI = strings.ToLower(r.URI)
	}
	for i := range p.Rules {
		rule := &p.Rules[i] // not a copy: a rule is a few hundred bytes, copied per rule per request
		if rule.match(r, lowerURI) {
			if rule.BanFor > 0 && p.Ban != nil && !p.Observe && !p.trusted(client) {
				p.Ban(client, rule.BanFor, "rule:"+rule.ID, rule.Title, p.Site, p.SiteScoped)
			}
			return block("rule:"+rule.ID, rule.Title)
		}
	}
	q := newScored(&r, r.Status) // decoded fields, shared by the attack score and the bot score
	if p.Scoring != nil {
		score, hits := p.Scoring.score(q)
		if p.Tracker != nil {
			ipScore, bursts := p.Tracker.ObserveIn(p.trackSite(), client, score, hits, r.Status, now)
			hits = append(hits, bursts...)
			score = max(score, ipScore)
		}
		d.Score, d.Level, d.Signals = score, p.Scoring.Level(score), hits
		if d.Level != "normal" {
			if res, done := apply(p.Scoring.Act(d.Level), "score:"+d.Level, fmt.Sprintf("score %d: %s", score, strings.Join(hits, " ")), "score:"+client.String()); done {
				return res
			}
		}
	}
	if p.BotScore != nil && d.Bot == nil {
		score, hits := p.BotScore.score(q)
		if p.BotTracker != nil {
			ipScore, bursts := p.BotTracker.ObserveIn(p.trackSite(), client, score, hits, r.Status, now)
			hits = append(hits, bursts...)
			score = max(score, ipScore)
		}
		if lvl := p.BotScore.Level(score); lvl != "normal" {
			act := p.BotScore.Act(lvl)
			d.Bot = &Bot{Status: "undeclared", Score: score, Level: lvl, Action: act.String(), Signals: hits}
			if res, done := apply(act, "bot-score:"+lvl, fmt.Sprintf("bot score %d: %s", score, strings.Join(hits, " ")), "botscore:"+client.String()); done {
				return res
			}
		}
	}
	return d
}

// trackSite keeps a site's per-IP history apart when its bans are its own (ban_scope: site): what an IP did there
// must not get it banned elsewhere.
func (p *Policy) trackSite() string {
	if p.SiteScoped && p.Site != "" {
		return p.Site
	}
	return ""
}
