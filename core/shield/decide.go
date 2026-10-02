package shield

import (
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// Request is what a reverse proxy tells the gate about one request.
type Request struct {
	Peer     string // TCP peer address as the proxy saw it (X-Makit-Peer)
	Client   string // client IP header from the proxy chain (X-Makit-Client, e.g. CF-Connecting-IP)
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
	Ban     func(addr netip.Addr, d time.Duration, source, reason string) // automatic bans (rules, scores)
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
	v = strings.TrimSpace(strings.Split(v, ",")[0])
	if ap, err := netip.ParseAddrPort(v); err == nil {
		return ap.Addr().Unmap(), true
	}
	a, err := netip.ParseAddr(strings.Trim(v, "[]"))
	return a.Unmap(), err == nil
}

// Decide applies, in order: client IP resolution (header only from trusted proxies) → allowlist → blocklist → rules.
func (p *Policy) Decide(r Request) Decision {
	peer, ok := firstIP(r.Peer)
	if !ok {
		return Decision{Allow: true, Verdict: "invalid", Reason: "no peer address (check the proxy snippet)", Peer: r.Peer}
	}
	client, via := peer, ""
	if r.Client != "" && p.trusted(peer) {
		if c, ok := firstIP(r.Client); ok {
			client, via = c, peer.String()
		}
	}
	d := Decision{Client: client.String(), Peer: peer.String(), Via: via, Allow: true, Verdict: "allowed"}
	if p.Pass {
		return d
	}
	now := r.Received
	if now.IsZero() {
		now = time.Now()
	}
	if e, ok := p.Allow.Match(client, now); ok {
		d.Verdict, d.Reason = "allowlisted", e.Prefix.String()
		return d
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
	// The peer itself (a direct client, or a proxy you banned) is checked too.
	for _, a := range []netip.Addr{client, peer} {
		if e, ok := p.Block.Match(a, now); ok {
			return block(e.Source, e.Prefix.String()+" "+e.Reason)
		}
		if p.Lists != nil {
			if e, ok := p.Lists.Match(a, now); ok {
				return block(e.Source, e.Prefix.String()+" "+e.Reason)
			}
		}
	}
	for _, rule := range p.Rules {
		if rule.Match(r) {
			if rule.BanFor > 0 && p.Ban != nil && !p.Observe {
				p.Ban(client, rule.BanFor, "rule:"+rule.ID, rule.Title)
			}
			return block("rule:"+rule.ID, rule.Title)
		}
	}
	if p.Scoring != nil {
		score, hits := p.Scoring.ScoreRequest(r, 0)
		if p.Tracker != nil {
			ipScore, bursts := p.Tracker.Observe(client, score, hits, 0, now)
			hits = append(hits, bursts...)
			score = max(score, ipScore)
		}
		d.Score, d.Level, d.Signals = score, p.Scoring.Level(score), hits
		switch act, dur := p.Scoring.Action(d.Level); act {
		case "block":
			return block("score:"+d.Level, fmt.Sprintf("score %d", score))
		case "ban":
			if p.Ban != nil && !p.Observe {
				p.Ban(client, dur, "score:"+d.Level, fmt.Sprintf("score %d: %s", score, strings.Join(hits, " ")))
			}
			return block("score:"+d.Level, fmt.Sprintf("score %d", score))
		}
	}
	return d
}
