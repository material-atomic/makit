package shield

import (
	"bufio"
	"io"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// Replay: a new config run against a real access log next to the current one. Both are enforced (observe mode is
// read as block) so the comparison shows what each would do; bans live in memory and expire in log time; bot
// verification uses the downloaded ranges and no DNS. Nothing is written and nothing is sent.

// Outcome of one request: allowed, limited or blocked.
func outcome(d Decision) string {
	switch {
	case d.Allow:
		return "allowed"
	case d.Status == 429:
		return "limited"
	}
	return "blocked"
}

// ReplayExample is one request whose outcome changes.
type ReplayExample struct {
	Time   time.Time `json:"time"`
	Client string    `json:"client"`
	Method string    `json:"method,omitempty"`
	Host   string    `json:"host,omitempty"`
	URI    string    `json:"uri"`
	Status int       `json:"status,omitempty"` // what the app answered in the log
	UA     string    `json:"ua,omitempty"`
	From   string    `json:"from"`
	To     string    `json:"to"`
	Rule   string    `json:"rule,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Likely bool      `json:"likely_false_positive,omitempty"`
}

// ReplayResult sums up how the outcome of every request changes from the current config to the new one.
type ReplayResult struct {
	Requests  int             `json:"requests"`
	Skipped   int             `json:"skipped_lines"`
	First     time.Time       `json:"first"`
	Last      time.Time       `json:"last"`
	Unchanged int             `json:"unchanged"`
	Changes   map[string]int  `json:"changes"` // "allowed → blocked": requests
	ByRule    map[string]int  `json:"by_rule"` // the new config's rule for requests it newly stops
	Clients   map[string]int  `json:"clients"` // "allowed → blocked": distinct clients
	Likely    int             `json:"likely_false_positives"`
	Examples  []ReplayExample `json:"examples"` // likely false positives first
	clientSet map[string]map[string]bool
}

// replayPolicy builds a policy for replay: enforced, with fresh trackers and limiter, and bans kept in memory.
func replayPolicy(cfg *Config, dirs []string, st *State, lists *Set) (*Policy, *time.Time, error) {
	p, err := buildPolicyWith(cfg, dirs, st, lists)
	if err != nil {
		return nil, nil, err
	}
	p.Observe = false
	if p.Scoring != nil {
		p.Tracker = NewTracker(p.Scoring, 500000)
	}
	if p.BotScore != nil {
		p.BotTracker = NewTracker(p.BotScore, 500000)
	}
	p.Limiter = NewLimiter()
	if p.Bots != nil {
		p.Verifier = NewVerifier()
		p.Verifier.LoadRanges(p.Bots)
		p.Verifier.Sync = true
		p.Verifier.LookupAddr = nil
	}
	clock := new(time.Time) // the log time of the request being replayed: bans last from then
	p.Ban = func(a netip.Addr, d time.Duration, src, why, site string, scoped bool) {
		e := Entry{Prefix: netip.PrefixFrom(a, a.BitLen()), Until: clock.Add(d), Reason: why, Source: src, Added: *clock}
		if scoped {
			if s := p.SiteBlockSet(site); s != nil {
				s.Add(e)
			}
			return
		}
		p.Block.Add(e)
	}
	p.Share()
	return p, clock, nil
}

// browserLike: a user agent a person's browser sends, not a library or a declared bot.
func browserLike(ua string) bool {
	l := strings.ToLower(ua)
	if !strings.HasPrefix(l, "mozilla/") {
		return false
	}
	for _, w := range []string{"bot", "crawl", "spider", "headless", "python", "curl", "scan"} {
		if strings.Contains(l, w) {
			return false
		}
	}
	return true
}

// Replay reads an access log and decides every request with both policies.
func Replay(cur, next *Policy, curClock, nextClock *time.Time, log io.Reader, format string, maxExamples int) (*ReplayResult, error) {
	res := &ReplayResult{Changes: map[string]int{}, ByRule: map[string]int{}, Clients: map[string]int{},
		clientSet: map[string]map[string]bool{}}
	var likely, other []ReplayExample
	sc := bufio.NewScanner(log)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		ll, ok := parseLogLine(sc.Text(), format)
		if !ok {
			if strings.TrimSpace(sc.Text()) != "" {
				res.Skipped++
			}
			continue
		}
		r := ll.Request
		if r.Headers == nil {
			r.Headers = map[string]string{}
			if r.UA != "" {
				r.Headers["user-agent"] = r.UA
			}
		}
		*curClock, *nextClock = r.Received, r.Received
		a, b := cur.Decide(r), next.Decide(r)
		res.Requests++
		if res.First.IsZero() || r.Received.Before(res.First) {
			res.First = r.Received
		}
		if r.Received.After(res.Last) {
			res.Last = r.Received
		}
		from, to := outcome(a), outcome(b)
		if from == to {
			res.Unchanged++
			continue
		}
		key := from + " → " + to
		res.Changes[key]++
		if res.clientSet[key] == nil {
			res.clientSet[key] = map[string]bool{}
		}
		res.clientSet[key][b.Client] = true
		if to != "allowed" {
			res.ByRule[firstNonEmpty(b.Rule, "-")]++
		}
		ex := ReplayExample{Time: r.Received, Client: b.Client, Method: r.Method, Host: r.Host, URI: r.URI, Status: r.Status, UA: r.UA,
			From: from, To: to, Rule: b.Rule, Reason: b.Reason}
		ex.Likely = to != "allowed" && r.Status >= 200 && r.Status < 400 && browserLike(r.UA)
		if ex.Likely {
			res.Likely++
			if len(likely) < maxExamples {
				likely = append(likely, ex)
			}
		} else if len(other) < maxExamples {
			other = append(other, ex)
		}
	}
	for k, s := range res.clientSet {
		res.Clients[k] = len(s)
	}
	res.Examples = append(likely, other...)
	if len(res.Examples) > maxExamples {
		res.Examples = res.Examples[:maxExamples]
	}
	sort.SliceStable(res.Examples, func(i, j int) bool { return res.Examples[i].Likely && !res.Examples[j].Likely })
	return res, sc.Err()
}
