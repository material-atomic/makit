package shield

import (
	"fmt"
	"html"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Scoring is security/scoring/http.yaml: signals that add points to a request, per-IP escalation and bursts, and the
// action for each level.
type Scoring struct {
	ID         string            `yaml:"id"`
	Doc        string            `yaml:"doc"`
	WindowRaw  string            `yaml:"window"`
	Levels     map[string]int    `yaml:"levels"`
	LevelOrder []string          `yaml:"level_order"` // lowest first; default low, medium, high, critical
	Actions    map[string]string `yaml:"actions"`
	Escalation struct {
		MinScore int `yaml:"min_score"`
		Every    int `yaml:"every"`
		Add      int `yaml:"add"`
	} `yaml:"escalation"`
	Profiles map[string]bool `yaml:"profiles"`
	Signals  []Signal        `yaml:"signals"`
	Bursts   []Burst         `yaml:"bursts"`
	Window   time.Duration   `yaml:"-"`
}

type Signal struct {
	ID            string `yaml:"id"`
	Field         string `yaml:"field"`
	Match         string `yaml:"match"`
	Score         int    `yaml:"score"`
	UnlessProfile string `yaml:"unless_profile"`
	Label         string `yaml:"label"` // human wording for reports
	Also          *struct {
		Field string `yaml:"field"`
		Match string `yaml:"match"`
	} `yaml:"also"`
	re, alsoRe *regexp.Regexp
}

type Burst struct {
	ID    string `yaml:"id"`
	Field string `yaml:"field"`
	Match string `yaml:"match"`
	Count int    `yaml:"count"`
	Score int    `yaml:"score"`
	Label string `yaml:"label"`
	re    *regexp.Regexp
}

// ScoringOverrides come from shield.yaml (scoring:): per-server profiles, actions and disabled signals.
type ScoringOverrides struct {
	Enabled  *bool             `yaml:"enabled"`
	Profiles map[string]bool   `yaml:"profiles"`
	Actions  map[string]string `yaml:"actions"`
	Disable  []string          `yaml:"disable"`
}

// LoadScoring reads <dir>/scoring/http.yaml from catalog directories (the last one found wins) — or file, when set —
// and applies overrides.
func LoadScoring(dirs []string, file string, o ScoringOverrides) (*Scoring, error) {
	return LoadScoringSet(dirs, "http.yaml", file, o)
}

// LoadScoringSet is LoadScoring for any scoring set (http.yaml, bots.yaml).
func LoadScoringSet(dirs []string, name, file string, o ScoringOverrides) (*Scoring, error) {
	var sc *Scoring
	paths := []string{}
	for _, d := range dirs {
		paths = append(paths, filepath.Join(d, "scoring", name))
	}
	if file != "" {
		if _, err := os.Stat(file); err != nil {
			return nil, fmt.Errorf("scoring.file: %w", err)
		}
		paths = []string{file}
	}
	for _, f := range paths {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var x Scoring
		if err := yaml.Unmarshal(b, &x); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		sc = &x
	}
	if sc == nil {
		return nil, nil
	}
	for k, v := range o.Profiles {
		if sc.Profiles == nil {
			sc.Profiles = map[string]bool{}
		}
		sc.Profiles[k] = v
	}
	if sc.Actions == nil {
		sc.Actions = map[string]string{}
	}
	for k, v := range o.Actions {
		sc.Actions[k] = v
	}
	off := map[string]bool{}
	for _, id := range o.Disable {
		off[id] = true
	}
	var err error
	if sc.Window, err = time.ParseDuration(firstNonEmpty(sc.WindowRaw, "10m")); err != nil {
		return nil, fmt.Errorf("scoring window: %w", err)
	}
	sigs := sc.Signals[:0]
	for _, s := range sc.Signals {
		if off[s.ID] || (s.UnlessProfile != "" && sc.Profiles[s.UnlessProfile]) {
			continue
		}
		if s.re, err = regexp.Compile(s.Match); err != nil {
			return nil, fmt.Errorf("signal %s: %w", s.ID, err)
		}
		if s.Also != nil {
			if s.alsoRe, err = regexp.Compile(s.Also.Match); err != nil {
				return nil, fmt.Errorf("signal %s: %w", s.ID, err)
			}
		}
		sigs = append(sigs, s)
	}
	sc.Signals = sigs
	bs := sc.Bursts[:0]
	for _, b := range sc.Bursts {
		if off[b.ID] {
			continue
		}
		if b.Match != "" {
			if b.re, err = regexp.Compile(b.Match); err != nil {
				return nil, fmt.Errorf("burst %s: %w", b.ID, err)
			}
		}
		bs = append(bs, b)
	}
	sc.Bursts = bs
	if len(sc.LevelOrder) == 0 {
		sc.LevelOrder = []string{"low", "medium", "high", "critical"}
	}
	for _, lvl := range sc.LevelOrder {
		if a := sc.Actions[lvl]; a != "" {
			if _, err := ParseAct(a); err != nil {
				return nil, fmt.Errorf("action %s: %w", lvl, err)
			}
		}
	}
	return sc, nil
}

// decode undoes URL encoding (up to 3 layers, so %253C → <), HTML entities and NUL bytes.
func decode(s string) string {
	for i := 0; i < 3; i++ {
		d := percentDecode(s)
		d = html.UnescapeString(d)
		if d == s {
			break
		}
		s = d
	}
	return strings.ReplaceAll(s, "\x00", "")
}

// percentDecode is tolerant: invalid escapes are kept as they are.
func percentDecode(s string) string {
	if !strings.ContainsAny(s, "%+") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		if c == '+' {
			c = ' '
		}
		b.WriteByte(c)
	}
	return b.String()
}

type scoredRequest struct {
	fields     map[string]string
	hasHeaders bool
}

// get returns a field; a header the client did not send is "" when headers are known (so '^$' means "missing").
func (q scoredRequest) get(field string) (string, bool) {
	v, ok := q.fields[field]
	if !ok && q.hasHeaders && strings.HasPrefix(field, "header:") {
		return "", true
	}
	return v, ok
}

func fieldsOf(r Request, status int) scoredRequest {
	path, query, _ := strings.Cut(r.URI, "?")
	path, query = decode(path), decode(query)
	raw := r.Raw
	if raw == "" {
		raw = r.Method + " " + r.URI
	}
	f := map[string]string{"method": r.Method, "path": path, "query": query, "path+query": path + "?" + query,
		"ua": r.UA, "host": r.Host, "referer": decode(r.Referer), "raw": raw}
	if status > 0 {
		f["status"] = strconv.Itoa(status)
	}
	any := []string{path, query, r.UA, f["referer"]}
	for k, v := range r.Headers {
		f["header:"+k] = v
		any = append(any, v)
	}
	f["any"] = strings.Join(any, "\n")
	return scoredRequest{f, r.Headers != nil}
}

// ScoreRequest adds the points of every matching signal (once each), capped at 200.
func (sc *Scoring) ScoreRequest(r Request, status int) (int, []string) {
	q := fieldsOf(r, status)
	total := 0
	var hits []string
	for _, s := range sc.Signals {
		v, ok := q.get(s.Field)
		if !ok || !s.re.MatchString(v) {
			continue
		}
		if s.Also != nil {
			av, ok := q.get(s.Also.Field)
			if !ok || !s.alsoRe.MatchString(av) {
				continue
			}
		}
		total += s.Score
		hits = append(hits, fmt.Sprintf("%s+%d", s.ID, s.Score))
	}
	return min(total, 200), hits
}

// Level maps a score to "normal" or the highest level reached (low, medium, high, critical by default).
func (sc *Scoring) Level(score int) string {
	lvl := "normal"
	order := sc.LevelOrder
	if len(order) == 0 {
		order = []string{"low", "medium", "high", "critical"}
	}
	for _, l := range order {
		if t, ok := sc.Levels[l]; ok && score >= t {
			lvl = l
		}
	}
	return lvl
}

// Act is a parsed action: allow, log, block, ban <duration> or limit <N>/<window>.
type Act struct {
	Kind string        // allow, log, block, ban, limit
	Dur  time.Duration // ban length, or the limit window
	N    int           // limit: requests allowed per window
}

func (a Act) String() string {
	switch a.Kind {
	case "ban":
		return "ban " + fmtDur(a.Dur)
	case "limit":
		return fmt.Sprintf("limit %d/%s", a.N, fmtDur(a.Dur))
	}
	return a.Kind
}

func fmtDur(d time.Duration) string {
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

func parseDur(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		v, err := strconv.Atoi(n)
		return time.Duration(v) * 24 * time.Hour, err
	}
	return time.ParseDuration(s)
}

// ParseAct reads "allow", "log", "block", "ban 1h", "ban 7d" or "limit 60/1m".
func ParseAct(a string) (Act, error) {
	f := strings.Fields(a)
	bad := fmt.Errorf("%q: use allow, log, block, ban <duration> or limit <N>/<window>", a)
	switch {
	case len(f) == 1 && (f[0] == "allow" || f[0] == "log" || f[0] == "block"):
		return Act{Kind: f[0]}, nil
	case len(f) == 2 && f[0] == "ban":
		d, err := parseDur(f[1])
		if err != nil || d <= 0 {
			return Act{}, bad
		}
		return Act{Kind: "ban", Dur: d}, nil
	case len(f) == 2 && f[0] == "limit":
		ns, ws, ok := strings.Cut(f[1], "/")
		n, err := strconv.Atoi(ns)
		if !ok || err != nil || n <= 0 {
			return Act{}, bad
		}
		if ws != "" && (ws[0] < '0' || ws[0] > '9') {
			ws = "1" + ws // limit 60/m
		}
		d, err := parseDur(ws)
		if err != nil || d <= 0 {
			return Act{}, bad
		}
		return Act{Kind: "limit", N: n, Dur: d}, nil
	}
	return Act{}, bad
}

// parseAction reads "log", "block" or "ban 1h" (kept for callers that only need kind and duration).
func parseAction(a string) (string, time.Duration, error) {
	x, err := ParseAct(a)
	return x.Kind, x.Dur, err
}

// Act returns the action for a level (log when unset or invalid).
func (sc *Scoring) Act(level string) Act {
	a, err := ParseAct(sc.Actions[level])
	if err != nil {
		return Act{Kind: "log"}
	}
	return a
}

func (sc *Scoring) Action(level string) (string, time.Duration) {
	a := sc.Act(level)
	return a.Kind, a.Dur
}

// Tracker keeps per-IP state within the scoring window (bounded: oldest IPs are dropped first).
type Tracker struct {
	mu  sync.Mutex
	ips map[netip.Addr]*ipState
	max int
	sc  *Scoring
}

type ipState struct {
	first, last time.Time
	count       int
	suspicious  int
	maxScore    int
	bursts      map[string]int
	signals     map[string]int
}

func NewTracker(sc *Scoring, max int) *Tracker {
	if max <= 0 {
		max = 200000
	}
	return &Tracker{ips: map[netip.Addr]*ipState{}, max: max, sc: sc}
}

// Observe records one request and returns the IP's score (highest request score + escalation + bursts) and the
// burst signals that fired.
func (t *Tracker) Observe(ip netip.Addr, reqScore int, signals []string, status int, at time.Time) (int, []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	st := t.ips[ip]
	if st == nil || at.Sub(st.first) > t.sc.Window {
		if st == nil && len(t.ips) >= t.max {
			t.evict(at)
		}
		st = &ipState{first: at, bursts: map[string]int{}, signals: map[string]int{}}
		t.ips[ip] = st
	}
	st.last = at
	st.count++
	st.maxScore = max(st.maxScore, reqScore)
	if reqScore >= t.sc.Escalation.MinScore && reqScore > 0 {
		st.suspicious++
	}
	for _, s := range signals {
		st.signals[strings.SplitN(s, "+", 2)[0]]++
	}
	score := st.maxScore
	if t.sc.Escalation.Every > 0 {
		score += t.sc.Escalation.Add * (st.suspicious / t.sc.Escalation.Every)
	}
	var fired []string
	for _, b := range t.sc.Bursts {
		matched := b.re == nil
		if b.re != nil && b.Field == "status" && status > 0 {
			matched = b.re.MatchString(strconv.Itoa(status))
		}
		if matched {
			st.bursts[b.ID]++
		}
		if st.bursts[b.ID] >= b.Count {
			score += b.Score
			fired = append(fired, fmt.Sprintf("%s+%d", b.ID, b.Score))
		}
	}
	return min(score, 200), fired
}

func (t *Tracker) evict(now time.Time) {
	for ip, st := range t.ips {
		if now.Sub(st.last) > t.sc.Window {
			delete(t.ips, ip)
		}
	}
	if len(t.ips) < t.max {
		return
	}
	type kv struct {
		ip   netip.Addr
		last time.Time
	}
	all := make([]kv, 0, len(t.ips))
	for ip, st := range t.ips {
		all = append(all, kv{ip, st.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].last.Before(all[j].last) })
	for _, x := range all[:len(all)/10+1] {
		delete(t.ips, x.ip)
	}
}

// TopIP is one line of an analysis report.
type TopIP struct {
	IP       string         `json:"ip"`
	Score    int            `json:"score"`
	Level    string         `json:"level"`
	Requests int            `json:"requests"`
	Signals  map[string]int `json:"signals"`
	First    time.Time      `json:"first"`
	Last     time.Time      `json:"last"`
}

// Top returns the IPs with the highest scores.
func (t *Tracker) Top(n int) []TopIP {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]TopIP, 0, len(t.ips))
	for ip, st := range t.ips {
		score := st.maxScore
		if t.sc.Escalation.Every > 0 {
			score += t.sc.Escalation.Add * (st.suspicious / t.sc.Escalation.Every)
		}
		for _, b := range t.sc.Bursts {
			if st.bursts[b.ID] >= b.Count {
				score += b.Score
			}
		}
		score = min(score, 200)
		out = append(out, TopIP{IP: ip.String(), Score: score, Level: t.sc.Level(score), Requests: st.count, Signals: st.signals, First: st.first, Last: st.last})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Requests > out[j].Requests
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Labels maps signal and burst ids to their human wording.
func (sc *Scoring) Labels() map[string]string {
	m := map[string]string{}
	for _, s := range sc.Signals {
		m[s.ID] = firstNonEmpty(s.Label, s.ID)
	}
	for _, b := range sc.Bursts {
		m[b.ID] = firstNonEmpty(b.Label, b.ID)
	}
	return m
}
