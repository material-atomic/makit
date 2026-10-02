package shield

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Reporter sums up what the gate saw in a window (5 minutes by default): totals, then one block per suspicious IP —
// score and level, what it did in plain words, sample paths, statuses, and what makit did about it. At the end of
// each window the report is appended to /var/log/makit/shield/reports/<date>.txt (and .jsonl), and sent through
// makit notify when it contains something at or above report.min_level, a ban, or a spoofed bot.
type Reporter struct {
	mu     sync.Mutex
	start  time.Time
	total  int
	byVerd map[string]int
	ips    map[string]*ipAgg
	bots   map[string]*botAgg
	err5xx int // server errors answered to suspicious requests (edge mode knows the upstream status)
	labels map[string]string
}

type ipAgg struct {
	IP       string         `json:"ip"`
	Requests int            `json:"requests"`
	Score    int            `json:"score"`
	Level    string         `json:"level"`
	Signals  map[string]int `json:"signals"`
	Paths    []string       `json:"paths"`
	MorePath int            `json:"more_paths,omitempty"`
	Status   map[int]int    `json:"status"`
	Blocked  int            `json:"blocked,omitempty"`
	Limited  int            `json:"limited,omitempty"`
	Would    int            `json:"would_block,omitempty"` // observe mode
	BanUntil time.Time      `json:"banned_until,omitempty"`
	BanWhy   string         `json:"ban_source,omitempty"`
	Rules    map[string]int `json:"rules,omitempty"`
	Bot      string         `json:"bot,omitempty"`
	Country  string         `json:"country,omitempty"`
}

type botAgg struct {
	Name     string `json:"name"`
	Status   string `json:"status"`
	Requests int    `json:"requests"`
	Denied   int    `json:"denied"`
}

// BatchReport is one window.
type BatchReport struct {
	Site     string         `json:"site,omitempty"`
	Host     string         `json:"host"`
	From     time.Time      `json:"from"`
	To       time.Time      `json:"to"`
	Total    int            `json:"requests"`
	Verdicts map[string]int `json:"verdicts"`
	IPs      []*ipAgg       `json:"ips"`
	MoreIPs  int            `json:"more_ips,omitempty"`
	Bots     []*botAgg      `json:"bots,omitempty"`
	Banned   int            `json:"banned"`
	Err5xx   int            `json:"server_errors_on_suspicious,omitempty"`
	Level    string         `json:"level"` // highest level in the window
	Text     string         `json:"-"`
}

var levelRank = map[string]int{"": 0, "normal": 0, "low": 1, "suspect": 1, "medium": 2, "likely": 2, "high": 3, "bot": 3, "critical": 4}

func NewReporter(now time.Time) *Reporter {
	r := &Reporter{}
	r.reset(now)
	return r
}

func (r *Reporter) reset(now time.Time) {
	r.start, r.total, r.err5xx = now, 0, 0
	r.byVerd, r.ips, r.bots = map[string]int{}, map[string]*ipAgg{}, map[string]*botAgg{}
}

// SetLabels gives signal ids their readable wording (from the scoring sets).
func (r *Reporter) SetLabels(m map[string]string) {
	r.mu.Lock()
	r.labels = m
	r.mu.Unlock()
}

func suspicious(s *Snapshot) bool {
	if s.Bot != nil && s.Bot.ID != "" && s.Bot.Status != "spoofed" && strings.HasPrefix(s.Rule, "bot:") {
		return false // a known bot handled by your policy: summed up in the bots line, not per IP
	}
	return !s.Allow || strings.HasPrefix(s.Verdict, "would-") || levelRank[s.Level] > 0 ||
		(s.Bot != nil && (s.Bot.Status == "spoofed" || levelRank[s.Bot.Level] >= 2))
}

// Observe adds one request.
func (r *Reporter) Observe(s Snapshot) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.total++
	r.byVerd[s.Verdict]++
	if b := s.Bot; b != nil && b.ID != "" {
		key := b.ID + "|" + b.Status
		a := r.bots[key]
		if a == nil {
			if len(r.bots) > 500 {
				goto ip
			}
			a = &botAgg{Name: b.Name, Status: b.Status}
			r.bots[key] = a
		}
		a.Requests++
		if !s.Allow {
			a.Denied++
		}
	}
ip:
	if !suspicious(&s) {
		return
	}
	a := r.ips[s.Client]
	if a == nil {
		if len(r.ips) >= 50000 { // bounded under a flood; totals stay exact
			return
		}
		a = &ipAgg{IP: s.Client, Signals: map[string]int{}, Status: map[int]int{}, Rules: map[string]int{}, Level: "normal"}
		r.ips[s.Client] = a
	}
	a.Requests++
	score, level := s.Score, s.Level
	if s.Bot != nil && s.Bot.Score > score { // undeclared bot: its own score
		score, level = s.Bot.Score, s.Bot.Level
	}
	if score > a.Score {
		a.Score = score
	}
	if levelRank[level] > levelRank[a.Level] {
		a.Level = level
	}
	for _, h := range s.Signals {
		a.Signals[strings.SplitN(h, "+", 2)[0]]++
	}
	if s.Bot != nil {
		for _, h := range s.Bot.Signals {
			a.Signals[strings.SplitN(h, "+", 2)[0]]++
		}
		if s.Bot.Status == "spoofed" {
			a.Bot = "fake " + s.Bot.Name
			a.Level = maxLevel(a.Level, "high")
		}
	}
	if s.Rule != "" && !strings.HasPrefix(s.Rule, "score:") {
		a.Rules[s.Rule]++
		if strings.HasPrefix(s.Rule, "rule:") || strings.HasPrefix(s.Rule, "list:") || s.Rule == "manual" {
			a.Level = maxLevel(a.Level, "high")
		}
	}
	switch s.Verdict {
	case "blocked":
		a.Blocked++
	case "limited":
		a.Limited++
	case "would-block", "would-limit":
		a.Would++
	}
	if s.Status > 0 {
		a.Status[s.Status]++
		if s.Status >= 500 {
			r.err5xx++
		}
	}
	if a.Country == "" {
		a.Country = s.Country
	}
	p := s.URI
	if p == "" {
		p = "(empty or binary request line)"
	}
	if !containsStr(a.Paths, p) {
		if len(a.Paths) < 3 {
			if len(p) > 120 {
				p = p[:117] + "…"
			}
			a.Paths = append(a.Paths, p)
		} else {
			a.MorePath++
		}
	}
}

func maxLevel(a, b string) string {
	if levelRank[b] > levelRank[a] {
		return b
	}
	return a
}

// Banned records an automatic ban (shown as the action taken).
func (r *Reporter) Banned(e Entry) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := e.Prefix.Addr().String()
	a := r.ips[k]
	if a == nil {
		a = &ipAgg{IP: k, Signals: map[string]int{}, Status: map[int]int{}, Rules: map[string]int{}, Level: "high"}
		r.ips[k] = a
	}
	a.BanUntil, a.BanWhy = e.Until, e.Source
	a.Level = maxLevel(a.Level, "high")
}

// Flush closes the window and returns its report (nil when nothing happened at all).
func (r *Reporter) Flush(now time.Time, host string) *BatchReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.total == 0 && len(r.ips) == 0 {
		r.reset(now)
		return nil
	}
	b := &BatchReport{Host: host, From: r.start, To: now, Total: r.total, Verdicts: r.byVerd, Err5xx: r.err5xx, Level: "normal"}
	for _, a := range r.ips {
		b.IPs = append(b.IPs, a)
		b.Level = maxLevel(b.Level, a.Level)
		if !a.BanUntil.IsZero() {
			b.Banned++
		}
	}
	sort.Slice(b.IPs, func(i, j int) bool {
		x, y := b.IPs[i], b.IPs[j]
		if levelRank[x.Level] != levelRank[y.Level] {
			return levelRank[x.Level] > levelRank[y.Level]
		}
		if x.Score != y.Score {
			return x.Score > y.Score
		}
		return x.Requests > y.Requests
	})
	if len(b.IPs) > 15 {
		b.MoreIPs, b.IPs = len(b.IPs)-15, b.IPs[:15]
	}
	for _, a := range r.bots {
		b.Bots = append(b.Bots, a)
	}
	sort.Slice(b.Bots, func(i, j int) bool { return b.Bots[i].Requests > b.Bots[j].Requests })
	if len(b.Bots) > 8 {
		b.Bots = b.Bots[:8]
	}
	b.Text = b.render(r.labels)
	r.reset(now)
	return b
}

// Worth says whether the report should be sent: something at minLevel or above, a ban, or a fake bot.
func (b *BatchReport) Worth(minLevel string) bool {
	if b == nil {
		return false
	}
	if b.Banned > 0 || levelRank[b.Level] >= levelRank[firstNonEmpty(minLevel, "high")] {
		return true
	}
	for _, x := range b.Bots {
		if x.Status == "spoofed" {
			return true
		}
	}
	return false
}

func thousands(n int) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + " " + s[i:]
	}
	return s
}

func (b *BatchReport) render(labels map[string]string) string {
	var w strings.Builder
	where := b.Host
	if b.Site != "" {
		where = b.Site + " (" + b.Host + ")"
	}
	fmt.Fprintf(&w, "makit shield · %s · %s–%s UTC\n", where, b.From.UTC().Format("2006-01-02 15:04"), b.To.UTC().Format("15:04"))
	counts := map[string]int{}
	for _, a := range b.IPs {
		counts[a.Level]++
	}
	line := []string{thousands(b.Total) + " requests", fmt.Sprintf("%d suspicious IPs", len(b.IPs)+b.MoreIPs)}
	if b.Banned > 0 {
		line = append(line, fmt.Sprintf("%d banned", b.Banned))
	}
	for _, v := range []string{"blocked", "limited", "would-block"} {
		if n := b.Verdicts[v]; n > 0 {
			line = append(line, fmt.Sprintf("%s %s", strings.ReplaceAll(v, "-", " "), thousands(n)))
		}
	}
	for _, l := range []string{"critical", "high", "medium"} {
		if counts[l] > 0 {
			line = append(line, fmt.Sprintf("%s %d", l, counts[l]))
		}
	}
	w.WriteString(strings.Join(line, " · ") + "\n")
	for _, a := range b.IPs {
		lvl := strings.ToUpper(firstNonEmpty(a.Level, "normal"))
		score := ""
		if a.Score > 0 {
			score = fmt.Sprintf(" %d", a.Score)
		}
		fmt.Fprintf(&w, "\n[%s%s] %s", lvl, score, a.IP)
		if a.Country != "" {
			fmt.Fprintf(&w, " (%s)", a.Country)
		}
		fmt.Fprintf(&w, " · %d req · %s\n", a.Requests, a.action())
		var what []string
		type kv struct {
			k string
			n int
		}
		var sig []kv
		for k, n := range a.Signals {
			sig = append(sig, kv{k, n})
		}
		sort.Slice(sig, func(i, j int) bool { return sig[i].n > sig[j].n || sig[i].n == sig[j].n && sig[i].k < sig[j].k })
		for i, s := range sig {
			if i == 4 {
				what = append(what, fmt.Sprintf("+%d more", len(sig)-4))
				break
			}
			l := firstNonEmpty(labels[s.k], s.k)
			if s.n > 1 {
				l += fmt.Sprintf(" ×%d", s.n)
			}
			what = append(what, l)
		}
		for r, n := range a.Rules {
			if !strings.HasPrefix(r, "bot:") { // bots are named below
				what = append(what, fmt.Sprintf("%s ×%d", r, n))
			}
		}
		if a.Bot != "" {
			what = append(what, a.Bot)
		}
		if len(what) > 0 {
			w.WriteString("   " + strings.Join(what, " · ") + "\n")
		}
		paths := strings.Join(a.Paths, ", ")
		if a.MorePath > 0 {
			paths += fmt.Sprintf(", +%d", a.MorePath)
		}
		var st []string
		codes := make([]int, 0, len(a.Status))
		for c := range a.Status {
			codes = append(codes, c)
		}
		sort.Ints(codes)
		for _, c := range codes {
			st = append(st, fmt.Sprintf("%d×%d", c, a.Status[c]))
		}
		if paths != "" || len(st) > 0 {
			fmt.Fprintf(&w, "   %s", paths)
			if len(st) > 0 {
				fmt.Fprintf(&w, " · status %s", strings.Join(st, " "))
			}
			w.WriteString("\n")
		}
	}
	if b.MoreIPs > 0 {
		fmt.Fprintf(&w, "\n+%d more suspicious IPs (makit shield log --blocked)\n", b.MoreIPs)
	}
	if len(b.Bots) > 0 {
		var parts []string
		for _, x := range b.Bots {
			st := map[string]string{"unknown": "unverified", "pending": "verifying", "spoofed": "fake"}[x.Status]
			p := fmt.Sprintf("%s %d (%s", x.Name, x.Requests, firstNonEmpty(st, x.Status))
			if x.Denied > 0 {
				p += fmt.Sprintf(", %d denied", x.Denied)
			}
			p += ")"
			parts = append(parts, p)
		}
		w.WriteString("\nbots: " + strings.Join(parts, " · ") + "\n")
	}
	if b.Err5xx > 0 {
		fmt.Fprintf(&w, "\n⚠ your app answered 5xx to %d suspicious requests — unknown paths should return 404, not an error\n", b.Err5xx)
	}
	return w.String()
}

func (a *ipAgg) action() string {
	switch {
	case !a.BanUntil.IsZero():
		return fmt.Sprintf("banned until %s UTC (%s)", a.BanUntil.UTC().Format("01-02 15:04"), a.BanWhy)
	case a.Blocked > 0:
		return fmt.Sprintf("blocked %d", a.Blocked)
	case a.Limited > 0:
		return fmt.Sprintf("rate-limited %d", a.Limited)
	case a.Would > 0:
		return fmt.Sprintf("would block %d (observe mode)", a.Would)
	}
	return "logged"
}

// Save appends the report to <dir>/<date>.txt and <date>.jsonl, and drops days older than keep.
func (b *BatchReport) Save(dir string, keepDays int) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	day := b.To.UTC().Format("2006-01-02")
	f, err := os.OpenFile(filepath.Join(dir, day+".txt"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	_, err = f.WriteString(b.Text + "\n────────\n\n")
	f.Close()
	if err != nil {
		return err
	}
	j, _ := json.Marshal(b)
	if f, err = os.OpenFile(filepath.Join(dir, day+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640); err == nil {
		f.Write(append(j, '\n'))
		f.Close()
	}
	if keepDays > 0 {
		cut := b.To.AddDate(0, 0, -keepDays).UTC().Format("2006-01-02")
		olds, _ := filepath.Glob(filepath.Join(dir, "*-*-*.*"))
		for _, o := range olds {
			if base := filepath.Base(o); len(base) >= 10 && base[:10] < cut {
				os.Remove(o)
			}
		}
	}
	return nil
}

var _ = netip.Addr{}
