package shield

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

func browserHeaders() map[string]string {
	return map[string]string{"accept": "text/html", "accept-language": "vi-VN,vi;q=0.9", "accept-encoding": "gzip, br",
		"sec-ch-ua": `"Chromium";v="126"`, "sec-fetch-mode": "navigate"}
}

func loadCatalogBots(t *testing.T, policy map[string]string) *BotCatalog {
	t.Helper()
	bc, err := LoadBots([]string{repoCatalog}, "", policy)
	if err != nil || bc == nil {
		t.Fatalf("load bots: %v", err)
	}
	return bc
}

func TestIdentifyAgents(t *testing.T) {
	bc := loadCatalogBots(t, nil)
	cases := map[string]string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)":                                  "googlebot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)":    "gptbot",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot": "chatgpt-user",
		"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)":   "claudebot",
		"Mozilla/5.0 (compatible; Claude-User/1.0; +Claude-User@anthropic.com)":                                     "claude-user",
		"Mozilla/5.0 (compatible; coccocbot-web/1.0; +http://help.coccoc.com/searchengine)":                         "coccocbot",
		"curl/8.5.0":             "curl",
		"python-requests/2.32.3": "python",
		"Mozilla/5.0 (X11; Linux x86_64) HeadlessChrome/126.0.0.0 Safari/537.36":    "headless-chrome",
		"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)": "facebook-preview",
		"Mozilla/5.0 (compatible; SomeNewBot/0.1)":                                  "other-bot",
		chromeUA: "",
		"Mozilla/5.0 (Linux; Android 12; CUBOT X30) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36": "",
	}
	for ua, want := range cases {
		got := ""
		if a := bc.Identify(Request{UA: ua}); a != nil {
			got = a.ID
		}
		if got != want {
			t.Errorf("%q → %q, want %q", ua, got, want)
		}
	}
	a := bc.Identify(Request{UA: chromeUA, Headers: map[string]string{"signature-agent": `"https://chatgpt.com"`}})
	if a == nil || a.ID != "chatgpt-agent" || a.Category != "ai-agent" {
		t.Errorf("signed ChatGPT agent: %+v", a)
	}
}

type fakeDNS struct {
	ptr map[string][]string
	fwd map[string][]net.IP
	err map[string]error
}

func (f fakeDNS) verifier() *Verifier {
	v := NewVerifier()
	v.Sync = true
	v.LookupAddr = func(_ context.Context, ip string) ([]string, error) {
		if e := f.err[ip]; e != nil {
			return nil, e
		}
		return f.ptr[ip], nil
	}
	v.LookupIP = func(_ context.Context, h string) ([]net.IP, error) { return f.fwd[h], nil }
	return v
}

func TestVerifyRDNSAndRanges(t *testing.T) {
	StateDir = t.TempDir()
	bc := loadCatalogBots(t, nil)
	byID := map[string]*Agent{}
	for _, a := range bc.Agents {
		byID[a.ID] = a
	}
	f := fakeDNS{
		ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}, "203.0.113.9": {"evil.example.net."},
			"203.0.113.10": {"crawl-1.googlebot.com.evil.net."}},
		fwd: map[string][]net.IP{"crawl-66-249-66-1.googlebot.com": {net.ParseIP("66.249.66.1")}},
		err: map[string]error{"203.0.113.11": &net.DNSError{Err: "no such host", IsNotFound: true},
			"203.0.113.12": &net.DNSError{Err: "timeout", IsTimeout: true}},
	}
	v := f.verifier()
	now := time.Now()
	for ip, want := range map[string]string{"66.249.66.1": "verified", "203.0.113.9": "spoofed", "203.0.113.10": "spoofed",
		"203.0.113.11": "spoofed", "203.0.113.12": "unknown"} {
		if got := v.Check(byID["yandexbot"], netip.MustParseAddr(ip), now); ip == "66.249.66.1" && got != "spoofed" {
			t.Errorf("googlebot PTR accepted for yandexbot: %s", got)
		}
		if got := v.Check(byID["googlebot"], netip.MustParseAddr(ip), now); got != want {
			t.Errorf("googlebot from %s: %s, want %s", ip, got, want)
		}
	}
	if got := v.Check(byID["claudebot"], netip.MustParseAddr("203.0.113.9"), now); got != "claimed" {
		t.Errorf("unverifiable agent: %s", got)
	}
	// Ranges only (GPTBot): unknown until downloaded, then verified inside / spoofed outside.
	if got := v.Check(byID["gptbot"], netip.MustParseAddr("132.196.86.5"), now); got != "unknown" {
		t.Errorf("gptbot before ranges: %s", got)
	}
	os.MkdirAll(botsDir(), 0o755)
	os.WriteFile(filepath.Join(botsDir(), "gptbot.txt"), []byte("# test\n132.196.86.0/24\n"), 0o644)
	v.LoadRanges(bc)
	if got := v.Check(byID["gptbot"], netip.MustParseAddr("132.196.86.5"), now); got != "verified" {
		t.Errorf("gptbot inside ranges: %s", got)
	}
	if got := v.Check(byID["gptbot"], netip.MustParseAddr("198.51.100.7"), now); got != "spoofed" {
		t.Errorf("gptbot outside ranges: %s", got)
	}
	// Async mode never blocks the request: first answer is pending, the next one has the result.
	va := f.verifier()
	va.Sync = false
	if got := va.Check(byID["googlebot"], netip.MustParseAddr("66.249.66.1"), now); got != "pending" {
		t.Errorf("async first check: %s", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for va.Check(byID["googlebot"], netip.MustParseAddr("66.249.66.1"), now) != "verified" {
		if time.Now().After(deadline) {
			t.Fatal("async verification never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func botPolicy(t *testing.T, policy map[string]string) *Policy {
	t.Helper()
	StateDir = t.TempDir()
	sc, err := LoadScoring([]string{repoCatalog}, "", ScoringOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := LoadScoringSet([]string{repoCatalog}, "bots.yaml", "", ScoringOverrides{Actions: map[string]string{"bot": "block"}})
	if err != nil || bs == nil {
		t.Fatalf("bot score: %v", err)
	}
	f := fakeDNS{ptr: map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		fwd: map[string][]net.IP{"crawl-66-249-66-1.googlebot.com": {net.ParseIP("66.249.66.1")}},
		err: map[string]error{"203.0.113.50": &net.DNSError{IsNotFound: true}}}
	return &Policy{Allow: NewSet(), Block: NewSet(), Scoring: sc, Tracker: NewTracker(sc, 100), Bots: loadCatalogBots(t, policy),
		BotScore: bs, BotTracker: NewTracker(bs, 100), Verifier: f.verifier(), Limiter: NewLimiter()}
}

func TestDecideBots(t *testing.T) {
	p := botPolicy(t, map[string]string{"ai-crawler": "block", "chatgpt-user": "limit 2/1m"})
	googleUA := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	// The real Googlebot following a spam link with an XSS payload is not punished.
	d := p.Decide(Request{Peer: "66.249.66.1", UA: googleUA, Method: "GET", URI: "/search?q=<script>alert(1)</script>"})
	if !d.Allow || d.Verdict != "bot-verified" || d.Bot.Status != "verified" {
		t.Errorf("verified googlebot: %+v %+v", d, d.Bot)
	}
	// A fake Googlebot is blocked by the spoofed policy.
	d = p.Decide(Request{Peer: "203.0.113.50", UA: googleUA, Method: "GET", URI: "/"})
	if d.Allow || d.Rule != "bot:spoofed" {
		t.Errorf("spoofed googlebot: %+v", d)
	}
	// Category policy.
	d = p.Decide(Request{Peer: "198.51.100.1", UA: "Mozilla/5.0 (compatible; ClaudeBot/1.0)", Method: "GET", URI: "/"})
	if d.Allow || d.Rule != "bot:claudebot" || d.Bot.Category != "ai-crawler" {
		t.Errorf("ai-crawler block: %+v", d)
	}
	// Agent limit, counted across IPs.
	var last Decision
	for i := 0; i < 3; i++ {
		last = p.Decide(Request{Peer: "198.51.100." + string(rune('2'+i)), UA: "ChatGPT-User/1.0", Method: "GET", URI: "/"})
	}
	if last.Allow || last.Verdict != "limited" || last.Status != 429 {
		t.Errorf("limit 2/1m, third request: %+v", last)
	}
	// Undeclared automation: a Chrome User-Agent without any of the headers Chrome sends.
	d = p.Decide(Request{Peer: "198.51.100.20", UA: chromeUA, Method: "GET", URI: "/", Headers: map[string]string{}})
	if d.Allow || d.Bot == nil || d.Bot.Status != "undeclared" || d.Bot.Level != "bot" {
		t.Errorf("headerless Chrome: %+v %+v", d, d.Bot)
	}
	// A real browser, and a log line without headers, are not bots.
	for _, h := range []map[string]string{browserHeaders(), nil} {
		d = p.Decide(Request{Peer: "198.51.100.21", UA: chromeUA, Method: "GET", URI: "/", Headers: h})
		if !d.Allow || d.Bot != nil {
			t.Errorf("browser (headers %v): %+v %+v", h != nil, d, d.Bot)
		}
	}
	// Observe mode reports instead of enforcing.
	p.Observe = true
	d = p.Decide(Request{Peer: "198.51.100.1", UA: "ClaudeBot/1.0", Method: "GET", URI: "/"})
	if !d.Allow || d.Verdict != "would-block" {
		t.Errorf("observe: %+v", d)
	}
}

func TestBotPolicyValidation(t *testing.T) {
	for _, bad := range []map[string]string{{"ai-crawlr": "block"}, {"gptbot": "kick"}, {"spoofed": "ban forever"}} {
		if _, err := LoadBots([]string{repoCatalog}, "", bad); err == nil {
			t.Errorf("accepted %v", bad)
		}
	}
	for in, want := range map[string]string{"allow": "allow", "ban 7d": "ban 7d", "ban 90m": "ban 1h30m", "limit 60/1m": "limit 60/1m", "limit 10/m": "limit 10/1m"} {
		a, err := ParseAct(in)
		if err != nil || a.String() != want {
			t.Errorf("%q → %q %v, want %q", in, a.String(), err, want)
		}
	}
	for _, bad := range []string{"limit 0/1m", "limit 5", "ban", "ban -1h", "drop"} {
		if _, err := ParseAct(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRobotsAndRanges(t *testing.T) {
	bc := loadCatalogBots(t, map[string]string{"ai-crawler": "block", "semrushbot": "ban 1d"})
	r := bc.Robots()
	for _, want := range []string{"User-agent: GPTBot", "User-agent: ClaudeBot", "User-agent: Google-Extended", "User-agent: SemrushBot", "Disallow: /"} {
		if !strings.Contains(r, want) {
			t.Errorf("robots.txt lacks %q:\n%s", want, r)
		}
	}
	if strings.Contains(r, "Googlebot") || strings.Contains(r, "AhrefsBot") {
		t.Errorf("robots.txt disallows an allowed bot:\n%s", r)
	}
	got := parseRanges([]byte(`{"creationTime":"x","prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`))
	if strings.Join(got, " ") != "157.55.39.0/24 2001:4860:4801:10::/64" {
		t.Errorf("json ranges: %v", got)
	}
	if got := parseRanges([]byte("# list\n1.2.3.0/24\nnot-an-ip\n")); len(got) != 1 {
		t.Errorf("text ranges: %v", got)
	}
}

func TestSetConfigPathAndCustomize(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shield.yaml")
	os.WriteFile(p, []byte("# my shield\nmode: block # keep me\nask: true\n"), 0o640)
	if err := SetConfigPath(p, []string{"bots", "policy", "ai-crawler"}, "ban 24h"); err != nil {
		t.Fatal(err)
	}
	if err := SetConfigPath(p, []string{"bots", "score", "actions", "bot"}, "limit 60/1m"); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil || c.Bots.Policy["ai-crawler"] != "ban 24h" || c.Bots.Score.Actions["bot"] != "limit 60/1m" || c.Mode != "block" {
		t.Fatalf("config: %+v %v", c.Bots, err)
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), "# keep me") {
		t.Errorf("comments lost:\n%s", b)
	}
	if err := SetConfigPath(p, []string{"bots", "policy", "ai-crawler"}, ""); err != nil {
		t.Fatal(err)
	}
	if c, _ := LoadConfig(p); c.Bots.Policy["ai-crawler"] != "" {
		t.Errorf("unset kept %q", c.Bots.Policy["ai-crawler"])
	}
	// customize copies the catalog files once, never over the maintainer's edits.
	local := filepath.Join(dir, "security")
	if err := cmdCustomize([]string{repoCatalog}, []string{"bots", "--to", local}); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(local, "scoring", "bots.yaml")
	os.WriteFile(f, []byte("mine"), 0o644)
	if err := cmdCustomize([]string{repoCatalog}, []string{"bots", "--to", local}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "mine" {
		t.Error("customize overwrote a local edit")
	}
	if _, err := os.Stat(filepath.Join(local, "bots", "agents.yaml")); err != nil {
		t.Error(err)
	}
	_ = errors.New
}
