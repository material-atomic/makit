package shield

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
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
	os.WriteFile(filepath.Join(botsDir(), feedFile("gptbot", "https://openai.com/gptbot.json")), []byte("# test\n132.196.86.0/24\n"), 0o644)
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

// GoesBot and goes.vn webhooks are let through by default — with no Accept-Language and a non-browser UA they would
// otherwise look like scripts — but a maintainer can still block them, and they get no rule/score bypass (unverified).
func TestGoesBotAllowedByDefault(t *testing.T) {
	p := botPolicy(t, map[string]string{"seo": "block", "library": "block"})
	p.BotScore.Actions["suspect"], p.BotScore.Actions["likely"] = "block", "block"
	for _, ua := range []string{"GoesBot/1.0 (+https://goes.vn/bot)", chromeUA + " GoesBot/1.0 (+https://goes.vn/bot)", "Goes-Webhooks/1.0 (+https://goes.vn)"} {
		d := p.Decide(Request{Peer: "198.51.100.9", UA: ua, Method: "GET", URI: "/", Headers: map[string]string{}})
		if !d.Allow || d.Bot == nil || d.Bot.Action != "allow" {
			t.Errorf("%s: %+v %+v", ua, d, d.Bot)
		}
	}
	d := p.Decide(Request{Peer: "198.51.100.9", UA: "GoesBot/1.0", Method: "GET", URI: "/.env"})
	if d.Allow {
		t.Error("a GoesBot User-Agent bypassed the rules (anyone can send it)")
	}
	blocked := botPolicy(t, map[string]string{"goesbot": "block"})
	if d := blocked.Decide(Request{Peer: "198.51.100.9", UA: "GoesBot/1.0", Method: "GET", URI: "/"}); d.Allow {
		t.Error("bots set goesbot block ignored")
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
	got, _ := parseRanges([]byte(`{"creationTime":"x","prefixes":[{"ipv4Prefix":"157.55.39.0/24"},{"ipv6Prefix":"2001:4860:4801:10::/64"}]}`))
	if len(got) != 2 || got[0].String() != "157.55.39.0/24" || got[1].String() != "2001:4860:4801:10::/64" {
		t.Errorf("json ranges: %v", got)
	}
	got, skipped := parseRanges([]byte("# list\n1.2.3.0/24 ; office\nnot-an-ip\n5.6.7.8,crawler-1\n0.0.0.0/0\n2001::/16\n1.2.3.0/24\n"))
	if len(got) != 2 || skipped != 2 {
		t.Errorf("text ranges: %v skipped %d", got, skipped)
	}
	if got, _ := parseRanges([]byte(`{"ips":["9.9.9.9","9.9.9.10"]}`)); len(got) != 2 {
		t.Errorf("json IP list: %v", got)
	}
}

func TestBotSourcesAndTypedIPs(t *testing.T) {
	StateDir = t.TempDir()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Write([]byte("# partner crawler\n192.0.2.0/24\n198.51.100.77\n"))
	}))
	defer srv.Close()
	cfg := filepath.Join(t.TempDir(), "shield.yaml")
	os.WriteFile(cfg, []byte("mode: block\n"), 0o640)
	dirs := []string{repoCatalog}
	if err := cmdBotSource(cfg, dirs, []string{"add", srv.URL + "/ips.txt", "--agent", "partner", "--category", "monitoring", "--every", "6h"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdBotSource(cfg, dirs, []string{"add", srv.URL + "/x", "--agent", "nobody"}, nil); err == nil {
		t.Error("new agent without a category accepted")
	}
	if err := cmdBotIP(cfg, dirs, []string{"add", "gptbot", "203.0.113.4", "203.0.113.0/28"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdBotIP(cfg, dirs, []string{"add", "office-monitor", "10.1.2.3", "--category", "monitoring", "--name", "Office monitor"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdBotIP(cfg, dirs, []string{"add", "gptbot", "0.0.0.0/1"}, nil); err == nil {
		t.Error("a /1 accepted as a bot range")
	}
	c, err := LoadConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	bc, err := LoadBotsConfig(dirs, c.Bots)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier()
	v.LoadRanges(bc)
	now := time.Now()
	if v.RangeCount("partner") != 2 || v.ByIP(netip.MustParseAddr("192.0.2.9"), now) != "partner" {
		t.Errorf("partner feed: %d ranges, byIP %q", v.RangeCount("partner"), v.ByIP(netip.MustParseAddr("192.0.2.9"), now))
	}
	if v.ByIP(netip.MustParseAddr("203.0.113.4"), now) != "" {
		t.Error("a catalog agent is recognised by IP without --by-ip")
	}
	if got := v.Check(bc.Agent("gptbot"), netip.MustParseAddr("203.0.113.4"), now); got != "verified" {
		t.Errorf("typed gptbot IP: %s", got)
	}
	// The policy sees an IP-only agent even with a browser User-Agent.
	p := &Policy{Allow: NewSet(), Block: NewSet(), Bots: bc, Verifier: v, Limiter: NewLimiter()}
	d := p.Decide(Request{Peer: "10.1.2.3", UA: chromeUA, Method: "GET", URI: "/"})
	if d.Verdict != "bot-verified" || d.Bot == nil || d.Bot.ID != "office-monitor" {
		t.Errorf("typed monitor IP: %+v %+v", d, d.Bot)
	}
	// Refresh only when due.
	if done, _ := RefreshBotRanges(bc, false, "partner"); len(done) != 0 || hits != 1 {
		t.Errorf("fresh feed downloaded again: %d (hits %d)", len(done), hits)
	}
	// Remove: the source and its cached file go; typed IPs stay until removed.
	if err := cmdBotSource(cfg, dirs, []string{"remove", srv.URL + "/ips.txt"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(botsDir(), feedFile("partner", srv.URL+"/ips.txt"))); !os.IsNotExist(err) {
		t.Error("cache file of a removed source kept")
	}
	if err := cmdBotIP(cfg, dirs, []string{"remove", "gptbot", "203.0.113.4", "203.0.113.0/28"}, nil); err != nil {
		t.Fatal(err)
	}
	c, _ = LoadConfig(cfg)
	if len(c.Bots.Sources) != 1 || c.Bots.Sources[0].Agent != "office-monitor" {
		t.Errorf("sources left: %+v", c.Bots.Sources)
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
