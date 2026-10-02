package shield

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sitesYAML = `mode: block
rules: true
bots:
  policy: { ai-crawler: block, claude-user: "limit 1/1m" }
ban_scope: server
sites:
  - name: blogcode
    match: [blogcode.vn, "*.blogcode.vn"]
    ban_scope: site
    allow: [203.0.113.0/24]
    rules: { disable: [MK-HTTP-PROBE] }
    scoring: { profiles: { wordpress: true } }
    bots: { policy: { ai-crawler: allow } }
    report: { notify: [blog-telegram] }
  - match: [shop.example.com]
    mode: observe
`

func sitePolicy(t *testing.T, yml string) (*Policy, *Config) {
	t.Helper()
	StateDir = t.TempDir()
	path := filepath.Join(t.TempDir(), "shield.yaml")
	os.WriteFile(path, []byte(yml), 0o640)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := buildPolicy(cfg, []string{repoCatalog}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	if p.Scoring != nil {
		p.Tracker = NewTracker(p.Scoring, 1000)
	}
	p.Limiter = NewLimiter()
	p.Share()
	return p, cfg
}

func TestSitesOverrideGlobal(t *testing.T) {
	p, _ := sitePolicy(t, sitesYAML)
	for host, want := range map[string]string{"blogcode.vn": "blogcode", "BlogCode.VN:443": "blogcode", "cdn.blogcode.vn": "blogcode",
		"shop.example.com": "shop.example.com", "example.org": "", "": "", "notblogcode.vn": ""} {
		if got := p.ForHost(host).Site; got != want {
			t.Errorf("%q → site %q, want %q", host, got, want)
		}
	}
	req := func(host, ip, uri, ua string) Decision {
		return p.Decide(Request{Peer: ip, Host: host, Method: "GET", URI: uri, UA: ua, Received: time.Now()})
	}
	gpt := "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
	// Bot policy: the site's ai-crawler: allow wins over the global block.
	if d := req("example.org", "198.51.100.1", "/", gpt); d.Allow {
		t.Error("global: GPTBot should be blocked")
	}
	if d := req("blogcode.vn", "198.51.100.1", "/", gpt); !d.Allow || d.Site != "blogcode" {
		t.Errorf("blogcode: GPTBot should be allowed: %+v", d)
	}
	// Scoring profile: WordPress paths are normal on blogcode only.
	wp := "/wp-login.php"
	if d := req("blogcode.vn", "198.51.100.2", wp, chromeUA); strings.Contains(strings.Join(d.Signals, " "), "path-wordpress") {
		t.Errorf("blogcode scored a WordPress path: %v", d.Signals)
	}
	if d := req("example.org", "198.51.100.3", wp, chromeUA); d.Allow && !strings.Contains(strings.Join(d.Signals, " "), "path-wordpress") {
		t.Errorf("global did not score a WordPress path: %+v", d)
	}
	// Rules: MK-HTTP-PROBE is off on blogcode only.
	if d := req("blogcode.vn", "198.51.100.4", "/.env", chromeUA); d.Rule == "rule:MK-HTTP-PROBE" {
		t.Error("blogcode applied a disabled rule")
	}
	if d := req("example.org", "198.51.100.5", "/.env", chromeUA); d.Rule != "rule:MK-HTTP-PROBE" {
		t.Errorf("global: probe rule not applied: %+v", d)
	}
	// Allowlist: the site's own entries add to the global allowlist, and only there.
	p.Block.Add(Entry{Prefix: pfx("203.0.113.7/32"), Source: "manual"})
	if d := req("blogcode.vn", "203.0.113.7", "/", chromeUA); d.Verdict != "allowlisted" {
		t.Errorf("site allow: %+v", d)
	}
	if d := req("example.org", "203.0.113.7", "/", chromeUA); d.Allow {
		t.Error("site allow leaked to the global policy")
	}
	// Mode: shop.example.com observes.
	if d := req("shop.example.com", "198.51.100.6", "/.env", chromeUA); !d.Allow || d.Verdict != "would-block" {
		t.Errorf("shop observe: %+v", d)
	}
	// Limits are counted per site.
	cu := "Claude-User/1.0"
	req("example.org", "198.51.100.8", "/", cu)
	if d := req("example.org", "198.51.100.9", "/", cu); d.Verdict != "limited" {
		t.Errorf("global limit: %+v", d)
	}
	if d := req("blogcode.vn", "198.51.100.9", "/", cu); d.Verdict == "limited" {
		t.Error("another site's requests counted against blogcode's limit")
	}
}

func TestBanScope(t *testing.T) {
	p, _ := sitePolicy(t, sitesYAML)
	g := &Gate{stats: map[string]int64{}}
	g.policy.Store(p)
	p.Ban = g.autoBan
	p.Share()
	xss := "/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
	req := func(host, ip, uri string) Decision {
		return p.Decide(Request{Peer: ip, Host: host, Method: "GET", URI: uri, UA: chromeUA, Received: time.Now()})
	}
	// blogcode bans for itself only.
	if d := req("blogcode.vn", "198.51.100.20", xss); d.Allow {
		t.Fatalf("attack allowed: %+v", d)
	}
	if d := req("blogcode.vn", "198.51.100.20", "/"); d.Allow {
		t.Error("blogcode: attacker not banned there")
	}
	if d := req("example.org", "198.51.100.20", "/"); !d.Allow {
		t.Errorf("a site-scoped ban applied to another site: %+v", d)
	}
	// The global policy bans on every site.
	req("example.org", "198.51.100.21", xss)
	if d := req("blogcode.vn", "198.51.100.21", "/"); d.Allow {
		t.Error("a server-wide ban did not apply to blogcode")
	}
	g.flushBans()
	st, _ := LoadState()
	scopes := map[string]string{}
	for _, e := range st.Block {
		scopes[e.Prefix.Addr().String()] = e.Site
	}
	if scopes["198.51.100.20"] != "blogcode" || scopes["198.51.100.21"] != "" {
		t.Errorf("saved scopes: %v", scopes)
	}
	// Reloading keeps both: the site's ban in its set, the server's in the global set.
	p2, _, err := buildPolicy(mustConfig(t, sitesYAML), []string{repoCatalog}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p2.SiteBlockSet("blogcode").Match(netip.MustParseAddr("198.51.100.20"), time.Now()); !ok {
		t.Error("site ban lost on reload")
	}
	if _, ok := p2.Block.Match(netip.MustParseAddr("198.51.100.20"), time.Now()); ok {
		t.Error("site ban loaded as server-wide")
	}
	// Each site gets its own report.
	g.record(Snapshot{Decision: Decision{Client: "198.51.100.20", Verdict: "blocked", Site: "blogcode", Level: "critical", Score: 120}, URI: xss, Status: 403})
	g.record(Snapshot{Decision: Decision{Client: "198.51.100.21", Verdict: "blocked", Level: "critical", Score: 120}, URI: xss, Status: 403})
	dir := t.TempDir()
	cfg := mustConfig(t, sitesYAML+"report: {dir: "+dir+"}\n")
	g.emitReport(cfg, "web-1")
	b, err := os.ReadFile(filepath.Join(dir, "blogcode", time.Now().UTC().Format("2006-01-02")+".txt"))
	if err != nil || !strings.Contains(string(b), "makit shield · blogcode (web-1)") || strings.Contains(string(b), "198.51.100.21") {
		t.Errorf("blogcode report: %v\n%s", err, b)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, time.Now().UTC().Format("2006-01-02")+".txt")); strings.Contains(string(b), "198.51.100.20 ") {
		t.Errorf("global report holds blogcode's IP:\n%s", b)
	}
}

func mustConfig(t *testing.T, yml string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shield.yaml")
	os.WriteFile(path, []byte(yml), 0o640)
	c, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestSitesValidation(t *testing.T) {
	StateDir = t.TempDir()
	for _, bad := range []string{
		"sites: [{match: [a.example], mode: shout}]",
		"sites: [{match: [a.example], ban_scope: planet}]",
		"sites: [{name: x}]",
		"sites: [{match: [a.example]}, {match: [a.example], name: other}]",
		"sites: [{match: [a.example], bots: {policy: {nobody: block}}}]",
		"ban_scope: galaxy",
	} {
		if _, _, err := buildPolicy(mustConfig(t, bad), []string{repoCatalog}, NewSet()); err == nil {
			t.Errorf("accepted: %s", bad)
		}
	}
}
