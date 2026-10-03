package shield

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

func issuesText(is []Issue) string {
	var b strings.Builder
	for _, i := range is {
		b.WriteString(i.Level + " " + i.String() + "\n")
	}
	return b.String()
}

func TestConfigCheckFindsWhatTheGateIgnores(t *testing.T) {
	cfg := `mode: block
trusted_proxy: [aws-alb]
kernel_block: true
allow: [192.0.2.10, not-an-ip]
listeners:
  - name: web
    listen: ":443"
    upstream: http://127.0.0.1:8080
    accept_proxy_protocl: true
    tls: { acme: ["*.example.com"] }
  - name: web2
    listen: "0.0.0.0:443"
    upstream: http://127.0.0.1:8081
report: { min_level: hgh }
sites:
  - match: [shop.example.com]
    mode: blok
  - match: []
`
	got := issuesText(CheckConfig([]byte(cfg), CheckOptions{}))
	for _, want := range []string{
		`error line 2: unknown key "trusted_proxy" — it is ignored, so this setting does nothing; did you mean "trusted_proxies"?`,
		`error line 4: allow entry "not-an-ip" is not an IP or CIDR`,
		`error line 9: unknown key "accept_proxy_protocl"`,
		`did you mean "accept_proxy_protocol"?`,
		`error line 10: listener web: *.example.com — automatic certificates (TLS-ALPN) cannot be wildcards`,
		`error line 12: listeners web and web2 both listen on port 443`,
		`error line 14: min_level "hgh": low, medium, high or critical`,
		`error line 17: site shop.example.com: mode must be block, observe or pass`,
		`error line 18: site 2 has no match`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestConfigCheckWarnings(t *testing.T) {
	cfg := `trusted_proxies: [aws-alb]
client_ip_header: X-Forwarded-For
kernel_block: true
admin: 0.0.0.0:9180
mode: pass
edge: true
`
	got := issuesText(CheckConfig([]byte(cfg), CheckOptions{}))
	for _, want := range []string{
		"warning line 3: kernel_block is on with private trusted proxies",
		"warning line 4: admin 0.0.0.0:9180 listens on public addresses",
		"warning line 5: mode pass",
		"warning line 6: edge is on but no listeners",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "error") {
		t.Errorf("warnings only expected:\n%s", got)
	}
	got = issuesText(CheckConfig([]byte("trusted_proxies: [0.0.0.0/0]\n"), CheckOptions{}))
	if !strings.Contains(got, "error line 1: trusted proxy range 0.0.0.0/0 is wider than /8") {
		t.Errorf("a trusted range anyone is in must be refused:\n%s", got)
	}
	got = issuesText(CheckConfig([]byte("client_ip_header: X-Forwarded-For\ntrusted_proxies: []\n"), CheckOptions{}))
	if !strings.Contains(got, "client_ip_header X-Forwarded-For is never read") {
		t.Errorf("header without trusted proxies:\n%s", got)
	}
}

func TestConfigCheckAgainstCatalogAndChannels(t *testing.T) {
	cfg := `bots:
  policy:
    ai-crawler: maybe
sites:
  - match: [a.example]
    report: { notify: [ops, nowhere] }
`
	got := issuesText(CheckConfig([]byte(cfg), CheckOptions{Dirs: []string{repoCatalog}, Channels: []string{"ops"}}))
	if !strings.Contains(got, "error") || !strings.Contains(got, "maybe") {
		t.Errorf("an unknown bot action must be an error:\n%s", got)
	}
	if !strings.Contains(got, `warning line 6: site a.example sends reports to channel "nowhere"`) {
		t.Errorf("unknown channel:\n%s", got)
	}
	// The default config and the shipped example are clean.
	for _, ok := range []string{"", "mode: observe\n", "trusted_proxies: [cloudflare, aws-alb]\nclient_ip_header: X-Forwarded-For\n"} {
		if is := CheckConfig([]byte(ok), CheckOptions{Dirs: []string{repoCatalog}}); len(is) != 0 {
			t.Errorf("%q: %s", ok, issuesText(is))
		}
	}
	if is := CheckConfig([]byte("mode: [block\n"), CheckOptions{}); len(is) == 0 || is[0].Level != "error" || is[0].Line == 0 {
		t.Errorf("broken YAML must be an error with its line: %+v", is)
	}
}

func TestReplay(t *testing.T) {
	cur, err := ParseConfig([]byte("mode: observe\n"), "cur")
	if err != nil {
		t.Fatal(err)
	}
	next, err := ParseConfig([]byte("mode: block\nbots:\n  policy:\n    ai-crawler: block\nallow: [198.51.100.66]\n"), "next")
	if err != nil {
		t.Fatal(err)
	}
	a, ac, err := replayPolicy(cur, []string{repoCatalog}, &State{}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	b, bc, err := replayPolicy(next, []string{repoCatalog}, &State{}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	log := strings.Join([]string{
		`192.0.2.44 - - [03/Oct/2026:09:10:00 +0000] "GET /blog HTTP/1.1" 200 5 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"`,
		`192.0.2.50 - - [03/Oct/2026:09:10:01 +0000] "GET /products HTTP/1.1" 200 5 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/126"`,
		`198.51.100.66 - - [03/Oct/2026:09:10:02 +0000] "GET /.env HTTP/1.1" 404 5 "-" "curl/8"`,
		`not a log line`,
	}, "\n")
	r, err := Replay(a, b, ac, bc, strings.NewReader(log), "auto", 10)
	if err != nil {
		t.Fatal(err)
	}
	if r.Requests != 3 || r.Skipped != 1 || r.Unchanged != 1 || r.Changes["allowed → blocked"] != 1 || r.Changes["blocked → allowed"] != 1 {
		t.Errorf("%+v", r)
	}
	if r.ByRule["bot:gptbot"] != 1 || r.Likely != 0 {
		t.Errorf("by rule / likely: %+v", r)
	}
	if !r.First.Equal(time.Date(2026, 10, 3, 9, 10, 0, 0, time.UTC)) {
		t.Errorf("first: %v", r.First)
	}
	// A browser the app answered 200 that the new policy blocks is flagged as a likely false positive.
	strict, _ := ParseConfig([]byte("mode: block\n"), "strict")
	banned := &State{Block: []Entry{{Prefix: netip.MustParsePrefix("192.0.2.50/32"), Source: "manual"}}}
	s, sc, err := replayPolicy(strict, []string{repoCatalog}, banned, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	a, ac, _ = replayPolicy(cur, []string{repoCatalog}, &State{}, NewSet())
	r, _ = Replay(a, s, ac, sc, strings.NewReader(`192.0.2.50 - - [03/Oct/2026:09:10:01 +0000] "GET / HTTP/1.1" 200 5 "-" "Mozilla/5.0 (Windows NT 10.0) Chrome/126"`), "auto", 10)
	if r.Changes["allowed → blocked"] != 1 || r.Likely != 1 {
		t.Errorf("a blocked browser answered 200 must be a likely false positive: %+v", r)
	}
}
