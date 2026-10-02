package shield

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var repoCatalog = filepath.Join("..", "..", "security")

func pfx(s string) netip.Prefix { p, _ := ParsePrefix(s); return p }

func TestSet(t *testing.T) {
	s, now := NewSet(), time.Now()
	s.Add(Entry{Prefix: pfx("203.0.113.0/24"), Reason: "range"})
	s.Add(Entry{Prefix: pfx("203.0.113.7"), Reason: "host"})
	s.Add(Entry{Prefix: pfx("198.51.100.1"), Until: now.Add(-time.Minute)})
	s.Add(Entry{Prefix: pfx("2001:db8::/32")})
	if e, ok := s.Match(netip.MustParseAddr("203.0.113.7"), now); !ok || e.Reason != "host" {
		t.Errorf("most specific match: %+v %v", e, ok)
	}
	if _, ok := s.Match(netip.MustParseAddr("203.0.113.8"), now); !ok {
		t.Error("CIDR match")
	}
	if _, ok := s.Match(netip.MustParseAddr("198.51.100.1"), now); ok {
		t.Error("expired entry matched")
	}
	if _, ok := s.Match(netip.MustParseAddr("::ffff:203.0.113.9"), now); !ok {
		t.Error("IPv4-mapped address")
	}
	if _, ok := s.Match(netip.MustParseAddr("2001:db8::1"), now); !ok {
		t.Error("IPv6 prefix")
	}
	if n := s.Prune(now); n != 1 || len(s.Live(now)) != 3 {
		t.Errorf("prune %d live %d", n, len(s.Live(now)))
	}
}

func policy(t *testing.T) *Policy {
	t.Helper()
	rules, err := LoadHTTPRules([]string{repoCatalog})
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Trusted: []netip.Prefix{pfx("104.16.0.0/13")}, Allow: NewSet(), Block: NewSet(), Rules: rules}
	p.Block.Add(Entry{Prefix: pfx("198.51.100.9"), Source: "manual"})
	p.Allow.Add(Entry{Prefix: pfx("192.0.2.10")})
	p.Block.Add(Entry{Prefix: pfx("192.0.2.10")}) // allowlist wins
	return p
}

func TestDecide(t *testing.T) {
	p := policy(t)
	var banned []string
	p.Ban = func(a netip.Addr, r HTTPRule) { banned = append(banned, a.String()+" "+r.ID) }
	cases := []struct {
		name            string
		r               Request
		allow           bool
		client, verdict string
	}{
		{"direct blocked", Request{Peer: "198.51.100.9:5000"}, false, "198.51.100.9", "blocked"},
		{"direct ok", Request{Peer: "198.51.100.10:5000"}, true, "198.51.100.10", "allowed"},
		{"via Cloudflare, real IP blocked", Request{Peer: "104.16.1.1", Client: "198.51.100.9"}, false, "198.51.100.9", "blocked"},
		{"via Cloudflare, real IP ok", Request{Peer: "104.16.1.1", Client: "198.51.100.10"}, true, "198.51.100.10", "allowed"},
		{"spoofed header from a direct client is ignored", Request{Peer: "198.51.100.10", Client: "192.0.2.10"}, true, "198.51.100.10", "allowed"},
		{"spoofed header cannot hide a banned peer", Request{Peer: "198.51.100.9", Client: "203.0.113.1"}, false, "198.51.100.9", "blocked"},
		{"allowlist beats blocklist", Request{Peer: "192.0.2.10"}, true, "192.0.2.10", "allowlisted"},
		{"probe rule", Request{Peer: "203.0.113.50", Method: "GET", URI: "/.env"}, false, "203.0.113.50", "blocked"},
		{"traversal rule", Request{Peer: "203.0.113.51", URI: "/static/..%2f..%2fetc/passwd"}, false, "203.0.113.51", "blocked"},
		{"React2Shell pattern", Request{Peer: "203.0.113.52", Method: "POST", URI: "/", UA: "python-requests/2.31",
			Headers: map[string]string{"next-action": "abc"}}, false, "203.0.113.52", "blocked"},
		{"browser Server Action is fine", Request{Peer: "203.0.113.53", Method: "POST", URI: "/", UA: "Mozilla/5.0",
			Headers: map[string]string{"next-action": "abc"}}, true, "203.0.113.53", "allowed"},
	}
	for _, c := range cases {
		if c.r.Headers == nil {
			c.r.Headers = map[string]string{}
		}
		d := p.Decide(c.r)
		if d.Allow != c.allow || d.Client != c.client || d.Verdict != c.verdict {
			t.Errorf("%s: got %+v", c.name, d)
		}
	}
	if strings.Join(banned, ",") != "203.0.113.50 MK-HTTP-PROBE,203.0.113.51 MK-HTTP-TRAVERSAL,203.0.113.52 MK-HTTP-R2S" {
		t.Errorf("auto-bans: %v", banned)
	}
	p.Observe = true
	if d := p.Decide(Request{Peer: "198.51.100.9"}); !d.Allow || d.Verdict != "would-block" {
		t.Errorf("observe: %+v", d)
	}
	p.Observe, p.Pass = false, true
	if d := p.Decide(Request{Peer: "198.51.100.9"}); !d.Allow {
		t.Errorf("pass: %+v", d)
	}
}

func TestNftScriptSafety(t *testing.T) {
	now := time.Now()
	s := NftScript([]Entry{
		{Prefix: pfx("198.51.100.9")}, {Prefix: pfx("203.0.113.0/24"), Until: now.Add(time.Hour)},
		{Prefix: pfx("10.1.2.3")}, {Prefix: pfx("127.0.0.1")}, {Prefix: pfx("0.0.0.0/0")}, {Prefix: pfx("2001:db8::1")},
	}, now)
	for _, want := range []string{"198.51.100.9", "203.0.113.0/24 timeout", "2001:db8::1", "priority raw", "ip saddr @block4 counter drop"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	for _, bad := range []string{"10.1.2.3", "127.0.0.1", "0.0.0.0/0"} {
		if strings.Contains(s, bad) {
			t.Errorf("unsafe %s reached the kernel set", bad)
		}
	}
}

func TestStateAndGuards(t *testing.T) {
	StateDir = t.TempDir()
	if _, err := withState(func(st *State) error {
		st.Block = upsert(st.Block, Entry{Prefix: pfx("198.51.100.9")})
		st.Block = upsert(st.Block, Entry{Prefix: pfx("198.51.100.8"), Until: time.Now().Add(-time.Hour)})
		st.Allow = upsert(st.Allow, Entry{Prefix: pfx("192.0.2.0/24")})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st, _ := LoadState()
	if len(st.Block) != 1 || len(st.Allow) != 1 {
		t.Errorf("state %+v (expired entries must be dropped on save)", st)
	}
	if err := lockoutGuard(pfx("104.16.0.0/16")); err == nil {
		t.Error("banning a Cloudflare range must be refused")
	}
	t.Setenv("SSH_CLIENT", "203.0.113.4 51234 22")
	if err := lockoutGuard(pfx("203.0.113.0/24")); err == nil {
		t.Error("banning your own SSH address must be refused")
	}
}

func gate(t *testing.T) *Gate {
	g := &Gate{header: "CF-Connecting-IP", stats: map[string]int64{}}
	g.policy.Store(policy(t))
	return g
}

func TestCheckHandler(t *testing.T) {
	h := gate(t).checkHandler()
	ask := func(remote string, hdr map[string]string) int {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9180/check", nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := ask("127.0.0.1:4000", map[string]string{"X-Makit-Peer": "104.16.1.1", "X-Makit-Client": "198.51.100.9"}); c != 403 {
		t.Errorf("blocked via Cloudflare: %d", c)
	}
	if c := ask("127.0.0.1:4000", map[string]string{"X-Makit-Peer": "198.51.100.10", "X-Forwarded-Uri": "/"}); c != 200 {
		t.Errorf("allowed: %d", c)
	}
	if c := ask("172.17.0.2:4000", map[string]string{"X-Makit-Peer": "198.51.100.10", "X-Forwarded-Uri": "/.git/config"}); c != 403 {
		t.Errorf("rule via Docker-network proxy: %d", c)
	}
	if c := ask("203.0.113.9:4000", map[string]string{"X-Makit-Peer": "198.51.100.10"}); c != 403 {
		t.Errorf("public callers must not use /check: %d", c)
	}
}

func TestEdgeHandler(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Header.Get("X-Forwarded-For")+"|"+r.Host)
	}))
	defer up.Close()
	h, err := gate(t).httpHandler(Listener{Name: "test", Upstream: up.URL})
	if err != nil {
		t.Fatal(err)
	}
	do := func(remote string, hdr map[string]string, path string) (int, string) {
		r := httptest.NewRequest("GET", "http://app.example"+path, nil)
		r.RemoteAddr = remote
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Body.String()
	}
	if c, _ := do("198.51.100.9:5555", nil, "/"); c != 403 {
		t.Errorf("banned direct client: %d", c)
	}
	if c, b := do("198.51.100.10:5555", map[string]string{"X-Forwarded-For": "1.2.3.4"}, "/"); c != 200 || b != "198.51.100.10|app.example" {
		t.Errorf("direct client: %d %q (spoofed X-Forwarded-For must be replaced, Host kept)", c, b)
	}
	if c, b := do("104.16.1.1:5555", map[string]string{"CF-Connecting-IP": "203.0.113.70"}, "/"); c != 200 || !strings.HasPrefix(b, "203.0.113.70|") {
		t.Errorf("via Cloudflare: %d %q", c, b)
	}
	if c, _ := do("104.16.1.1:5555", map[string]string{"CF-Connecting-IP": "198.51.100.9"}, "/"); c != 403 {
		t.Errorf("banned client via Cloudflare: %d", c)
	}
}

func TestRuleDocsExist(t *testing.T) {
	rules, err := LoadHTTPRules([]string{repoCatalog})
	if err != nil || len(rules) < 4 {
		t.Fatalf("rules: %d %v", len(rules), err)
	}
	for _, r := range rules {
		file, anchor, _ := strings.Cut(r.Doc, "#")
		b, err := os.ReadFile(filepath.Join("..", "..", file))
		if err != nil {
			t.Errorf("%s: %v", r.ID, err)
			continue
		}
		if anchor != "" && !strings.Contains(strings.ToLower(string(b)), "\n## "+strings.ReplaceAll(anchor, "-", " ")) {
			t.Errorf("%s: no heading #%s in %s", r.ID, anchor, file)
		}
	}
}
