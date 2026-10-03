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
	p.Ban = func(a netip.Addr, d time.Duration, src, why, site string, scoped bool) {
		banned = append(banned, a.String()+" "+strings.TrimPrefix(src, "rule:"))
	}
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

func TestNftScriptSafetyAndBatches(t *testing.T) {
	now := time.Now()
	s := NftScript([]Entry{
		{Prefix: pfx("198.51.100.9")}, {Prefix: pfx("203.0.113.0/24"), Until: now.Add(time.Hour)},
		{Prefix: pfx("10.1.2.3")}, {Prefix: pfx("127.0.0.1")}, {Prefix: pfx("0.0.0.0/0")}, {Prefix: pfx("2001:db8::1")},
	}, now)
	for _, want := range []string{"198.51.100.9", "203.0.113.0/24 timeout", "2001:db8::1", "priority raw", "ip saddr @block4 counter drop", "ip6 saddr @list6net counter drop", "flush set inet makit_shield block4"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
	for _, bad := range []string{"10.1.2.3", "127.0.0.1", "0.0.0.0/0", "delete table"} {
		if strings.Contains(s, bad) {
			t.Errorf("unsafe %s in the kernel script", bad)
		}
	}
	l := NewSet()
	var ps []netip.Prefix
	for i := 0; i < 45000; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 0, byte(i >> 8), byte(i)}), 32))
	}
	l.AddMany(ps, time.Time{}, "feed", "list:test")
	l.Add(Entry{Prefix: pfx("192.0.2.0/24")})
	b := NftListBatches(l, now, 20000)
	if len(b) != 1+3+1 || !strings.Contains(b[0], "flush set inet makit_shield list4ip") || !strings.Contains(b[4], "list4net") {
		t.Errorf("batches: %d", len(b))
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

func askingGate(t *testing.T) *Gate {
	g := gate(t)
	g.ask.Store(true)
	return g
}

func TestCheckHandler(t *testing.T) {
	h := askingGate(t).checkHandler()
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

func TestSetConfigKeepsComments(t *testing.T) {
	f := filepath.Join(t.TempDir(), "shield.yaml")
	if err := os.WriteFile(f, []byte("# my notes\nmode: observe   # keep this\nallow: [192.0.2.1]\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, kv := range [][2]string{{"mode", "block"}, {"ask", "off"}, {"edge", "on"}} {
		if err := SetConfig(f, kv[0], kv[1]); err != nil {
			t.Fatal(err)
		}
	}
	c, err := LoadConfig(f)
	if err != nil || c.Mode != "block" || c.Ask || !c.Edge || len(c.Allow) != 1 {
		t.Fatalf("config %+v %v", c, err)
	}
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "# my notes") || !strings.Contains(string(b), "# keep this") {
		t.Errorf("comments lost:\n%s", b)
	}
	if SetConfig(f, "mode", "nonsense") == nil || SetConfig(f, "ask", "maybe") == nil || SetConfig(f, "port", "1") == nil {
		t.Error("invalid values accepted")
	}
}

func TestAskSwitch(t *testing.T) {
	g := gate(t)
	h := g.checkHandler()
	r := httptest.NewRequest("GET", "http://127.0.0.1:9180/check", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("X-Makit-Peer", "198.51.100.9")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r) // ask is off by default in a fresh Gate
	if w.Code != 200 {
		t.Errorf("ask off must allow: %d", w.Code)
	}
	g.ask.Store(true)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Errorf("ask on must block: %d", w.Code)
	}
}

func TestListsImportAndMatch(t *testing.T) {
	StateDir = t.TempDir()
	src := filepath.Join(t.TempDir(), "drop.txt")
	feed := "; Spamhaus DROP style\n198.51.100.0/24 ; SBL1\n203.0.113.5\n# comment\nnot-an-ip\n2001:db8:dead::/48\n"
	if err := os.WriteFile(src, []byte(feed), 0o644); err != nil {
		t.Fatal(err)
	}
	l, bad, err := ImportList("drop", src, 24*time.Hour, "Spamhaus DROP")
	if err != nil || l.Count != 3 || bad != 1 {
		t.Fatalf("import: %+v bad=%d err=%v", l, bad, err)
	}
	set, fp, err := LoadLists()
	if err != nil || set.Len() != 3 || fp == "" {
		t.Fatalf("load: %d %v", set.Len(), err)
	}
	e, ok := set.Match(netip.MustParseAddr("198.51.100.77"), time.Now())
	if !ok || e.Source != "list:drop" || e.Reason != "Spamhaus DROP" || e.Until.IsZero() {
		t.Errorf("match: %+v %v", e, ok)
	}
	if _, ok := set.Match(netip.MustParseAddr("2001:db8:dead:1::1"), time.Now()); !ok {
		t.Error("IPv6 range from list")
	}
	if _, _, err := ImportList("Bad Name", src, 0, ""); err == nil {
		t.Error("invalid list name accepted")
	}
}

// One million banned addresses and 100k ranges: lookups must stay O(prefix lengths), not O(entries).
func TestMillionEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("large")
	}
	s := NewSet()
	ps := make([]netip.Prefix, 0, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	start := time.Now()
	s.AddMany(ps, time.Time{}, "feed", "list:big")
	nets := make([]netip.Prefix, 0, 100_000)
	for i := 0; i < 100_000; i++ {
		nets = append(nets, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(60 + i>>16), byte(i >> 8), byte(i), 0}), 24))
	}
	s.AddMany(nets, time.Time{}, "feed", "list:nets")
	build := time.Since(start)
	if s.Len() != 1_100_000 {
		t.Fatalf("len %d", s.Len())
	}
	now := time.Now()
	start = time.Now()
	const n = 200_000
	hits := 0
	for i := 0; i < n; i++ {
		a := netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)})
		if _, ok := s.Match(a, now); ok {
			hits++
		}
		if j := i % 100_000; true {
			if _, ok := s.Match(netip.AddrFrom4([4]byte{byte(60 + j>>16), byte(j >> 8), byte(j), 200}), now); ok {
				hits++
			}
		}
		if false {
			hits++
		}
	}
	per := time.Since(start) / (2 * n)
	t.Logf("1.1M entries built in %s; %s per lookup", build.Round(time.Millisecond), per)
	if hits != 2*n {
		t.Errorf("hits %d", hits)
	}
	if per > 5*time.Microsecond {
		t.Errorf("lookup too slow: %s", per)
	}
}

func BenchmarkMatchMillion(b *testing.B) {
	s := NewSet()
	ps := make([]netip.Prefix, 0, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	s.AddMany(ps, time.Time{}, "feed", "list:big")
	s.Add(Entry{Prefix: pfx("60.0.0.0/8")})
	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Match(netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}), now)
	}
}

// A flood of automatic bans must not touch the disk per request: bans are active at once and saved in batches.
func TestAutoBanBatched(t *testing.T) {
	StateDir = t.TempDir()
	g := &Gate{stats: map[string]int64{}}
	p := &Policy{Allow: NewSet(), Block: NewSet()}
	g.policy.Store(p)
	start := time.Now()
	for i := 0; i < 20000; i++ {
		g.autoBan(netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}), time.Hour, "score:critical", "test", "", false)
	}
	if el := time.Since(start); el > time.Second {
		t.Errorf("20000 bans took %s in the request path", el)
	}
	if _, ok := p.Block.Match(netip.MustParseAddr("100.64.1.1"), time.Now()); !ok {
		t.Error("ban not active before it is saved")
	}
	if st, _ := LoadState(); len(st.Block) != 0 {
		t.Error("state written in the request path")
	}
	if n := len(g.unsaved()); n != 20000 {
		t.Errorf("unsaved %d", n)
	}
	g.flushBans()
	st, _ := LoadState()
	if len(st.Block) != 20000 || len(g.unsaved()) != 0 || g.selfWrite.Load() == 0 {
		t.Errorf("after flush: state %d, unsaved %d, selfWrite %d", len(st.Block), len(g.unsaved()), g.selfWrite.Load())
	}
	// Banning again updates in place.
	g.autoBan(netip.MustParseAddr("100.64.1.1"), 48*time.Hour, "rule:x", "again", "", false)
	g.flushBans()
	if st, _ := LoadState(); len(st.Block) != 20000 {
		t.Errorf("re-ban duplicated: %d", len(st.Block))
	}
}

// A catalog copied from a Mac carries AppleDouble "._*.yaml" files; they are not rules and must not stop the gate.
func TestCatalogSkipsHiddenFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "http"), 0o755); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(filepath.Join(repoCatalog, "http", "probes.yaml"))
	_ = os.WriteFile(filepath.Join(dir, "http", "probes.yaml"), src, 0o644)
	_ = os.WriteFile(filepath.Join(dir, "http", "._probes.yaml"), []byte("\x00\x05\x16\x07Mac OS X\x00\x00"), 0o644)
	if rules, err := LoadHTTPRules([]string{dir}); err != nil || len(rules) == 0 {
		t.Errorf("rules %d, err %v", len(rules), err)
	}
}
