package shield

import (
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// albPolicy trusts Cloudflare's 104.16.0.0/13 and the private ranges an AWS ALB takes its addresses from.
func albPolicy(t *testing.T) *Policy {
	p := policy(t)
	cfg := Config{TrustedProxies: []string{"aws-alb"}}
	alb, err := cfg.Trusted()
	if err != nil {
		t.Fatal(err)
	}
	p.Trusted = append(p.Trusted, alb...)
	return p
}

// A visitor writes whatever it likes into X-Forwarded-For; each trusted proxy appends the address it saw. Only the
// first address from the right that is not a trusted proxy may decide.
func TestClientFromForwardedChain(t *testing.T) {
	p := albPolicy(t)
	cases := []struct {
		name, peer, chain, client string
		allow                     bool
	}{
		{"ALB appends the real client; the forged left part is ignored", "10.0.1.5", "1.2.3.4, 203.0.113.7", "203.0.113.7", true},
		{"a banned visitor cannot hide behind a forged address", "10.0.1.5", "1.2.3.4, 198.51.100.9", "198.51.100.9", false},
		{"a forged allowlisted address does not allowlist the visitor", "10.0.1.5", "192.0.2.10, 198.51.100.9", "198.51.100.9", false},
		{"a forged trusted proxy in the chain changes nothing", "10.0.1.5", "198.51.100.9, 104.16.1.1, 198.51.100.10", "198.51.100.10", true},
		{"Cloudflare in front of the ALB", "10.0.1.5", "6.6.6.6, 198.51.100.9, 104.16.1.1", "198.51.100.9", false},
		{"several proxies inside the VPC", "10.0.1.5", "198.51.100.9, 10.0.2.8, 10.0.3.9", "198.51.100.9", false},
		{"every hop trusted: the left-most is the client", "10.0.1.5", "10.0.9.9, 10.0.2.8", "10.0.9.9", true},
		{"garbage from a trusted proxy stops the walk", "10.0.1.5", "198.51.100.9, not-an-ip, 10.0.2.8", "10.0.2.8", true},
		{"ports and IPv6 brackets", "10.0.1.5", "[2001:db8::1]:443, 198.51.100.9:5555", "198.51.100.9", false},
		{"IPv6 client", "10.0.1.5", "1.2.3.4, 2001:db8::7", "2001:db8::7", true},
		{"a direct client's header is ignored", "198.51.100.10", "192.0.2.10", "198.51.100.10", true},
		{"a direct banned client's header is ignored", "198.51.100.9", "203.0.113.1", "198.51.100.9", false},
		{"no header: the proxy itself", "10.0.1.5", "", "10.0.1.5", true},
	}
	for _, c := range cases {
		d := p.Decide(Request{Peer: c.peer, Client: c.chain, Headers: map[string]string{}})
		if d.Client != c.client || d.Allow != c.allow {
			t.Errorf("%s: client %s allow %v, want %s %v (%+v)", c.name, d.Client, d.Allow, c.client, c.allow, d)
		}
	}
	// A chain longer than any real one is cut off, not walked to the end.
	long := strings.Repeat("10.0.0.1, ", 1000) + "10.0.0.2"
	if d := p.Decide(Request{Peer: "10.0.1.5", Client: long, Headers: map[string]string{}}); d.Client != "10.0.0.1" {
		t.Errorf("long chain: %+v", d)
	}
}

// A trusted proxy carries every visitor behind it: a rule may block its own request, but it is never banned.
func TestTrustedProxyNeverBanned(t *testing.T) {
	p := albPolicy(t)
	var banned []string
	p.Ban = func(a netip.Addr, d time.Duration, src, why, site string, scoped bool) {
		banned = append(banned, a.String())
	}
	if d := p.Decide(Request{Peer: "10.0.1.5", URI: "/.env", Method: "GET", Headers: map[string]string{}}); d.Allow {
		t.Errorf("the probe itself must be blocked: %+v", d)
	}
	if len(banned) != 0 {
		t.Errorf("trusted proxy banned: %v", banned)
	}
	if d := p.Decide(Request{Peer: "10.0.1.5", Client: "203.0.113.60", URI: "/.env", Method: "GET", Headers: map[string]string{}}); d.Allow ||
		strings.Join(banned, ",") != "203.0.113.60" {
		t.Errorf("the visitor behind it is banned: %+v %v", d, banned)
	}
}

// Traefik forwardAuth and ingress-nginx auth-url send no X-Makit-Peer: the asking proxy's own hop is the right-most
// X-Forwarded-For entry, and the visitor is read from the right of the whole chain, across header lines.
func TestCheckWithoutPeerHeader(t *testing.T) {
	g := askingGate(t)
	g.policy.Store(albPolicy(t))
	h := g.checkHandler()
	ask := func(lines ...string) (int, string) {
		r := httptest.NewRequest("GET", "http://10.0.0.20:9180/check", nil)
		r.RemoteAddr = "10.0.0.30:4000"
		for _, l := range lines {
			r.Header.Add("X-Forwarded-For", l)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code, w.Header().Get("X-Makit-Client")
	}
	if c, cl := ask("192.0.2.10, 198.51.100.9, 10.0.1.5"); c != 403 || cl != "198.51.100.9" {
		t.Errorf("forged left-most address must not decide: %d %s", c, cl)
	}
	if c, cl := ask("192.0.2.10", "198.51.100.9, 10.0.1.5"); c != 403 || cl != "198.51.100.9" {
		t.Errorf("chain split over two header lines: %d %s", c, cl)
	}
	if c, cl := ask("1.2.3.4, 198.51.100.10, 10.0.1.5"); c != 200 || cl != "198.51.100.10" {
		t.Errorf("real visitor allowed: %d %s", c, cl)
	}
	// Directly from a visitor (no trusted proxy as the last hop), the header is not believed at all.
	if c, cl := ask("192.0.2.10, 198.51.100.9"); c != 403 || cl != "198.51.100.9" {
		t.Errorf("untrusted last hop: %d %s", c, cl)
	}
}

func TestBanRefusesTrustedProxyRange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shield.yaml")
	if err := os.WriteFile(path, []byte("trusted_proxies: [aws-alb]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("MAKIT_SHIELD_CONFIG", path)
	t.Setenv("SSH_CLIENT", "")
	if err := lockoutGuard(pfx("10.0.0.0/16")); err == nil || !strings.Contains(err.Error(), "trusted proxy") {
		t.Errorf("banning the load balancer's subnet must be refused: %v", err)
	}
	if err := lockoutGuard(pfx("203.0.113.9")); err != nil {
		t.Errorf("a public address is fine: %v", err)
	}
}

func BenchmarkClientIPChain(b *testing.B) {
	p := &Policy{}
	cfg := Config{TrustedProxies: []string{"aws-alb"}}
	p.Trusted, _ = cfg.Trusted()
	p.Trusted = append(p.Trusted, CloudflareRanges()...)
	peer := netip.MustParseAddr("10.0.1.5")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if c, _ := p.clientIP(peer, "1.2.3.4, 198.51.100.9, 104.16.1.1"); c.IsUnspecified() {
			b.Fatal(c)
		}
	}
}

// Whatever sits in front — Cloudflare, a cloud load balancer, both, a CDN, or nothing — makit reads the fields every
// proxy writes: X-Forwarded-For (or Forwarded), with the asking proxy's own hop right-most. A provider's own header
// (CF-Connecting-IP) passes through every proxy untouched, so it is never read: through a load balancer's public
// address anyone could set it.
func TestCheckBehindAnyInfrastructure(t *testing.T) {
	g := askingGate(t)
	p := albPolicy(t) // Cloudflare's 104.16.0.0/13 and the private ranges a VPC uses
	g.policy.Store(p)
	h := g.checkHandler()
	ask := func(hdr map[string]string) string {
		r := httptest.NewRequest("GET", "http://172.17.0.1:9180/check", nil)
		r.RemoteAddr = "172.18.0.5:40000" // Caddy in Docker
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Header().Get("X-Makit-Client")
	}
	cases := []struct {
		name   string
		hdr    map[string]string
		client string
	}{
		{"Cloudflare → load balancer → Caddy", map[string]string{"X-Forwarded-For": "45.155.207.1, 104.16.1.1, 10.104.0.2"}, "45.155.207.1"},
		{"the same, the visitor's own X-Forwarded-For to the left",
			map[string]string{"X-Forwarded-For": "1.2.3.4, 45.155.207.1, 104.16.1.1, 10.104.0.2"}, "45.155.207.1"},
		{"straight to the load balancer, CF-Connecting-IP and X-Forwarded-For forged",
			map[string]string{"X-Forwarded-For": "192.0.2.10, 104.16.1.1, 172.72.9.9, 10.104.0.2", "CF-Connecting-IP": "192.0.2.10"}, "172.72.9.9"},
		{"Cloudflare → Caddy", map[string]string{"X-Forwarded-For": "45.155.207.1, 104.16.1.1"}, "45.155.207.1"},
		{"not Cloudflare, CF-Connecting-IP forged", map[string]string{"X-Forwarded-For": "203.0.113.66", "CF-Connecting-IP": "192.0.2.10"}, "203.0.113.66"},
		{"AWS ALB alone", map[string]string{"X-Forwarded-For": "1.2.3.4, 203.0.113.7, 10.0.1.5"}, "203.0.113.7"},
		{"Caddy appending to a missing header", map[string]string{"X-Forwarded-For": ", 203.0.113.8"}, "203.0.113.8"},
		{"RFC 7239 Forwarded", map[string]string{"Forwarded": `for=192.0.2.10, for="[2001:db8::1]:443";proto=https, for=10.0.1.5`}, "2001:db8::1"},
		{"Forwarded with an obfuscated hop stops at the last trusted one", map[string]string{"Forwarded": "for=_hidden, for=10.0.1.5"}, "10.0.1.5"},
		{"X-Real-IP from a trusted proxy", map[string]string{"X-Forwarded-For": "10.0.1.5", "X-Real-IP": "203.0.113.9"}, "203.0.113.9"},
		{"X-Real-IP from anyone else", map[string]string{"X-Forwarded-For": "203.0.113.66", "X-Real-IP": "192.0.2.10"}, "203.0.113.66"},
		{"X-Makit-* headers are not input", map[string]string{"X-Forwarded-For": "203.0.113.66", "X-Makit-Peer": "104.16.1.1",
			"X-Makit-Client": "192.0.2.10"}, "203.0.113.66"},
	}
	for _, c := range cases {
		if got := ask(c.hdr); got != c.client {
			t.Errorf("%s: client %s, want %s", c.name, got, c.client)
		}
	}
}
