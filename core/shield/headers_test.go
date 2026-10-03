package shield

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// headerPolicy is the whole catalog as a server runs it: rules, scoring, bots (no DNS).
func headerPolicy(t *testing.T) *Policy {
	t.Helper()
	StateDir = t.TempDir()
	dirs := []string{repoCatalog}
	rules, err := LoadHTTPRules(dirs)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := LoadScoring(dirs, "", ScoringOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	bs, err := LoadScoringSet(dirs, "bots.yaml", "", ScoringOverrides{})
	if err != nil {
		t.Fatal(err)
	}
	bc, err := LoadBots(dirs, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier()
	v.LookupAddr = nil
	return &Policy{Trusted: []netip.Prefix{pfx("104.16.0.0/13")}, Allow: NewSet(), Block: NewSet(), Lists: NewSet(), Rules: rules,
		Scoring: sc, Tracker: NewTracker(sc, 1000), Bots: bc, BotScore: bs, BotTracker: NewTracker(bs, 1000), Verifier: v,
		Limiter: NewLimiter(), Ban: func(netip.Addr, time.Duration, string, string, string, bool) {}}
}

// Exploits that live in a header, sent the way their public proof-of-concept sends them. Each is stopped by its own
// rule, or scored by its signal, and says so.
func TestHeaderExploitsReplayed(t *testing.T) {
	p := headerPolicy(t)
	cases := []struct {
		name, method, uri, ua string
		hdr                   map[string]string
		want                  string // rule:ID or signal id
		blocked               bool
	}{
		{"CVE-2025-29927, Next.js 13+ (name five times)", "GET", "/dashboard", chromeUA,
			map[string]string{"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"}, "rule:MK-HTTP-NEXT-MIDDLEWARE", true},
		{"CVE-2025-29927, src/ layout", "GET", "/admin", "curl/8.5.0",
			map[string]string{"x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"}, "rule:MK-HTTP-NEXT-MIDDLEWARE", true},
		{"CVE-2025-29927, Next.js 12 (pages/_middleware)", "GET", "/api/private", chromeUA,
			map[string]string{"x-middleware-subrequest": "pages/_middleware"}, "rule:MK-HTTP-NEXT-MIDDLEWARE", true},
		{"CVE-2022-1388 F5 iControl", "POST", "/mgmt/tm/util/bash", "python-requests/2.31.0",
			map[string]string{"content-type": "application/json", "x-f5-auth-token": "a", "connection": "keep-alive, X-F5-Auth-Token"}, "rule:MK-HTTP-F5-ICONTROL", true},
		{"CVE-2022-1388, the token dropped as hop-by-hop by the proxy", "POST", "/mgmt/tm/util/bash", "python-requests/2.31.0",
			map[string]string{"content-type": "application/json"}, "rule:MK-HTTP-F5-ICONTROL", true},
		{"CVE-2022-40684 Fortinet", "PUT", "/api/v2/cmdb/system/admin/admin", "Report Runner",
			map[string]string{"forwarded": `for="[127.0.0.1]:8000";by="[127.0.0.1]:9000";`, "content-type": "application/json"}, "rule:MK-HTTP-FORTINET-AUTH", true},
		{"CVE-2017-5638 Struts S2-045", "GET", "/index.action", "Mozilla/5.0",
			map[string]string{"content-type": "%{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']))).(#cmd='id')}"},
			"rule:MK-HTTP-STRUTS-OGNL", true},
		{"CVE-2022-22963 Spring Cloud Function", "POST", "/functionRouter", "curl/7.88.1",
			map[string]string{"spring.cloud.function.routing-expression": `T(java.lang.Runtime).getRuntime().exec("touch /tmp/pwned")`}, "rule:MK-HTTP-SPRING-CLOUD-FUNCTION", true},
		{"CVE-2019-5418 Rails Accept", "GET", "/robots", "Mozilla/5.0",
			map[string]string{"accept": "../../../../../../../../etc/passwd{{"}, "rule:MK-HTTP-ACCEPT-TRAVERSAL", true},
		{"CVE-2018-14773 X-Rewrite-URL", "GET", "/", chromeUA,
			map[string]string{"x-rewrite-url": "/admin"}, "rule:MK-HTTP-REWRITE-URL", true},
		{"CVE-2014-6271 Shellshock in User-Agent", "GET", "/status", "() { :; }; /bin/bash -c 'cat /etc/passwd'",
			map[string]string{}, "shellshock", true},
		{"CVE-2014-6271 Shellshock in Referer-like header", "GET", "/", chromeUA,
			map[string]string{"x-api-version": "() { ignored;}; echo; /usr/bin/id"}, "shellshock", true},
		{"X-Original-URL from a visitor: scored, not blocked alone", "GET", "/", chromeUA,
			map[string]string{"x-original-url": "/admin"}, "path-override-header", false},
	}
	for i, c := range cases {
		hdr := browserHeaders()
		for k, v := range c.hdr {
			hdr[k] = v
		}
		d := p.Decide(Request{Peer: fmt.Sprintf("203.0.113.%d", 10+i), Method: c.method, Host: "example.com", URI: c.uri, UA: c.ua,
			Headers: hdr, Received: time.Now()})
		found := d.Rule == c.want
		for _, s := range d.Signals {
			found = found || strings.HasPrefix(s, c.want+"+")
		}
		if !found || d.Allow == c.blocked {
			t.Errorf("%s: allow %v rule %q signals %v (%s), want %s blocked=%v", c.name, d.Allow, d.Rule, d.Signals, d.Reason, c.want, c.blocked)
		}
	}
}

// What real clients send must never trip the header rules: browsers (with client hints, fetch metadata, prefetch),
// CDNs and load balancers, API clients, uploads, tracing.
func TestHeaderRulesSpareRealTraffic(t *testing.T) {
	p := headerPolicy(t)
	safari := "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Mobile/15E148 Safari/604.1"
	firefox := "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"
	cases := []struct {
		name, method, uri, ua string
		hdr                   map[string]string
	}{
		{"Chrome navigation with client hints and prefetch", "GET", "/pricing", chromeUA, map[string]string{
			"accept":             "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
			"sec-ch-ua-platform": `"macOS"`, "sec-ch-ua-mobile": "?0", "sec-fetch-site": "same-origin", "sec-fetch-dest": "document",
			"sec-fetch-user": "?1", "sec-purpose": "prefetch;prerender", "priority": "u=0, i", "upgrade-insecure-requests": "1", "sec-gpc": "1"}},
		{"Safari XHR", "POST", "/api/goesvn/graphql", safari, map[string]string{"accept": "application/json, text/plain, */*",
			"content-type": "application/json; charset=utf-8", "origin": "https://app.example.com"}},
		{"Firefox upload", "POST", "/upload", firefox, map[string]string{"accept": "*/*",
			"content-type": "multipart/form-data; boundary=----geckoformboundary7f3a9c2e1d"}},
		{"behind Cloudflare and an ALB, with tracing", "GET", "/", chromeUA, map[string]string{"cf-ray": "8d1c2e3f4a5b6c7d-SIN",
			"cf-visitor": `{"scheme":"https"}`, "cf-ipcountry": "VN", "cdn-loop": "cloudflare", "x-amzn-trace-id": "Root=1-67891233-abcdef012345678912345678",
			"x-forwarded-proto": "https", "x-forwarded-port": "443", "via": "1.1 google", "traceparent": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
			"forwarded": `for=198.51.100.17;proto=https;by=10.0.1.5`}},
		{"webhook with a JSON body", "POST", "/api/goesvn/webhooks/stripe", "Stripe/1.0 (+https://stripe.com/docs/webhooks)", map[string]string{
			"content-type": "application/json; charset=utf-8", "stripe-signature": "t=1492774577,v1=5257a869e7ecebeda32affa62cdca3fa51cad7e77a0e56ff536d0ce8e108d8bd"}},
		{"a JavaScript snippet in the Referer and query", "GET", "/share?code=" + "const f = () => { return 1; };", chromeUA, map[string]string{
			"referer": "https://codepen.io/pen/?code=function()%20{a;};"}},
		{"a Next.js app's own RSC request", "GET", "/dashboard?_rsc=1x2y3", chromeUA, map[string]string{"rsc": "1",
			"next-router-state-tree": "%5B%22%22%2C%7B%22children%22%3A%5B%22dashboard%22%5D%7D%5D", "next-url": "/dashboard"}},
		{"Accept with a vendor media type", "GET", "/api/v2/users", "okhttp/4.12.0", map[string]string{"accept": "application/vnd.github+json"}},
	}
	for i, c := range cases {
		hdr := browserHeaders()
		for k, v := range c.hdr {
			hdr[k] = v
		}
		d := p.Decide(Request{Peer: fmt.Sprintf("198.51.100.%d", 100+i), Method: c.method, Host: "example.com", URI: c.uri, UA: c.ua,
			Headers: hdr, Received: time.Now()})
		if !d.Allow || d.Rule != "" || d.Level == "high" || d.Level == "critical" {
			t.Errorf("%s: %s rule %q signals %v level %s", c.name, d.Verdict, d.Rule, d.Signals, d.Level)
		}
	}
}

// In ask mode the asking proxy writes headers about the request (its method, URI, host; ingress-nginx the original
// URL): they are not the visitor's and score nothing. A visitor's own X-Original-URL still counts.
func TestAskProtocolHeadersAreNotTheVisitors(t *testing.T) {
	header := func(kv ...string) (http.Header, map[string]string) {
		h, hm := http.Header{}, map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			h.Set(kv[i], kv[i+1])
			hm[strings.ToLower(kv[i])] = kv[i+1]
		}
		return h, hm
	}
	for name, kv := range map[string][]string{
		"ingress-nginx":           {"X-Original-URL", "https://app.example.com/pricing?x=1", "X-Original-Method", "GET"},
		"traefik":                 {"X-Forwarded-Uri", "/pricing?x=1", "X-Forwarded-Host", "app.example.com", "X-Forwarded-Method", "GET"},
		"caddy, the URL repeated": {"X-Forwarded-Uri", "/pricing?x=1", "X-Original-URL", "/pricing?x=1"},
	} {
		h, hm := header(kv...)
		askOnly(hm, h, "/pricing?x=1")
		if len(hm) != 0 {
			t.Errorf("%s: left for rules to read: %v", name, hm)
		}
	}
	h, hm := header("X-Forwarded-Uri", "/", "X-Original-URL", "/admin")
	askOnly(hm, h, "/")
	if hm["x-original-url"] != "/admin" {
		t.Error("a visitor's own X-Original-URL must stay to be judged")
	}
	// Through the gate: neither request is blocked (the visitor's X-Original-URL only scores 40, a log line).
	g := askingGate(t)
	g.policy.Store(headerPolicy(t))
	ch := g.checkHandler()
	for _, c := range []struct{ kv []string }{
		{[]string{"X-Forwarded-For", "198.51.100.30", "X-Original-URL", "https://app.example.com/pricing", "X-Original-Method", "GET"}},
		{[]string{"X-Forwarded-For", "198.51.100.31", "X-Forwarded-Uri", "/", "X-Original-URL", "/admin"}},
	} {
		r := httptest.NewRequest("GET", "http://172.17.0.1:9180/check", nil)
		r.RemoteAddr = "172.18.0.5:40000"
		r.Header, _ = header(c.kv...)
		r.Header.Set("User-Agent", chromeUA)
		w := httptest.NewRecorder()
		ch.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Errorf("%v: %d (a score of 40 only logs)", c.kv, w.Code)
		}
	}
}
