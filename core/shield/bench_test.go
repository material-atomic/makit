package shield

// Benchmarks behind benchmark/README.md. Run them all with ./benchmark/run.sh micro, or:
//   go test -run '^$' -bench . -benchmem ./shield

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// benchPolicy is a production-like gate: 1M listed IPs, 100 bans, catalog rules, scoring, bot catalog with
// Googlebot's ranges loaded, bot score, Cloudflare trusted.
func benchPolicy(b *testing.B) *Policy {
	b.Helper()
	StateDir = b.TempDir()
	dirs := []string{repoCatalog}
	lists := NewSet()
	ps := make([]netip.Prefix, 0, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	lists.AddMany(ps, time.Time{}, "feed", "list:bench")
	block := NewSet()
	for i := 0; i < 100; i++ {
		block.Add(Entry{Prefix: netip.PrefixFrom(netip.AddrFrom4([4]byte{198, 18, byte(i), 0}), 24), Source: "manual"})
	}
	rules, err := LoadHTTPRules(dirs)
	if err != nil {
		b.Fatal(err)
	}
	sc, err := LoadScoring(dirs, "", ScoringOverrides{})
	if err != nil {
		b.Fatal(err)
	}
	bs, err := LoadScoringSet(dirs, "bots.yaml", "", ScoringOverrides{})
	if err != nil {
		b.Fatal(err)
	}
	bc, err := LoadBots(dirs, "", nil)
	if err != nil {
		b.Fatal(err)
	}
	os.MkdirAll(botsDir(), 0o755)
	os.WriteFile(filepath.Join(botsDir(), feedFile("googlebot", "https://developers.google.com/static/search/apis/ipranges/googlebot.json")),
		[]byte("66.249.64.0/19\n"), 0o644)
	v := NewVerifier()
	v.LoadRanges(bc)
	cf, _ := ParsePrefix("173.245.48.0/20")
	return &Policy{Trusted: []netip.Prefix{cf}, Allow: NewSet(), Block: block, Lists: lists, Rules: rules,
		Scoring: sc, Tracker: NewTracker(sc, 200000), Bots: bc, BotScore: bs, BotTracker: NewTracker(bs, 200000),
		Verifier: v, Limiter: NewLimiter()}
}

// clientIP spreads requests over 100k visitors (public addresses outside the list).
func clientIP(i int) string {
	i %= 100_000
	return fmt.Sprintf("100.%d.%d.%d", 64+(i>>16)&63, (i>>8)&255, i&255)
}

func browserReq(peer string) Request {
	return Request{Peer: peer, Method: "GET", Host: "example.com", URI: "/blog/how-to-harden-ssh?ref=home", UA: chromeUA,
		Referer: "https://example.com/", Headers: browserHeaders(), Received: time.Now()}
}

func BenchmarkDecide(b *testing.B) {
	p := benchPolicy(b)
	cases := []struct {
		name string
		req  func(i int) Request
	}{
		{"browser", func(i int) Request { return browserReq(clientIP(i)) }},
		{"browser-via-cloudflare", func(i int) Request {
			r := browserReq("173.245.48.10")
			r.Client = clientIP(i)
			return r
		}},
		{"listed-ip-1M", func(i int) Request { return browserReq(fmt.Sprintf("11.%d.%d.%d", (i>>16)&15, (i>>8)&255, i&255)) }},
		{"attack-xss", func(i int) Request {
			r := browserReq(clientIP(i))
			r.URI = "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
			return r
		}},
		{"probe-dotenv", func(i int) Request {
			r := browserReq(clientIP(i))
			r.URI = "/.env"
			return r
		}},
		{"googlebot-verified", func(i int) Request {
			r := browserReq(fmt.Sprintf("66.249.%d.%d", 64+(i>>8)&31, i&255))
			r.UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
			return r
		}},
		{"undeclared-bot", func(i int) Request {
			r := browserReq(clientIP(i))
			r.Headers = map[string]string{}
			return r
		}},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			reqs := make([]Request, 4096)
			for i := range reqs {
				reqs[i] = c.req(i * 7919)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p.Decide(reqs[i&4095])
			}
		})
	}
}

func BenchmarkDecideParallel(b *testing.B) {
	p := benchPolicy(b)
	reqs := make([]Request, 4096)
	for i := range reqs {
		reqs[i] = browserReq(clientIP(i * 7919))
	}
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			p.Decide(reqs[i&4095])
			i++
		}
	})
}

func BenchmarkScore(b *testing.B) {
	p := benchPolicy(b)
	r := browserReq("100.64.0.1")
	b.Run("http", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p.Scoring.ScoreRequest(r, 0)
		}
	})
	b.Run("bots", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p.BotScore.ScoreRequest(r, 0)
		}
	})
}

func BenchmarkIdentifyBot(b *testing.B) {
	p := benchPolicy(b)
	for name, ua := range map[string]string{"browser": chromeUA, "googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1)",
		"last-in-catalog": "Mozilla/5.0 (compatible; SomeNewBot/0.1)"} {
		b.Run(name, func(b *testing.B) {
			r := Request{UA: ua, Headers: browserHeaders()}
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p.Bots.Identify(r)
			}
		})
	}
}

func BenchmarkBotIPIndex1M(b *testing.B) {
	StateDir = b.TempDir()
	cfg := BotsConfig{}
	bc, err := LoadBotsConfig([]string{repoCatalog}, cfg)
	if err != nil {
		b.Fatal(err)
	}
	ps := make([]netip.Prefix, 0, 1_000_000)
	for i := 0; i < 1_000_000; i++ {
		ps = append(ps, netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(11 + i>>24), byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	a := &Agent{ID: "big-feed", Category: "monitoring", ByIP: true, feeds: []feed{{URL: "x", File: "big.txt"}}}
	bc.Agents = append(bc.Agents, a)
	os.MkdirAll(botsDir(), 0o755)
	if err := writePrefixes(filepath.Join(botsDir(), "big.txt"), "bench", ps); err != nil {
		b.Fatal(err)
	}
	v := NewVerifier()
	start := time.Now()
	v.LoadRanges(bc)
	b.ReportMetric(float64(time.Since(start).Milliseconds()), "ms-load")
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v.ByIP(netip.AddrFrom4([4]byte{byte(11 + (i>>24)&3), byte(i >> 16), byte(i >> 8), byte(i)}), now)
	}
}

// BenchmarkCheckEndpoint is one Caddy forward_auth / nginx auth_request call, with the snapshot written to disk.
func BenchmarkCheckEndpoint(b *testing.B) {
	p := benchPolicy(b)
	rec, err := NewRecorder(filepath.Join(b.TempDir(), "requests.jsonl"), 50, 2)
	if err != nil {
		b.Fatal(err)
	}
	g := &Gate{rec: rec, stats: map[string]int64{}}
	g.policy.Store(p)
	g.ask.Store(true)
	h := g.checkHandler()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest("GET", "http://127.0.0.1:9180/check", nil)
		r.RemoteAddr = "127.0.0.1:50000"
		r.Header.Set("X-Forwarded-For", clientIP(i))
		r.Header.Set("X-Forwarded-Uri", "/blog/how-to-harden-ssh")
		r.Header.Set("X-Forwarded-Method", "GET")
		r.Header.Set("User-Agent", chromeUA)
		for k, v := range browserHeaders() {
			r.Header.Set(k, v)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			b.Fatalf("status %d", w.Code)
		}
	}
}
