package shield

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBatchReport(t *testing.T) {
	p := botPolicy(t, map[string]string{"gptbot": "limit 2/1m"})
	labels := p.Scoring.Labels()
	for k, v := range p.BotScore.Labels() {
		labels[k] = v
	}
	start := time.Date(2026, 5, 21, 14, 40, 0, 0, time.UTC)
	rep := NewReporter(start)
	rep.SetLabels(labels)
	see := func(r Request, status int) {
		d := p.Decide(r)
		if !d.Allow && d.Status == 0 {
			status = 403
		}
		if d.Status != 0 {
			status = d.Status
		}
		rep.Observe(Snapshot{Time: start, Decision: d, Method: r.Method, URI: r.URI, UA: r.UA, Status: status})
	}
	for i := 0; i < 500; i++ { // ordinary visitors
		see(browserReq(clientIP(i)), 200)
	}
	p.Observe = true // this part in observe mode: requests reach the app, which answers 500
	for _, path := range []string{"/wp1/wp-includes/wlwmanifest.xml", "/cms/wp-includes/wlwmanifest.xml",
		"/blog/wp-includes/wlwmanifest.xml", "/wp/wp-includes/wlwmanifest.xml", "/site/wp-includes/wlwmanifest.xml"} {
		r := browserReq("85.204.70.96")
		r.URI, r.UA, r.Headers = path, "", nil
		see(r, 500) // the app errors on unknown paths
	}
	p.Observe = false
	r := browserReq("91.238.181.96")
	r.Method, r.URI, r.Raw, r.UA, r.Headers = "", "", "\\x03\\x00\\x00/*\\xE0\\x00\\x00\\x00\\x00\\x00Cookie: mstshash=Administr", "", nil
	see(r, 400)
	g := browserReq("203.0.113.50") // fake Googlebot (DNS says no)
	g.UA = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	see(g, 200)
	for i := 0; i < 4; i++ {
		q := browserReq(fmt.Sprintf("198.51.100.%d", i))
		q.UA = "GPTBot/1.2"
		see(q, 200)
	}
	rep.Banned(Entry{Prefix: pfx("85.204.70.96/32"), Until: start.Add(24 * time.Hour), Source: "score:critical"})
	b := rep.Flush(start.Add(5*time.Minute), "blogcode.vn")
	t.Log("\n" + b.Text)
	for _, want := range []string{
		"makit shield · blogcode.vn · 2026-05-21 14:40–14:45 UTC",
		"511 requests",
		"85.204.70.96 · 5 req · banned until 05-22 14:40 UTC (score:critical)",
		"(empty or binary request line)", "GPTBot 4 (unverified, 2 denied)",
		"WordPress", "status 500×5",
		"91.238.181.96", "RDP",
		"fake Googlebot",
		"Googlebot 1 (fake, 1 denied)",
		"⚠ your app answered 5xx to 5 suspicious requests",
	} {
		if !strings.Contains(b.Text, want) {
			t.Errorf("report lacks %q", want)
		}
	}
	if strings.Contains(b.Text, clientIP(1)+" ") || strings.Contains(b.Text, "198.51.100.") || strings.Contains(b.Text, "bot:spoofed") {
		t.Error("an ordinary visitor, a rate-limited known bot or a raw bot rule is listed")
	}
	if !b.Worth("critical") || b.Banned != 1 {
		t.Errorf("worth/banned: %v %d", b.Worth("critical"), b.Banned)
	}
	// The next window starts empty; a quiet window is not sent.
	rep.Observe(Snapshot{Decision: Decision{Client: "100.64.0.1", Allow: true, Verdict: "allowed"}, Status: 200})
	if q := rep.Flush(start.Add(10*time.Minute), "x"); q == nil || q.Total != 1 || len(q.IPs) != 0 || q.Worth("high") {
		t.Errorf("quiet window: %+v", q)
	}
	if rep.Flush(start.Add(15*time.Minute), "x") != nil {
		t.Error("an empty window produced a report")
	}
	// Saved and read back with makit shield report.
	dir := t.TempDir()
	if err := b.Save(dir, 30); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(dir, "shield.yaml")
	os.WriteFile(cfg, []byte("report: {dir: "+dir+"}\n"), 0o640)
	if err := cmdReport(cfg, nil); err != nil {
		t.Fatal(err)
	}
}
