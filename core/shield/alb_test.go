package shield

import (
	"bufio"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Lines in the format of the AWS documentation (Elastic Load Balancing, "Access logs for your Application Load
// Balancer"), with addresses from the documentation ranges.
const albLog = `https 2026-10-03T09:00:01.186641Z app/my-loadbalancer/50dc6c495c0c9188 203.0.113.9:2817 10.0.0.1:80 0.086 0.048 0.037 404 404 0 57 "GET https://shop.example:443/.env HTTP/1.1" "curl/8.4.0" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337262-36d228ad5d99923122bbe354" "shop.example" "arn:aws:acm:us-east-2:123456789012:certificate/12345678-1234-1234-1234-123456789012" 0 2026-10-03T09:00:01.100000Z "forward" "-" "-" "10.0.0.1:80" "404" "-" "-" TID_1234abcd
h2 2026-10-03T09:00:02.000000Z app/my-loadbalancer/50dc6c495c0c9188 198.51.100.20:41000 10.0.0.1:80 0.001 0.020 0.001 200 200 34 366 "GET https://shop.example:443/products?page=2 HTTP/2.0" "Mozilla/5.0 (Windows NT 10.0) Chrome/126" ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/my-targets/73e2d6bc24d8a067 "Root=1-58337364-23a8c76965a2ef7629b185e3" "shop.example" "-" 1 2026-10-03T09:00:01.990000Z "forward" "-" "-" "10.0.0.1:80" "200" "-" "-" TID_5678
http 2026-10-03T09:00:03.000000Z app/my-loadbalancer/50dc6c495c0c9188 192.0.2.7:500 - -1 -1 -1 400 - 0 0 "- - - " "-" - - - "-" "-" "-" - 2026-10-03T09:00:03.000000Z "-" "-" "-" "-" "-" "-" "-" -`

func TestParseALB(t *testing.T) {
	lines := strings.Split(albLog, "\n")
	l, ok := parseLogLine(lines[0], "auto")
	if !ok || l.Format != "alb" || l.Peer != "203.0.113.9:2817" || l.Method != "GET" || l.URI != "/.env" || l.Host != "shop.example" ||
		l.Status != 404 || l.UA != "curl/8.4.0" || !l.Received.Equal(time.Date(2026, 10, 3, 9, 0, 1, 186641000, time.UTC)) {
		t.Errorf("https line: %+v", l)
	}
	l, ok = parseLogLine(lines[1], "alb")
	if !ok || l.URI != "/products?page=2" || l.Status != 200 || l.Headers != nil {
		t.Errorf("h2 line: %+v", l)
	}
	// A request the ALB could not parse still counts as the client's request (status 400), with no method.
	if l, ok = parseLogLine(lines[2], "auto"); !ok || l.Status != 400 || l.Method != "" {
		t.Errorf("malformed request line: %+v %v", l, ok)
	}
	// An nginx line is not taken for an ALB one.
	if l, ok := parseLogLine(`203.0.113.9 - - [03/Oct/2026:09:00:01 +0000] "GET / HTTP/1.1" 200 5 "-" "curl/8"`, "auto"); !ok || l.Format != "nginx" {
		t.Errorf("nginx line: %+v", l)
	}
}

// ALB logs arrive gzipped, one file per 5 minutes per node: a .gz file and a directory of them read as one log.
func TestOpenLogGzipAndDirectory(t *testing.T) {
	dir := t.TempDir()
	lines := strings.Split(albLog, "\n")
	for i, l := range lines[:2] {
		f, err := os.Create(filepath.Join(dir, "123456789012_elasticloadbalancing_us-east-2_app.my-lb_2026100"+string(rune('0'+i))+".log.gz"))
		if err != nil {
			t.Fatal(err)
		}
		zw := gzip.NewWriter(f)
		_, _ = zw.Write([]byte(l + "\n"))
		_ = zw.Close()
		_ = f.Close()
	}
	_ = os.WriteFile(filepath.Join(dir, "README.txt"), []byte("not a log"), 0o644)
	for _, path := range []string{dir, filepath.Join(dir, "123456789012_elasticloadbalancing_us-east-2_app.my-lb_20261000.log.gz")} {
		r, err := openLog(path)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if l, ok := parseLogLine(sc.Text(), "auto"); ok {
				got = append(got, l.URI)
			}
		}
		r.Close()
		want := "/.env /products?page=2"
		if path != dir {
			want = "/.env"
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%s: %v", filepath.Base(path), got)
		}
	}
	// replay reads ALB logs the same way: the probe is blocked by both configs, the browser by neither.
	cur, _ := ParseConfig([]byte("mode: observe\n"), "cur")
	a, ac, err := replayPolicy(cur, []string{repoCatalog}, &State{}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	b, bc, _ := replayPolicy(cur, []string{repoCatalog}, &State{}, NewSet())
	r, _ := openLog(dir)
	defer r.Close()
	res, err := Replay(a, b, ac, bc, r, "auto", 5)
	if err != nil || res.Requests != 2 || res.Unchanged != 2 {
		t.Errorf("replay of an ALB directory: %+v %v", res, err)
	}
}

// A browser in a log that records only the User-Agent (ALB, nginx combined) is not scored for the headers the log
// never had: no bot score, no level, through every request of a session.
func TestHeaderlessLogsDoNotScoreBrowsers(t *testing.T) {
	cfg, _ := ParseConfig([]byte("mode: block\nbots:\n  score:\n    actions: { suspect: block, likely: block, bot: block }\n"), "c")
	p, clock, err := replayPolicy(cfg, []string{repoCatalog}, &State{}, NewSet())
	if err != nil {
		t.Fatal(err)
	}
	alb := strings.Split(albLog, "\n")[1]
	nginx := `198.51.100.21 - - [03/Oct/2026:09:00:02 +0000] "GET /products HTTP/1.1" 200 5 "https://shop.example/" "Mozilla/5.0 (Windows NT 10.0) Chrome/126"`
	for _, line := range []string{alb, nginx} {
		l, _ := parseLogLine(line, "auto")
		for i := 0; i < 30; i++ {
			*clock = l.Received
			if d := p.Decide(l.Request); !d.Allow || d.Bot != nil {
				t.Fatalf("%s: request %d of a browser: %+v (bot %+v)", l.Format, i, d, d.Bot)
			}
		}
	}
}
