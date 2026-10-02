package shield

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const nginxLog = `85.204.70.96 - - [21/May/2026:14:24:01 +0000] "GET /wp1/wp-includes/wlwmanifest.xml HTTP/1.1" 500 0 "-" "-"
85.204.70.96 - - [21/May/2026:14:24:02 +0000] "GET /cms/wp-includes/wlwmanifest.xml HTTP/1.1" 500 0 "-" "-"
85.204.70.96 - - [21/May/2026:14:24:03 +0000] "\x16\x03\x01\x02\x00\x01\x00\x01\xFC\x03\x03" 400 157 "-" "-"
91.238.181.96 - - [21/May/2026:14:26:11 +0000] "\x03\x00\x00/*\xE0\x00\x00\x00\x00\x00Cookie: mstshash=Administr" 400 157 "-" "-"
172.70.1.2 - - [21/May/2026:14:27:00 +0000] "GET /blog/x HTTP/1.1" 200 5120 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0 Safari/537.36" "203.0.113.70" "example.com"
198.51.100.4 - - [21/May/2026:14:28:00 +0000] "GET /?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1" 200 10 "-" "Mozilla/5.0 Chrome/126.0"
192.0.2.1 - - [21/May/2026:14:28:30 +0000] "" 400 0 "-" "-"
garbage line
198.51.100.5 - - [21/May/2026:14:52:00 +0000] "GET /.env HTTP/1.1" 404 10 "-" "curl/8.5"
`

const caddyLog = `{"level":"info","ts":1779374700.5,"logger":"http.log.access","msg":"handled request","request":{"remote_ip":"198.51.100.9","client_ip":"198.51.100.9","proto":"HTTP/1.1","method":"GET","host":"example.com","uri":"/.git/config","headers":{"User-Agent":["Mozilla/5.0 Chrome/120.0"],"Cookie":["secret=1"]}},"status":404}
`

func runAnalyze(t *testing.T, log string, args ...string) string {
	t.Helper()
	StateDir = t.TempDir()
	f := filepath.Join(t.TempDir(), "access.log")
	os.WriteFile(f, []byte(log), 0o644)
	cfg := filepath.Join(t.TempDir(), "shield.yaml")
	os.WriteFile(cfg, []byte("trusted_proxies: [172.64.0.0/13]\n"), 0o640)
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := cmdAnalyze(cfg, []string{repoCatalog}, append([]string{f, "--verify=false"}, args...))
	w.Close()
	os.Stdout = old
	var b bytes.Buffer
	io.Copy(&b, r)
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func TestAnalyzeNginx(t *testing.T) {
	out := runAnalyze(t, nginxLog)
	t.Log("\n" + out)
	for _, want := range []string{
		"2026-05-21 14:20–14:25 UTC", "85.204.70.96", "WordPress probing ×2", "TLS handshake",
		"2026-05-21 14:25–14:30 UTC", "91.238.181.96", "RDP scan",
		"198.51.100.4", "XSS (script/svg tag)",
		"would block", "⚠ your app answered 5xx to 2 suspicious requests",
		"2026-05-21 14:50–14:55 UTC", "198.51.100.5",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("analysis lacks %q", want)
		}
	}
	if strings.Contains(out, "203.0.113.70") || strings.Contains(out, "172.70.1.2 ") {
		t.Error("an ordinary visitor (behind Cloudflare) is listed")
	}
	if strings.Contains(out, "14:30–14:35") {
		t.Error("an empty window was printed")
	}
	if st, _ := LoadState(); len(st.Block) != 0 {
		t.Error("analysis without --ban banned")
	}
}

func TestAnalyzeBanAndCaddy(t *testing.T) {
	out := runAnalyze(t, nginxLog, "--ban", "--quiet")
	st, _ := LoadState()
	if len(st.Block) == 0 || !strings.Contains(out, "banned until") {
		t.Errorf("--ban: %d bans\n%s", len(st.Block), out)
	}
	out = runAnalyze(t, caddyLog, "--json")
	if !strings.Contains(out, `"ip":"198.51.100.9"`) || strings.Contains(out, "secret") {
		t.Errorf("caddy json: %s", out)
	}
}

func TestParseLogLines(t *testing.T) {
	l, ok := parseLogLine(`1.2.3.4 - - [21/May/2026:14:24:01 +0700] "GET /a?b=1 HTTP/2.0" 301 0 "https://r/" "UA \"quoted\"" "-" "h.example"`, "auto")
	if !ok || l.Method != "GET" || l.URI != "/a?b=1" || l.Status != 301 || l.UA != `UA \"quoted\"` || l.Client != "" || l.Host != "h.example" ||
		l.Received.UTC().Hour() != 7 {
		t.Errorf("nginx: %+v", l)
	}
	if _, ok := parseLogLine("not a log line", "auto"); ok {
		t.Error("garbage parsed")
	}
}
