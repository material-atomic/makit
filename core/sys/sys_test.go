package sys

import (
	"os"
	"path/filepath"
	"testing"
)

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

func TestReaders(t *testing.T) {
	r := t.TempDir()
	write(t, r, "proc/stat", "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 50 0 25 400 25 0 0 0 0 0\ncpu1 50 0 25 400 25 0 0 0 0 0\nintr 1\n")
	write(t, r, "proc/meminfo", "MemTotal: 1000 kB\nMemFree: 100 kB\nMemAvailable: 400 kB\nSwapTotal: 200 kB\nSwapFree: 150 kB\n")
	write(t, r, "proc/loadavg", "0.50 0.40 0.30 2/300 999\n")
	write(t, r, "proc/1/stat", "1 (my (weird) proc) S 0 1 1 0 -1 4194560 1 0 0 0 30 20 0 0 20 0 3 0 10 100000 25 0\n")
	write(t, r, "proc/1/cmdline", "/usr/bin/x\x00--flag\x00")
	write(t, r, "proc/1/status", "Name:\tx\nUid:\t0\t0\t0\t0\n")
	write(t, r, "etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")

	total, cores, err := Root(r).ReadCPU()
	if err != nil || total.Total() != 1000 || len(cores) != 2 {
		t.Fatalf("cpu %+v %d %v", total, len(cores), err)
	}
	if u := Usage(CPUTimes{Idle: 100}, CPUTimes{User: 50, Idle: 150}); u != 0.5 {
		t.Fatalf("usage %v", u)
	}
	m, _ := Root(r).ReadMem()
	if m.Used() != 600*1024 || m.SwapUsed() != 50*1024 {
		t.Fatalf("mem %+v", m)
	}
	h := Root(r).ReadHost()
	if h.Load[0] != 0.5 || h.Running != 2 || h.Total != 300 {
		t.Fatalf("host %+v", h)
	}
	ps, _ := Root(r).ReadProcs(Root(r).Users())
	if len(ps) != 1 || ps[0].Name != "my (weird) proc" || ps[0].Ticks != 50 || ps[0].User != "root" || ps[0].Cmd != "/usr/bin/x --flag" || ps[0].Threads != 3 {
		t.Fatalf("procs %+v", ps)
	}
}

func TestParsers(t *testing.T) {
	ms := ParseMounts([]string{"/dev/vda1 / ext4 rw 0 0", "proc /proc proc rw 0 0", "/dev/sda /mnt/my\\040data ext4 rw 0 0", "/dev/vda1 /var/lib/docker/x ext4 rw 0 0"})
	if len(ms) != 2 || ms[1].Path != "/mnt/my data" {
		t.Fatalf("mounts %+v", ms)
	}
	us := ParseUnits("ssh.service loaded active running OpenBSD Secure Shell server\nfoo.socket loaded active listening x\n")
	if len(us) != 1 || us[0].Description != "OpenBSD Secure Shell server" {
		t.Fatalf("units %+v", us)
	}
	mux := append([]byte{1, 0, 0, 0, 0, 0, 0, 6}, []byte("hello\n")...)
	mux = append(mux, append([]byte{2, 0, 0, 0, 0, 0, 0, 4}, []byte("err\n")...)...)
	if got := DemuxLogs(mux); got != "hello\nerr\n" {
		t.Fatalf("demux %q", got)
	}
	if StripANSI("\x1b[1m▶ x\x1b[0m") != "▶ x" {
		t.Fatal("ansi")
	}
}
