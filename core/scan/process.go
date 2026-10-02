package scan

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var tempPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/", "/run/user/", "/var/run/user/"}
var systemNames = map[string]bool{"vim": true, "vi": true, "sshd": true, "systemd": true, "crond": true, "cron": true, "bash": true,
	"sh": true, "nginx": true, "httpd": true, "apache2": true, "php-fpm": true, "node": true, "python": true, "python3": true,
	"dbus-daemon": true, "rsyslogd": true, "kthreadd": true, "kworker": true, "ksoftirqd": true, "top": true, "ps": true, "docker": true,
	"containerd": true, "dockerd": true, "init": true, "agetty": true, "atd": true, "irqbalance": true, "udevd": true, "systemd-journald": true}
var minerPorts = map[int]bool{3333: true, 4444: true, 5555: true, 6666: true, 7777: true, 9999: true, 14433: true, 14444: true, 45560: true, 45700: true}
var cidRe = regexp.MustCompile(`[0-9a-f]{64}`)

func inTemp(p string) bool {
	for _, t := range tempPrefixes {
		if strings.HasPrefix(p, t) {
			return true
		}
	}
	return false
}

// hidden reports a path with a dot-directory or dot-file component (/tmp/.X/…, /root/.cache/x is fine).
func hidden(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if strings.HasPrefix(part, ".") && part != "." && part != ".." && part != ".cache" && part != ".local" &&
			part != ".config" && part != ".npm" && part != ".nvm" && part != ".cargo" && part != ".rustup" && part != ".vscode-server" {
			return true
		}
	}
	return false
}

func (s *scanner) containerOf(pid int) string {
	b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	id := cidRe.FindString(string(b))
	if id == "" {
		return ""
	}
	if n, ok := s.contOf[id]; ok {
		return n
	}
	return id[:12]
}

type sock struct {
	local, remote string
	rport         int
	state         string
}

func (s *scanner) processes(allProcs bool, targets []target) {
	want := map[string]bool{}
	for _, t := range targets {
		want[t.name] = true
	}
	ents, _ := os.ReadDir("/proc")
	inodePid := map[string]int{}
	netns := map[string]int{} // net namespace → one pid inside it
	type pinfo struct {
		target, exe, argv0 string
		temp               bool
	}
	procs := map[int]pinfo{}
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == os.Getpid() {
			continue
		}
		base := fmt.Sprintf("/proc/%d/", pid)
		tname := "host"
		if c := s.containerOf(pid); c != "" {
			tname = "container:" + c
		}
		if !allProcs && !want[tname] {
			continue
		}
		s.rep.Stats.Processes++
		cmd, _ := os.ReadFile(base + "cmdline")
		args := strings.Split(strings.TrimRight(string(cmd), "\x00"), "\x00")
		argv0, cmdline := args[0], strings.Join(args, " ")
		exe, err := os.Readlink(base + "exe")
		if err != nil {
			continue // kernel thread, or not visible without root
		}
		deleted := strings.HasSuffix(exe, " (deleted)")
		path := strings.TrimSuffix(exe, " (deleted)")
		f := Finding{Target: tname, Kind: "process", PID: pid, Path: path, Evidence: []string{"cmdline: " + clip(cmdline, 160)}}
		report := func(sev Severity, title string, ev ...string) {
			g := f
			g.Severity, g.Title, g.Evidence = sev, title, append(append([]string{}, f.Evidence...), ev...)
			s.rep.add(g)
		}
		memfd := strings.HasPrefix(path, "/memfd:")
		temp := inTemp(path) || hidden(path)
		switch {
		case memfd:
			report(Medium, "Process runs from memory only (memfd, no file on disk)")
		case deleted && temp:
			report(Critical, "Process runs a deleted executable from a temporary/hidden path (dropper pattern: run then rm)")
		case deleted:
			report(Low, "Process runs an executable that was replaced or deleted (often just an update: restart it)")
		case temp:
			report(High, "Process runs from a temporary or hidden directory")
		}
		if strings.HasPrefix(argv0, "[") && strings.HasSuffix(strings.Fields(argv0 + " x")[0], "]") {
			report(High, "User process disguised as a kernel thread", "kernel threads have no executable; this one runs "+exe)
		}
		n0, ne := filepath.Base(strings.Fields(argv0 + " x")[0]), filepath.Base(path)
		if systemNames[n0] && n0 != ne && !strings.HasPrefix(ne, n0) && (temp || deleted || memfd) {
			report(High, fmt.Sprintf("Process name %q does not match its executable %q", n0, ne))
		}
		if note, ok := s.iocs.path[path]; ok {
			report(Critical, "Process runs a known malware path", note)
		}
		for _, i := range s.iocs.Strings {
			if strings.Contains(cmdline, i.Value) {
				report(Critical, "Process command line contains a known indicator", i.Value+" — "+i.Note)
			}
		}
		// Hash what actually runs (/proc/<pid>/exe works even after rm). Skip large system binaries for speed.
		if temp || deleted || memfd || !strings.HasPrefix(path, "/usr/") {
			if sum := s.sha256(base + "exe"); sum != "" {
				if note, ok := s.iocs.sha[sum]; ok {
					report(Critical, "Process executable matches known malware (SHA256)", sum, note)
				}
			}
		}
		procs[pid] = pinfo{tname, exe, argv0, temp || deleted || memfd}
		if ns, err := os.Readlink(base + "ns/net"); err == nil {
			if _, ok := netns[ns]; !ok {
				netns[ns] = pid
			}
		}
		fds, _ := os.ReadDir(base + "fd")
		for _, fd := range fds {
			if l, err := os.Readlink(base + "fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
				inodePid[l[8:len(l)-1]] = pid
			}
		}
	}

	for _, pid := range netns {
		for _, file := range []string{"tcp", "tcp6"} {
			for ino, sk := range readSockets(fmt.Sprintf("/proc/%d/net/%s", pid, file)) {
				s.rep.Stats.Sockets++
				owner, ok := inodePid[ino]
				if !ok {
					continue
				}
				p := procs[owner]
				ip, _, _ := net.SplitHostPort(sk.remote)
				f := Finding{Target: p.target, Kind: "network", PID: owner, Path: p.exe,
					Evidence: []string{fmt.Sprintf("%s → %s (%s)", sk.local, sk.remote, sk.state)}}
				if note, ok := s.iocs.ip[ip]; ok {
					f.Severity, f.Title = Critical, "Connection to a known malicious IP"
					f.Evidence = append(f.Evidence, note)
					s.rep.add(f)
				} else if minerPorts[sk.rport] {
					f.Severity, f.Title = Medium, fmt.Sprintf("Outbound connection to port %d (common for miners/backdoors)", sk.rport)
					s.rep.add(f)
				} else if p.temp {
					f.Severity, f.Title = High, "Process from a temporary/deleted executable has a network connection"
					s.rep.add(f)
				}
			}
		}
	}
}

var tcpStates = map[string]string{"01": "ESTABLISHED", "02": "SYN_SENT"}

// readSockets returns outbound-looking TCP sockets (established / connecting) by inode.
func readSockets(path string) map[string]sock {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	out := map[string]sock{}
	for _, l := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		st, ok := tcpStates[f[3]]
		if !ok {
			continue
		}
		lip, _ := hexAddr(f[1])
		rip, rport := hexAddr(f[2])
		if rip == "" || strings.HasPrefix(rip, "127.") || rip == "::1" {
			continue
		}
		out[f[9]] = sock{lip, net.JoinHostPort(rip, strconv.Itoa(rport)), rport, st}
	}
	return out
}

// hexAddr decodes /proc/net/tcp "0100007F:0050" (little-endian words) into ip:port.
func hexAddr(s string) (string, int) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0
	}
	port, _ := strconv.ParseUint(p, 16, 16)
	b, err := hex.DecodeString(h)
	if err != nil || (len(b) != 4 && len(b) != 16) {
		return "", 0
	}
	for i := 0; i < len(b); i += 4 {
		b[i], b[i+1], b[i+2], b[i+3] = b[i+3], b[i+2], b[i+1], b[i]
	}
	ip := net.IP(b)
	if v4 := ip.To4(); v4 != nil {
		return v4.String(), int(port)
	}
	return ip.String(), int(port)
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
