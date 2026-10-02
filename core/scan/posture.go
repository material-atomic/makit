package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/material-atomic/makit/core/sys"
)

// Posture checks read configuration only (files, /proc, and read-only commands such as `sshd -T`, `ufw status`,
// `iptables -S`, `apt-get -s`). Host checks run when the host is a target; container checks for each scanned container.

func runRO(name string, args ...string) (string, bool) {
	if _, err := exec.LookPath(name); err != nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err == nil
}

// riskyPorts are services that should never face the internet directly.
var riskyPorts = map[int]string{
	2375: "Docker API (root on the host)", 2376: "Docker API (TLS)", 2379: "etcd", 3306: "MySQL/MariaDB", 5432: "PostgreSQL",
	5601: "Kibana", 5672: "RabbitMQ", 6379: "Redis", 8123: "ClickHouse HTTP", 8500: "Consul", 9000: "ClickHouse native / MinIO",
	9090: "Prometheus", 9092: "Kafka", 9200: "Elasticsearch/OpenSearch", 9300: "Elasticsearch transport", 11211: "Memcached",
	15672: "RabbitMQ management", 27017: "MongoDB", 7233: "Temporal", 8233: "Temporal UI", 4317: "OTLP gRPC",
}

func (s *scanner) posture(host bool, containers []target) {
	if host {
		s.hostPosture()
	}
	s.containerPosture(host, containers)
}

func (s *scanner) hostPosture() {
	t := "host"
	f := func(kind, path string) Finding { return Finding{Target: t, Kind: kind, Path: path} }

	// SSH (effective configuration).
	if out, ok := runRO("sshd", "-T"); ok {
		for _, is := range sshIssues(parseKV(out)) {
			s.emit(is.id, f("config", "sshd -T"), "", nil, is.ev)
		}
	}

	// Firewall.
	if !firewallActive() {
		s.emit("MK-FW-INACTIVE", f("config", "firewall"), "", nil, "ufw inactive and no INPUT drop policy found")
	}

	// Services listening on every interface.
	pids := socketOwners()
	for _, l := range listeners("/proc/net/tcp", "/proc/net/tcp6") {
		name, risky := riskyPorts[l.port]
		if !risky || !l.public {
			continue
		}
		owner := pids[l.inode]
		if owner == "docker-proxy" {
			continue // reported per container below
		}
		id := "MK-NET-PUBLIC-SERVICE"
		g := f("network", fmt.Sprintf("%s:%d", l.addr, l.port))
		ev := []string{name + " listens on all interfaces", "process: " + orDash(owner), "bind it to 127.0.0.1 or close the port in the firewall"}
		if l.port == 2375 || l.port == 2376 {
			s.emit(id, g, "Docker API reachable on all interfaces", []string{"MK-DOCKER-SOCK"}, ev...)
			continue
		}
		s.emit(id, g, "", nil, ev...)
	}

	// Docker vs ufw, and egress.
	if _, err := os.Stat("/var/run/docker.sock"); err == nil {
		if out, ok := runRO("iptables", "-S", "DOCKER-USER"); ok {
			rules := dockerUserRules(out)
			if len(rules) == 0 {
				s.emit("MK-DOCKER-UFW", f("config", "iptables DOCKER-USER"), "", nil, "only the default RETURN rule: published ports are open to the internet regardless of ufw")
			}
			if !strings.Contains(out, "MAKIT-EGRESS") {
				s.emit("MK-EGRESS-OPEN", f("config", "iptables DOCKER-USER"), "", nil, "containers may open connections to any port on the internet")
			}
		}
	}

	// Updates.
	if b, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades"); err != nil || !strings.Contains(string(b), `Unattended-Upgrade "1"`) {
		if _, err := os.Stat("/usr/bin/apt-get"); err == nil {
			s.emit("MK-UPDATES-AUTO-OFF", f("config", "/etc/apt/apt.conf.d/20auto-upgrades"), "", nil)
		}
	}
	if out, ok := runRO("apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade"); ok {
		if n := securityUpdates(out); n > 0 {
			s.emit("MK-UPDATES-PENDING", f("config", "apt"), "", nil, fmt.Sprintf("%d security update(s) pending", n))
		}
	}
	if b, err := os.ReadFile("/var/run/reboot-required.pkgs"); err == nil {
		s.emit("MK-UPDATES-REBOOT", f("config", "/var/run/reboot-required"), "", nil, "packages: "+strings.Join(strings.Fields(string(b)), " "))
	} else if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		s.emit("MK-UPDATES-REBOOT", f("config", "/var/run/reboot-required"), "", nil)
	}

	// Kernel and mounts.
	if miss := missingSysctls(sys.Root("/")); len(miss) > 0 {
		s.emit("MK-KERNEL-SYSCTL", f("config", "/proc/sys"), "", nil, strings.Join(miss, ", "))
	}
	if b, err := os.ReadFile("/proc/mounts"); err == nil {
		for _, m := range execTmpMounts(string(b)) {
			s.emit("MK-HOST-TMP-EXEC", f("config", m), "", nil, m+" is mounted without noexec")
		}
	}

	// fail2ban, AppArmor, logging.
	if _, err := exec.LookPath("sshd"); err == nil {
		if !processRunning("fail2ban-server") {
			s.emit("MK-F2B-INACTIVE", f("config", "fail2ban"), "", nil)
		} else if out, ok := runRO("fail2ban-client", "status"); ok && !strings.Contains(out, "sshd") {
			s.emit("MK-F2B-NO-SSHD", f("config", "fail2ban"), "", nil, strings.TrimSpace(out))
		}
	}
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err != nil || strings.TrimSpace(string(b)) != "Y" {
		s.emit("MK-APPARMOR-OFF", f("config", "/sys/module/apparmor"), "", nil)
	}
	if !processRunning("auditd") {
		s.emit("MK-LOG-AUDITD", f("config", "auditd"), "", nil)
	}
	if !logShipping() {
		s.emit("MK-LOG-REMOTE", f("config", "logging"), "", nil)
	}

	// Secrets readable by others.
	for _, p := range secretFiles(sys.Root("/"), append([]string{"/srv", "/opt", "/app", "/var/www", "/root", "/home"}, s.extra...)) {
		s.emit("MK-SECRET-PERMS", f("file", p.path), "", nil, fmt.Sprintf("mode %04o (readable by other users) — chmod 600", p.mode))
	}
}

// ---- pure helpers (unit-tested)

func parseKV(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), " ")
		if ok {
			m[strings.ToLower(k)] = strings.TrimSpace(v)
		}
	}
	return m
}

type issue struct{ id, ev string }

func sshIssues(c map[string]string) []issue {
	var out []issue
	if c["passwordauthentication"] == "yes" {
		out = append(out, issue{"MK-SSH-PASSWORD", "PasswordAuthentication yes"})
	}
	if c["permitrootlogin"] == "yes" {
		out = append(out, issue{"MK-SSH-ROOT-PASSWORD", "PermitRootLogin yes"})
	}
	var weak []string
	if n, err := strconv.Atoi(c["maxauthtries"]); err == nil && n > 4 {
		weak = append(weak, "MaxAuthTries "+c["maxauthtries"])
	}
	if n, err := strconv.Atoi(c["logingracetime"]); err == nil && n > 60 {
		weak = append(weak, "LoginGraceTime "+c["logingracetime"])
	}
	if c["x11forwarding"] == "yes" {
		weak = append(weak, "X11Forwarding yes")
	}
	if len(weak) > 0 {
		out = append(out, issue{"MK-SSH-WEAK-SETTINGS", strings.Join(weak, ", ")})
	}
	return out
}

func firewallActive() bool {
	if out, ok := runRO("ufw", "status"); ok && strings.Contains(out, "Status: active") {
		return true
	}
	if out, ok := runRO("iptables", "-S", "INPUT"); ok && strings.Contains(out, "-P INPUT DROP") {
		return true
	}
	if out, ok := runRO("nft", "list", "ruleset"); ok && strings.Contains(out, "hook input") && strings.Contains(out, "policy drop") {
		return true
	}
	return false
}

// dockerUserRules returns the DOCKER-USER rules other than the chain declaration and Docker's default RETURN.
func dockerUserRules(out string) []string {
	var r []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || l == "-N DOCKER-USER" || l == "-A DOCKER-USER -j RETURN" {
			continue
		}
		r = append(r, l)
	}
	return r
}

// securityUpdates counts `apt-get -s upgrade` lines installing from a security pocket.
func securityUpdates(out string) int {
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "Inst ") && strings.Contains(strings.ToLower(l), "security") {
			n++
		}
	}
	return n
}

// sysctlBaseline: setting → minimum acceptable value (docs/security/kernel.md).
var sysctlBaseline = []struct {
	key  string
	want int
	max  bool // value must be <= want instead of >=
}{
	{"kernel.kptr_restrict", 1, false}, {"kernel.dmesg_restrict", 1, false}, {"kernel.yama.ptrace_scope", 1, false},
	{"fs.protected_symlinks", 1, false}, {"fs.protected_hardlinks", 1, false}, {"fs.protected_fifos", 1, false},
	{"fs.protected_regular", 1, false}, {"fs.suid_dumpable", 0, true}, {"net.ipv4.conf.all.rp_filter", 1, false},
	{"net.ipv4.conf.all.accept_redirects", 0, true}, {"net.ipv4.conf.all.send_redirects", 0, true},
	{"net.ipv4.conf.all.accept_source_route", 0, true}, {"net.ipv4.tcp_syncookies", 1, false},
}

func missingSysctls(r sys.Root) []string {
	var miss []string
	for _, b := range sysctlBaseline {
		raw, err := os.ReadFile(filepath.Join(string(r), "proc/sys", strings.ReplaceAll(b.key, ".", "/")))
		if err != nil {
			continue // not present on this kernel
		}
		v, err := strconv.Atoi(strings.TrimSpace(string(raw)))
		if err != nil {
			continue
		}
		if (b.max && v > b.want) || (!b.max && v < b.want) {
			miss = append(miss, fmt.Sprintf("%s=%d", b.key, v))
		}
	}
	return miss
}

// execTmpMounts lists /dev/shm and /tmp (when separately mounted) without noexec.
func execTmpMounts(mounts string) []string {
	var out []string
	for _, l := range strings.Split(mounts, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || (f[1] != "/dev/shm" && f[1] != "/tmp" && f[1] != "/var/tmp") {
			continue
		}
		if !strings.Contains(","+f[3]+",", ",noexec,") {
			out = append(out, f[1])
		}
	}
	sort.Strings(out)
	return out
}

type listener struct {
	addr   string
	port   int
	public bool
	inode  string
}

// listeners returns LISTEN sockets from /proc/net/tcp files.
func listeners(files ...string) []listener {
	var out []listener
	for _, file := range files {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(b), "\n")[1:] {
			f := strings.Fields(l)
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			ip, port := hexAddr(f[1])
			out = append(out, listener{ip, port, ip == "0.0.0.0" || ip == "::", f[9]})
		}
	}
	return out
}

// socketOwners maps socket inode → process name.
func socketOwners() map[string]string {
	m := map[string]string{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		comm, _ := os.ReadFile("/proc/" + e.Name() + "/comm")
		fds, _ := os.ReadDir("/proc/" + e.Name() + "/fd")
		for _, fd := range fds {
			if l, err := os.Readlink("/proc/" + e.Name() + "/fd/" + fd.Name()); err == nil && strings.HasPrefix(l, "socket:[") {
				m[l[8:len(l)-1]] = strings.TrimSpace(string(comm))
			}
		}
	}
	return m
}

func processRunning(name string) bool {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		if b, _ := os.ReadFile("/proc/" + e.Name() + "/comm"); strings.TrimSpace(string(b)) == name {
			return true
		}
	}
	return false
}

var shippers = []string{"systemd-journal-upload", "vector", "fluent-bit", "fluentd", "td-agent-bit", "promtail", "grafana-agent",
	"alloy", "datadog-agent", "agent", "otelcol", "otelcol-contrib", "filebeat", "nxlog", "logstash"}

func logShipping() bool {
	for _, p := range shippers {
		if p != "agent" && processRunning(p) {
			return true
		}
	}
	files, _ := filepath.Glob("/etc/rsyslog.d/*.conf")
	for _, f := range append(files, "/etc/rsyslog.conf") {
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if !strings.HasPrefix(l, "#") && (strings.Contains(l, "@@") || strings.Contains(l, "omfwd") || strings.Contains(l, " @")) {
				return true
			}
		}
	}
	return false
}

type secretFile struct {
	path string
	mode fs.FileMode
}

// secretFiles finds .env-style files readable by "other" under the given roots (4 levels deep).
func secretFiles(r sys.Root, roots []string) []secretFile {
	var out []secretFile
	seen := map[string]bool{}
	for _, root := range roots {
		base := filepath.Join(string(r), root)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] || strings.Count(strings.TrimPrefix(p, base), "/") > 4 {
					return filepath.SkipDir
				}
				return nil
			}
			n := d.Name()
			if !(n == ".env" || strings.HasPrefix(n, ".env.") || strings.HasSuffix(n, ".env")) || strings.Contains(n, "example") ||
				strings.Contains(n, "sample") || strings.Contains(n, "template") || strings.HasSuffix(n, ".dist") {
				return nil
			}
			st, err := os.Stat(p)
			if err != nil || !st.Mode().IsRegular() || st.Mode().Perm()&0o004 == 0 {
				return nil
			}
			disp := strings.TrimPrefix(p, strings.TrimSuffix(string(r), "/"))
			if !seen[disp] {
				seen[disp] = true
				out = append(out, secretFile{disp, st.Mode().Perm()})
			}
			return nil
		})
	}
	return out
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
