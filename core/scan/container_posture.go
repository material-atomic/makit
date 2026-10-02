package scan

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/material-atomic/makit/core/sys"
)

var dangerousCaps = map[string]bool{"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "NET_ADMIN": true,
	"DAC_READ_SEARCH": true, "SYS_RAWIO": true, "SYS_BOOT": true, "SYS_TIME": true, "BPF": true, "PERFMON": true, "MAC_ADMIN": true}

// inspection is the part of `docker inspect` the checks need.
type inspection struct {
	ID     string
	Name   string
	State  struct{ Pid int }
	Config struct {
		User string
	}
	HostConfig struct {
		Privileged     bool
		NetworkMode    string
		PidMode        string
		CapAdd         []string
		SecurityOpt    []string
		ReadonlyRootfs bool
	}
	Mounts []struct {
		Source      string
		Destination string
	}
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIp   string
			HostPort string
		}
	}
}

// containerIssues evaluates one container. uid is its main process uid (-1 unknown); tmpExec tells whether /tmp
// inside it is writable and executable.
func containerIssues(c inspection, uid int, tmpExec bool) []issue {
	var out []issue
	if c.HostConfig.Privileged {
		out = append(out, issue{"MK-DOCKER-PRIVILEGED", "privileged: true"})
	}
	for _, m := range c.Mounts {
		if m.Source == "/var/run/docker.sock" || m.Source == "/run/docker.sock" {
			out = append(out, issue{"MK-DOCKER-SOCK", m.Source + " mounted at " + m.Destination})
		}
	}
	var ns []string
	if c.HostConfig.NetworkMode == "host" {
		ns = append(ns, "network_mode: host")
	}
	if c.HostConfig.PidMode == "host" {
		ns = append(ns, "pid: host")
	}
	if len(ns) > 0 {
		out = append(out, issue{"MK-DOCKER-HOST-NS", strings.Join(ns, ", ")})
	}
	var caps []string
	for _, cp := range c.HostConfig.CapAdd {
		if n := strings.TrimPrefix(strings.ToUpper(cp), "CAP_"); dangerousCaps[n] {
			caps = append(caps, n)
		}
	}
	if len(caps) > 0 {
		out = append(out, issue{"MK-DOCKER-CAPS", "cap_add: " + strings.Join(caps, ", ")})
	}
	if uid == 0 {
		out = append(out, issue{"MK-DOCKER-ROOT", "main process uid 0 (user: " + orDash(c.Config.User) + ")"})
	}
	if tmpExec {
		out = append(out, issue{"MK-DOCKER-TMP-EXEC", "/tmp is writable and executable — mount it as tmpfs with noexec"})
	}
	nnp := false
	for _, o := range c.HostConfig.SecurityOpt {
		if strings.HasPrefix(o, "no-new-privileges") && !strings.HasSuffix(o, "false") {
			nnp = true
		}
	}
	if !nnp && !c.HostConfig.Privileged {
		out = append(out, issue{"MK-DOCKER-NO-NEW-PRIVS", "security_opt: [no-new-privileges:true] is not set"})
	}
	if !c.HostConfig.ReadonlyRootfs {
		out = append(out, issue{"MK-DOCKER-RW-ROOT", "read_only: true is not set"})
	}
	var pub []string
	for p, binds := range c.NetworkSettings.Ports {
		port, _ := strconv.Atoi(strings.Split(p, "/")[0])
		name, risky := riskyPorts[port]
		if !risky {
			continue
		}
		for _, b := range binds {
			if b.HostIp == "" || b.HostIp == "0.0.0.0" || b.HostIp == "::" {
				pub = append(pub, fmt.Sprintf("%s published on %s:%s (%s)", p, orDash(b.HostIp), b.HostPort, name))
			}
		}
	}
	sort.Strings(pub)
	for _, p := range pub {
		out = append(out, issue{"MK-NET-PUBLIC-SERVICE", p + " — publish as 127.0.0.1:PORT:PORT or not at all"})
	}
	return out
}

// tmpExecutable reads a process's mount table: /tmp mounted noexec → false; no /tmp mount → root fs decides.
func tmpExecutable(mountinfo string, readonlyRoot bool) bool {
	for _, l := range strings.Split(mountinfo, "\n") {
		f := strings.Fields(l)
		if len(f) < 6 || f[4] != "/tmp" {
			continue
		}
		opts := f[5]
		for i, x := range f {
			if x == "-" && i+3 < len(f) {
				opts += "," + f[i+3] // super options
			}
		}
		o := "," + opts + ","
		return !strings.Contains(o, ",noexec,") && !strings.Contains(o, ",ro,")
	}
	return !readonlyRoot
}

func procUID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			if f := strings.Fields(v); len(f) > 0 {
				n, _ := strconv.Atoi(f[0])
				return n
			}
		}
	}
	return -1
}

func (s *scanner) containerPosture(all bool, targets []target) {
	d := sys.NewDocker("/var/run/docker.sock")
	list, err := d.Containers()
	if err != nil {
		return
	}
	want := map[string]bool{}
	for _, t := range targets {
		want[strings.TrimPrefix(t.name, "container:")] = true
	}
	for _, c := range list {
		if c.State != "running" || (!all && !want[c.Name]) {
			continue
		}
		var ins inspection
		if d.Get("/containers/"+c.ID+"/json", &ins) != nil || ins.State.Pid == 0 {
			continue
		}
		mi, _ := os.ReadFile(fmt.Sprintf("/proc/%d/mountinfo", ins.State.Pid))
		for _, is := range containerIssues(ins, procUID(ins.State.Pid), tmpExecutable(string(mi), ins.HostConfig.ReadonlyRootfs)) {
			s.emit(is.id, Finding{Target: "container:" + c.Name, Kind: "config", Path: c.Image}, "", nil, is.ev)
		}
	}
}
