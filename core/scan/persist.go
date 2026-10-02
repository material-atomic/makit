package scan

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// persistence reads the places malware uses to survive a reboot or a new shell.
func (s *scanner) persistence(t target) {
	j := func(p string) string { return filepath.Join(t.root, p) }
	var files []string
	add := func(globs ...string) {
		for _, g := range globs {
			m, _ := filepath.Glob(j(g))
			files = append(files, m...)
		}
	}
	add("/etc/crontab", "/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/cron.monthly/*",
		"/var/spool/cron/*", "/var/spool/cron/crontabs/*", "/etc/crontabs/*", "/etc/rc.local", "/etc/profile", "/etc/profile.d/*", "/etc/bash.bashrc",
		"/etc/environment", "/root/.bashrc", "/root/.profile", "/root/.bash_profile", "/root/.zshrc",
		"/home/*/.bashrc", "/home/*/.profile", "/home/*/.bash_profile", "/home/*/.zshrc",
		"/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/systemd/system/*/*.service",
		"/root/.config/systemd/user/*.service", "/home/*/.config/systemd/user/*.service", "/etc/init.d/*", "/etc/xdg/autostart/*")
	recent := time.Now().Add(-7 * 24 * time.Hour)
	for _, f := range files {
		disp := strings.TrimPrefix(f, strings.TrimSuffix(t.root, "/"))
		s.inspect(t, disp, f, fileCtx{startup: true})
		st, err := os.Stat(f)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		text := string(readHead(f, 256<<10))
		for _, l := range strings.Split(text, "\n") {
			l = strings.TrimSpace(l)
			if strings.HasPrefix(l, "#") || l == "" {
				continue
			}
			if strings.Contains(l, "ExecStart") || strings.Contains(disp, "cron") || strings.HasSuffix(disp, "rc.local") {
				for _, w := range strings.Fields(l) {
					w = strings.Trim(w, `"';=`)
					if inTemp(w) || (strings.HasPrefix(w, "/") && hidden(w) && !strings.Contains(w, "/.config/") && !strings.Contains(w, "/.local/")) {
						s.rep.add(Finding{Severity: High, Target: t.name, Kind: "persistence", Path: disp,
							Title: "Start-up entry runs a program from a temporary or hidden path", Evidence: []string{clip(l, 200)}})
					}
				}
			}
		}
		if (strings.Contains(disp, "cron") || strings.Contains(disp, "systemd/system")) && st.ModTime().After(recent) {
			s.rep.add(Finding{Severity: Info, Target: t.name, Kind: "persistence", Path: disp,
				Title: "Start-up entry changed in the last 7 days (review)", Evidence: []string{"modified " + st.ModTime().Format("2006-01-02 15:04")}})
		}
	}
	if b, err := os.ReadFile(j("/etc/ld.so.preload")); err == nil && strings.TrimSpace(string(b)) != "" {
		s.rep.add(Finding{Severity: High, Target: t.name, Kind: "persistence", Path: "/etc/ld.so.preload",
			Title: "Libraries are force-loaded into every process (common rootkit technique)", Evidence: strings.Fields(string(b))})
	}
	keys, _ := filepath.Glob(j("/root/.ssh/authorized_keys"))
	more, _ := filepath.Glob(j("/home/*/.ssh/authorized_keys"))
	for _, k := range append(keys, more...) {
		st, err := os.Stat(k)
		if err != nil {
			continue
		}
		n := 0
		var names []string
		for _, l := range strings.Split(string(readHead(k, 1<<20)), "\n") {
			if f := strings.Fields(l); len(f) >= 2 && !strings.HasPrefix(l, "#") {
				n++
				if len(f) >= 3 {
					names = append(names, f[len(f)-1])
				}
			}
		}
		sev, title := Info, "Authorized SSH keys"
		if st.ModTime().After(recent) {
			sev, title = Low, "Authorized SSH keys changed in the last 7 days (verify every key is yours)"
		}
		s.rep.add(Finding{Severity: sev, Target: t.name, Kind: "persistence", Path: strings.TrimPrefix(k, strings.TrimSuffix(t.root, "/")), Title: title,
			Evidence: []string{strings.Join(append([]string{itoa(n) + " key(s)"}, names...), ", "), "modified " + st.ModTime().Format("2006-01-02 15:04")}})
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
