package scan

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const maxFilesPerTarget = 200000

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "proc": true, "sys": true, ".pnpm-store": true}

// Dropper / downloader patterns (from the CVE-2025-55182 analysis and common Linux droppers).
var dropperRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\b(wget|curl)\b[^\n|;]*https?://\d{1,3}(\.\d{1,3}){3}[^\s'"]*`),
	regexp.MustCompile(`(?i)\b(wget|curl)\b[^\n]*\|\s*(ba|da)?sh\b`),
	regexp.MustCompile(`(?i)\b(wget|curl)\b[^\n]*-[oO]\s*/(tmp|var/tmp|dev/shm)/`),
	regexp.MustCompile(`(?i)chmod\s+(\+x|[0-7]*7[0-7]{2})\s+/(tmp|var/tmp|dev/shm)/`),
	regexp.MustCompile(`(?i)nohup\s+/(tmp|var/tmp|dev/shm)/`),
	regexp.MustCompile(`(?i)base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh\b`),
	regexp.MustCompile(`/dev/tcp/\d{1,3}(\.\d{1,3}){3}/\d+`),
	regexp.MustCompile(`(?i)\brm\s+-f\s+/(tmp|var/tmp|dev/shm)/\S+`),
}

type fileCtx struct {
	temp, changed, startup bool
}

func (s *scanner) sha256(path string) string {
	if h, ok := s.hashes[path]; ok {
		return h
	}
	f, err := os.Open(path) // read-only
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || st.Size() > s.maxSize {
		return ""
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	s.hashes[path] = sum
	return sum
}

// goNetworkTraits mirrors the analysis' YARA rule: Go runtime + HTTP + SOCKS5 + TLS/ChaCha20. Common in any Go network
// tool, so it only matters together with where the file sits.
func goNetworkTraits(b []byte) bool {
	has := func(s string) bool { return bytes.Contains(b, []byte(s)) }
	return (has("runtime.main") || has("runtime.goexit")) && has("net/http") && has("socks5") &&
		(has("crypto/tls") || has("chacha20poly1305"))
}

func readHead(path string, n int64) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, n))
	return b
}

func (s *scanner) dropperHits(text string) []string {
	var hits []string
	for _, re := range dropperRes {
		if m := re.FindString(text); m != "" {
			hits = append(hits, clip(strings.TrimSpace(m), 160))
		}
	}
	for _, i := range s.iocs.Strings {
		if strings.Contains(text, i.Value) {
			hits = append(hits, "indicator "+i.Value+" — "+i.Note)
		}
	}
	return hits
}

// inspect checks one file. disp is the path as seen inside the target, full the path on the host.
func (s *scanner) inspect(t target, disp, full string, ctx fileCtx) {
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	s.rep.Stats.Files++
	f := Finding{Target: t.name, Kind: "file", Path: disp}
	add := func(sev Severity, title string, ev ...string) {
		g := f
		g.Severity, g.Title, g.Evidence = sev, title, ev
		s.rep.add(g)
	}
	if note, ok := s.iocs.path[disp]; ok {
		add(High, "File at a known malware path", note)
	}
	head := readHead(full, 4)
	isELF := bytes.Equal(head, []byte{0x7f, 'E', 'L', 'F'})
	hid := hidden(disp)
	if isELF {
		sum := s.sha256(full)
		if note, ok := s.iocs.sha[sum]; ok && sum != "" {
			add(Critical, "Known malware (SHA256 match)", sum, note)
			return
		}
		if !(ctx.temp || ctx.changed || hid) {
			return // executables elsewhere in homes are normal
		}
		ev := []string{"ELF executable, " + humanSize(st.Size()), "sha256 " + sum, "modified " + st.ModTime().Format("2006-01-02 15:04")}
		sev, title := Medium, "Executable in a temporary directory"
		if ctx.changed {
			title = "Executable added to the container after it started"
		}
		if hid {
			sev, title = High, "Executable hidden in a dot-directory/dot-file"
		}
		if st.Size() <= s.maxSize && goNetworkTraits(readHead(full, s.maxSize)) {
			sev = High
			ev = append(ev, "Go binary with HTTP + SOCKS5 + TLS/ChaCha20 (same traits as the CVE-2025-55182 backdoor)")
		}
		if filepath.Base(disp) == "vim" || systemNames[filepath.Base(disp)] {
			sev = High
			ev = append(ev, "named like a system tool ("+filepath.Base(disp)+") outside system directories")
		}
		add(sev, title, ev...)
		return
	}
	if st.Size() > 1<<20 || !(ctx.temp || ctx.changed || ctx.startup || hid) {
		return
	}
	text := string(readHead(full, 1<<20))
	if bytes.IndexByte([]byte(text), 0) >= 0 {
		return // binary data
	}
	if hits := s.dropperHits(text); len(hits) >= 2 || (len(hits) == 1 && (strings.HasPrefix(hits[0], "indicator") || ctx.startup)) {
		sev, title := High, "Script downloads and runs code (dropper pattern)"
		if ctx.startup {
			title = "Start-up entry downloads or runs code from a temporary path"
		}
		add(sev, title, hits...)
	}
}

func (s *scanner) walk(t target, dir string, depth int, ctx fileCtx) {
	root := filepath.Join(t.root, dir)
	count := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, strings.TrimSuffix(t.root, "/"))
		if rel == "" {
			rel = "/"
		}
		if d.IsDir() {
			if p != root && (skipDirs[d.Name()] || strings.Count(strings.TrimPrefix(p, root), "/") > depth) {
				return filepath.SkipDir
			}
			return nil
		}
		if count++; count > maxFilesPerTarget {
			return filepath.SkipAll
		}
		s.inspect(t, rel, p, ctx)
		return nil
	})
}

func (s *scanner) files(t target) {
	for _, d := range []struct {
		dir   string
		depth int
		temp  bool
	}{{"/tmp", 8, true}, {"/var/tmp", 8, true}, {"/dev/shm", 8, true}, {"/run", 3, true}, {"/root", 6, false}, {"/home", 7, false}} {
		s.walk(t, d.dir, d.depth, fileCtx{temp: d.temp})
	}
	for _, p := range s.extra {
		s.walk(t, p, 10, fileCtx{temp: true})
	}
	if t.workdir != "" && t.workdir != "/" {
		s.walk(t, t.workdir, 6, fileCtx{})
	}
	for _, c := range t.changed { // docker diff: anything written since the container started
		if strings.HasPrefix(c, "/proc") || strings.HasPrefix(c, "/sys") || strings.Contains(c, "/node_modules/.cache/") || startupPath(c) {
			continue
		}
		s.inspect(t, c, filepath.Join(t.root, c), fileCtx{changed: true, temp: inTemp(c + "/")})
	}
}

func humanSize(n int64) string {
	const k = 1024
	switch {
	case n >= k*k:
		return fmt.Sprintf("%.1f MiB", float64(n)/k/k)
	case n >= k:
		return fmt.Sprintf("%.1f KiB", float64(n)/k)
	}
	return fmt.Sprintf("%d B", n)
}

// startupPath is covered by the persistence check (avoids reporting the same file twice).
func startupPath(p string) bool {
	for _, pre := range []string{"/etc/cron", "/etc/crontab", "/var/spool/cron", "/etc/systemd/", "/etc/rc.local", "/etc/profile",
		"/etc/bash.bashrc", "/etc/environment", "/etc/init.d/", "/etc/xdg/autostart/", "/etc/ld.so.preload"} {
		if strings.HasPrefix(p, pre) {
			return true
		}
	}
	return false
}
