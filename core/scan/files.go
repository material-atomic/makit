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
	"strings"
)

const maxFilesPerTarget = 200000

var skipDirs = map[string]bool{"node_modules": true, ".git": true, "proc": true, "sys": true, ".pnpm-store": true}

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

// goNetworkTraits mirrors the React2Shell analysis' YARA rule: Go runtime + HTTP + SOCKS5 + TLS/ChaCha20. Common in
// any Go network tool, so it only matters together with where the file sits.
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

// scriptFindings applies every pattern rule of the catalog to a text file.
func (s *scanner) scriptFindings(t target, disp, text string, ctx fileCtx) {
	indicators := s.cat.stringHits(text)
	for _, r := range s.cat.Rules {
		if len(r.Patterns) == 0 {
			continue
		}
		var hits []string
		for _, p := range r.Patterns {
			if m := p.re.FindString(text); m != "" {
				hits = append(hits, p.ID+": "+clip(strings.TrimSpace(m), 160))
			}
		}
		need := r.MinMatches
		if need < 1 || ctx.startup || len(indicators) > 0 {
			need = 1
		}
		if len(hits) < need {
			continue
		}
		title := r.Title
		if ctx.startup {
			title = "Start-up entry: " + strings.ToLower(title[:1]) + title[1:]
		}
		for _, m := range indicators {
			hits = append(hits, "indicator "+m.note)
		}
		s.emitRule(r, High, Finding{Target: t.name, Kind: "file", Path: disp}, title, hits...)
		return
	}
	for _, m := range indicators { // an indicator alone (no pattern rule matched)
		s.emitRule(m.rule, High, Finding{Target: t.name, Kind: "file", Path: disp}, "File contains a known indicator: "+m.rule.Title, m.note)
	}
}

// inspect checks one file. disp is the path as seen inside the target, full the path on the host.
func (s *scanner) inspect(t target, disp, full string, ctx fileCtx) {
	st, err := os.Lstat(full)
	if err != nil || !st.Mode().IsRegular() {
		return
	}
	s.rep.Stats.Files++
	f := Finding{Target: t.name, Kind: "file", Path: disp}
	if m, ok := s.cat.path[disp]; ok {
		s.emitRule(m.rule, High, f, "File at a known malware path: "+m.rule.Title, m.note)
	}
	head := readHead(full, 4)
	isELF := bytes.Equal(head, []byte{0x7f, 'E', 'L', 'F'})
	hid := hidden(disp)
	if isELF {
		sum := s.sha256(full)
		if m, ok := s.cat.sha[sum]; ok && sum != "" {
			s.emitRule(m.rule, Critical, f, "Known malware (SHA256 match): "+m.rule.Title, sum, m.note)
			return
		}
		if !(ctx.temp || ctx.changed || hid) {
			return // executables elsewhere in homes are normal
		}
		ev := []string{fmt.Sprintf("ELF executable, %.1f MiB", float64(st.Size())/(1<<20)), "sha256 " + sum, "modified " + st.ModTime().Format("2006-01-02 15:04")}
		id := "MK-FILE-EXEC-TEMP"
		if ctx.changed {
			id = "MK-FILE-EXEC-ADDED"
		}
		if hid {
			id = "MK-FILE-EXEC-HIDDEN"
		}
		var extra []string
		if st.Size() <= s.maxSize && goNetworkTraits(readHead(full, s.maxSize)) {
			extra = append(extra, "MK-FILE-GO-TRAITS")
			ev = append(ev, "Go binary with HTTP + SOCKS5 + TLS/ChaCha20 (same traits as the CVE-2025-55182 backdoor)")
		}
		if b := filepath.Base(disp); systemNames[b] || strings.HasPrefix(b, "kworker") {
			extra = append(extra, "MK-FILE-SYSTEM-NAME")
			ev = append(ev, "named like a system tool ("+b+") outside system directories")
		}
		s.emit(id, f, "", extra, ev...)
		return
	}
	if st.Size() > 1<<20 || !(ctx.temp || ctx.changed || ctx.startup || hid) {
		return
	}
	text := readHead(full, 1<<20)
	if bytes.IndexByte(text, 0) >= 0 {
		return // binary data
	}
	s.scriptFindings(t, disp, string(text), ctx)
}

func (s *scanner) walk(t target, dir string, depth int, ctx fileCtx) {
	root := filepath.Join(t.root, dir)
	count := 0
	_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		rel := strings.TrimPrefix(p, strings.TrimSuffix(t.root, "/"))
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
