package scan

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// CVE-2025-55182 (React2Shell): fixed versions per the React and Next.js advisories (Dec 2025).
var nextFixed15 = map[int]int{0: 5, 1: 9, 2: 6, 3: 6, 4: 8, 5: 7} // 15.<minor>.<patch ≥ fixed>
var rsdVulnerable = map[string]bool{"19.0.0": true, "19.1.0": true, "19.1.1": true, "19.2.0": true}
var rsdPackages = []string{"react-server-dom-webpack", "react-server-dom-turbopack", "react-server-dom-parcel"}

func semver(v string) (int, int, int, string) {
	core, pre, _ := strings.Cut(strings.TrimPrefix(v, "v"), "-")
	p := strings.SplitN(core, ".", 3)
	n := func(i int) int {
		if i >= len(p) {
			return 0
		}
		x, _ := strconv.Atoi(p[i])
		return x
	}
	return n(0), n(1), n(2), pre
}

// nextVulnerable returns the advice when this Next.js version is affected.
func nextVulnerable(v string) (bool, string) {
	ma, mi, pa, pre := semver(v)
	switch {
	case ma == 14 && mi == 3 && strings.HasPrefix(pre, "canary"):
		return true, "upgrade to a patched 15.x/16.x release (14.3 canaries are affected)"
	case ma == 15:
		if f, ok := nextFixed15[mi]; ok && (pa < f || (pa == f && pre != "")) {
			return true, fmt.Sprintf("upgrade to ≥ 15.%d.%d", mi, f)
		}
	case ma == 16 && mi == 0 && pa < 7:
		return true, "upgrade to ≥ 16.0.7"
	}
	return false, ""
}

func pkgVersion(path string) string {
	var p struct{ Version string }
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	return p.Version
}

func (s *scanner) packages(t target) {
	roots := []string{"/app", "/srv", "/opt", "/var/www", "/home", "/root", "/usr/src", "/workspace"}
	if t.workdir != "" {
		roots = append(roots, t.workdir)
	}
	roots = append(roots, s.extra...)
	seen := map[string]bool{}
	for _, r := range roots {
		base := filepath.Join(t.root, r)
		_ = filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if strings.Count(strings.TrimPrefix(p, base), "/") > 5 || d.Name() == ".git" {
				return filepath.SkipDir
			}
			if d.Name() != "node_modules" {
				return nil
			}
			if !seen[p] {
				seen[p] = true
				s.checkNodeModules(t, p)
			}
			return filepath.SkipDir
		})
	}
}

func (s *scanner) checkNodeModules(t target, nm string) {
	disp := func(p string) string { return strings.TrimPrefix(p, strings.TrimSuffix(t.root, "/")) }
	report := func(pkg, ver, path, advice string) {
		s.rep.add(Finding{Severity: High, Target: t.name, Kind: "package", Path: disp(path),
			Title:    fmt.Sprintf("%s %s is vulnerable to CVE-2025-55182 (React2Shell, remote code execution)", pkg, ver),
			Evidence: []string{advice, "the entry point used to drop backdoors like /tmp/vim — patch, rebuild and redeploy"}})
	}
	check := func(name, pj string) {
		v := pkgVersion(pj)
		if v == "" {
			return
		}
		s.rep.Stats.Packages++
		if name == "next" {
			if bad, adv := nextVulnerable(v); bad {
				report("next", v, pj, adv)
			}
		} else if rsdVulnerable[v] {
			report(name, v, pj, "upgrade to 19.0.1, 19.1.2 or 19.2.1+")
		}
	}
	check("next", filepath.Join(nm, "next", "package.json"))
	for _, r := range rsdPackages {
		check(r, filepath.Join(nm, r, "package.json"))
	}
	// pnpm keeps every version under node_modules/.pnpm/<name>@<version>…/node_modules/<name>.
	ents, _ := os.ReadDir(filepath.Join(nm, ".pnpm"))
	for _, e := range ents {
		name, _, ok := strings.Cut(e.Name(), "@")
		if !ok || (name != "next" && !strings.HasPrefix(name, "react-server-dom-")) {
			continue
		}
		check(name, filepath.Join(nm, ".pnpm", e.Name(), "node_modules", name, "package.json"))
	}
}
