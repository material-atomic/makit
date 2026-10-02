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

// Vuln is the subset of the OSV format (https://ossf.github.io/osv-schema/) makit uses, so advisories from osv.dev
// or GitHub can be dropped into security/vulns/ unchanged.
type Vuln struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases,omitempty"`
	Summary          string   `json:"summary"`
	Details          string   `json:"details,omitempty"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references,omitempty"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges,omitempty"`
		Versions []string `json:"versions,omitempty"`
	} `json:"affected"`
	From string `json:"from"`
}

// Affects reports whether name@version is affected, and the fixed version of the matching range ("" if unknown).
func (v *Vuln) Affects(ecosystem, name, version string) (bool, string) {
	for _, a := range v.Affected {
		if a.Package.Ecosystem != ecosystem || a.Package.Name != name {
			continue
		}
		for _, x := range a.Versions {
			if x == version {
				return true, ""
			}
		}
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			in, fixed := false, ""
			for _, e := range r.Events {
				if x, ok := e["introduced"]; ok && (x == "0" || cmpSemver(version, x) >= 0) {
					in = true
				}
				if x, ok := e["fixed"]; ok {
					fixed = x
					if cmpSemver(version, x) >= 0 {
						in = false
					}
				}
				if x, ok := e["last_affected"]; ok && cmpSemver(version, x) > 0 {
					in = false
				}
			}
			if in {
				return true, fixed
			}
		}
	}
	return false, ""
}

// cmpSemver compares semantic versions, including pre-releases (1.0.0-canary.2 < 1.0.0-canary.10 < 1.0.0).
func cmpSemver(a, b string) int {
	ac, ap, _ := strings.Cut(strings.TrimPrefix(strings.SplitN(a, "+", 2)[0], "v"), "-")
	bc, bp, _ := strings.Cut(strings.TrimPrefix(strings.SplitN(b, "+", 2)[0], "v"), "-")
	as, bs := strings.Split(ac, "."), strings.Split(bc, ".")
	for i := 0; i < 3; i++ {
		if d := cmpNum(at(as, i), at(bs, i)); d != 0 {
			return d
		}
	}
	switch {
	case ap == "" && bp == "":
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	ai, bi := strings.Split(ap, "."), strings.Split(bp, ".")
	for i := 0; i < len(ai) || i < len(bi); i++ {
		if i >= len(ai) {
			return -1
		}
		if i >= len(bi) {
			return 1
		}
		an, aerr := strconv.Atoi(ai[i])
		bn, berr := strconv.Atoi(bi[i])
		switch {
		case aerr == nil && berr == nil && an != bn:
			if an < bn {
				return -1
			}
			return 1
		case aerr == nil && berr != nil:
			return -1
		case aerr != nil && berr == nil:
			return 1
		case aerr != nil && ai[i] != bi[i]:
			if ai[i] < bi[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func at(s []string, i int) string {
	if i < len(s) {
		return s[i]
	}
	return "0"
}

func cmpNum(a, b string) int {
	x, _ := strconv.Atoi(a)
	y, _ := strconv.Atoi(b)
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

func pkgVersion(path string) string {
	var p struct{ Version string }
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &p)
	}
	return p.Version
}

// packages inventories npm packages named in the catalog and matches them against its advisories.
func (s *scanner) packages(t target) {
	if len(s.cat.npm) == 0 {
		return
	}
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
	check := func(name, pj string) {
		v := pkgVersion(pj)
		if v == "" {
			return
		}
		s.rep.Stats.Packages++
		for _, vu := range s.cat.npm[name] {
			bad, fixed := vu.Affects("npm", name, v)
			if !bad {
				continue
			}
			sev, ok := s.cat.check("MK-VULN")
			if !ok {
				return
			}
			if adv, ok := parseSeverity(vu.DatabaseSpecific.Severity); ok {
				sev = adv
			}
			ev := []string{vu.Summary}
			if fixed != "" {
				ev = append(ev, "upgrade to ≥ "+fixed+" (or a later patched release of your line)")
			}
			for _, r := range vu.References {
				if r.Type == "ADVISORY" {
					ev = append(ev, r.URL)
					break
				}
			}
			ids := append([]string{vu.ID}, vu.Aliases...)
			s.rep.add(Finding{Severity: sev, Target: t.name, Kind: "package", Rule: "MK-VULN", Refs: ids,
				Path:  strings.TrimPrefix(pj, strings.TrimSuffix(t.root, "/")),
				Title: fmt.Sprintf("%s %s is affected by %s", name, v, strings.Join(ids, " / ")), Evidence: ev})
		}
	}
	for name := range s.cat.npm {
		check(name, filepath.Join(nm, name, "package.json"))
	}
	// pnpm keeps every version under node_modules/.pnpm/<name>@<version>…/node_modules/<name>.
	ents, _ := os.ReadDir(filepath.Join(nm, ".pnpm"))
	for _, e := range ents {
		at := strings.LastIndex(e.Name(), "@")
		if at <= 0 {
			continue
		}
		name := strings.ReplaceAll(e.Name()[:at], "+", "/") // @scope+pkg → @scope/pkg
		if _, ok := s.cat.npm[name]; ok {
			check(name, filepath.Join(nm, ".pnpm", e.Name(), "node_modules", name, "package.json"))
		}
	}
}
