package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the newest catalog format this makit understands (security/index.yaml "schema").
const SchemaVersion = 1

type Indicator struct {
	Value string `yaml:"value" json:"value"`
	Note  string `yaml:"note" json:"note,omitempty"`
}

type Pattern struct {
	ID    string `yaml:"id" json:"id"`
	Regex string `yaml:"regex" json:"regex"`
	re    *regexp.Regexp
}

type Port struct {
	Value int    `yaml:"value" json:"value"`
	Note  string `yaml:"note" json:"note,omitempty"`
}

// Rule is one file in security/rules/ (except builtin.yaml).
type Rule struct {
	ID         string   `yaml:"id" json:"id"`
	Title      string   `yaml:"title" json:"title"`
	Severity   string   `yaml:"severity" json:"severity,omitempty"`
	Refs       []string `yaml:"refs" json:"refs,omitempty"`
	Sources    []string `yaml:"sources" json:"sources,omitempty"`
	Indicators struct {
		SHA256  []Indicator `yaml:"sha256" json:"sha256,omitempty"`
		IPs     []Indicator `yaml:"ips" json:"ips,omitempty"`
		Strings []Indicator `yaml:"strings" json:"strings,omitempty"`
		Paths   []Indicator `yaml:"paths" json:"paths,omitempty"`
	} `yaml:"indicators" json:"indicators"`
	MinMatches int       `yaml:"min_matches" json:"min_matches,omitempty"`
	Patterns   []Pattern `yaml:"patterns" json:"patterns,omitempty"`
	Ports      []Port    `yaml:"ports" json:"ports,omitempty"`
	From       string    `yaml:"-" json:"from"`
}

// Check tunes a built-in check (security/rules/builtin.yaml).
type Check struct {
	Severity string `yaml:"severity" json:"severity"`
	Title    string `yaml:"title" json:"title"`
	Disabled bool   `yaml:"disabled" json:"disabled,omitempty"`
}

// match ties an indicator value back to its rule.
type match struct {
	rule *Rule
	note string
}

type Catalog struct {
	Sources []string         `json:"sources"`
	Checks  map[string]Check `json:"checks"`
	Rules   map[string]*Rule `json:"rules"`
	Vulns   map[string]*Vuln `json:"vulns"`

	sha, ip, path map[string]match
	strs          []struct {
		value string
		m     match
	}
	ports map[int]match
	npm   map[string][]*Vuln
}

// LoadCatalog reads catalogs in order; later directories override entries with the same id.
func LoadCatalog(dirs []string) (*Catalog, error) {
	c := &Catalog{Checks: map[string]Check{}, Rules: map[string]*Rule{}, Vulns: map[string]*Vuln{}}
	for _, d := range dirs {
		if _, err := os.Stat(d); err != nil {
			continue
		}
		if err := c.loadDir(d); err != nil {
			return nil, fmt.Errorf("%s: %w", d, err)
		}
		c.Sources = append(c.Sources, d)
	}
	if len(c.Sources) == 0 {
		return nil, fmt.Errorf("no security catalog found (looked in %s) — reinstall makit or pass --rules DIR", strings.Join(dirs, ", "))
	}
	return c, c.index()
}

func (c *Catalog) loadDir(dir string) error {
	var idx struct{ Schema int }
	if b, err := os.ReadFile(filepath.Join(dir, "index.yaml")); err == nil {
		if err := yaml.Unmarshal(b, &idx); err != nil {
			return fmt.Errorf("index.yaml: %w", err)
		}
		if idx.Schema > SchemaVersion {
			return fmt.Errorf("catalog schema %d is newer than this makit supports (%d) — run: makit self-update", idx.Schema, SchemaVersion)
		}
	}
	files, _ := filepath.Glob(filepath.Join(dir, "rules", "*.yaml"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		if filepath.Base(f) == "builtin.yaml" {
			var x struct{ Checks map[string]Check }
			if err := yaml.Unmarshal(b, &x); err != nil {
				return fmt.Errorf("%s: %w", filepath.Base(f), err)
			}
			for k, v := range x.Checks {
				c.Checks[k] = v
			}
			continue
		}
		var r Rule
		if err := yaml.Unmarshal(b, &r); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if r.ID == "" {
			return fmt.Errorf("%s: missing id", filepath.Base(f))
		}
		r.From = f
		c.Rules[r.ID] = &r
	}
	vfiles, _ := filepath.Glob(filepath.Join(dir, "vulns", "*.json"))
	for _, f := range vfiles {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		var v Vuln
		if err := json.Unmarshal(b, &v); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(f), err)
		}
		if v.ID == "" {
			return fmt.Errorf("%s: missing id", filepath.Base(f))
		}
		v.From = f
		c.Vulns[v.ID] = &v
	}
	return nil
}

func (c *Catalog) index() error {
	c.sha, c.ip, c.path, c.ports, c.npm = map[string]match{}, map[string]match{}, map[string]match{}, map[int]match{}, map[string][]*Vuln{}
	ids := make([]string, 0, len(c.Rules))
	for id := range c.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := c.Rules[id]
		for _, i := range r.Indicators.SHA256 {
			c.sha[strings.ToLower(i.Value)] = match{r, i.Note}
		}
		for _, i := range r.Indicators.IPs {
			c.ip[i.Value] = match{r, i.Note}
		}
		for _, i := range r.Indicators.Paths {
			c.path[i.Value] = match{r, i.Note}
		}
		for _, i := range r.Indicators.Strings {
			c.strs = append(c.strs, struct {
				value string
				m     match
			}{i.Value, match{r, i.Note}})
		}
		for _, p := range r.Ports {
			c.ports[p.Value] = match{r, p.Note}
		}
		for i := range r.Patterns {
			re, err := regexp.Compile(r.Patterns[i].Regex)
			if err != nil {
				return fmt.Errorf("rule %s pattern %s: %w", r.ID, r.Patterns[i].ID, err)
			}
			r.Patterns[i].re = re
		}
	}
	for _, v := range c.Vulns {
		for _, a := range v.Affected {
			if a.Package.Ecosystem == "npm" {
				c.npm[a.Package.Name] = append(c.npm[a.Package.Name], v)
			}
		}
	}
	return nil
}

// builtinDefaults keep checks working with an older/partial builtin.yaml.
var builtinDefaults = map[string]Severity{
	"MK-PROC-DELETED-TEMP": Critical, "MK-PROC-DELETED": Low, "MK-PROC-MEMFD": Medium, "MK-PROC-TEMP": High,
	"MK-PROC-KTHREAD": High, "MK-PROC-NAME-MISMATCH": High, "MK-PROC-IOC": Critical, "MK-NET-IOC": Critical,
	"MK-NET-PORT": Medium, "MK-NET-SUSPICIOUS": High, "MK-FILE-IOC": Critical, "MK-FILE-EXEC-TEMP": Medium,
	"MK-FILE-EXEC-ADDED": Medium, "MK-FILE-EXEC-HIDDEN": High, "MK-FILE-GO-TRAITS": High, "MK-FILE-SYSTEM-NAME": High,
	"MK-PERSIST-TEMP-EXEC": High, "MK-PERSIST-RECENT": Info, "MK-PERSIST-PRELOAD": High, "MK-PERSIST-SSH-KEYS": Info, "MK-VULN": High,
}

// check returns the severity of a built-in check and whether it is enabled.
func (c *Catalog) check(id string) (Severity, bool) {
	sev := builtinDefaults[id]
	if ch, ok := c.Checks[id]; ok {
		if ch.Disabled {
			return sev, false
		}
		if s, ok := parseSeverity(ch.Severity); ok {
			sev = s
		}
	}
	return sev, true
}

func parseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return Info, true
	case "low":
		return Low, true
	case "medium", "moderate":
		return Medium, true
	case "high":
		return High, true
	case "critical":
		return Critical, true
	}
	return Info, false
}

// stringHits returns indicator strings (from any rule) found in text.
func (c *Catalog) stringHits(text string) []match {
	var out []match
	for _, s := range c.strs {
		if strings.Contains(text, s.value) {
			out = append(out, match{s.m.rule, s.value + " — " + s.m.note})
		}
	}
	return out
}

// Print is the human summary behind `makit scan --list-rules`.
func (c *Catalog) Print(w io.Writer) {
	fmt.Fprintf(w, "sources (later overrides earlier):\n")
	for _, s := range c.Sources {
		fmt.Fprintf(w, "  %s\n", s)
	}
	ids := make([]string, 0, len(c.Checks))
	for id := range c.Checks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "\nbuilt-in checks (%d):\n", len(ids))
	for _, id := range ids {
		sev, on := c.check(id)
		state := sev.String()
		if !on {
			state = "off"
		}
		fmt.Fprintf(w, "  %-22s %-8s %s\n", id, state, c.Checks[id].Title)
	}
	ids = ids[:0]
	for id := range c.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "\nrules (%d):\n", len(ids))
	for _, id := range ids {
		r := c.Rules[id]
		n := len(r.Indicators.SHA256) + len(r.Indicators.IPs) + len(r.Indicators.Strings) + len(r.Indicators.Paths)
		fmt.Fprintf(w, "  %-12s %s  (%d indicators, %d patterns, %d ports)  %s\n", id, r.Title, n, len(r.Patterns), len(r.Ports), strings.Join(r.Refs, ", "))
	}
	ids = ids[:0]
	for id := range c.Vulns {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	fmt.Fprintf(w, "\nvulnerabilities (%d):\n", len(ids))
	for _, id := range ids {
		v := c.Vulns[id]
		var pk []string
		for _, a := range v.Affected {
			pk = append(pk, a.Package.Ecosystem+":"+a.Package.Name)
		}
		fmt.Fprintf(w, "  %-16s %-9s %s  [%s]\n", id, v.DatabaseSpecific.Severity, v.Summary, strings.Join(pk, ", "))
	}
}
