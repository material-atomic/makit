package scan

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

func (s Severity) String() string {
	return [...]string{"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

type Finding struct {
	Severity Severity `json:"severity"`
	Target   string   `json:"target"` // host, or container:<name>
	Kind     string   `json:"kind"`   // process, file, persistence, network, package
	Rule     string   `json:"rule"`   // MK-… check or rule id from the catalog
	Refs     []string `json:"refs,omitempty"`
	Title    string   `json:"title"`
	Path     string   `json:"path,omitempty"`
	PID      int      `json:"pid,omitempty"`
	Evidence []string `json:"evidence,omitempty"`
}

type Report struct {
	Version  string    `json:"version"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
	Host     string    `json:"host"`
	Operator string    `json:"operator"`
	Targets  []string  `json:"targets"`
	Catalog  []string  `json:"catalog"`
	Stats    Stats     `json:"stats"`
	Findings []Finding `json:"findings"`
	Notes    []string  `json:"notes,omitempty"`
}

type Stats struct {
	Processes, Files, Sockets, Packages int
}

func (r *Report) add(f Finding) {
	for _, x := range r.Findings { // one finding per (target, title, path, pid)
		if x.Target == f.Target && x.Title == f.Title && x.Path == f.Path && x.PID == f.PID {
			return
		}
	}
	r.Findings = append(r.Findings, f)
}

func (r *Report) worst() Severity {
	w := Info
	for _, f := range r.Findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}

func (r *Report) sort() {
	sort.SliceStable(r.Findings, func(i, j int) bool {
		a, b := r.Findings[i], r.Findings[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Target != b.Target {
			return a.Target < b.Target
		}
		return a.Path < b.Path
	})
}

var sevColor = map[Severity]string{Critical: "\033[1;41;97m", High: "\033[1;31m", Medium: "\033[33m", Low: "\033[36m", Info: "\033[2m"}

func (r *Report) Print(w io.Writer, color bool) {
	c := func(s Severity, t string) string {
		if !color {
			return t
		}
		return sevColor[s] + t + "\033[0m"
	}
	fmt.Fprintf(w, "\nmakit scan %s · %s · %s → %s\n", r.Version, r.Host, r.Started.Format(time.RFC3339), r.Finished.Format("15:04:05"))
	fmt.Fprintf(w, "targets: %s\n", strings.Join(r.Targets, ", "))
	fmt.Fprintf(w, "catalog: %s\n", strings.Join(r.Catalog, ", "))
	fmt.Fprintf(w, "checked: %d processes, %d files, %d sockets, %d packages\n\n", r.Stats.Processes, r.Stats.Files, r.Stats.Sockets, r.Stats.Packages)
	counts := map[Severity]int{}
	for _, f := range r.Findings {
		counts[f.Severity]++
	}
	if len(r.Findings) == 0 {
		fmt.Fprintln(w, "No suspicious items found.")
	}
	for _, f := range r.Findings {
		loc := f.Path
		if f.PID > 0 {
			loc = fmt.Sprintf("pid %d %s", f.PID, f.Path)
		}
		refs := ""
		if len(f.Refs) > 0 {
			refs = " · " + strings.Join(f.Refs, ", ")
		}
		fmt.Fprintf(w, "%s %s · %s · %s%s\n", c(f.Severity, fmt.Sprintf("[%s]", f.Severity)), f.Title, f.Target, f.Rule, refs)
		if loc != "" {
			fmt.Fprintf(w, "    %s\n", loc)
		}
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "    · %s\n", e)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "\nnote: %s", n)
	}
	fmt.Fprintf(w, "\n\nsummary: %d critical, %d high, %d medium, %d low, %d info\n", counts[Critical], counts[High], counts[Medium], counts[Low], counts[Info])
	if r.worst() >= High {
		fmt.Fprintln(w, `
Nothing was changed. Suggested response (manual):
  1. Keep evidence first: copy suspicious files and /proc/<pid>/exe of live processes somewhere safe.
  2. Isolate: stop the affected container / block egress; do not just delete the file (the process keeps running).
  3. Patch the entry point (e.g. Next.js/React for CVE-2025-55182), rebuild from a clean image, redeploy.
  4. Rotate every secret the host or container could read (DB, JWT, API keys, SSH keys).`)
	}
}
