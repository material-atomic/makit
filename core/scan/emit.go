package scan

import "strings"

// emit records a finding for built-in check id (severity and on/off come from the catalog).
// extra raises the severity to the highest of other checks that also matched (e.g. Go traits on a temp executable).
func (s *scanner) emit(id string, f Finding, title string, extra []string, ev ...string) {
	sev, ok := s.cat.check(id)
	if !ok {
		return
	}
	for _, x := range extra {
		if xs, on := s.cat.check(x); on && xs > sev {
			sev = xs
		}
	}
	ch := s.cat.Checks[id]
	if title == "" {
		title = ch.Title
	}
	f.Severity, f.Rule, f.Title, f.Doc = sev, id, title, docURL(ch.Doc)
	f.Evidence = append(append([]string{}, f.Evidence...), ev...)
	s.rep.add(f)
}

// emitRule records a finding for a catalog rule (indicator or pattern match).
func (s *scanner) emitRule(r *Rule, def Severity, f Finding, title string, ev ...string) {
	sev := def
	if x, ok := parseSeverity(r.Severity); ok {
		sev = x
	}
	f.Severity, f.Rule, f.Refs, f.Title, f.Doc = sev, r.ID, r.Refs, title, docURL(r.Doc)
	f.Evidence = append(append([]string{}, f.Evidence...), ev...)
	s.rep.add(f)
}

// DocBase is where documentation links point; the ref is the running version's tag (main for dev builds).
var DocBase = "https://github.com/material-atomic/makit/blob/"

func docURL(path string) string {
	if path == "" || strings.HasPrefix(path, "http") {
		return path
	}
	ref := "main"
	if v := strings.TrimPrefix(Version, "v"); v != "" && v[0] >= '0' && v[0] <= '9' && !strings.ContainsAny(v, "-+") {
		ref = "v" + v
	}
	return DocBase + ref + "/" + strings.TrimPrefix(path, "/")
}
