package scan

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
	if ch, ok := s.cat.Checks[id]; ok && title == "" {
		title = ch.Title
	}
	f.Severity, f.Rule, f.Title = sev, id, title
	f.Evidence = append(append([]string{}, f.Evidence...), ev...)
	s.rep.add(f)
}

// emitRule records a finding for a catalog rule (indicator or pattern match).
func (s *scanner) emitRule(r *Rule, def Severity, f Finding, title string, ev ...string) {
	sev := def
	if x, ok := parseSeverity(r.Severity); ok {
		sev = x
	}
	f.Severity, f.Rule, f.Refs, f.Title = sev, r.ID, r.Refs, title
	f.Evidence = append(append([]string{}, f.Evidence...), ev...)
	s.rep.add(f)
}
