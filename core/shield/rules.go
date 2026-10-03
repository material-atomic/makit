package shield

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// HTTPRule is one file in security/http/: what a request looks like, and how long to ban its client.
// Fields are ANDed; patterns inside a field are ORed. Regexes are RE2.
type HTTPRule struct {
	ID       string        `yaml:"id"`
	Title    string        `yaml:"title"`
	Doc      string        `yaml:"doc"`
	Refs     []string      `yaml:"refs"`
	Disabled bool          `yaml:"disabled"`
	BanFor   time.Duration `yaml:"-"`
	BanRaw   string        `yaml:"ban_for"`
	When     struct {
		Methods    []string          `yaml:"methods"`
		Paths      []string          `yaml:"paths"`
		UserAgents []string          `yaml:"user_agents"`
		Headers    map[string]string `yaml:"headers"`
	} `yaml:"match"`
	paths, uas []*matcher
	headers    []headerMatch // a slice, not a map: ranging over a map costs more than the lookups it drives
	uaMemo     *memo[bool]
}

func (r *HTTPRule) compile() error {
	var err error
	if r.BanRaw != "" {
		if r.BanFor, err = time.ParseDuration(r.BanRaw); err != nil {
			return fmt.Errorf("ban_for: %w", err)
		}
	}
	for _, p := range r.When.Paths {
		re, err := compileMatcher(p)
		if err != nil {
			return err
		}
		r.paths = append(r.paths, re)
	}
	for _, p := range r.When.UserAgents {
		re, err := compileMatcher(p)
		if err != nil {
			return err
		}
		r.uas = append(r.uas, re)
	}
	if len(r.uas) > 0 {
		r.uaMemo = newMemo[bool]()
	}
	r.headers = nil
	for h, p := range r.When.Headers {
		re, err := compileMatcher(p)
		if err != nil {
			return err
		}
		r.headers = append(r.headers, headerMatch{strings.ToLower(h), re})
	}
	sort.Slice(r.headers, func(i, j int) bool { return r.headers[i].name < r.headers[j].name })
	return nil
}

type headerMatch struct {
	name string
	re   *matcher
}

func anyMatch(res []*matcher, s string) bool {
	return anyMatchLower(res, s, strings.ToLower(s))
}

func anyMatchLower(res []*matcher, s, lower string) bool {
	for _, re := range res {
		if re.matchLower(s, lower) {
			return true
		}
	}
	return false
}

func (r *HTTPRule) Match(q Request) bool {
	return r.match(q, "")
}

// match is Match with the URI already lower-cased for the literal prefilters ("" to lower it here): the rules of one
// request share a single copy instead of making one each.
func (r *HTTPRule) match(q Request, lowerURI string) bool {
	if len(r.When.Methods) > 0 {
		ok := false
		for _, m := range r.When.Methods {
			if strings.EqualFold(m, q.Method) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	if len(r.paths) > 0 {
		if lowerURI == "" {
			lowerURI = strings.ToLower(q.URI)
		}
		if !anyMatchLower(r.paths, q.URI, lowerURI) {
			return false
		}
	}
	if len(r.uas) > 0 && !r.uaMemo.get(q.UA, func() bool { return anyMatch(r.uas, q.UA) }) {
		return false
	}
	for _, hm := range r.headers {
		v, ok := q.Headers[hm.name]
		if !ok || !hm.re.MatchString(v) {
			return false
		}
	}
	return len(r.paths) > 0 || len(r.uas) > 0 || len(r.headers) > 0 || len(r.When.Methods) > 0
}

// LoadHTTPRules reads <dir>/http/*.yaml from catalog directories; later directories override the same id.
func LoadHTTPRules(dirs []string) ([]HTTPRule, error) {
	byID := map[string]HTTPRule{}
	for _, d := range dirs {
		files, _ := globCatalog(filepath.Join(d, "http", "*.yaml"))
		sort.Strings(files)
		for _, f := range files {
			b, err := readCatalog(f)
			if err != nil {
				return nil, err
			}
			var r HTTPRule
			if err := yaml.Unmarshal(b, &r); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			if r.ID == "" {
				return nil, fmt.Errorf("%s: missing id", f)
			}
			if err := r.compile(); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			byID[r.ID] = r
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]HTTPRule, 0, len(ids))
	for _, id := range ids {
		if !byID[id].Disabled {
			out = append(out, byID[id])
		}
	}
	return out, nil
}
