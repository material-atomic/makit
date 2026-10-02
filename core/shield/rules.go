package shield

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
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
	paths, uas []*regexp.Regexp
	headers    map[string]*regexp.Regexp
}

func (r *HTTPRule) compile() error {
	var err error
	if r.BanRaw != "" {
		if r.BanFor, err = time.ParseDuration(r.BanRaw); err != nil {
			return fmt.Errorf("ban_for: %w", err)
		}
	}
	for _, p := range r.When.Paths {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.paths = append(r.paths, re)
	}
	for _, p := range r.When.UserAgents {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.uas = append(r.uas, re)
	}
	r.headers = map[string]*regexp.Regexp{}
	for h, p := range r.When.Headers {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.headers[strings.ToLower(h)] = re
	}
	return nil
}

func anyMatch(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

func (r *HTTPRule) Match(q Request) bool {
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
	if len(r.paths) > 0 && !anyMatch(r.paths, q.URI) {
		return false
	}
	if len(r.uas) > 0 && !anyMatch(r.uas, q.UA) {
		return false
	}
	for h, re := range r.headers {
		v, ok := q.Headers[h]
		if !ok || !re.MatchString(v) {
			return false
		}
	}
	return len(r.paths) > 0 || len(r.uas) > 0 || len(r.headers) > 0 || len(r.When.Methods) > 0
}

// LoadHTTPRules reads <dir>/http/*.yaml from catalog directories; later directories override the same id.
func LoadHTTPRules(dirs []string) ([]HTTPRule, error) {
	byID := map[string]HTTPRule{}
	for _, d := range dirs {
		files, _ := filepath.Glob(filepath.Join(d, "http", "*.yaml"))
		sort.Strings(files)
		for _, f := range files {
			b, err := os.ReadFile(f)
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
