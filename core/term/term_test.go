package term

import (
	"regexp"
	"strings"
	"testing"
)

var ansi = regexp.MustCompile("\033\\[[0-9;]*m")

const usage = `makit shield — IP gate for web traffic

  serve                         run the gate (systemd: makit-shield.service)
  ban IP|CIDR [--for 24h] [--reason TEXT] [--site NAME]
  check --peer IP [--client IP]
                                what the gate would decide
`

const report = `makit shield · app.example (web-1) · 2026-10-03 09:00–09:05 UTC
1,204 requests · 2 suspicious IPs · 1 banned · blocked 14 · high 1

[CRITICAL 120] 203.0.113.9 (NL) · 31 req · banned until 10-04 09:03 UTC (score critical)
   /.env /wp-login.php · status 403
[MEDIUM 40] 198.51.100.7 · 9 req · would block 9 (observe mode)

+3 more suspicious IPs (makit shield log --blocked)

⚠ your app answered 5xx to 2 suspicious requests — unknown paths should return 404, not an error`

// Colour must never change what is printed: stripped of escapes, the text is the same, columns included.
func TestColourKeepsText(t *testing.T) {
	On = true
	defer func() { On = false }()
	for name, c := range map[string][2]string{
		"usage":  {usage, Usage(usage)},
		"report": {report, Report(report)},
	} {
		if c[1] == c[0] {
			t.Errorf("%s: nothing coloured", name)
		}
		if got := ansi.ReplaceAllString(c[1], ""); got != c[0] {
			t.Errorf("%s: text changed:\n%s\nwant:\n%s", name, got, c[0])
		}
	}
	if !strings.Contains(Report(report), Alert("[CRITICAL 120]")) || !strings.Contains(Report(report), Yellow("would block 9 (observe mode)")) {
		t.Errorf("report: level or action not coloured as expected:\n%q", Report(report))
	}
	if Verdict("blocked", "x") != Red("x") || Verdict("allowed", "x") != Green("x") || Verdict("limit 60/1m", "x") != Yellow("x") {
		t.Error("verdict colours")
	}
}

func TestOffIsPlain(t *testing.T) {
	On = false
	if Usage(usage) != usage || Report(report) != report || Ok("x") != "✓ x" || Red("x") != "x" {
		t.Error("colour off must print plain text")
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("FORCE_COLOR", "")
	t.Setenv("CLICOLOR_FORCE", "")
	t.Setenv("NO_COLOR", "1")
	if detect() {
		t.Error("NO_COLOR must turn colour off")
	}
	t.Setenv("FORCE_COLOR", "1")
	if !detect() {
		t.Error("FORCE_COLOR must turn colour on")
	}
}
