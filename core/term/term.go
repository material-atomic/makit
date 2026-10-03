// Package term colours what makit prints for a person at a terminal. Colour is on only when stdout is a terminal,
// NO_COLOR is unset and TERM is not "dumb"; FORCE_COLOR or CLICOLOR_FORCE turn it on anywhere (CI logs, `less -R`).
// Text that is saved or sent (reports, notifications, --json) never goes through here.
package term

import (
	"os"
	"regexp"
	"strings"
)

// TTY tells whether stdout is a terminal: a person reads it, so a command may print a summary instead of JSON.
var TTY = isTTY()

// On tells whether output is coloured. Tests and callers may set it.
var On = detect()

func isTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func detect() bool {
	if v := os.Getenv("FORCE_COLOR"); v != "" && v != "0" {
		return true
	}
	if v := os.Getenv("CLICOLOR_FORCE"); v != "" && v != "0" {
		return true
	}
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	return TTY
}

func paint(code, s string) string {
	if !On || s == "" {
		return s
	}
	return "\033[" + code + "m" + s + "\033[0m"
}

func Bold(s string) string    { return paint("1", s) }
func Dim(s string) string     { return paint("2", s) }
func Red(s string) string     { return paint("31", s) }
func Green(s string) string   { return paint("32", s) }
func Yellow(s string) string  { return paint("33", s) }
func Blue(s string) string    { return paint("34", s) }
func Magenta(s string) string { return paint("35", s) }
func Cyan(s string) string    { return paint("36", s) }
func BoldRed(s string) string { return paint("1;31", s) }
func Alert(s string) string   { return paint("1;41;97", s) } // white on red: the worst news

// Ok, Warn and Fail mark a line's outcome: ✓ green, ⚠ yellow, ✗ red.
func Ok(s string) string   { return Green("✓") + " " + s }
func Warn(s string) string { return Yellow("⚠ " + s) }
func Fail(s string) string { return Red("✗ " + s) }

// Verdict colours s by what a shield verdict or action means for the visitor: let through green, stopped red,
// only counted (observe mode, limits, logging) yellow. s may be padded; the word is looked up trimmed.
func Verdict(v, s string) string {
	switch strings.TrimSpace(strings.ToLower(v)) {
	case "allowed", "allowlisted", "allow", "bot-verified", "verified", "pass", "ok", "on":
		return Green(s)
	case "blocked", "block", "ban", "banned", "dropped", "drop", "deny", "spoofed", "fake", "off", "invalid":
		return Red(s)
	case "would-block", "would-limit", "limited", "observe", "log", "logged", "unverified", "unknown", "pending":
		return Yellow(s)
	}
	if strings.HasPrefix(strings.TrimSpace(v), "limit") {
		return Yellow(s)
	}
	return s
}

// Level colours s by a scoring level: critical white on red, high red, medium yellow, low cyan, normal dim.
func Level(l, s string) string {
	switch strings.ToLower(strings.TrimSpace(l)) {
	case "critical":
		return Alert(s)
	case "high":
		return BoldRed(s)
	case "medium":
		return Yellow(s)
	case "low":
		return Cyan(s)
	case "normal", "":
		return Dim(s)
	}
	return s
}

// Usage colours a help text laid out the makit way: the first line is the title, a heading ends in a colon at the
// margin, and a line indented by two spaces starts with a command (cyan). Descriptions stay plain to be read; the
// examples or asides in parentheses at the end of a line are dimmed. lib/common.sh usage_colour does the same.
func Usage(text string) string {
	if !On {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		t := strings.TrimSpace(l)
		switch {
		case t == "":
		case i == 0:
			if name, rest, ok := strings.Cut(l, " — "); ok {
				lines[i] = Bold(name) + Dim(" — ") + rest
			} else {
				lines[i] = Bold(l)
			}
		case l[0] != ' ' && strings.HasSuffix(t, ":"):
			lines[i] = Bold(l)
		case strings.HasPrefix(l, "  ") && !strings.HasPrefix(l, "    ") && !strings.HasPrefix(t, "#"):
			lines[i] = dimAside(usageLine(l))
		case strings.HasPrefix(l, "    "):
			lines[i] = dimAside(l)
		}
	}
	return strings.Join(lines, "\n")
}

// usageLine: "  cmd ARGS   description" → cyan command, the rest as it is.
func usageLine(l string) string {
	cmd, rest, _ := strings.Cut(l[2:], " ")
	if rest != "" {
		rest = " " + rest
	}
	return "  " + Cyan(cmd) + rest
}

var aside = regexp.MustCompile(`(\s)(\([^()]*\))$`)

// dimAside dims a closing "(…)" aside, such as "(systemd: makit-shield.service)".
func dimAside(l string) string { return aside.ReplaceAllString(l, "${1}"+Dim("$2")) }

var (
	reportHead  = regexp.MustCompile(`^makit shield · `)
	reportLevel = regexp.MustCompile(`^\[([A-Z]+)( \d+)?\]`)
	reportAct   = regexp.MustCompile(`(banned until [^·]*|blocked \d+|rate-limited \d+|would block \d+ \(observe mode\))\s*$`)
)

// Report colours a shield batch report (the same text that is saved and sent) for reading in a terminal.
func Report(text string) string {
	if !On {
		return text
	}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		switch {
		case reportHead.MatchString(l):
			lines[i] = Bold(l)
		case strings.HasPrefix(l, "────"):
			lines[i] = Dim(l)
		case strings.HasPrefix(l, "⚠"):
			lines[i] = Yellow(l)
		case strings.HasPrefix(l, "+") && strings.Contains(l, "more suspicious"):
			lines[i] = Dim(l)
		case reportLevel.MatchString(l):
			m := reportLevel.FindStringSubmatchIndex(l)
			tag, rest := l[:m[1]], l[m[1]:]
			if a := reportAct.FindStringIndex(rest); a != nil {
				act := rest[a[0]:a[1]]
				c := Red(act)
				if strings.HasPrefix(act, "rate") || strings.HasPrefix(act, "would") {
					c = Yellow(act)
				}
				rest = rest[:a[0]] + c
			}
			lines[i] = Level(l[m[2]:m[3]], tag) + Bold(firstField(rest)) + afterFirstField(rest)
		case strings.HasPrefix(l, "   "):
			lines[i] = Dim(l)
		}
	}
	return strings.Join(lines, "\n")
}

// firstField / afterFirstField split " 1.2.3.4 (VN) · 12 req" after the address.
func firstField(s string) string {
	t := strings.TrimLeft(s, " ")
	lead := s[:len(s)-len(t)]
	if i := strings.IndexByte(t, ' '); i >= 0 {
		return lead + t[:i]
	}
	return lead + t
}

func afterFirstField(s string) string { return s[len(firstField(s)):] }
