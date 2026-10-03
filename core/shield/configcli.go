package shield

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/material-atomic/makit/core/notify"
	"github.com/material-atomic/makit/core/term"
)

// errInvalidConfig makes `makit shield config check` exit 1 after it has printed its findings.
var errInvalidConfig = errors.New("")

func cmdConfig(cfgPath string, dirs []string, args []string) error {
	sub, rest := splitFirst(args)
	if sub != "check" {
		return fmt.Errorf("usage: config check [FILE|-] [--replay LOG [--format auto|nginx|caddy] [--against FILE]] [--json]")
	}
	fs := flag.NewFlagSet("config check", flag.ContinueOnError)
	replay := fs.String("replay", "", "an access log to run the new config against, next to the current one")
	format := fs.String("format", "auto", "access log format: auto, nginx, caddy or alb")
	against := fs.String("against", cfgPath, "the current config to compare with")
	asJSON := fs.Bool("json", false, "JSON output")
	n := fs.Int("n", 10, "examples to show")
	file, more := splitFirst(rest)
	if strings.HasPrefix(file, "-") && file != "-" {
		file, more = "", rest
	}
	if err := fs.Parse(more); err != nil {
		return err
	}
	if file == "" {
		file = cfgPath
	}
	var b []byte
	var err error
	if file == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(file)
	}
	if err != nil {
		return err
	}
	opt := CheckOptions{Dirs: dirs, Files: true, InPod: os.Getenv("KUBERNETES_SERVICE_HOST") != ""}
	if nc, err := notify.Load(firstNonEmpty(os.Getenv("MAKIT_NOTIFY_CONFIG"), notify.DefaultConfig)); err == nil {
		opt.Channels = []string{}
		for _, ch := range nc.Channels {
			opt.Channels = append(opt.Channels, ch.Name)
		}
	}
	issues := CheckConfig(b, opt)
	errs := 0
	for _, i := range issues {
		if i.Level == "error" {
			errs++
		}
	}
	var res *ReplayResult
	if *replay != "" && errs == 0 {
		if res, err = replayConfigs(*against, b, dirs, *replay, *format, *n); err != nil {
			return err
		}
	}
	if *asJSON {
		out := map[string]any{"file": file, "valid": errs == 0, "issues": issues}
		if res != nil {
			out["replay"] = res
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	} else {
		printIssues(file, issues, errs)
		if res != nil {
			printReplay(res, *against)
		}
	}
	if errs > 0 {
		return errInvalidConfig
	}
	return nil
}

func printIssues(file string, issues []Issue, errs int) {
	for _, i := range issues {
		mark := term.Yellow("⚠")
		if i.Level == "error" {
			mark = term.Red("✗")
		}
		where := ""
		if i.Line > 0 {
			where = term.Dim(fmt.Sprintf("line %d: ", i.Line))
		}
		fmt.Printf("  %s %s%s\n", mark, where, i.Message)
	}
	warns := len(issues) - errs
	plural := func(n int, w string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", w)
		}
		return fmt.Sprintf("%d %ss", n, w)
	}
	switch {
	case errs > 0:
		fmt.Println(term.Red(fmt.Sprintf("✗ %s: %s, %s", file, plural(errs, "error"), plural(warns, "warning"))) +
			term.Dim(" — not loaded; the running shield keeps its current config"))
	case warns > 0:
		fmt.Println(term.Yellow(fmt.Sprintf("✓ %s is valid, with %s", file, plural(warns, "warning"))))
	default:
		fmt.Println(term.Ok(file + " is valid"))
	}
}

func replayConfigs(currentPath string, next []byte, dirs []string, logPath, format string, n int) (*ReplayResult, error) {
	curCfg, err := LoadConfig(currentPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("current config: %w", err)
		}
		curCfg = defaultConfig()
	}
	nextCfg, err := ParseConfig(next, "new config")
	if err != nil {
		return nil, err
	}
	st, err := LoadState()
	if err != nil {
		st = &State{}
	}
	lists, _, err := LoadLists()
	if err != nil {
		lists = NewSet()
	}
	cur, curClock, err := replayPolicy(curCfg, dirs, st, lists)
	if err != nil {
		return nil, fmt.Errorf("current config: %w", err)
	}
	nxt, nextClock, err := replayPolicy(nextCfg, dirs, st, lists)
	if err != nil {
		return nil, err
	}
	f, err := openLog(logPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Replay(cur, nxt, curClock, nextClock, f, format, n)
}

func printReplay(r *ReplayResult, against string) {
	fmt.Printf("\n%s %s requests %s\n", term.Bold("replay:"), thousands(r.Requests),
		term.Dim(fmt.Sprintf("(%s → %s, compared with %s; both enforced, nothing written)", r.First.Format("01-02 15:04"),
			r.Last.Format("01-02 15:04"), against)))
	if r.Skipped > 0 {
		fmt.Println(term.Dim(fmt.Sprintf("  %d lines not recognised, skipped", r.Skipped)))
	}
	if r.Requests == 0 {
		fmt.Println(term.Yellow("  no request in the log could be read — try --format nginx or --format caddy"))
		return
	}
	fmt.Printf("  %-22s %s\n", "unchanged", thousands(r.Unchanged))
	keys := make([]string, 0, len(r.Changes))
	for k := range r.Changes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return r.Changes[keys[i]] > r.Changes[keys[j]] })
	for _, k := range keys {
		_, to, _ := strings.Cut(k, " → ")
		fmt.Printf("  %s %s %s\n", term.Verdict(to, fmt.Sprintf("%-22s", k)), thousands(r.Changes[k]),
			term.Dim(fmt.Sprintf("(%d clients)", r.Clients[k])))
	}
	if len(r.ByRule) > 0 {
		rules := make([]string, 0, len(r.ByRule))
		for k := range r.ByRule {
			rules = append(rules, k)
		}
		sort.Slice(rules, func(i, j int) bool { return r.ByRule[rules[i]] > r.ByRule[rules[j]] })
		var parts []string
		for _, k := range rules {
			parts = append(parts, fmt.Sprintf("%s %d", term.Cyan(k), r.ByRule[k]))
		}
		fmt.Printf("  %s %s\n", term.Dim("newly stopped by:"), strings.Join(parts, " · "))
	}
	if r.Likely > 0 {
		fmt.Println(term.Yellow(fmt.Sprintf("  ⚠ %d newly stopped requests look like real visitors: a browser the app answered with 2xx/3xx — check them before you load this config", r.Likely)))
	}
	if len(r.Examples) > 0 {
		fmt.Println(term.Dim("  examples:"))
	}
	for _, e := range r.Examples {
		mark := " "
		if e.Likely {
			mark = term.Yellow("⚠")
		}
		fmt.Printf("  %s %s %s %s %s → %s %s %s\n", mark, term.Bold(fmt.Sprintf("%-15s", e.Client)), e.Method, e.Host+e.URI,
			term.Dim(fmt.Sprintf("[%d]", e.Status)), term.Verdict(e.To, e.To), term.Cyan(e.Rule), term.Dim(e.Reason))
	}
	if len(r.Changes) == 0 {
		fmt.Println(term.Ok("the new config decides every request in this log the same way"))
	}
}
