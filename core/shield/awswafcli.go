package shield

import (
	"context"
	"flag"
	"fmt"
	"time"

	"github.com/material-atomic/makit/core/term"
)

// cmdWAF: makit shield waf sync [--dry-run] — the same sync the gate runs, from the state on disk.
func cmdWAF(cfgPath string, args []string) error {
	sub, rest := splitFirst(args)
	if sub != "sync" {
		return fmt.Errorf("usage: waf sync [--dry-run]")
	}
	fs := flag.NewFlagSet("waf sync", flag.ContinueOnError)
	dry := fs.Bool("dry-run", false, "show what would change, change nothing")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if !cfg.AWSWAF.Enabled() {
		return fmt.Errorf("no aws_waf: in %s (makit docs kubernetes)", cfgPath)
	}
	st, err := LoadState()
	if err != nil {
		return err
	}
	trusted, err := cfg.Trusted()
	if err != nil {
		return err
	}
	allow, block := st.Sets(cfg.Allow)
	now := time.Now()
	pl := planWAF(append(block.Live(now), siteBans(st, now)...), allow.Live(now), trusted, now, cfg.AWSWAF.max())
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	w, err := NewWAFSync(ctx, cfg.AWSWAF)
	if err != nil {
		return err
	}
	res, err := w.Sync(ctx, pl, *dry)
	fmt.Printf("%s %d IPv4 · %d IPv6\n", term.Bold("bans for the IP sets:"), len(pl.V4), len(pl.V6))
	for _, x := range []struct {
		n    int
		what string
	}{{pl.Allowed, "overlap an allow entry"}, {pl.Trusted, "overlap a trusted proxy"}, {pl.Site, "are for one site only"},
		{pl.TooWide, "are wider than /8 (IPv4) or /32 (IPv6)"}, {pl.OverMax, "are the oldest beyond the IP set limit"}} {
		if x.n > 0 {
			fmt.Println(term.Dim(fmt.Sprintf("  left out: %d that %s", x.n, x.what)))
		}
	}
	switch {
	case err != nil:
		return err
	case !res.Changed:
		fmt.Println(term.Ok("the IP sets are up to date"))
	case *dry:
		fmt.Println(term.Yellow("the IP sets differ — run without --dry-run to update them"))
	default:
		fmt.Println(term.Ok("IP sets updated"))
	}
	return nil
}

// siteBans returns the site-only bans of a state (the plan leaves them out and counts them).
func siteBans(st *State, now time.Time) []Entry {
	var out []Entry
	for _, e := range live(append([]Entry(nil), st.Block...), now) {
		if e.Site != "" {
			out = append(out, e)
		}
	}
	return out
}
