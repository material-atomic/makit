package shield

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const botsUsage = `makit shield bots — known bots, crawlers and AI agents, and what to do with them

  bots [list]                   categories with their action, the spoofed action and the bot score actions
  bots agents [CATEGORY] [--json]
  bots set KEY ACTION           KEY: a category (ai-crawler…), an agent id (gptbot…), spoofed, or score.LEVEL
                                ACTION: allow | log | block | "ban 24h" | "limit 60/1m"
  bots unset KEY                back to the catalog default
  bots check --ua TEXT [--ip IP] [--header k=v]…
                                how a client would be classified (verifies the IP now)
  bots update                   download the crawlers' published IP ranges (the gate does this daily)
  bots robots                   robots.txt lines for every bot your policy blocks
`

func cmdBots(cfgPath string, dirs []string, args []string) error {
	sub, rest := splitFirst(args)
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	load := func() (*BotCatalog, *Scoring, error) {
		bc, err := LoadBots(dirs, cfg.Bots.File, cfg.Bots.Policy)
		if err != nil || bc == nil {
			if err == nil {
				err = fmt.Errorf("no bots catalog (security/bots/agents.yaml) — makit rules update")
			}
			return nil, nil, err
		}
		sc, err := LoadScoringSet(dirs, "bots.yaml", cfg.Bots.ScoreFile, cfg.Bots.Score)
		return bc, sc, err
	}
	switch sub {
	case "", "list":
		bc, sc, err := load()
		if err != nil {
			return err
		}
		count := map[string]int{}
		for _, a := range bc.Agents {
			count[a.Category]++
		}
		cats := make([]string, 0, len(bc.Categories))
		for c := range bc.Categories {
			cats = append(cats, c)
		}
		sort.Strings(cats)
		fmt.Println("CATEGORY       ACTION         AGENTS  ")
		for _, c := range cats {
			a, _ := bc.Policy(c)
			fmt.Printf("  %-13s %-14s %3d     %s\n", c, a, count[c], bc.Categories[c].Label)
		}
		sp, _ := bc.Policy("spoofed")
		fmt.Printf("  %-13s %-14s         pretends to be a verifiable bot\n", "spoofed", sp)
		var own []string
		for k, v := range cfg.Bots.Policy {
			if _, isCat := bc.Categories[k]; !isCat && k != "spoofed" {
				own = append(own, fmt.Sprintf("%s=%s", k, v))
			}
		}
		if len(own) > 0 {
			sort.Strings(own)
			fmt.Println("agent overrides:", strings.Join(own, "  "))
		}
		if sc != nil {
			fmt.Print("bot score (undeclared clients):")
			for _, l := range sc.LevelOrder {
				fmt.Printf("  %s≥%d → %s", l, sc.Levels[l], sc.Act(l))
			}
			fmt.Println()
		}
		return nil
	case "agents":
		bc, _, err := load()
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("agents", flag.ContinueOnError)
		asJSON := fs.Bool("json", false, "JSON")
		cat, more := splitFirst(rest)
		if strings.HasPrefix(cat, "-") {
			cat, more = "", rest
		}
		if err := fs.Parse(more); err != nil {
			return err
		}
		var out []*Agent
		for _, a := range bc.Agents {
			if cat == "" || a.Category == cat {
				out = append(out, a)
			}
		}
		if *asJSON {
			return json.NewEncoder(os.Stdout).Encode(out)
		}
		for _, a := range out {
			v := "claimed"
			if a.Verifiable() {
				v = "verifiable"
			}
			fmt.Printf("  %-22s %-13s %-14s %-10s %s\n", a.ID, a.Category, bc.PolicyFor(a), v, firstNonEmpty(a.Operator, "-"))
		}
		return nil
	case "set", "unset":
		key, val := "", ""
		if sub == "set" {
			if len(rest) != 2 {
				return fmt.Errorf("usage: bots set KEY ACTION (quote actions with spaces: \"ban 24h\")")
			}
			key, val = rest[0], rest[1]
		} else if len(rest) == 1 {
			key = rest[0]
		} else {
			return fmt.Errorf("usage: bots unset KEY")
		}
		path := []string{"bots", "policy", key}
		if lvl, ok := strings.CutPrefix(key, "score."); ok {
			path = []string{"bots", "score", "actions", lvl}
		}
		if sub == "set" {
			if _, err := ParseAct(val); err != nil {
				return err
			}
		}
		if err := SetConfigPath(cfgPath, path, val); err != nil {
			return err
		}
		// Validate the result the way the gate will (unknown keys or levels fail here, not at reload).
		if c2, err := LoadConfig(cfgPath); err == nil {
			cfg = c2
		}
		if _, sc, err := load(); err != nil {
			_ = SetConfigPath(cfgPath, path, "") // undo
			return err
		} else if lvl, ok := strings.CutPrefix(key, "score."); ok && sc != nil {
			if _, known := sc.Levels[lvl]; !known {
				_ = SetConfigPath(cfgPath, path, "")
				return fmt.Errorf("bot score has no level %q (%s)", lvl, strings.Join(sc.LevelOrder, ", "))
			}
		}
		if sub == "set" {
			fmt.Printf("bots: %s → %s\n", key, val)
		} else {
			fmt.Printf("bots: %s back to the catalog default\n", key)
		}
		return nil
	case "check":
		bc, sc, err := load()
		if err != nil {
			return err
		}
		fs := flag.NewFlagSet("check", flag.ContinueOnError)
		ua := fs.String("ua", "", "User-Agent")
		ip := fs.String("ip", "", "client IP (verifies the claimed identity)")
		var hdr multi
		fs.Var(&hdr, "header", "request header k=v (repeatable); any header makes missing ones count")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		r := Request{UA: *ua, Method: "GET", URI: "/"}
		for _, h := range hdr {
			k, v, _ := strings.Cut(h, "=")
			if r.Headers == nil {
				r.Headers = map[string]string{}
			}
			r.Headers[strings.ToLower(k)] = v
		}
		a := bc.Identify(r)
		if a == nil {
			fmt.Println("not a known bot")
			if sc != nil {
				s, hits := sc.ScoreRequest(r, 0)
				fmt.Printf("bot score %d (%s) → %s  %s\n", s, sc.Level(s), sc.Act(sc.Level(s)), strings.Join(hits, " "))
			}
			return nil
		}
		st := "claimed"
		if a.Verifiable() {
			st = "not checked (pass --ip)"
			if *ip != "" {
				addr, err := netip.ParseAddr(*ip)
				if err != nil {
					return err
				}
				v := NewVerifier()
				v.Sync = true
				v.LoadRanges(bc)
				st = v.Check(a, addr, time.Now())
			}
		}
		act := bc.PolicyFor(a)
		if st == "spoofed" {
			act, _ = bc.Policy("spoofed")
		}
		fmt.Printf("%s (%s) · %s · %s → %s\n", a.Name, a.ID, bc.Categories[a.Category].Label, st, act)
		if a.URL != "" {
			fmt.Println("  ", a.URL)
		}
		return nil
	case "update":
		bc, _, err := load()
		if err != nil {
			return err
		}
		n, errs := UpdateBotRanges(bc)
		ids := make([]string, 0, len(n))
		for id := range n {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			fmt.Printf("  %-18s %d ranges\n", id, n[id])
		}
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "  ✗", e)
		}
		if len(n) == 0 && len(errs) > 0 {
			return fmt.Errorf("no ranges downloaded")
		}
		return nil
	case "robots":
		bc, _, err := load()
		if err != nil {
			return err
		}
		fmt.Print(bc.Robots())
		return nil
	case "help", "-h", "--help":
		fmt.Print(botsUsage)
		return nil
	}
	fmt.Fprint(os.Stderr, botsUsage)
	return fmt.Errorf("unknown bots command %q", sub)
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// SetConfigPath sets (or, with value "", removes) a nested key in the YAML config, keeping comments.
func SetConfigPath(path string, keys []string, value string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	m := doc.Content[0]
	for i, k := range keys {
		if m.Kind != yaml.MappingNode {
			return fmt.Errorf("%s: %s is not a mapping", path, strings.Join(keys[:i], "."))
		}
		var next *yaml.Node
		at := -1
		for j := 0; j+1 < len(m.Content); j += 2 {
			if m.Content[j].Value == k {
				next, at = m.Content[j+1], j
			}
		}
		last := i == len(keys)-1
		if last {
			if value == "" {
				if at >= 0 {
					m.Content = append(m.Content[:at], m.Content[at+2:]...)
				}
				break
			}
			if next == nil {
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.ScalarNode})
				next = m.Content[len(m.Content)-1]
			}
			next.Kind, next.Tag, next.Value, next.Style, next.Content = yaml.ScalarNode, "!!str", value, 0, nil
			break
		}
		if next == nil || (next.Kind == yaml.ScalarNode && next.Tag == "!!null") {
			if value == "" {
				return nil // nothing to remove
			}
			if next == nil {
				m.Content = append(m.Content, &yaml.Node{Kind: yaml.ScalarNode, Value: k}, &yaml.Node{Kind: yaml.MappingNode})
				next = m.Content[len(m.Content)-1]
			} else {
				next.Kind, next.Tag, next.Value = yaml.MappingNode, "", ""
			}
		}
		m = next
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, st.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LocalCatalog is where maintainers keep their own catalog files; it overrides the bundled and downloaded ones.
var LocalCatalog = "/etc/makit/security"

var customizable = map[string][]string{
	"scoring": {"scoring/http.yaml"},
	"bots":    {"bots/agents.yaml", "scoring/bots.yaml"},
	"rules":   {"http"},
}

// cmdCustomize copies the catalog's files into /etc/makit/security so the maintainer can edit them; they then win
// over the bundled set and `makit rules update` never overwrites them.
func cmdCustomize(dirs []string, args []string) error {
	what, rest := splitFirst(args)
	fs := flag.NewFlagSet("customize", flag.ContinueOnError)
	to := fs.String("to", LocalCatalog, "local catalog directory")
	force := fs.Bool("force", false, "overwrite files already customized")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	files, ok := customizable[what]
	if !ok {
		return fmt.Errorf("customize scoring|bots|rules [--to DIR] [--force]")
	}
	for _, rel := range files {
		var src string
		for _, d := range dirs { // newest source that is not the destination
			p := filepath.Join(d, rel)
			if _, err := os.Stat(p); err == nil && filepath.Clean(d) != filepath.Clean(*to) {
				src = p
			}
		}
		if src == "" {
			return fmt.Errorf("%s not found in the catalog", rel)
		}
		if err := copyTree(src, filepath.Join(*to, rel), *force); err != nil {
			return err
		}
	}
	fmt.Printf("edit the files under %s — they override the bundled catalog; the running gate reloads them within 2 s\n", *to)
	return nil
}

func copyTree(src, dst string, force bool) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		ents, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name()), force); err != nil {
				return err
			}
		}
		return nil
	}
	if _, err := os.Stat(dst); err == nil && !force {
		fmt.Printf("  kept   %s (already customized; --force to replace)\n", dst)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	fmt.Printf("  copied %s\n", dst)
	return out.Close()
}
