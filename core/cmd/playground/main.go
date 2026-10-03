//go:build js && wasm

// The config playground on makit.sh: makit's own config check, compiled to WebAssembly, against an embedded copy of
// the security catalog — the browser checks a shield.yaml exactly as `makit shield config check` does, and nothing
// leaves the page. Build: scripts/playground.sh.
package main

import (
	"embed"
	"encoding/json"
	"io/fs"
	"sort"
	"syscall/js"

	"github.com/material-atomic/makit/core/shield"
)

//go:embed all:catalog
var catalog embed.FS

// The catalog is embedded under catalog/security; the loaders look for <dir>/http, <dir>/scoring, <dir>/bots.
const dir = "security"

func main() {
	sub, err := fs.Sub(catalog, "catalog")
	if err != nil {
		panic(err)
	}
	shield.CatalogFS = sub
	js.Global().Set("makitCheck", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) == 0 {
			return `{"error":"makitCheck(yaml)"}`
		}
		opt := shield.CheckOptions{Dirs: []string{dir}, Away: true}
		if len(args) > 1 && args[1].Type() == js.TypeObject {
			opt.InPod = args[1].Get("kubernetes").Truthy()
		}
		issues := shield.CheckConfig([]byte(args[0].String()), opt)
		if issues == nil {
			issues = []shield.Issue{} // [] in JSON, not null
		}
		valid := true
		for _, i := range issues {
			if i.Level == "error" {
				valid = false
			}
		}
		b, _ := json.Marshal(map[string]any{"valid": valid, "issues": issues, "version": shield.Version})
		return string(b)
	}))
	js.Global().Set("makitCatalog", js.FuncOf(func(this js.Value, args []js.Value) any { return catalogJSON() }))
	select {} // keep the functions alive
}

// catalogJSON is what the builder offers: bot categories and agents, score levels and their default actions,
// scoring profiles and signals, HTTP rules — read from the same catalog the check uses.
func catalogJSON() string {
	out := map[string]any{"version": shield.Version}
	if bc, err := shield.LoadBots([]string{dir}, "", nil); err == nil {
		type agent struct{ ID, Name, Category string }
		var agents []agent
		for _, a := range bc.Agents {
			agents = append(agents, agent{a.ID, a.Name, a.Category})
		}
		out["bot_categories"] = bc.Categories
		out["bot_agents"] = agents
		out["spoofed"] = bc.Spoofed
	}
	for name, file := range map[string]string{"http": "http.yaml", "bots": "bots.yaml"} {
		sc, err := shield.LoadScoringSet([]string{dir}, file, "", shield.ScoringOverrides{})
		if err != nil {
			continue
		}
		var signals []string
		for _, s := range sc.Signals {
			signals = append(signals, s.ID)
		}
		profiles := make([]string, 0, len(sc.Profiles))
		for p := range sc.Profiles {
			profiles = append(profiles, p)
		}
		sort.Strings(profiles)
		out["score_"+name] = map[string]any{"levels": sc.LevelOrder, "thresholds": sc.Levels, "actions": sc.Actions,
			"profiles": profiles, "signals": signals}
	}
	if rules, err := shield.LoadHTTPRules([]string{dir}); err == nil {
		var ids []map[string]string
		for _, r := range rules {
			ids = append(ids, map[string]string{"id": r.ID, "title": r.Title})
		}
		out["rules"] = ids
	}
	b, _ := json.Marshal(out)
	return string(b)
}
