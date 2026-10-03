package shield

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"time"
)

// State is the persisted block and allow lists (the source of truth; the kernel set and the running gate follow it).
type State struct {
	Block []Entry `json:"block"`
	Allow []Entry `json:"allow"`
}

func statePath() string { return filepath.Join(StateDir, "state.json") }

// withState loads the state under an exclusive lock, lets fn change it, and saves it atomically.
func withState(fn func(*State) error) (*State, error) {
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(statePath()+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	if err := lockFile(lock); err != nil {
		return nil, err
	}
	st, err := LoadState()
	if err != nil {
		return nil, err
	}
	if fn != nil {
		if err := fn(st); err != nil {
			return nil, err
		}
		now := time.Now()
		st.Block, st.Allow = live(st.Block, now), live(st.Allow, now)
		b, _ := json.MarshalIndent(st, "", "  ")
		tmp := statePath() + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, statePath()); err != nil {
			return nil, err
		}
	}
	return st, nil
}

func LoadState() (*State, error) {
	st := &State{}
	b, err := os.ReadFile(statePath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	return st, json.Unmarshal(b, st)
}

func live(es []Entry, now time.Time) []Entry {
	out := es[:0]
	for _, e := range es {
		if e.Until.IsZero() || now.Before(e.Until) {
			out = append(out, e)
		}
	}
	return out
}

func upsert(es []Entry, e Entry) []Entry {
	for i := range es {
		if es[i].Prefix == e.Prefix && es[i].Site == e.Site {
			es[i] = e
			return es
		}
	}
	return append(es, e)
}

// remove drops the entries for p — of one site, or every scope when site is "*".
func remove(es []Entry, p netip.Prefix, site ...string) ([]Entry, bool) {
	want := "*"
	if len(site) > 0 {
		want = site[0]
	}
	out, found := es[:0], false
	for _, e := range es {
		if e.Prefix == p && (want == "*" || e.Site == want) {
			found = true
			continue
		}
		out = append(out, e)
	}
	return out, found
}

// Sets turns the state plus config allow entries into lookup sets: server-wide ones, and per site.
func (st *State) Sets(cfgAllow []string) (allow, block *Set) {
	allow, block, _, _ = st.SiteSets(cfgAllow)
	return allow, block
}

func (st *State) SiteSets(cfgAllow []string) (allow, block *Set, siteAllow, siteBlock map[string]*Set) {
	allow, block = NewSet(), NewSet()
	siteAllow, siteBlock = map[string]*Set{}, map[string]*Set{}
	get := func(m map[string]*Set, k string) *Set {
		if m[k] == nil {
			m[k] = NewSet()
		}
		return m[k]
	}
	for _, e := range st.Allow {
		if e.Site != "" {
			get(siteAllow, e.Site).Add(e)
		} else {
			allow.Add(e)
		}
	}
	for _, a := range cfgAllow {
		if p, err := ParsePrefix(a); err == nil {
			allow.Add(Entry{Prefix: p, Source: "config", Reason: "shield.yaml allow"})
		}
	}
	for _, e := range st.Block {
		if e.Site != "" {
			get(siteBlock, e.Site).Add(e)
		} else {
			block.Add(e)
		}
	}
	return
}
