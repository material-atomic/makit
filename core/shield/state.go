package shield

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"syscall"
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
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
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
		if es[i].Prefix == e.Prefix {
			es[i] = e
			return es
		}
	}
	return append(es, e)
}

func remove(es []Entry, p netip.Prefix) ([]Entry, bool) {
	for i := range es {
		if es[i].Prefix == p {
			return append(es[:i], es[i+1:]...), true
		}
	}
	return es, false
}

// Sets turns the state plus config allow entries into lookup sets.
func (st *State) Sets(cfgAllow []string) (allow, block *Set) {
	allow, block = NewSet(), NewSet()
	for _, e := range st.Allow {
		allow.Add(e)
	}
	for _, a := range cfgAllow {
		if p, err := ParsePrefix(a); err == nil {
			allow.Add(Entry{Prefix: p, Source: "config", Reason: "shield.yaml allow"})
		}
	}
	for _, e := range st.Block {
		block.Add(e)
	}
	return allow, block
}
