package shield

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Bulk lists (feeds, exports from other tools, your own millions of IPs) live as text files, one IP/CIDR per line,
// in <StateDir>/lists/<name>.txt with a header line:
//   # makit list: name=<name> until=<RFC3339 or empty> reason=<text>
// They are separate from state.json so a manual ban never re-reads millions of entries.

type List struct {
	Name     string    `json:"name"`
	Until    time.Time `json:"until,omitempty"`
	Reason   string    `json:"reason,omitempty"`
	Count    int       `json:"count"`
	Path     string    `json:"path"`
	Modified time.Time `json:"modified"`
}

func listsDir() string { return filepath.Join(StateDir, "lists") }

func validName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for _, r := range n {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// ReadList parses a list file: header metadata and its prefixes (invalid lines are counted, not fatal).
func ReadList(path string) (List, []netip.Prefix, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return List{}, nil, 0, err
	}
	defer f.Close()
	st, _ := f.Stat()
	l := List{Name: strings.TrimSuffix(filepath.Base(path), ".txt"), Path: path, Modified: st.ModTime()}
	var ps []netip.Prefix
	bad := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if h, ok := strings.CutPrefix(line, "# makit list:"); ok {
			for _, kv := range strings.Fields(h) {
				k, v, _ := strings.Cut(kv, "=")
				switch k {
				case "until":
					l.Until, _ = time.Parse(time.RFC3339, v)
				case "reason":
					l.Reason = strings.ReplaceAll(v, "_", " ")
				}
			}
			continue
		}
		// Feeds often append "; comment" or "# comment" after the address.
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := ParsePrefix(strings.Fields(line)[0])
		if err != nil {
			bad++
			continue
		}
		ps = append(ps, p)
	}
	l.Count = len(ps)
	return l, ps, bad, sc.Err()
}

// ImportList normalises src into the lists directory under name.
func ImportList(name, src string, dur time.Duration, reason string) (List, int, error) {
	if !validName(name) {
		return List{}, 0, fmt.Errorf("list name: lowercase letters, digits, - and _ (max 64)")
	}
	_, ps, bad, err := ReadList(src)
	if err != nil {
		return List{}, 0, err
	}
	if len(ps) == 0 {
		return List{}, bad, fmt.Errorf("%s: no valid IP or CIDR", src)
	}
	if err := os.MkdirAll(listsDir(), 0o750); err != nil {
		return List{}, 0, err
	}
	var until time.Time
	if dur > 0 {
		until = time.Now().Add(dur)
	}
	dst := filepath.Join(listsDir(), name+".txt")
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return List{}, 0, err
	}
	w := bufio.NewWriterSize(f, 1<<20)
	u := ""
	if !until.IsZero() {
		u = until.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(w, "# makit list: name=%s until=%s reason=%s\n", name, u, strings.ReplaceAll(reason, " ", "_"))
	for _, p := range ps {
		w.WriteString(p.String())
		w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return List{}, 0, err
	}
	f.Close()
	if err := os.Rename(tmp, dst); err != nil {
		return List{}, 0, err
	}
	l, _, _, err := ReadList(dst)
	return l, bad, err
}

// Lists returns the metadata of every list file (sorted by name).
func Lists() ([]List, error) {
	files, _ := filepath.Glob(filepath.Join(listsDir(), "*.txt"))
	sort.Strings(files)
	var out []List
	for _, f := range files {
		l, _, _, err := ReadList(f)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

// LoadLists builds one set from every live list file, and a fingerprint (names + mtimes) to detect changes.
func LoadLists() (*Set, string, error) {
	set := NewSet()
	files, _ := filepath.Glob(filepath.Join(listsDir(), "*.txt"))
	sort.Strings(files)
	var fp strings.Builder
	for _, f := range files {
		l, ps, _, err := ReadList(f)
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(&fp, "%s@%d;", f, l.Modified.UnixNano())
		if !l.Until.IsZero() && time.Now().After(l.Until) {
			continue
		}
		set.AddMany(ps, l.Until, l.Reason, "list:"+l.Name)
	}
	return set, fp.String(), nil
}

func listsFingerprint() string {
	files, _ := filepath.Glob(filepath.Join(listsDir(), "*.txt"))
	sort.Strings(files)
	var fp strings.Builder
	for _, f := range files {
		if st, err := os.Stat(f); err == nil {
			fmt.Fprintf(&fp, "%s@%d;", f, st.ModTime().UnixNano())
		}
	}
	return fp.String()
}

func RemoveList(name string) error {
	if !validName(name) {
		return fmt.Errorf("bad list name")
	}
	return os.Remove(filepath.Join(listsDir(), name+".txt"))
}
