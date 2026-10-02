package scan

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

//go:embed iocs/default.json
var defaultIOCs []byte

type indicator struct {
	Value string `json:"value"`
	Note  string `json:"note"`
}

// IOCs are exact indicators; heuristics live in the checks. Extra sets use the same JSON shape (--iocs file).
type IOCs struct {
	Name    string      `json:"name"`
	Sources []string    `json:"sources"`
	SHA256  []indicator `json:"sha256"`
	IPs     []indicator `json:"ips"`
	Strings []indicator `json:"strings"`
	Paths   []indicator `json:"paths"`

	sha, ip, path map[string]string
}

func loadIOCs(extra []string) (*IOCs, error) {
	all := &IOCs{}
	if err := json.Unmarshal(defaultIOCs, all); err != nil {
		return nil, err
	}
	for _, f := range extra {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var x IOCs
		if err := json.Unmarshal(b, &x); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		all.SHA256 = append(all.SHA256, x.SHA256...)
		all.IPs = append(all.IPs, x.IPs...)
		all.Strings = append(all.Strings, x.Strings...)
		all.Paths = append(all.Paths, x.Paths...)
		all.Sources = append(all.Sources, f)
	}
	all.sha, all.ip, all.path = map[string]string{}, map[string]string{}, map[string]string{}
	for _, i := range all.SHA256 {
		all.sha[strings.ToLower(i.Value)] = i.Note
	}
	for _, i := range all.IPs {
		all.ip[i.Value] = i.Note
	}
	for _, i := range all.Paths {
		all.path[i.Value] = i.Note
	}
	return all, nil
}
