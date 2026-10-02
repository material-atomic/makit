package shield

import (
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultConfig = "/etc/makit/shield.yaml"

// StateDir holds state.json (block/allow lists), the Cloudflare range cache and ACME certificates.
var StateDir = "/var/lib/makit/shield"

// Listener is one public port makit owns. Upstream is the service behind it (Caddy, nginx, an app).
type Listener struct {
	Name     string `yaml:"name"`
	Listen   string `yaml:"listen"`   // ":443"
	Upstream string `yaml:"upstream"` // http://127.0.0.1:8080, https://127.0.0.1:8443, tcp://127.0.0.1:22
	TLS      *struct {
		Cert    string   `yaml:"cert"` // PEM files (e.g. a Cloudflare Origin Certificate)
		Key     string   `yaml:"key"`
		ACME    []string `yaml:"acme"` // domains for automatic certificates (Let's Encrypt, TLS-ALPN-01)
		Email   string   `yaml:"email"`
		Default string   `yaml:"default_sni"`
	} `yaml:"tls"`
	ProxyProtocol       bool `yaml:"proxy_protocol"`        // tcp:// upstreams: send PROXY v1 so the service still sees the client IP
	InsecureUpstreamTLS bool `yaml:"insecure_upstream_tls"` // https:// upstream with a self-signed/internal certificate
}

type Config struct {
	Mode           string     `yaml:"mode"` // block | observe (pass = allow everything)
	Ask            bool       `yaml:"ask"`  // /check enforces (Caddy/nginx ask makit); off = /check always allows
	Edge           bool       `yaml:"edge"` // makit in front: run the listeners
	Listeners      []Listener `yaml:"listeners"`
	TrustedProxies []string   `yaml:"trusted_proxies"` // "cloudflare" or CIDRs whose client-IP header is believed
	ClientHeader   string     `yaml:"client_ip_header"`
	Allow          []string   `yaml:"allow"`        // never blocked (your office, monitoring, CI)
	KernelBlock    bool       `yaml:"kernel_block"` // also mirror the block set into nftables (ports makit does not front, floods)
	Rules          bool       `yaml:"rules"`        // apply the catalog's HTTP rules (security/http/*.yaml)
	RulesDirs      []string   `yaml:"rules_dirs"`   // default: the catalog directories
	Snapshot       struct {
		Path  string `yaml:"path"`
		MaxMB int    `yaml:"max_mb"`
		Keep  int    `yaml:"keep"`
	} `yaml:"snapshot"`
	Admin   string `yaml:"admin"` // local status endpoint, default 127.0.0.1:9180
	Scoring struct {
		ScoringOverrides `yaml:",inline"`
		File             string `yaml:"file"` // your own scoring file instead of the catalog's (same format)
	} `yaml:"scoring"`
	Bots BotsConfig `yaml:"bots"` // known bots / AI agents policy and the bot score
}

func LoadConfig(path string) (*Config, error) {
	c := &Config{Mode: "observe", Ask: true, ClientHeader: "CF-Connecting-IP", TrustedProxies: []string{"cloudflare"}, Rules: true, Admin: "127.0.0.1:9180", KernelBlock: false}
	c.Snapshot.Path, c.Snapshot.MaxMB, c.Snapshot.Keep = "/var/log/makit/shield/requests.jsonl", 50, 5
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch c.Mode {
	case "block", "observe", "pass":
	default:
		return nil, fmt.Errorf("%s: mode must be block, observe or pass", path)
	}
	for i, l := range c.Listeners {
		if l.Listen == "" || l.Upstream == "" {
			return nil, fmt.Errorf("%s: listener %d needs listen and upstream", path, i+1)
		}
		if l.Name == "" {
			c.Listeners[i].Name = l.Listen
		}
		if !strings.HasPrefix(l.Upstream, "http://") && !strings.HasPrefix(l.Upstream, "https://") && !strings.HasPrefix(l.Upstream, "tcp://") {
			return nil, fmt.Errorf("%s: upstream %q must start with http://, https:// or tcp://", path, l.Upstream)
		}
	}
	return c, nil
}

// Trusted expands trusted_proxies ("cloudflare" → the cached or built-in Cloudflare ranges).
func (c *Config) Trusted() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, t := range c.TrustedProxies {
		if t == "cloudflare" {
			out = append(out, CloudflareRanges()...)
			continue
		}
		p, err := ParsePrefix(t)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxies: %w", err)
		}
		out = append(out, p)
	}
	return out, nil
}

func cfCache() string { return filepath.Join(StateDir, "cloudflare.txt") }

// CloudflareRanges returns the last downloaded list, or the built-in one.
func CloudflareRanges() []netip.Prefix {
	if ps, err := ReadPrefixes(cfCache()); err == nil && len(ps) > 10 {
		return ps
	}
	var out []netip.Prefix
	for _, s := range CloudflareFallback {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// UpdateCloudflare downloads https://www.cloudflare.com/ips-v4 and ips-v6 into the cache (validated first).
func UpdateCloudflare() (int, error) {
	var lines []string
	for _, u := range []string{"https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"} {
		cl := &http.Client{Timeout: 15 * time.Second}
		res, err := cl.Get(u)
		if err != nil {
			return 0, err
		}
		b, err := io.ReadAll(io.LimitReader(res.Body, 1<<16))
		res.Body.Close()
		if err != nil || res.StatusCode != 200 {
			return 0, fmt.Errorf("%s: %s", u, res.Status)
		}
		for _, l := range strings.Fields(string(b)) {
			if _, err := ParsePrefix(l); err != nil {
				return 0, fmt.Errorf("%s: unexpected line %q", u, l)
			}
			lines = append(lines, l)
		}
	}
	if len(lines) < 10 {
		return 0, fmt.Errorf("only %d ranges downloaded — kept the previous list", len(lines))
	}
	if err := os.MkdirAll(StateDir, 0o755); err != nil {
		return 0, err
	}
	tmp := cfCache() + ".tmp"
	if err := os.WriteFile(tmp, []byte("# https://www.cloudflare.com/ips/ — "+time.Now().UTC().Format(time.RFC3339)+"\n"+strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		return 0, err
	}
	return len(lines), os.Rename(tmp, cfCache())
}

// SetConfig changes one top-level key (mode, ask, edge) in the YAML file, keeping comments and the rest as written.
func SetConfig(path, key, value string) error {
	switch key {
	case "mode":
		if value != "block" && value != "observe" && value != "pass" {
			return fmt.Errorf("mode: block, observe or pass")
		}
	case "ask", "edge":
		switch value {
		case "on", "true":
			value = "true"
		case "off", "false":
			value = "false"
		default:
			return fmt.Errorf("%s: on or off", key)
		}
	default:
		return fmt.Errorf("unknown setting %q (mode, ask, edge)", key)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: not a YAML mapping", path)
	}
	m := doc.Content[0]
	tag := "!!str"
	if key != "mode" {
		tag = "!!bool"
	}
	found := false
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1].Value, m.Content[i+1].Tag, m.Content[i+1].Kind = value, tag, yaml.ScalarNode
			found = true
		}
	}
	if !found {
		m.Content = append([]*yaml.Node{{Kind: yaml.ScalarNode, Value: key}, {Kind: yaml.ScalarNode, Value: value, Tag: tag}}, m.Content...)
	}
	out, err := yaml.Marshal(&doc)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o640); err != nil {
		return err
	}
	if _, err := LoadConfig(tmp); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}
