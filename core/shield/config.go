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
	Mode           string     `yaml:"mode"` // block | observe | pass
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
	Admin string `yaml:"admin"` // local status endpoint, default 127.0.0.1:9180
}

func LoadConfig(path string) (*Config, error) {
	c := &Config{Mode: "observe", ClientHeader: "CF-Connecting-IP", TrustedProxies: []string{"cloudflare"}, Rules: true, Admin: "127.0.0.1:9180", KernelBlock: false}
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
