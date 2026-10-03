package shield

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config check: everything that would make shield.yaml fail to load, or load and do something the person did not
// mean — a misspelt key that is silently ignored, a trusted range anyone can send from, the kernel layer behind a load
// balancer. The same checks run on the server (makit shield config check) and in the playground on makit.sh, so a
// pasted file never takes the shield down.

// Issue is one finding of the config check.
type Issue struct {
	Level   string `json:"level"` // error: the gate would refuse the file; warning: it loads, but probably not as meant
	Line    int    `json:"line,omitempty"`
	Key     string `json:"key,omitempty"`
	Message string `json:"message"`
}

func (i Issue) String() string {
	where := ""
	if i.Line > 0 {
		where = fmt.Sprintf("line %d: ", i.Line)
	}
	return where + i.Message
}

// CheckOptions say what else the check may look at.
type CheckOptions struct {
	Dirs     []string // catalog directories: rules, scoring and bots are loaded and checked against them (nil: skipped)
	Files    bool     // the file is on the server it configures: certificate files must exist
	Channels []string // makit notify channel names (nil: not checked)
	InPod    bool     // running in a Kubernetes pod: listening on every address is the norm there
}

// CheckConfig checks shield.yaml given as bytes and returns its issues, errors first, in line order.
func CheckConfig(b []byte, opt CheckOptions) []Issue {
	c := &checker{}
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		c.yamlError(err)
		return c.sorted()
	}
	c.root = &root
	// Unknown keys and wrong types, with the line they are on. The gate ignores unknown keys, so a typo such as
	// trusted_proxy: is not an error there — it is here, because the setting the person wrote does nothing.
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(defaultConfig()); err != nil && !errors.Is(err, io.EOF) { // EOF: an empty file
		c.yamlError(err)
	}
	cfg, err := ParseConfig(b, "shield.yaml")
	if err != nil {
		c.add("error", c.lineFor(err.Error()), "", strings.TrimPrefix(err.Error(), "shield.yaml: "))
		return c.sorted()
	}
	c.config(cfg, opt)
	if opt.Dirs != nil && !c.hasErrors() {
		lists := NewSet()
		if _, err := buildPolicyWith(cfg, opt.Dirs, &State{}, lists); err != nil {
			c.add("error", c.lineFor(err.Error()), "", err.Error())
		}
	}
	return c.sorted()
}

type checker struct {
	root   *yaml.Node
	issues []Issue
}

func (c *checker) add(level string, line int, key, msg string) {
	for _, i := range c.issues {
		if i.Line == line && i.Message == msg {
			return
		}
	}
	c.issues = append(c.issues, Issue{Level: level, Line: line, Key: key, Message: msg})
}

func (c *checker) hasErrors() bool {
	for _, i := range c.issues {
		if i.Level == "error" {
			return true
		}
	}
	return false
}

func (c *checker) sorted() []Issue {
	sort.SliceStable(c.issues, func(a, b int) bool {
		if (c.issues[a].Level == "error") != (c.issues[b].Level == "error") {
			return c.issues[a].Level == "error"
		}
		return c.issues[a].Line < c.issues[b].Line
	})
	return c.issues
}

var (
	reYAMLLine    = regexp.MustCompile(`line (\d+): (.*)`)
	reUnknownKey  = regexp.MustCompile(`^field (\S+) not found in type (\S+)$`)
	reCannotParse = regexp.MustCompile("^cannot unmarshal !!(\\w+) `(.*)` into (\\S+)$")
)

// yamlError turns yaml's messages ("line 3: field trusted_proxy not found in type shield.Config") into issues a person
// can act on.
func (c *checker) yamlError(err error) {
	var te *yaml.TypeError
	msgs := []string{err.Error()}
	if errors.As(err, &te) {
		msgs = te.Errors
	}
	for _, m := range msgs {
		m = strings.TrimPrefix(m, "yaml: ")
		line, text := 0, m
		if s := reYAMLLine.FindStringSubmatch(m); s != nil {
			line, _ = strconv.Atoi(s[1])
			text = s[2]
		}
		switch {
		case reUnknownKey.MatchString(text):
			s := reUnknownKey.FindStringSubmatch(text)
			msg := fmt.Sprintf("unknown key %q — it is ignored, so this setting does nothing", s[1])
			if alt := closest(s[1], knownKeys(s[2])); alt != "" {
				msg += fmt.Sprintf("; did you mean %q?", alt)
			}
			c.add("error", line, s[1], msg)
		case reCannotParse.MatchString(text):
			s := reCannotParse.FindStringSubmatch(text)
			c.add("error", line, "", fmt.Sprintf("%q is not %s", s[2], typeWord(s[3])))
		default:
			c.add("error", line, "", text)
		}
	}
}

func typeWord(goType string) string {
	switch {
	case goType == "bool" || strings.HasSuffix(goType, "*bool"):
		return "true or false"
	case strings.HasPrefix(goType, "int") || strings.HasPrefix(goType, "uint"):
		return "a number"
	case goType == "string":
		return "a single value"
	case strings.HasPrefix(goType, "[]"):
		return "a list"
	case strings.HasPrefix(goType, "map["):
		return "a mapping (key: value)"
	}
	return "the expected kind of value"
}

// knownKeys lists the yaml keys of a config type by its Go name ("shield.Config", "shield.Listener", or an anonymous
// struct, which yaml names by its full type).
func knownKeys(typeName string) []string {
	var out []string
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] {
			return
		}
		seen[t] = true
		match := t.String() == typeName
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")
			if match && tag[0] != "" && tag[0] != "-" {
				out = append(out, tag[0])
			}
			if match && len(tag) > 1 && tag[1] == "inline" {
				out = append(out, knownKeys(f.Type.String())...)
			}
			walk(f.Type)
		}
	}
	walk(reflect.TypeOf(Config{}))
	return out
}

// closest is the known key nearest to a typo (edit distance at most a third of its length, and at least 2).
func closest(s string, keys []string) string {
	best, bestD := "", len(s)/3+1
	if bestD < 2 {
		bestD = 2
	}
	for _, k := range keys {
		if d := editDistance(strings.ToLower(s), k); d <= bestD {
			best, bestD = k, d
		}
	}
	return best
}

func editDistance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(a); i++ {
		cur := make([]int, len(b)+1)
		cur[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(b)]
}

// node finds the node at a path of keys and list indexes ("listeners", "0", "upstream").
func (c *checker) node(path ...string) *yaml.Node {
	if c.root == nil || len(c.root.Content) == 0 {
		return nil
	}
	n := c.root.Content[0]
	for _, p := range path {
		switch n.Kind {
		case yaml.MappingNode:
			var next *yaml.Node
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == p {
					next = n.Content[i+1]
					break
				}
			}
			if next == nil {
				return n
			}
			n = next
		case yaml.SequenceNode:
			i, err := strconv.Atoi(p)
			if err != nil || i >= len(n.Content) {
				return n
			}
			n = n.Content[i]
		default:
			return n
		}
	}
	return n
}

func (c *checker) line(path ...string) int {
	if n := c.node(path...); n != nil {
		return n.Line
	}
	return 0
}

// lineFor guesses the line of an error message that names a value in the file (an upstream, a site, a rule id).
func (c *checker) lineFor(msg string) int {
	if c.root == nil {
		return 0
	}
	best := 0
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if best != 0 {
			return
		}
		if n.Kind == yaml.ScalarNode && len(n.Value) > 2 && strings.Contains(msg, n.Value) {
			best = n.Line
			return
		}
		for _, ch := range n.Content {
			walk(ch)
		}
	}
	walk(c.root)
	return best
}

func (c *checker) config(cfg *Config, opt CheckOptions) {
	trusted, err := cfg.Trusted()
	if err != nil {
		c.add("error", c.line("trusted_proxies"), "trusted_proxies", err.Error()+
			" (presets: cloudflare, aws-alb, vpc, loopback; or CIDRs such as 10.0.1.0/24)")
	}
	for i, t := range cfg.TrustedProxies {
		if t == "cloudflare" || ProxyPresets[t] != nil {
			continue
		}
		if p, err := ParsePrefix(t); err == nil && p.Bits() < map[bool]int{true: 8, false: 32}[p.Addr().Is4()] {
			c.add("error", c.line("trusted_proxies", strconv.Itoa(i)), "trusted_proxies",
				fmt.Sprintf("trusted proxy range %s is wider than /%d: anyone in it can name their own client IP — list your proxies' subnets", p,
					map[bool]int{true: 8, false: 32}[p.Addr().Is4()]))
		}
	}
	if len(trusted) == 0 && cfg.ClientHeader != "" && cfg.ClientHeader != "CF-Connecting-IP" {
		c.add("warning", c.line("client_ip_header"), "client_ip_header",
			fmt.Sprintf("client_ip_header %s is never read: no trusted_proxies are set, so every client is judged on its own address", cfg.ClientHeader))
	}
	private := false
	for _, p := range trusted {
		if p.Addr().IsPrivate() {
			private = true
		}
	}
	if cfg.KernelBlock && private {
		c.add("warning", c.line("kernel_block"), "kernel_block",
			"kernel_block is on with private trusted proxies (a load balancer): the kernel sees only the load balancer's addresses, never a visitor's — turn it off there (makit docs shield)")
	}
	if cfg.Mode == "pass" {
		c.add("warning", c.line("mode"), "mode", "mode pass: every request is let through and nothing is checked")
	}
	if host, _, err := net.SplitHostPort(cfg.Admin); err != nil {
		c.add("error", c.line("admin"), "admin", fmt.Sprintf("admin %q must be host:port, e.g. 127.0.0.1:9180", cfg.Admin))
	} else if a, err := netip.ParseAddr(host); !opt.InPod && (host == "" || (err == nil && !a.IsLoopback() && !a.IsPrivate())) {
		c.add("warning", c.line("admin"), "admin",
			fmt.Sprintf("admin %s listens on public addresses: fine in a Kubernetes pod (private network), but on a server with a public IP keep it on 127.0.0.1 or a private address — /check, /status and /metrics answer only private callers, still", cfg.Admin))
	}
	for i, a := range cfg.Allow {
		if _, err := ParsePrefix(a); err != nil {
			c.add("error", c.line("allow", strconv.Itoa(i)), "allow", fmt.Sprintf("allow entry %q is not an IP or CIDR", a))
		}
	}
	switch cfg.BanScope {
	case "", "server", "site":
	default:
		c.add("error", c.line("ban_scope"), "ban_scope", "ban_scope must be server or site")
	}
	c.listeners(cfg, opt, len(trusted) > 0)
	c.cluster(cfg.Cluster)
	c.awsWAF(cfg.AWSWAF)
	c.report(cfg.Report.Every, cfg.Report.MinLevel, "report")
	if opt.Channels != nil {
		known := map[string]bool{}
		for _, ch := range opt.Channels {
			known[ch] = true
		}
		for i, s := range cfg.Sites {
			for j, ch := range s.Report.Notify {
				if !known[ch] {
					c.add("warning", c.line("sites", strconv.Itoa(i), "report", "notify", strconv.Itoa(j)), "notify",
						fmt.Sprintf("site %s sends reports to channel %q, which makit notify does not have (makit notify list)", s.ID(), ch))
				}
			}
		}
	}
	names := map[string]int{}
	for i, s := range cfg.Sites {
		at := func(k ...string) int { return c.line(append([]string{"sites", strconv.Itoa(i)}, k...)...) }
		if len(s.Match) == 0 {
			c.add("error", at(), "sites", fmt.Sprintf("site %d has no match: list its host names", i+1))
		}
		if prev, ok := names[s.ID()]; ok && s.ID() != "" {
			c.add("error", at(), "sites", fmt.Sprintf("site %q is defined twice (also site %d)", s.ID(), prev+1))
		}
		names[s.ID()] = i
		switch s.Mode {
		case "", "block", "observe", "pass":
		default:
			c.add("error", at("mode"), "mode", fmt.Sprintf("site %s: mode must be block, observe or pass", s.ID()))
		}
		switch s.BanScope {
		case "", "server", "site":
		default:
			c.add("error", at("ban_scope"), "ban_scope", fmt.Sprintf("site %s: ban_scope must be server or site", s.ID()))
		}
		for j, a := range s.Allow {
			if _, err := ParsePrefix(a); err != nil {
				c.add("error", at("allow", strconv.Itoa(j)), "allow", fmt.Sprintf("site %s: allow entry %q is not an IP or CIDR", s.ID(), a))
			}
		}
		if s.Report.MinLevel != "" {
			c.report("", s.Report.MinLevel, "sites", strconv.Itoa(i), "report")
		}
	}
}

func (c *checker) cluster(cl ClusterConfig) {
	if cl.Listen == "" && len(cl.Peers) == 0 {
		return
	}
	if !cl.Enabled() {
		c.add("warning", c.line("cluster"), "cluster", "cluster needs both listen and peers: as it is, this replica shares nothing")
		return
	}
	if _, port, err := net.SplitHostPort(cl.Listen); err != nil || port == "" {
		c.add("error", c.line("cluster", "listen"), "listen", fmt.Sprintf("cluster listen %q must be [address]:port, e.g. :9181", cl.Listen))
	}
	for i, p := range cl.Peers {
		hostPort := strings.TrimPrefix(p, "dns:")
		if _, _, err := net.SplitHostPort(hostPort); err != nil {
			c.add("error", c.line("cluster", "peers", strconv.Itoa(i)), "peers",
				fmt.Sprintf("cluster peer %q: host:port, or dns:NAME:PORT for every address of a name", p))
		}
	}
	if cl.Sync != "" {
		if d, err := time.ParseDuration(cl.Sync); err != nil || d < 100*time.Millisecond {
			c.add("error", c.line("cluster", "sync"), "sync", fmt.Sprintf("cluster sync %q: a duration of 100ms or more", cl.Sync))
		}
	}
	if _, err := cl.secret(); err != nil {
		c.add("warning", c.line("cluster"), "cluster", err.Error()+" — the gate will not start without it")
	}
}

func (c *checker) awsWAF(w AWSWAFConfig) {
	if !w.Enabled() && w.IPv4.Name == "" && w.IPv6.Name == "" {
		return
	}
	switch strings.ToUpper(w.Scope) {
	case "", "REGIONAL", "CLOUDFRONT":
	default:
		c.add("error", c.line("aws_waf", "scope"), "scope", "aws_waf scope must be REGIONAL (ALB, API Gateway) or CLOUDFRONT")
	}
	if strings.EqualFold(w.Scope, "CLOUDFRONT") && w.Region != "" && w.Region != "us-east-1" {
		c.add("error", c.line("aws_waf", "region"), "region", "aws_waf: CLOUDFRONT IP sets live in us-east-1")
	}
	for name, s := range map[string]AWSWAFIPSet{"ipv4": w.IPv4, "ipv6": w.IPv6} {
		if (s.Name == "") != (s.ID == "") {
			c.add("error", c.line("aws_waf", name), name, fmt.Sprintf("aws_waf %s needs both name and id (aws wafv2 list-ip-sets)", name))
		}
	}
	if w.Every != "" {
		if d, err := time.ParseDuration(w.Every); err != nil || d < 10*time.Second {
			c.add("error", c.line("aws_waf", "every"), "every", fmt.Sprintf("aws_waf every %q: a duration of 10s or more", w.Every))
		}
	}
	if w.Max < 0 || w.Max > 10000 {
		c.add("error", c.line("aws_waf", "max"), "max", "aws_waf max: 1 to 10000 (an AWS WAF IP set holds at most 10,000 addresses)")
	}
}

func (c *checker) report(every, minLevel string, path ...string) {
	if every != "" && every != "off" {
		if d, err := parseDur(every); err != nil || d.Minutes() < 1 {
			c.add("error", c.line(append(path, "every")...), "every", fmt.Sprintf("report every %q: a duration of 1m or more, or off", every))
		}
	}
	if _, ok := levelRank[minLevel]; minLevel != "" && (!ok || minLevel == "normal") {
		c.add("error", c.line(append(path, "min_level")...), "min_level",
			fmt.Sprintf("min_level %q: low, medium, high or critical", minLevel))
	}
}

func (c *checker) listeners(cfg *Config, opt CheckOptions, haveTrusted bool) {
	type bound struct {
		host string
		i    int
	}
	byPort := map[string][]bound{}
	for i, l := range cfg.Listeners {
		at := func(k ...string) int { return c.line(append([]string{"listeners", strconv.Itoa(i)}, k...)...) }
		host, port, err := net.SplitHostPort(l.Listen)
		if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 {
			c.add("error", at("listen"), "listen", fmt.Sprintf("listener %s: listen %q must be [address]:port, e.g. :443", l.Name, l.Listen))
		} else {
			// Two listeners clash on a port when they bind the same address, or either binds every address.
			for _, b := range byPort[port] {
				if b.host == host || b.host == "" || host == "" {
					c.add("error", at("listen"), "listen",
						fmt.Sprintf("listeners %s and %s both listen on port %s", cfg.Listeners[b.i].Name, l.Name, port))
				}
			}
			byPort[port] = append(byPort[port], bound{host, i})
		}
		tcp := strings.HasPrefix(l.Upstream, "tcp://")
		if _, _, err := net.SplitHostPort(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(l.Upstream, "tcp://"), "http://"), "https://")); err != nil &&
			tcp {
			c.add("error", at("upstream"), "upstream", fmt.Sprintf("listener %s: tcp upstream %q needs host:port", l.Name, l.Upstream))
		}
		if l.TLS != nil {
			t := l.TLS
			switch {
			case tcp:
				c.add("error", at("tls"), "tls", fmt.Sprintf("listener %s: tls does not apply to a tcp:// upstream (it passes TLS through untouched)", l.Name))
			case (t.Cert == "") != (t.Key == ""):
				c.add("error", at("tls"), "tls", fmt.Sprintf("listener %s: tls needs both cert and key", l.Name))
			case t.Cert == "" && len(t.ACME) == 0:
				c.add("error", at("tls"), "tls", fmt.Sprintf("listener %s: tls needs cert and key, or acme domains", l.Name))
			}
			for j, d := range t.ACME {
				if strings.Contains(d, "*") {
					c.add("error", at("tls", "acme", strconv.Itoa(j)), "acme",
						fmt.Sprintf("listener %s: %s — automatic certificates (TLS-ALPN) cannot be wildcards; list each name, or use cert and key", l.Name, d))
				}
			}
			if opt.Files {
				for _, f := range []string{t.Cert, t.Key} {
					if f == "" {
						continue
					}
					if _, err := os.Stat(f); err != nil {
						c.add("error", at("tls"), "tls", fmt.Sprintf("listener %s: %v", l.Name, err))
					}
				}
			}
		}
		if l.AcceptProxyProtocol && !haveTrusted {
			c.add("warning", at("accept_proxy_protocol"), "accept_proxy_protocol",
				fmt.Sprintf("listener %s: accept_proxy_protocol is on but no trusted_proxies are set, so no PROXY header is ever believed", l.Name))
		}
		if l.ProxyProtocol && !tcp {
			c.add("warning", at("proxy_protocol"), "proxy_protocol",
				fmt.Sprintf("listener %s: proxy_protocol only applies to tcp:// upstreams (HTTP upstreams get X-Forwarded-For)", l.Name))
		}
	}
	if cfg.Edge && len(cfg.Listeners) == 0 {
		c.add("warning", c.line("edge"), "edge", "edge is on but no listeners are configured: makit is not in front of anything")
	}
}
