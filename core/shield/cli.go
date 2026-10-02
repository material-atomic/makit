package shield

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

const usage = `makit shield — IP gate for web traffic (own IP set + allowlist, Cloudflare-aware)

  serve                         run the gate (systemd: makit-shield.service)
  ban IP|CIDR [--for 24h] [--reason TEXT]
  unban IP|CIDR
  allow IP|CIDR [--reason TEXT] never blocked (whitelist)
  unallow IP|CIDR
  list [--json]                 block and allow entries with expiry, and bulk list sizes
  import FILE --name NAME [--for 7d] [--reason TEXT]
                                load a bulk list (one IP/CIDR per line; feeds with comments are fine) — millions OK
  lists                         bulk lists with their sizes
  drop-list NAME                remove a bulk list
  check --peer IP [--client IP] [--uri /path] [--method GET] [--ua TEXT]
                                what the gate would decide (uses the current config, lists and rules)
  log [-n 50] [--blocked]       recent request snapshots
  status                        live counters from the running gate
  cloudflare-update             refresh Cloudflare's IP ranges now
  set mode block|observe|pass · set ask on|off · set edge on|off
                                change a switch in the config (the running gate reloads within 2 s)
  bots …                        known bots, crawlers and AI agents: policy per category or agent (makit shield bots help)
  customize scoring|bots|rules [--to /etc/makit/security]
                                copy catalog files to edit locally; your copies override the bundled ones
  snippet caddy|nginx [--addr 127.0.0.1:9180]
                                configuration that makes Caddy/nginx ask makit before every request
`

// Main is `makit-core shield …`.
func Main(args []string, dirs []string) int {
	if len(args) == 0 {
		fmt.Print(usage)
		return 2
	}
	cfgPath := os.Getenv("MAKIT_SHIELD_CONFIG")
	if cfgPath == "" {
		cfgPath = DefaultConfig
	}
	sub, rest := args[0], args[1:]
	var err error
	switch sub {
	case "serve":
		err = Serve(cfgPath, dirs)
	case "ban", "allow":
		err = cmdAdd(sub, rest)
	case "unban", "unallow":
		err = cmdRemove(sub, rest)
	case "list":
		err = cmdList(rest)
	case "import":
		err = cmdImport(rest)
	case "lists":
		err = cmdLists()
	case "drop-list":
		name, _ := splitFirst(rest)
		if err = RemoveList(name); err == nil {
			fmt.Printf("list %s removed\n", name)
		}
	case "check":
		err = cmdCheck(cfgPath, dirs, rest)
	case "log":
		err = cmdLog(cfgPath, rest)
	case "status":
		err = cmdStatus(cfgPath)
	case "cloudflare-update":
		var n int
		if n, err = UpdateCloudflare(); err == nil {
			fmt.Printf("Cloudflare ranges updated: %d\n", n)
		}
	case "snippet":
		err = cmdSnippet(rest)
	case "set":
		if len(rest) != 2 {
			err = fmt.Errorf("usage: set mode|ask|edge VALUE")
		} else if err = SetConfig(cfgPath, rest[0], rest[1]); err == nil {
			fmt.Printf("%s = %s\n", rest[0], rest[1])
		}
	case "bots":
		err = cmdBots(cfgPath, dirs, rest)
	case "customize":
		err = cmdCustomize(dirs, rest)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "makit shield:", err)
		return 1
	}
	return 0
}

func cmdAdd(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	dur := fs.Duration("for", 0, "expire after this long (e.g. 24h); default: permanent")
	reason := fs.String("reason", "", "why (shown in list and logs)")
	force := fs.Bool("force", false, "ban even a trusted proxy range or your own SSH address")
	target, rest := splitFirst(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	p, err := ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("%q is not an IP or CIDR", target)
	}
	e := Entry{Prefix: p, Reason: *reason, Source: "manual", Added: time.Now()}
	if *dur > 0 {
		e.Until = time.Now().Add(*dur)
	}
	if kind == "ban" && !*force {
		if err := lockoutGuard(p); err != nil {
			return err
		}
	}
	_, err = withState(func(st *State) error {
		if kind == "ban" {
			st.Block = upsert(st.Block, e)
		} else {
			st.Allow = upsert(st.Allow, e)
		}
		return nil
	})
	if err != nil {
		return err
	}
	exp := "permanently"
	if !e.Until.IsZero() {
		exp = "until " + e.Until.Format("2006-01-02 15:04")
	}
	verb := map[string]string{"ban": "blocked", "allow": "allowlisted"}[kind]
	fmt.Printf("%s %s %s (the running gate picks it up within 2 s)\n", p, verb, exp)
	return nil
}

// lockoutGuard refuses bans that would cut you off or block every proxied request.
func lockoutGuard(p netip.Prefix) error {
	if ssh := strings.Fields(os.Getenv("SSH_CLIENT")); len(ssh) > 0 {
		if a, err := netip.ParseAddr(ssh[0]); err == nil && p.Contains(a.Unmap()) {
			return fmt.Errorf("%s contains your SSH address %s — use --force if you really mean it", p, a)
		}
	}
	for _, cf := range CloudflareRanges() {
		if cf.Overlaps(p) {
			return fmt.Errorf("%s overlaps Cloudflare %s: that blocks every visitor coming through Cloudflare — ban the client IP instead (--force to insist)", p, cf)
		}
	}
	return nil
}

func cmdRemove(kind string, args []string) error {
	target, _ := splitFirst(args)
	p, err := ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("%q is not an IP or CIDR", target)
	}
	found := false
	_, err = withState(func(st *State) error {
		if kind == "unban" {
			st.Block, found = remove(st.Block, p)
		} else {
			st.Allow, found = remove(st.Allow, p)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("%s is not in the %s list", p, map[string]string{"unban": "block", "unallow": "allow"}[kind])
	}
	fmt.Printf("%s removed\n", p)
	return nil
}

func cmdList(args []string) error {
	st, err := LoadState()
	if err != nil {
		return err
	}
	now := time.Now()
	st.Block, st.Allow = live(st.Block, now), live(st.Allow, now)
	if len(args) > 0 && args[0] == "--json" {
		return json.NewEncoder(os.Stdout).Encode(st)
	}
	show := func(title string, es []Entry) {
		fmt.Printf("%s (%d)\n", title, len(es))
		for _, e := range es {
			exp := "permanent"
			if !e.Until.IsZero() {
				exp = "until " + e.Until.Format("01-02 15:04") + " (" + time.Until(e.Until).Round(time.Minute).String() + ")"
			}
			fmt.Printf("  %-22s %-28s %-14s %s\n", e.Prefix, exp, e.Source, e.Reason)
		}
	}
	show("blocked", st.Block)
	show("allowed", st.Allow)
	return cmdLists()
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	name := fs.String("name", "", "list name (letters, digits, - _)")
	dur := fs.Duration("for", 0, "expire the whole list after this long")
	reason := fs.String("reason", "", "why")
	file, rest := splitFirst(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	start := time.Now()
	l, bad, err := ImportList(*name, file, *dur, *reason)
	if err != nil {
		return err
	}
	fmt.Printf("list %s: %d entries (%d invalid lines skipped) in %s — the running gate loads it within 2 s\n", l.Name, l.Count, bad, time.Since(start).Round(time.Millisecond))
	return nil
}

func cmdLists() error {
	ls, err := Lists()
	if err != nil {
		return err
	}
	fmt.Printf("bulk lists (%d)\n", len(ls))
	for _, l := range ls {
		exp := "permanent"
		if !l.Until.IsZero() {
			exp = "until " + l.Until.Format("2006-01-02 15:04")
		}
		fmt.Printf("  %-20s %10d  %-24s %s\n", l.Name, l.Count, exp, l.Reason)
	}
	return nil
}

func cmdCheck(cfgPath string, dirs []string, args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	peer := fs.String("peer", "", "TCP peer (the visitor, or the proxy such as Cloudflare)")
	client := fs.String("client", "", "client IP header value (CF-Connecting-IP)")
	uri := fs.String("uri", "/", "request URI")
	method := fs.String("method", "GET", "method")
	ua := fs.String("ua", "", "user agent")
	var hdr multi
	fs.Var(&hdr, "header", "request header k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	p, _, err := buildPolicy(cfg, dirs, nil)
	if err != nil {
		return err
	}
	if p.Bots != nil {
		p.Verifier = NewVerifier()
		p.Verifier.Sync = true // a one-off check can wait for DNS
		p.Verifier.LoadRanges(p.Bots)
	}
	var hdrs map[string]string // nil: header-based bot signals are skipped unless headers are given
	for _, h := range hdr {
		k, v, _ := strings.Cut(h, "=")
		if hdrs == nil {
			hdrs = map[string]string{}
		}
		hdrs[strings.ToLower(k)] = v
	}
	d := p.Decide(Request{Peer: *peer, Client: *client, Method: *method, URI: *uri, UA: *ua, Headers: hdrs, Received: time.Now()})
	b, _ := json.MarshalIndent(d, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdLog(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("log", flag.ContinueOnError)
	n := fs.Int("n", 50, "lines")
	blocked := fs.Bool("blocked", false, "only blocked / would-block / dropped")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	f, err := os.Open(cfg.Snapshot.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var s Snapshot
		if json.Unmarshal(sc.Bytes(), &s) != nil || (*blocked && s.Allow) {
			continue
		}
		via := ""
		if s.Via != "" {
			via = " via " + s.Via
		}
		lines = append(lines, fmt.Sprintf("%s %-12s %-16s%s %s %s %s %s %s", s.Time.Format("01-02 15:04:05"), s.Verdict, s.Client, via,
			s.Method, s.Host, s.URI, s.Rule, s.Reason))
		if len(lines) > *n {
			lines = lines[1:]
		}
	}
	fmt.Println(strings.Join(lines, "\n"))
	return sc.Err()
}

func cmdStatus(cfgPath string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	cl := &http.Client{Timeout: 3 * time.Second}
	res, err := cl.Get("http://" + cfg.Admin + "/status")
	if err != nil {
		return fmt.Errorf("gate not reachable on %s (is makit-shield running?): %w", cfg.Admin, err)
	}
	defer res.Body.Close()
	_, err = io.Copy(os.Stdout, res.Body)
	return err
}

func cmdSnippet(args []string) error {
	kind, rest := splitFirst(args)
	fs := flag.NewFlagSet("snippet", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:9180", "where the gate listens (Caddy in Docker: the host's bridge address, e.g. 172.17.0.1:9180)")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	switch kind {
	case "caddy":
		fmt.Printf(`# Caddyfile — define once, then "import makit_shield" in every site block.
(makit_shield) {
	forward_auth %s {
		uri /check
		header_up X-Makit-Peer {remote_host}
		header_up X-Makit-Client {http.request.header.CF-Connecting-IP}
		copy_headers X-Makit-Client
	}
}

example.com {
	import makit_shield
	reverse_proxy app:3000
}
`, *addr)
	case "nginx":
		fmt.Printf(`# nginx — in each server {} that should be protected.
location = /_makit_shield {
    internal;
    proxy_pass http://%s/check?deny=403;   # nginx only passes 401/403 through
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Makit-Peer $remote_addr;           # do not use real_ip_header together with this
    proxy_set_header X-Makit-Client $http_cf_connecting_ip;
    proxy_set_header X-Forwarded-Method $request_method;
    proxy_set_header X-Forwarded-Uri $request_uri;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header User-Agent $http_user_agent;
}

location / {
    auth_request /_makit_shield;
    auth_request_set $makit_client $upstream_http_x_makit_client;
    proxy_set_header X-Real-IP $makit_client;
    proxy_pass http://app;
}
`, *addr)
	default:
		return fmt.Errorf("snippet caddy|nginx")
	}
	return nil
}

func splitFirst(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}
