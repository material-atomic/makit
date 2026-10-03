package shield

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/material-atomic/makit/core/term"
)

const usage = `makit shield — IP gate for web traffic (own IP set + allowlist, Cloudflare-aware)

  serve                         run the gate (systemd: makit-shield.service)
  ban IP|CIDR [--for 24h] [--reason TEXT] [--site NAME]
  unban IP|CIDR [--site NAME]
  allow IP|CIDR [--reason TEXT] [--site NAME]   never blocked (whitelist)
  unallow IP|CIDR [--site NAME]
  list [--json]                 block and allow entries with expiry, and bulk list sizes
  import FILE --name NAME [--for 7d] [--reason TEXT]
                                load a bulk list (one IP/CIDR per line; feeds with comments are fine) — millions OK
  lists                         bulk lists with their sizes
  drop-list NAME                remove a bulk list
  check --peer IP [--client IP] [--uri /path] [--method GET] [--ua TEXT]
                                what the gate would decide (uses the current config, lists and rules)
  log [-n 50] [--blocked]       recent request snapshots
  status [--json]               live counters from the running gate
  cloudflare-update             refresh Cloudflare's IP ranges now
  set mode block|observe|pass · set ask on|off · set edge on|off
                                change a switch in the config (the running gate reloads within 2 s)
  analyze FILE|- [--format nginx|caddy] [--batch 5m] [--follow] [--ban] [--notify] [--json] [--quiet]
                                score an nginx/Caddy access log with the same policy and print batch reports
  sites                         per-domain settings (sites: in shield.yaml) and what each changes
  report [-n 1] [--date YYYY-MM-DD] [--site NAME]
                                the latest batch reports (also sent through makit notify when worth it)
  bots …                        known bots, crawlers and AI agents: policy per category or agent (makit shield bots help)
  config check [FILE|-] [--replay LOG] [--against FILE] [--json]
                                check a config before it is loaded (every key, listener, range and catalog
                                setting); --replay runs it against an access log next to the current one
  waf sync [--dry-run]          push the live bans to the AWS WAF IP sets in aws_waf: now (the gate does it every 30 s)
  customize scoring|bots|rules [--to /etc/makit/security]
                                copy catalog files to edit locally; your copies override the bundled ones
  snippet caddy|nginx [--addr 127.0.0.1:9180]
                                configuration that makes Caddy/nginx ask makit before every request
  snippet envoy-gateway|istio|envoy|traefik|ingress-nginx [--service makit-shield --namespace makit --port 9180]
                                the same for a gateway in Kubernetes (Envoy Gateway: --gateway NAME --gateway-namespace NS)
`

// Main is `makit-core shield …`.
func Main(args []string, dirs []string) int {
	if len(args) == 0 {
		fmt.Print(term.Usage(usage))
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
			fmt.Println(term.Ok("list " + name + " removed"))
		}
	case "check":
		err = cmdCheck(cfgPath, dirs, rest)
	case "log":
		err = cmdLog(cfgPath, rest)
	case "status":
		err = cmdStatus(cfgPath, rest)
	case "cloudflare-update":
		var n int
		if n, err = UpdateCloudflare(); err == nil {
			fmt.Println(term.Ok(fmt.Sprintf("Cloudflare ranges updated: %d", n)))
		}
	case "snippet":
		err = cmdSnippet(rest)
	case "set":
		if len(rest) != 2 {
			err = fmt.Errorf("usage: set mode|ask|edge VALUE")
		} else if err = SetConfig(cfgPath, rest[0], rest[1]); err == nil {
			fmt.Println(term.Ok(rest[0] + " = " + term.Bold(rest[1])))
		}
	case "bots":
		err = cmdBots(cfgPath, dirs, rest)
	case "report":
		err = cmdReport(cfgPath, rest)
	case "sites":
		err = cmdSites(cfgPath)
	case "analyze":
		err = cmdAnalyze(cfgPath, dirs, rest)
	case "customize":
		err = cmdCustomize(dirs, rest)
	case "config":
		err = cmdConfig(cfgPath, dirs, rest)
	case "waf":
		err = cmdWAF(cfgPath, rest)
	case "help", "--help", "-h":
		fmt.Print(term.Usage(usage))
	default:
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	if errors.Is(err, errInvalidConfig) {
		return 1 // the findings are printed already
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, term.Red("makit shield: "+err.Error()))
		return 1
	}
	return 0
}

func cmdAdd(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	dur := fs.Duration("for", 0, "expire after this long (e.g. 24h); default: permanent")
	reason := fs.String("reason", "", "why (shown in list and logs)")
	force := fs.Bool("force", false, "ban even a trusted proxy range or your own SSH address")
	site := fs.String("site", "", "only for this site (a name from sites: in shield.yaml); default: every site")
	target, rest := splitFirst(args)
	if err := fs.Parse(rest); err != nil {
		return err
	}
	p, err := ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("%q is not an IP or CIDR", target)
	}
	if *site != "" {
		if err := knownSite(*site); err != nil {
			return err
		}
	}
	e := Entry{Prefix: p, Reason: *reason, Source: "manual", Added: time.Now(), Site: *site}
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
	where := "on every site"
	if *site != "" {
		where = "on " + *site
	}
	fmt.Printf("%s %s %s %s %s\n", term.Ok(term.Bold(p.String())), term.Verdict(verb, verb), where, exp,
		term.Dim("(the running gate picks it up within 2 s)"))
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
	path := firstNonEmpty(os.Getenv("MAKIT_SHIELD_CONFIG"), DefaultConfig)
	if cfg, err := LoadConfig(path); err == nil {
		trusted, _ := cfg.Trusted()
		for _, t := range trusted {
			if t.Overlaps(p) {
				return fmt.Errorf("%s overlaps the trusted proxy range %s (trusted_proxies in %s): every visitor coming through that proxy would be blocked — ban the client IP instead (--force to insist)", p, t, path)
			}
		}
	}
	return nil
}

func cmdRemove(kind string, args []string) error {
	target, rest := splitFirst(args)
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	site := fs.String("site", "*", "only the entry of this site (\"\" = the server-wide one); default: all")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	p, err := ParsePrefix(target)
	if err != nil {
		return fmt.Errorf("%q is not an IP or CIDR", target)
	}
	found := false
	_, err = withState(func(st *State) error {
		if kind == "unban" {
			st.Block, found = remove(st.Block, p, *site)
		} else {
			st.Allow, found = remove(st.Allow, p, *site)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !found {
		if kind == "unban" { // the gate saves automatic bans once a second: one made just now may not be there yet
			return fmt.Errorf("%s is not in the block list (an automatic ban is saved within a second of the request — if it was just banned, run this again)", p)
		}
		return fmt.Errorf("%s is not in the allow list", p)
	}
	fmt.Println(term.Ok(term.Bold(p.String()) + " removed"))
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
		fmt.Printf("%s %s\n", term.Verdict(title, term.Bold(title)), term.Dim(fmt.Sprintf("(%d)", len(es))))
		for _, e := range es {
			exp := "permanent"
			if !e.Until.IsZero() {
				exp = "until " + e.Until.Format("01-02 15:04") + " (" + time.Until(e.Until).Round(time.Minute).String() + ")"
			}
			where := "all sites"
			if e.Site != "" {
				where = e.Site
			}
			fmt.Printf("  %s %-16s %s %s %s\n", term.Bold(fmt.Sprintf("%-22s", e.Prefix)), where, term.Dim(fmt.Sprintf("%-28s", exp)),
				term.Cyan(fmt.Sprintf("%-14s", e.Source)), e.Reason)
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
	fmt.Println(term.Ok(fmt.Sprintf("list %s: %d entries (%d invalid lines skipped) in %s", term.Bold(l.Name), l.Count, bad,
		time.Since(start).Round(time.Millisecond))) + term.Dim(" — the running gate loads it within 2 s"))
	return nil
}

func cmdLists() error {
	ls, err := Lists()
	if err != nil {
		return err
	}
	fmt.Printf("%s %s\n", term.Bold("bulk lists"), term.Dim(fmt.Sprintf("(%d)", len(ls))))
	for _, l := range ls {
		exp := "permanent"
		if !l.Until.IsZero() {
			exp = "until " + l.Until.Format("2006-01-02 15:04")
		}
		fmt.Printf("  %s %10d  %s %s\n", term.Bold(fmt.Sprintf("%-20s", l.Name)), l.Count, term.Dim(fmt.Sprintf("%-24s", exp)), l.Reason)
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
	host := fs.String("host", "", "Host header (picks the site)")
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
	p.Share()
	d := p.Decide(Request{Peer: *peer, Client: *client, Method: *method, Host: *host, URI: *uri, UA: *ua, Headers: hdrs, Received: time.Now()})
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
		lines = append(lines, fmt.Sprintf("%s %s %s%s %s %s %s %s %s", term.Dim(s.Time.Format("01-02 15:04:05")),
			term.Verdict(s.Verdict, fmt.Sprintf("%-12s", s.Verdict)), term.Bold(fmt.Sprintf("%-16s", s.Client)), term.Dim(via),
			s.Method, s.Host, s.URI, term.Cyan(s.Rule), s.Reason))
		if len(lines) > *n {
			lines = lines[1:]
		}
	}
	fmt.Println(strings.Join(lines, "\n"))
	return sc.Err()
}

// AdminClient talks to the gate's admin address. Never through a proxy: the address is on this machine or its
// private network, and an http_proxy set for downloads would otherwise answer in the gate's place.
func AdminClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: &http.Transport{Proxy: nil}}
}

// AdminURL is the URL of a path on the admin address; a gate listening on every address is asked on loopback.
func AdminURL(admin, path string) string {
	if h, p, err := net.SplitHostPort(admin); err == nil && (h == "0.0.0.0" || h == "" || h == "::") {
		admin = net.JoinHostPort("127.0.0.1", p)
	}
	return "http://" + admin + path
}

// firstLine is the start of an answer that was not what we asked for, to show in an error.
func firstLine(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 300))
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	if line == "" {
		return "(empty)"
	}
	return line
}

func cmdStatus(cfgPath string, args []string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	res, err := AdminClient(3 * time.Second).Get(AdminURL(cfg.Admin, "/status"))
	if err != nil {
		return fmt.Errorf("gate not reachable on %s (is makit-shield running?): %w", cfg.Admin, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("gate on %s answered %s: %s", cfg.Admin, res.Status, firstLine(res.Body))
	}
	if (len(args) > 0 && args[0] == "--json") || !term.TTY {
		_, err = io.Copy(os.Stdout, res.Body)
		return err
	}
	var s struct {
		Version     string           `json:"version"`
		Mode        string           `json:"mode"`
		Ask         bool             `json:"ask"`
		Edge        bool             `json:"edge"`
		EdgeError   string           `json:"edge_error"`
		Stats       map[string]int64 `json:"stats"`
		Block       int              `json:"block"`
		Lists       int              `json:"lists"`
		Allow       int              `json:"allow"`
		Rules       int              `json:"rules"`
		Trusted     int              `json:"trusted"`
		Listeners   int              `json:"listeners"`
		KernelBlock bool             `json:"kernel_block"`
		Cluster     *struct {
			Node  string `json:"node"`
			Peers []struct {
				Addr    string    `json:"addr"`
				LastOK  time.Time `json:"last_ok"`
				Error   string    `json:"error"`
				Pending int       `json:"pending"`
			} `json:"peers"`
		} `json:"cluster"`
	}
	if err := json.NewDecoder(res.Body).Decode(&s); err != nil {
		return fmt.Errorf("gate on %s answered something unexpected: %w", cfg.Admin, err)
	}
	onOff := func(b bool) string {
		if b {
			return term.Green("on")
		}
		return term.Dim("off")
	}
	mode := map[string]string{"block": term.Green("block"), "observe": term.Yellow("observe"), "pass": term.Red("pass")}[s.Mode]
	fmt.Printf("%s %s · mode %s · ask %s · edge %s · kernel %s\n", term.Bold("makit shield"), term.Dim(s.Version), firstNonEmpty(mode, s.Mode),
		onOff(s.Ask), onOff(s.Edge), onOff(s.KernelBlock))
	if s.EdgeError != "" {
		fmt.Println(term.Fail("edge: " + s.EdgeError))
	}
	fmt.Printf("  %s %s blocked · %s in bulk lists · %s allowed · %s rules · %s trusted proxies · %s listeners\n", term.Dim("entries "),
		term.Bold(thousands(s.Block)), term.Bold(thousands(s.Lists)), term.Bold(thousands(s.Allow)), term.Bold(thousands(s.Rules)),
		term.Bold(thousands(s.Trusted)), term.Bold(thousands(s.Listeners)))
	keys := make([]string, 0, len(s.Stats))
	for k := range s.Stats {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return s.Stats[keys[i]] > s.Stats[keys[j]] })
	var parts []string
	for _, k := range keys {
		parts = append(parts, term.Verdict(k, k)+" "+term.Bold(thousands(int(s.Stats[k]))))
	}
	if len(parts) == 0 {
		parts = []string{term.Dim("no requests yet")}
	}
	fmt.Printf("  %s %s\n", term.Dim("requests"), strings.Join(parts, " · "))
	if cl := s.Cluster; cl != nil {
		fmt.Printf("  %s %s %s\n", term.Dim("cluster "), term.Bold(cl.Node), term.Dim(fmt.Sprintf("· %d peers", len(cl.Peers))))
		for _, p := range cl.Peers {
			state := term.Green("in sync")
			switch {
			case p.Error != "":
				state = term.Red("unreachable: " + p.Error)
			case p.LastOK.IsZero():
				state = term.Yellow("not reached yet")
			case time.Since(p.LastOK) > 15*time.Second:
				state = term.Yellow(fmt.Sprintf("last sync %s ago", time.Since(p.LastOK).Round(time.Second)))
			}
			pending := ""
			if p.Pending > 0 {
				pending = term.Yellow(fmt.Sprintf(" · %d changes waiting", p.Pending))
			}
			fmt.Printf("           %-22s %s%s\n", p.Addr, state, pending)
		}
	}
	return nil
}

func cmdSnippet(args []string) error {
	kind, rest := splitFirst(args)
	fs := flag.NewFlagSet("snippet", flag.ContinueOnError)
	addr := fs.String("addr", "127.0.0.1:9180", "where the gate listens (Caddy in Docker: the host's bridge address, e.g. 172.17.0.1:9180)")
	o := snippetOpts{}
	fs.StringVar(&o.service, "service", "makit-shield", "Kubernetes: the makit Service")
	fs.StringVar(&o.namespace, "namespace", "makit", "Kubernetes: its namespace")
	fs.IntVar(&o.port, "port", 9180, "Kubernetes: its port")
	fs.StringVar(&o.gateway, "gateway", "eg", "Envoy Gateway: the Gateway to protect")
	fs.StringVar(&o.gatewayNS, "gateway-namespace", "default", "Envoy Gateway: its namespace")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if kind == "envoy" && *addr == "127.0.0.1:9180" {
		*addr = fmt.Sprintf("%s.%s.svc.cluster.local:%d", o.service, o.namespace, o.port)
	}
	o.addr = *addr
	if s, ok := k8sSnippet(kind, o); ok {
		fmt.Print(s)
		return nil
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
		return fmt.Errorf("snippet caddy|nginx|envoy-gateway|istio|envoy|traefik|ingress-nginx")
	}
	return nil
}

func splitFirst(args []string) (string, []string) {
	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

func cmdReport(cfgPath string, args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	n := fs.Int("n", 1, "how many reports")
	date := fs.String("date", "", "day (default: the latest)")
	site := fs.String("site", "", "a site's reports (default: the global one)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	dir := cfg.Report.Directory()
	if *site != "" {
		dir = filepath.Join(dir, *site)
	}
	file := filepath.Join(dir, *date+".txt")
	if *date == "" {
		files, _ := filepath.Glob(filepath.Join(dir, "*.txt"))
		if len(files) == 0 {
			return fmt.Errorf("no reports yet in %s (one is written every report.every, 5m by default)", dir)
		}
		sort.Strings(files)
		file = files[len(files)-1]
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	parts := strings.Split(strings.TrimSpace(string(b)), "────────")
	var out []string
	for i := len(parts) - 1; i >= 0 && len(out) < *n; i-- {
		if p := strings.TrimSpace(parts[i]); p != "" {
			out = append([]string{p}, out...)
		}
	}
	fmt.Println(term.Report(strings.Join(out, "\n\n────────\n\n")))
	return nil
}

// knownSite checks a --site name against the config.
func knownSite(name string) error {
	path := os.Getenv("MAKIT_SHIELD_CONFIG")
	if path == "" {
		path = DefaultConfig
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		return err
	}
	var names []string
	for _, sc := range cfg.Sites {
		if sc.ID() == name {
			return nil
		}
		names = append(names, sc.ID())
	}
	if len(names) == 0 {
		return fmt.Errorf("no sites in %s (sites: …) — leave out --site to ban on every site", path)
	}
	return fmt.Errorf("no site %q (sites: %s)", name, strings.Join(names, ", "))
}

// cmdSites lists the sites with what each changes from the global settings.
func cmdSites(cfgPath string) error {
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	scope := firstNonEmpty(cfg.BanScope, "server")
	fmt.Printf("%s mode %s · bans %s %s\n", term.Bold("global:"), term.Bold(cfg.Mode), scope, term.Dim("· every host not listed below"))
	if len(cfg.Sites) == 0 {
		fmt.Println(term.Dim("no sites — add per-domain settings under sites: in " + cfgPath + " (makit docs shield)"))
		return nil
	}
	for _, sc := range cfg.Sites {
		var diff []string
		if sc.Mode != "" {
			diff = append(diff, "mode "+sc.Mode)
		}
		diff = append(diff, "bans "+firstNonEmpty(sc.BanScope, scope))
		if len(sc.Allow) > 0 {
			diff = append(diff, fmt.Sprintf("+%d allow", len(sc.Allow)))
		}
		if sc.Rules.Enabled != nil && !*sc.Rules.Enabled {
			diff = append(diff, "rules off")
		} else if sc.Rules.Disable != nil {
			diff = append(diff, "rules off: "+strings.Join(sc.Rules.Disable, ","))
		}
		if !sc.Scoring.empty() {
			diff = append(diff, "own scoring")
		}
		if len(sc.Bots.Policy) > 0 {
			var b []string
			for k, v := range sc.Bots.Policy {
				b = append(b, k+"="+v)
			}
			sort.Strings(b)
			diff = append(diff, "bots "+strings.Join(b, " "))
		}
		if len(sc.Report.Notify) > 0 {
			diff = append(diff, "reports → "+strings.Join(sc.Report.Notify, ","))
		}
		fmt.Printf("  %s %s %s\n", term.Cyan(fmt.Sprintf("%-18s", sc.ID())), fmt.Sprintf("%-36s", strings.Join(sc.Match, " ")), strings.Join(diff, " · "))
	}
	return nil
}
