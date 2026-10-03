package shield

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/material-atomic/makit/core/term"
)

// Log analysis: nginx (combined, or makit's format with the Cloudflare IP and host) and Caddy (JSON access logs),
// scored with the same policy as the gate and summed up in the same batch reports.

// LogLine is one parsed access-log entry.
type LogLine struct {
	Request
	Format string
}

// nginx: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer"
// "$http_user_agent" ["$http_cf_connecting_ip" ["$host"]]
func parseNginx(line string) (LogLine, bool) {
	var f []string
	i := 0
	for i < len(line) {
		switch c := line[i]; {
		case c == ' ':
			i++
		case c == '"':
			j := i + 1
			var b strings.Builder
			for j < len(line) && line[j] != '"' {
				if line[j] == '\\' && j+1 < len(line) {
					b.WriteByte(line[j])
					j++
				}
				b.WriteByte(line[j])
				j++
			}
			f = append(f, b.String())
			i = j + 1
		case c == '[':
			j := strings.IndexByte(line[i:], ']')
			if j < 0 {
				return LogLine{}, false
			}
			f = append(f, line[i+1:i+j])
			i += j + 1
		default:
			j := strings.IndexByte(line[i:], ' ')
			if j < 0 {
				j = len(line) - i
			}
			f = append(f, line[i:i+j])
			i += j
		}
	}
	if len(f) < 9 {
		return LogLine{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", f[3])
	if err != nil {
		return LogLine{}, false
	}
	status, _ := strconv.Atoi(f[5])
	r := Request{Peer: f[0], Raw: f[4], Status: status, Referer: dash(f[7]), UA: dash(f[8]), Received: t}
	if parts := strings.Fields(f[4]); len(parts) == 3 && strings.HasPrefix(parts[2], "HTTP/") {
		r.Method, r.URI = parts[0], parts[1]
	}
	if len(f) > 9 {
		r.Client = dash(f[9])
	}
	if len(f) > 10 {
		r.Host = dash(f[10])
	}
	return LogLine{Request: r, Format: "nginx"}, true
}

func dash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// Caddy: the JSON access log ("logger":"http.log.access…"), which also carries request headers.
func parseCaddy(line string) (LogLine, bool) {
	var x struct {
		TS      float64 `json:"ts"`
		Status  int     `json:"status"`
		Request struct {
			RemoteIP string              `json:"remote_ip"`
			ClientIP string              `json:"client_ip"`
			Proto    string              `json:"proto"`
			Method   string              `json:"method"`
			Host     string              `json:"host"`
			URI      string              `json:"uri"`
			Headers  map[string][]string `json:"headers"`
		} `json:"request"`
	}
	if err := json.Unmarshal([]byte(line), &x); err != nil || x.Request.RemoteIP == "" {
		return LogLine{}, false
	}
	q := x.Request
	r := Request{Peer: firstNonEmpty(q.ClientIP, q.RemoteIP), Method: q.Method, Host: q.Host, URI: q.URI, Status: x.Status,
		Raw: strings.TrimSpace(q.Method + " " + q.URI + " " + q.Proto), Headers: map[string]string{}}
	sec := int64(x.TS)
	r.Received = time.Unix(sec, int64((x.TS-float64(sec))*1e9))
	for k, v := range q.Headers {
		lk := strings.ToLower(k)
		if lk == "cookie" || lk == "authorization" || lk == "proxy-authorization" {
			continue
		}
		r.Headers[lk] = strings.Join(v, ", ")
	}
	r.UA, r.Referer = r.Headers["user-agent"], r.Headers["referer"]
	return LogLine{Request: r, Format: "caddy"}, true
}

func parseLogLine(line, format string) (LogLine, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return LogLine{}, false
	}
	if format == "caddy" || (format == "auto" && line[0] == '{') {
		return parseCaddy(line)
	}
	return parseNginx(line)
}

type analyzeOpts struct {
	format, batch         string
	follow, ban, asJSON   bool
	notify, verify, quiet bool
	minLevel              string
}

const nginxFormatHint = `log_format makit '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_cf_connecting_ip" "$host"';
access_log /var/log/nginx/access.log makit;`

func cmdAnalyze(cfgPath string, dirs []string, args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	o := analyzeOpts{}
	fs.StringVar(&o.format, "format", "auto", "nginx, caddy or auto")
	fs.StringVar(&o.batch, "batch", "5m", "report window (log time)")
	fs.BoolVar(&o.follow, "follow", false, "keep reading as the log grows (survives rotation)")
	fs.BoolVar(&o.ban, "ban", false, "apply the policy's bans (makit shield ban), instead of only reporting")
	fs.BoolVar(&o.asJSON, "json", false, "one JSON report per line")
	fs.BoolVar(&o.notify, "notify", false, "send reports worth it through makit notify")
	fs.BoolVar(&o.verify, "verify", true, "verify claimed bots (reverse DNS); off for speed")
	fs.BoolVar(&o.quiet, "quiet", false, "print only reports with something at --min-level, a ban or a fake bot")
	fs.StringVar(&o.minLevel, "min-level", "", "level that makes a report worth printing/sending (default: report.min_level, high)")
	file, rest := splitFirst(args)
	if strings.HasPrefix(file, "-") || file == "" {
		file, rest = "", args
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if file == "" && fs.NArg() > 0 {
		file = fs.Arg(0)
	}
	if file == "" {
		return fmt.Errorf("usage: analyze FILE|- [--format nginx|caddy] [--batch 5m] [--follow] [--ban] [--notify] [--json]\n\nnginx: log the Cloudflare IP and host too —\n%s", nginxFormatHint)
	}
	window, err := parseDur(o.batch)
	if err != nil || window < time.Minute {
		return fmt.Errorf("--batch: a duration of 1m or more")
	}
	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		cfg, _ = LoadConfig("/dev/null")
	}
	p, _, err := buildPolicy(cfg, dirs, nil)
	if err != nil {
		return err
	}
	p.Observe, p.Pass = !o.ban, false
	if p.Scoring != nil {
		p.Tracker = NewTracker(p.Scoring, 500000)
	}
	if p.BotScore != nil {
		p.BotTracker = NewTracker(p.BotScore, 500000)
	}
	p.Limiter = NewLimiter()
	if p.Bots != nil {
		p.Verifier = NewVerifier()
		p.Verifier.LoadRanges(p.Bots)
		p.Verifier.Sync = true
		if !o.verify {
			p.Verifier.LookupAddr = nil
		}
	}
	reps := map[string]*Reporter{} // per site ("" = global)
	labels := map[string]string{}
	for _, sc := range []*Scoring{p.Scoring, p.BotScore} {
		if sc != nil {
			for k, v := range sc.Labels() {
				labels[k] = v
			}
		}
	}
	var winStart time.Time
	repFor := func(site string) *Reporter {
		r := reps[site]
		if r == nil {
			r = NewReporter(winStart)
			r.SetLabels(labels)
			reps[site] = r
		}
		return r
	}
	var bans []Entry
	p.Ban = func(a netip.Addr, d time.Duration, src, why, site string, scoped bool) {
		now := time.Now() // a ban from an old log line still lasts its full duration from now
		e := Entry{Prefix: netip.PrefixFrom(a, a.BitLen()), Until: now.Add(d), Reason: why, Source: src, Added: now}
		if scoped {
			e.Site = site
			if s := p.SiteBlockSet(site); s != nil {
				s.Add(e)
			}
		} else {
			p.Block.Add(e)
		}
		bans = append(bans, e)
		repFor(site).Banned(e)
	}
	p.Share()
	host, _ := os.Hostname()
	minLevel := firstNonEmpty(o.minLevel, cfg.Report.MinLevel, "high")
	parsed, skipped := 0, 0
	emit := func(to time.Time) error {
		if len(bans) > 0 {
			if err := saveBans(bans); err != nil {
				return fmt.Errorf("saving bans: %w", err)
			}
			bans = nil
		}
		sites := make([]string, 0, len(reps))
		for site := range reps {
			sites = append(sites, site)
		}
		sort.Strings(sites)
		for _, site := range sites {
			b := reps[site].Flush(to, host)
			if b == nil {
				continue
			}
			b.Site = site
			b.Text = b.render(labels)
			min, channels := minLevel, []string(nil)
			for _, sc := range cfg.Sites {
				if sc.ID() == site {
					min, channels = firstNonEmpty(o.minLevel, sc.Report.MinLevel, minLevel), sc.Report.Notify
				}
			}
			if o.quiet && !b.Worth(min) {
				continue
			}
			if o.asJSON {
				j, _ := json.Marshal(b)
				fmt.Println(string(j))
			} else {
				fmt.Println(term.Report(b.Text))
			}
			if o.notify && b.Worth(min) {
				sendReport(b, channels)
			}
		}
		return nil
	}
	handle := func(line string) error {
		l, ok := parseLogLine(line, o.format)
		if !ok {
			skipped++
			return nil
		}
		parsed++
		t := l.Received
		if winStart.IsZero() {
			winStart = t.Truncate(window)
		}
		for !t.Before(winStart.Add(window)) { // close every window the log has moved past
			if err := emit(winStart.Add(window)); err != nil {
				return err
			}
			winStart = winStart.Add(window)
			if t.Sub(winStart) > window { // jump over quiet hours
				winStart = t.Truncate(window)
				for _, r := range reps {
					r.reset(winStart)
				}
			}
		}
		d := p.Decide(l.Request)
		status := l.Status
		repFor(d.Site).Observe(Snapshot{Time: t, Listener: "log", Decision: d, Method: l.Method, Host: l.Host, URI: l.URI, UA: l.UA,
			Referer: l.Referer, Status: status})
		return nil
	}
	if err := readLines(file, o.follow, handle, func() error { // follow mode: close the window by wall clock too
		if !winStart.IsZero() && time.Since(winStart) > window+10*time.Second {
			if err := emit(winStart.Add(window)); err != nil {
				return err
			}
			winStart = winStart.Add(window)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := emit(winStart.Add(window)); err != nil {
		return err
	}
	if parsed == 0 {
		return fmt.Errorf("no access-log lines recognised (%d skipped) — nginx combined/makit format or Caddy JSON\n\n%s", skipped, nginxFormatHint)
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "(%d lines not recognised, skipped)\n", skipped)
	}
	return nil
}

// readLines reads a file (or stdin for "-"); with follow it waits for new lines and reopens the file when it is
// rotated, calling idle about once a second while waiting.
func readLines(path string, follow bool, fn func(string) error, idle func() error) error {
	var f *os.File
	var err error
	if path == "-" {
		f = os.Stdin
	} else if f, err = os.Open(path); err != nil {
		return err
	}
	defer func() { f.Close() }()
	br := bufio.NewReaderSize(f, 1<<20)
	var partial string
	for {
		line, err := br.ReadString('\n')
		if err == nil {
			if e := fn(partial + line); e != nil {
				return e
			}
			partial = ""
			continue
		}
		if err != io.EOF {
			return err
		}
		partial += line
		if !follow || path == "-" {
			if partial != "" {
				return fn(partial)
			}
			return nil
		}
		time.Sleep(time.Second)
		if e := idle(); e != nil {
			return e
		}
		if rotated(f, path) {
			nf, err := os.Open(path)
			if err != nil {
				continue // being recreated
			}
			f.Close()
			f, br = nf, bufio.NewReaderSize(nf, 1<<20)
		}
	}
}

func rotated(f *os.File, path string) bool {
	a, err1 := f.Stat()
	b, err2 := os.Stat(path)
	if err1 != nil || err2 != nil {
		return false
	}
	sa, ok1 := a.Sys().(*syscall.Stat_t)
	sb, ok2 := b.Sys().(*syscall.Stat_t)
	if ok1 && ok2 && sa.Ino != sb.Ino {
		return true
	}
	pos, _ := f.Seek(0, io.SeekCurrent)
	return b.Size() < pos // truncated in place (copytruncate)
}

// saveBans writes bans in one state.json update; a running gate picks them up within 2 s.
func saveBans(es []Entry) error {
	_, err := withState(func(st *State) error {
		type key struct {
			p    netip.Prefix
			site string
		}
		at := make(map[key]int, len(st.Block))
		for i, e := range st.Block {
			at[key{e.Prefix, e.Site}] = i
		}
		for _, e := range es {
			k := key{e.Prefix, e.Site}
			if i, ok := at[k]; ok {
				st.Block[i] = e
			} else {
				at[k] = len(st.Block)
				st.Block = append(st.Block, e)
			}
		}
		return nil
	})
	return err
}
