package top

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/material-atomic/makit/core/shield"
	"github.com/material-atomic/makit/core/sys"
)

// The Shield tab: the gate's two switches (ask: Caddy/nginx ask makit · edge: makit checks and blocks in front),
// its mode and counters, and the lists you manage — bans, allowlist, bot IPs and bot IP sources — with inputs to
// add to them. Every action runs the makit CLI, so the TUI and the command line behave the same.

type gateStatus struct {
	Mode        string           `json:"mode"`
	Ask         bool             `json:"ask"`
	Edge        bool             `json:"edge"`
	EdgeError   string           `json:"edge_error"`
	Listeners   int              `json:"listeners"`
	Block       int              `json:"block"`
	Lists       int              `json:"lists"`
	Allow       int              `json:"allow"`
	KernelBlock bool             `json:"kernel_block"`
	Stats       map[string]int64 `json:"stats"`
}

type shieldRow struct {
	kind, addr, when, source, note string
	del                            []string // makit arguments that remove it
}

type shieldMsg struct {
	configured bool
	service    string // active, inactive, failed…
	status     *gateStatus
	cfg        *shield.Config
	rows       []shieldRow
	err        string
}

type shieldState struct {
	shieldMsg
	loaded bool
	hits   []hit // buttons: see shieldButtons
	busy   string
}

type inputBox struct {
	prompt, hint, value string
	submit              func(v string) tea.Cmd
}

func shieldConfigPath() string {
	if p := os.Getenv("MAKIT_SHIELD_CONFIG"); p != "" {
		return p
	}
	return shield.DefaultConfig
}

func (m *model) loadShield() tea.Cmd {
	return func() tea.Msg {
		var s shieldMsg
		path := shieldConfigPath()
		if _, err := os.Stat(path); err != nil {
			return s // not set up yet
		}
		s.configured = true
		out, _ := exec.Command("systemctl", "is-active", "makit-shield").Output()
		s.service = strings.TrimSpace(string(out))
		cfg, err := shield.LoadConfig(path)
		if err != nil {
			s.err = err.Error()
			return s
		}
		s.cfg = cfg
		if res, err := shield.AdminClient(800 * time.Millisecond).Get(shield.AdminURL(cfg.Admin, "/status")); err == nil {
			var st gateStatus
			if json.NewDecoder(res.Body).Decode(&st) == nil {
				s.status = &st
			}
			res.Body.Close()
		}
		st, err := shield.LoadState()
		if err != nil {
			s.err = "state: " + err.Error() + " (run as root: sudo makit top)"
		} else {
			now := time.Now()
			for _, e := range st.Allow {
				s.rows = append(s.rows, shieldRow{"allow", e.Prefix.String(), "permanent", atSite(e), e.Reason, []string{"shield", "unallow", e.Prefix.String(), "--site", e.Site}})
			}
			for _, a := range cfg.Allow {
				s.rows = append(s.rows, shieldRow{"allow", a, "permanent", "shield.yaml", "edit /etc/makit/shield.yaml to remove", nil})
			}
			sort.Slice(st.Block, func(i, j int) bool { return st.Block[i].Added.After(st.Block[j].Added) })
			for _, e := range st.Block {
				when := "permanent"
				if !e.Until.IsZero() {
					if e.Until.Before(now) {
						continue
					}
					when = "until " + e.Until.Local().Format("01-02 15:04")
				}
				s.rows = append(s.rows, shieldRow{"ban", e.Prefix.String(), when, atSite(e), e.Reason, []string{"shield", "unban", e.Prefix.String(), "--site", e.Site}})
			}
		}
		feeds := shield.FeedStatuses()
		for _, src := range cfg.Bots.Sources {
			for _, ip := range src.IPs {
				s.rows = append(s.rows, shieldRow{"bot ip", ip, "", src.Agent, firstNonEmptyS(src.Category, "catalog agent"),
					[]string{"shield", "bots", "ip", "remove", src.Agent, ip}})
			}
			if src.URL != "" {
				note := "not downloaded yet"
				if f, ok := feeds[shield.FeedFile(src.Agent, src.URL)]; ok {
					if !f.OK.IsZero() {
						note = fmt.Sprintf("%d ranges · %s ago", f.Count, dur(time.Since(f.OK)))
					}
					if f.Error != "" {
						note += " · last try failed: " + f.Error
					}
				}
				s.rows = append(s.rows, shieldRow{"bot url", src.URL, "every " + firstNonEmptyS(src.Every, firstNonEmptyS(cfg.Bots.Refresh, "24h")),
					src.Agent, note, []string{"shield", "bots", "source", "remove", src.URL}})
			}
		}
		return s
	}
}

func firstNonEmptyS(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func (m *model) shieldRows() []shieldRow {
	var out []shieldRow
	for _, r := range m.shield.rows {
		if m.match(r.kind, r.addr, r.source, r.note) {
			out = append(out, r)
		}
	}
	return out
}

// runShield runs `makit <args…>` in the background and reports its last line.
func (m *model) runShield(what string, args []string) tea.Cmd {
	if m.needRoot() || m.makit == "" {
		return nil
	}
	m.shield.busy = what
	return func() tea.Msg {
		var last string
		err := sys.RunMakitArgs(m.makit, args, func(l string) { last = l })
		if err != nil {
			if last == "" {
				last = err.Error()
			}
			return shieldDoneMsg{what + " failed: " + last}
		}
		if last == "" {
			last = "done"
		}
		return shieldDoneMsg{what + ": " + last}
	}
}

type shieldDoneMsg struct{ text string }

// ---- switches and inputs

const (
	btnService = iota + 1
	btnAsk
	btnEdge
	btnMode
	btnBan
	btnAllow
	btnBotIP
	btnBotURL
	btnReport
)

func (m *model) shieldButton(b int) tea.Cmd {
	s := m.shield
	if !s.configured && b != btnService {
		m.say("shield is not set up — press s (makit shield on --observe)")
		return nil
	}
	switch b {
	case btnService:
		if s.service == "active" {
			m.ask("Turn the shield off? (ask off, edge off, gate keeps running for the CLI)", func() tea.Cmd {
				return m.runShield("shield off", []string{"shield", "off"})
			})
			return nil
		}
		m.ask("Turn the shield on in observe mode? (logs what it would block; switch to block with m)", func() tea.Cmd {
			return m.runShield("shield on", []string{"shield", "on", "--observe"})
		})
	case btnAsk:
		v := "on"
		if s.cfg != nil && s.cfg.Ask {
			v = "off"
		}
		return m.runShield("ask "+v, []string{"shield", "ask", v})
	case btnEdge:
		v := "on"
		if s.cfg != nil && s.cfg.Edge {
			v = "off"
		}
		if v == "on" && (s.cfg == nil || len(s.cfg.Listeners) == 0) {
			m.say("edge needs listeners in /etc/makit/shield.yaml (makit shield edit) — makit then owns ports 80/443")
			return nil
		}
		m.ask(fmt.Sprintf("Turn edge %s? (makit %s the public ports in front of Caddy/nginx)", v, map[string]string{"on": "takes", "off": "releases"}[v]), func() tea.Cmd {
			return m.runShield("edge "+v, []string{"shield", "edge", v})
		})
	case btnMode:
		v := "block"
		if s.cfg != nil && s.cfg.Mode == "block" {
			v = "observe"
		}
		return m.runShield("mode "+v, []string{"shield", "mode", v})
	case btnBan:
		m.input = &inputBox{prompt: "Ban", hint: "IP or CIDR [duration: 24h, 7d] [@site] [reason…]", submit: func(v string) tea.Cmd {
			f, site := siteToken(strings.Fields(v))
			if len(f) == 0 {
				return nil
			}
			args := append([]string{"shield", "ban", f[0]}, site...)
			rest := f[1:]
			if len(rest) > 0 && looksLikeDuration(rest[0]) {
				args, rest = append(args, "--for", rest[0]), rest[1:]
			}
			if len(rest) > 0 {
				args = append(args, "--reason", strings.Join(rest, " "))
			}
			return m.runShield("ban "+f[0], args)
		}}
	case btnAllow:
		m.input = &inputBox{prompt: "Allow", hint: "IP or CIDR [@site] [reason…] — never blocked", submit: func(v string) tea.Cmd {
			f, site := siteToken(strings.Fields(v))
			if len(f) == 0 {
				return nil
			}
			args := append([]string{"shield", "allow", f[0]}, site...)
			if len(f) > 1 {
				args = append(args, "--reason", strings.Join(f[1:], " "))
			}
			return m.runShield("allow "+f[0], args)
		}}
	case btnBotIP:
		m.input = &inputBox{prompt: "Bot IP", hint: "AGENT IP|CIDR [category for a new agent] — e.g. office-monitor 203.0.113.10 monitoring", submit: func(v string) tea.Cmd {
			f := strings.Fields(v)
			if len(f) < 2 {
				m.say("Bot IP: AGENT IP [category]")
				return nil
			}
			args := []string{"shield", "bots", "ip", "add", f[0], f[1]}
			if len(f) > 2 {
				args = append(args, "--category", f[2])
			}
			return m.runShield("bot ip "+f[1], args)
		}}
	case btnBotURL:
		m.input = &inputBox{prompt: "Bot URL", hint: "AGENT URL [every: 6h] [category for a new agent]", submit: func(v string) tea.Cmd {
			f := strings.Fields(v)
			if len(f) < 2 {
				m.say("Bot URL: AGENT URL [every] [category]")
				return nil
			}
			args := []string{"shield", "bots", "source", "add", f[1], "--agent", f[0]}
			rest := f[2:]
			if len(rest) > 0 && looksLikeDuration(rest[0]) {
				args, rest = append(args, "--every", rest[0]), rest[1:]
			}
			if len(rest) > 0 {
				args = append(args, "--category", rest[0])
			}
			return m.runShield("bot url", args)
		}}
	case btnReport:
		m.openViewer("Shield · latest batch reports", func() tea.Msg {
			var lines []string
			err := sys.RunMakitArgs(m.makit, []string{"shield", "report", "-n", "3"}, func(l string) { lines = append(lines, l) })
			if err != nil && len(lines) == 0 {
				return viewerMsg{nil, err}
			}
			return viewerMsg{lines, nil}
		})
		return m.viewer.reload()
	}
	return nil
}

func looksLikeDuration(s string) bool {
	if strings.HasSuffix(s, "d") {
		_, err := fmt.Sscanf(strings.TrimSuffix(s, "d"), "%d", new(int))
		return err == nil
	}
	_, err := time.ParseDuration(s)
	return err == nil
}

func (m *model) shieldDelete() {
	rows := m.shieldRows()
	ls := m.lists[tShield]
	if ls.cursor >= len(rows) || m.needRoot() {
		return
	}
	r := rows[ls.cursor]
	if r.del == nil {
		m.say(r.note)
		return
	}
	m.ask(fmt.Sprintf("Remove %s %s?", r.kind, trunc(r.addr, 50)), func() tea.Cmd {
		return m.runShield("remove "+r.kind+" "+trunc(r.addr, 30), r.del)
	})
}

// ---- view

func onOff(on bool) string {
	if on {
		return sOK.Render("● ON ")
	}
	return sDim.Render("○ off")
}

func (m *model) shieldView(h int) []string {
	s := &m.shield
	s.hits = s.hits[:0]
	if !s.loaded {
		return []string{"", "  loading…"}
	}
	var l []string
	y := 2
	btn := func(line *strings.Builder, label string, id int, on bool) {
		st := sButton
		if !on {
			st = sButtonD
		}
		x := ansi.StringWidth(line.String())
		r := st.Render(label)
		line.WriteString(r)
		s.hits = append(s.hits, hit{x, x + ansi.StringWidth(r), y + len(l), id})
	}
	if !s.configured {
		var b strings.Builder
		b.WriteString("  The shield is not set up on this server.  ")
		btn(&b, " Turn on (observe) · s ", btnService, true)
		l = append(l, "", b.String(), "",
			sDim.Render("  It checks every web request: its own IP set and allowlist, Cloudflare-aware client IPs, HTTP rules,"),
			sDim.Render("  scoring, bots and AI agents. Observe mode only logs what it would block. Guide: makit docs shield"))
		return l
	}
	// Line 1: service and switches.
	var b strings.Builder
	svc := s.service
	switch svc {
	case "active":
		svc = sOK.Render("● running")
	case "":
		svc = sDim.Render("? unknown")
	default:
		svc = sBad.Render("● " + svc)
	}
	cfg := s.cfg
	b.WriteString(" Service " + svc + " ")
	btn(&b, map[bool]string{true: " Turn off · s ", false: " Turn on · s "}[s.service == "active"], btnService, true)
	if cfg != nil {
		b.WriteString("   Mode ")
		mode := cfg.Mode
		if mode == "block" {
			mode = sOK.Render("block")
		} else {
			mode = sWarn.Render(mode)
		}
		b.WriteString(mode + " ")
		btn(&b, " switch · m ", btnMode, true)
	}
	l = append(l, b.String())
	if cfg != nil {
		b.Reset()
		b.WriteString(" Ask  " + onOff(cfg.Ask && cfg.Mode != "pass") + " Caddy/nginx ask makit before each request   ")
		btn(&b, " toggle · a ", btnAsk, true)
		l = append(l, b.String())
		b.Reset()
		edge := fmt.Sprintf(" makit checks and blocks in front (%d listener", len(cfg.Listeners))
		if len(cfg.Listeners) != 1 {
			edge += "s"
		}
		edge += ")   "
		b.WriteString(" Edge " + onOff(cfg.Edge) + edge)
		btn(&b, " toggle · e ", btnEdge, true)
		if st := s.status; st != nil && st.EdgeError != "" {
			b.WriteString("  " + sBad.Render(st.EdgeError))
		}
		l = append(l, b.String())
	}
	// Counters.
	if st := s.status; st != nil {
		parts := []string{}
		for _, k := range []string{"allowed", "allowlisted", "bot-verified", "blocked", "limited", "would-block", "dropped", "ask-off"} {
			if n := st.Stats[k]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %s", k, thousandsN(n)))
			}
		}
		if len(parts) == 0 {
			parts = append(parts, "no requests yet")
		}
		l = append(l, sDim.Render(" since start: "+strings.Join(parts, " · ")+fmt.Sprintf("   │ bans %d · listed %s · allow %d",
			st.Block, thousandsN(int64(st.Lists)), st.Allow)))
	} else {
		l = append(l, sWarn.Render(" the gate does not answer on its admin address — is makit-shield running? (makit shield status)"))
	}
	if s.err != "" {
		l = append(l, " "+sBad.Render(s.err))
	}
	// Buttons.
	b.Reset()
	b.WriteString(" ")
	for _, x := range []struct {
		label string
		id    int
	}{{" + Ban IP · b ", btnBan}, {" + Allow IP · w ", btnAllow}, {" + Bot IP · i ", btnBotIP}, {" + Bot URL · u ", btnBotURL}, {" Reports · R ", btnReport}} {
		btn(&b, x.label, x.id, s.busy == "")
		b.WriteString(" ")
	}
	if s.busy != "" {
		b.WriteString(sWarn.Render(" " + s.busy + "…"))
	}
	l = append(l, b.String())
	rows := m.shieldRows()
	cols := []column{{"TYPE", 8, false}, {"ADDRESS", 34, false}, {"WHEN", 18, false}, {"SOURCE", 18, false}, {"NOTE", 0, false}}
	lines, _ := m.table(cols, len(rows), func(i int) []cell {
		r := rows[i]
		kst := sDim
		switch r.kind {
		case "ban":
			kst = sBad
		case "allow":
			kst = sOK
		case "bot ip", "bot url":
			kst = sAccent
		}
		return []cell{styled(r.kind, kst), plain(r.addr), plain(r.when), plain(r.source), styled(r.note, sDim)}
	}, y+len(l), h-len(l))
	l = append(l, lines...)
	if len(rows) == 0 {
		l = append(l, sDim.Render("  no bans, allowlist entries or bot sources yet — add one with the buttons above"))
	}
	return l
}

func thousandsN(n int64) string {
	s := fmt.Sprint(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + " " + s[i:]
	}
	return s
}

// siteToken takes "@name" out of the words: the entry is then for that site only.
func siteToken(f []string) ([]string, []string) {
	out := f[:0:0]
	var site []string
	for _, w := range f {
		if name, ok := strings.CutPrefix(w, "@"); ok && name != "" {
			site = []string{"--site", name}
			continue
		}
		out = append(out, w)
	}
	return out, site
}

func atSite(e shield.Entry) string {
	if e.Site != "" {
		return e.Source + " @" + e.Site
	}
	return e.Source
}
