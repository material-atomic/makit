package top

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/material-atomic/makit/core/sys"
)

type column struct {
	title string
	w     int // 0 = flexible (takes the remaining width)
	right bool
}

type cell struct {
	s  string
	st *lipgloss.Style
}

func plain(s string) cell                     { return cell{s: s} }
func styled(s string, st lipgloss.Style) cell { return cell{s, &st} }

// table renders a header and the visible rows from y0, recording mouse regions. It returns the lines and each column's x.
func (m *model) table(cols []column, n int, row func(i int) []cell, y0, height int) ([]string, []int) {
	ls := m.list()
	fixed, flex := len(cols)-1, 0
	for _, c := range cols {
		if c.w == 0 {
			flex++
		}
		fixed += c.w
	}
	fw := 0
	if flex > 0 {
		fw = (m.w - fixed) / flex
		if fw < 8 {
			fw = 8
		}
	}
	widths, xs := make([]int, len(cols)), make([]int, len(cols))
	x := 0
	for i, c := range cols {
		widths[i] = c.w
		if c.w == 0 {
			widths[i] = fw
		}
		xs[i] = x
		x += widths[i] + 1
	}
	m.headHits = m.headHits[:0]
	var head strings.Builder
	for i, c := range cols {
		t := c.title
		if ls != nil && ls.sortCol == i && c.title != "" && m.tab != tSetup && m.tab != tShield {
			if ls.desc {
				t += "▼"
			} else {
				t += "▲"
			}
		}
		if c.right {
			head.WriteString(fitRight(t, widths[i]))
		} else {
			head.WriteString(fit(t, widths[i]))
		}
		if i < len(cols)-1 {
			head.WriteByte(' ')
		}
		m.headHits = append(m.headHits, hit{xs[i], xs[i] + widths[i], y0, i})
	}
	lines := []string{sHead.Render(fit(head.String(), m.w))}

	visible := height - 1
	if visible < 0 {
		visible = 0
	}
	m.rowsY, m.rows = y0+1, visible
	if ls != nil {
		if ls.cursor >= n {
			ls.cursor = n - 1
		}
		if ls.cursor < 0 {
			ls.cursor = 0
		}
		if ls.offset > ls.cursor {
			ls.offset = ls.cursor
		}
		if ls.cursor >= ls.offset+visible {
			ls.offset = ls.cursor - visible + 1
		}
		if ls.offset > n-visible {
			ls.offset = max(0, n-visible)
		}
	}
	off := 0
	if ls != nil {
		off = ls.offset
	}
	for i := off; i < n && i < off+visible; i++ {
		cells := row(i)
		selected := ls != nil && i == ls.cursor
		var b strings.Builder
		for j, c := range cells {
			if j >= len(cols) {
				break
			}
			s := c.s
			if cols[j].right {
				s = fitRight(s, widths[j])
			} else {
				s = fit(s, widths[j])
			}
			if c.st != nil && !selected {
				s = c.st.Render(s)
			}
			b.WriteString(s)
			if j < len(cols)-1 {
				b.WriteByte(' ')
			}
		}
		line := fit(b.String(), m.w)
		if selected {
			line = sSel.Render(ansi.Strip(line))
		}
		lines = append(lines, line)
	}
	return lines, xs
}

func (m *model) View() string {
	if m.w == 0 {
		return "loading…"
	}
	if m.w < 60 || m.h < 15 {
		return "makit top needs at least 60×15 (now " + fmt.Sprint(m.w, "×", m.h) + ")"
	}
	m.btnHits, m.confirmHits = m.btnHits[:0], m.confirmHits[:0]
	out := []string{m.titleLine(), m.tabsLine()}
	bodyH := m.h - 3
	var body []string
	if m.viewer != nil {
		body = m.viewerView(m.viewer, 2, bodyH, "esc close · ↑↓ PgUp PgDn scroll · End follow · r reload")
	} else {
		switch m.tab {
		case tOverview:
			body = m.overview(bodyH)
		case tProcs:
			body = m.procsView(bodyH)
		case tContainers:
			body = m.containersView(bodyH)
		case tServices:
			body = m.servicesView(bodyH)
		case tDisks:
			body = m.disksView(bodyH)
		case tLogs:
			body = m.viewerView(&m.journal, 2, bodyH, "↑↓ PgUp PgDn scroll · End follow · r reload")
		case tSetup:
			body = m.setupView(bodyH)
		case tShield:
			body = m.shieldView(bodyH)
		}
	}
	for len(body) < bodyH {
		body = append(body, "")
	}
	for i := range body[:bodyH] {
		body[i] = fit(body[i], m.w)
	}
	out = append(out, body[:bodyH]...)
	out = append(out, m.statusLine())
	return strings.Join(out, "\n")
}

func (m *model) titleLine() string {
	h := m.host
	left := sAccent.Render(" makit top ") + sBold.Render(h.Hostname) + sDim.Render(" · "+h.OS+" · "+h.Kernel)
	right := fmt.Sprintf("up %s · load %.2f %.2f %.2f · tasks %d/%d ", dur(h.Uptime), h.Load[0], h.Load[1], h.Load[2], h.Running, h.Total)
	gap := m.w - ansi.StringWidth(left) - ansi.StringWidth(right)
	if gap < 1 {
		return fit(left, m.w)
	}
	return left + strings.Repeat(" ", gap) + sDim.Render(right)
}

func (m *model) tabsLine() string {
	m.tabHits = m.tabHits[:0]
	var b strings.Builder
	x := 0
	for i, n := range tabNames {
		label := fmt.Sprintf(" %d %s ", i+1, n)
		if tab(i) == m.tab && m.viewer == nil {
			b.WriteString(sTabOn.Render(label))
		} else {
			b.WriteString(sTabOff.Render(label))
		}
		w := ansi.StringWidth(label)
		m.tabHits = append(m.tabHits, hit{x, x + w, 1, i})
		x += w
		b.WriteString(" ")
		x++
	}
	m.versionInTabs = false
	if v := m.versionLabel(); m.w-x-ansi.StringWidth(v)-1 >= 2 {
		b.WriteString(strings.Repeat(" ", m.w-x-ansi.StringWidth(v)-1) + v)
		m.versionInTabs = true
	}
	return b.String()
}

func (m *model) statusLine() string {
	y := m.h - 1
	if c := m.confirm; c != nil {
		yes, no := sButton.Render(" Yes (y) "), sButtonD.Render(" No (n) ")
		text := " " + sWarn.Render("?") + " " + c.text + "  "
		x := ansi.StringWidth(text)
		m.confirmHits = append(m.confirmHits, hit{x, x + ansi.StringWidth(yes), y, 1})
		x2 := x + ansi.StringWidth(yes) + 1
		m.confirmHits = append(m.confirmHits, hit{x2, x2 + ansi.StringWidth(no), y, 0})
		return fit(text+yes+" "+no, m.w)
	}
	var left string
	switch {
	case m.input != nil:
		left = " " + sAccent.Render(m.input.prompt+":") + " " + m.input.value + "█  " + sDim.Render(m.input.hint+" · Enter add · Esc cancel")
	case m.filtering:
		left = " filter: " + m.filter + "█  (Enter keep · Esc clear)"
	case m.flash != "" && time.Since(m.flashAt) < 5*time.Second:
		left = " " + sWarn.Render(m.flash)
	default:
		hints := map[tab]string{
			tOverview:   "1-8/click tabs · q quit",
			tShield:     "s on/off · a ask · e edge · m mode · b ban · w allow · i bot IP · u bot URL · d remove · R reports · / filter",
			tProcs:      "↑↓ select · click header/o sort · / filter · k kill · q quit",
			tContainers: "↑↓ select · Enter/l logs · r restart · s start/stop · / filter · q quit",
			tServices:   "↑↓ select · Enter/l logs · r restart · f failed only · / filter · q quit",
			tDisks:      "click header/o sort · q quit",
			tLogs:       "↑↓ PgUp PgDn scroll · End follow · r reload · q quit",
			tSetup:      "↑↓ select · Enter/i/click install · a install all missing · r recheck · q quit",
		}
		left = " " + sDim.Render(hints[m.tab])
		if m.filter != "" {
			left = " " + sAccent.Render("filter: "+m.filter) + sDim.Render(" (Esc clear) · ") + sDim.Render(hints[m.tab])
		}
	}
	who := "user"
	if m.isRoot {
		who = "root"
	}
	right := sDim.Render(who + " ")
	if !m.versionInTabs { // narrow screen: the version line moves here
		right = m.versionLabel() + sDim.Render(" · "+who+" ")
	}
	gap := m.w - ansi.StringWidth(left) - ansi.StringWidth(right)
	if gap < 1 {
		return fit(left, m.w)
	}
	return left + strings.Repeat(" ", gap) + right
}

// ---- tabs

func (m *model) overview(h int) []string {
	var l []string
	w := m.w
	cpu := 0.0
	if n := len(m.cpuHist); n > 0 {
		cpu = m.cpuHist[n-1] / 100
	}
	label := func(s string) string { return sBold.Render(fit(s, 6)) }
	l = append(l, label("CPU")+bar(cpu, w-20)+fitRight(pct(cpu*100)+"%", 8)+sDim.Render(fmt.Sprintf(" ×%d", len(m.coreCur))))

	// Per-core grid.
	cols := max(1, w/30)
	cw := w / cols
	maxRows := 6
	n := len(m.coreCur)
	rows := (n + cols - 1) / cols
	if rows > maxRows {
		rows = maxRows
	}
	for r := 0; r < rows; r++ {
		var b strings.Builder
		for c := 0; c < cols; c++ {
			i := r*cols + c
			if i >= n || (r == rows-1 && c == cols-1 && n > rows*cols) {
				if i < n {
					b.WriteString(sDim.Render(fmt.Sprintf("  +%d more cores", n-i)))
				}
				break
			}
			u := 0.0
			if i < len(m.corePrev) {
				u = sys.Usage(m.corePrev[i], m.coreCur[i])
			}
			b.WriteString(fit(sDim.Render(fmt.Sprintf("%4d ", i))+bar(u, cw-12)+fitRight(fmt.Sprintf("%.0f%%", u*100), 5), cw))
		}
		l = append(l, b.String())
	}
	l = append(l, label("")+sAccent.Render(spark(m.cpuHist, w-11, 100))+sDim.Render(" cpu"))

	mem := m.mem
	mf := 0.0
	if mem.Total > 0 {
		mf = float64(mem.Used()) / float64(mem.Total)
	}
	l = append(l, "", label("Mem")+bar(mf, w-26)+fitRight(human(mem.Used())+" / "+human(mem.Total), 20))
	sf := 0.0
	if mem.SwapTotal > 0 {
		sf = float64(mem.SwapUsed()) / float64(mem.SwapTotal)
	}
	swapText := "none"
	if mem.SwapTotal > 0 {
		swapText = human(mem.SwapUsed()) + " / " + human(mem.SwapTotal)
	}
	l = append(l, label("Swap")+bar(sf, w-26)+fitRight(swapText, 20))

	var rx, tx float64
	if k := len(m.rxHist); k > 0 {
		rx, tx = m.rxHist[k-1], m.txHist[k-1]
	}
	half := (w - 34) / 2
	l = append(l, "", label("Net")+fit("↓ "+rate(rx), 13)+sOK.Render(spark(m.rxHist, half, 0))+"  "+fit("↑ "+rate(tx), 13)+sWarn.Render(spark(m.txHist, half, 0)))

	l = append(l, "")
	for i, mt := range m.mounts {
		if i >= 4 {
			l = append(l, sDim.Render(fmt.Sprintf("      +%d more — tab 5", len(m.mounts)-4)))
			break
		}
		f := 0.0
		if mt.Size > 0 {
			f = float64(mt.Used) / float64(mt.Size)
		}
		l = append(l, label(map[bool]string{true: "Disk", false: ""}[i == 0])+fit(mt.Path, 16)+bar(f, w-46)+fitRight(human(mt.Used)+" / "+human(mt.Size), 18))
	}

	running := 0
	for _, c := range m.containers {
		if c.State == "running" {
			running++
		}
	}
	failed := 0
	for _, s := range m.services {
		if s.Active == "failed" {
			failed++
		}
	}
	missing := 0
	for _, c := range m.comps {
		if !c.Installed {
			missing++
		}
	}
	dockerPart := fmt.Sprintf("Containers %d/%d running", running, len(m.containers))
	if m.dockerErr != "" {
		dockerPart = sDim.Render("Docker not available")
	}
	svcPart := sOK.Render("Services ok")
	if failed > 0 {
		svcPart = sBad.Render(fmt.Sprintf("Services %d failed", failed))
	}
	setupPart := sOK.Render("Setup complete")
	if missing > 0 {
		setupPart = sWarn.Render(fmt.Sprintf("Setup: %d missing (tab %d)", missing, int(tSetup)+1))
	}
	l = append(l, "", " "+dockerPart+sDim.Render("  ·  ")+svcPart+sDim.Render("  ·  ")+setupPart, "")

	// Top processes by CPU fill the rest.
	rest := h - len(l)
	if rest > 2 {
		procs := append([]procRow(nil), m.procs...)
		sortProcs(procs)
		l = append(l, sHead.Render(fit(fmt.Sprintf("%7s %-10s %6s %6s  %s", "PID", "USER", "CPU%", "MEM%", "COMMAND"), w)))
		for i := 0; i < len(procs) && i < rest-1; i++ {
			p := procs[i]
			l = append(l, fmt.Sprintf("%7d %-10s %6s %6s  %s", p.PID, trunc(p.User, 10), pct(p.CPU), pct(p.MemPct), p.Cmd))
		}
	}
	return l
}

func sortProcs(p []procRow) {
	for i := 1; i < len(p); i++ { // insertion sort is fine for a few hundred rows
		for j := i; j > 0 && p[j].CPU > p[j-1].CPU; j-- {
			p[j], p[j-1] = p[j-1], p[j]
		}
	}
}

func (m *model) procsView(h int) []string {
	rows := m.procRows()
	cols := []column{{"PID", 7, true}, {"USER", 10, false}, {"CPU%", 6, true}, {"MEM%", 6, true}, {"RSS", 7, true}, {"THR", 4, true}, {"S", 1, false}, {"COMMAND", 0, false}}
	lines, _ := m.table(cols, len(rows), func(i int) []cell {
		p := rows[i]
		st := plain(string(p.State))
		if p.State == 'R' {
			st = styled("R", sOK)
		} else if p.State == 'D' || p.State == 'Z' {
			st = styled(string(p.State), sBad)
		}
		cpu := plain(pct(p.CPU))
		if p.CPU >= 50 {
			cpu = styled(pct(p.CPU), sWarn)
		}
		return []cell{plain(fmt.Sprint(p.PID)), plain(p.User), cpu, plain(pct(p.MemPct)), plain(human(p.RSS)), plain(fmt.Sprint(p.Threads)), st, plain(p.Cmd)}
	}, 2, h)
	return lines
}

func (m *model) containersView(h int) []string {
	if m.dockerErr != "" && len(m.containers) == 0 {
		m.rows = 0
		return []string{"", "  Docker is not available: " + sDim.Render(m.dockerErr), "", "  Install it from the Setup tab (7) or with: makit docker"}
	}
	rows := m.containerRows()
	cols := []column{{"NAME", 24, false}, {"STATE", 9, false}, {"CPU%", 6, true}, {"MEM", 8, true}, {"STATUS", 20, false}, {"IMAGE", 0, false}}
	lines, _ := m.table(cols, len(rows), func(i int) []cell {
		c := rows[i]
		state := styled(c.State, sOK)
		if c.State != "running" {
			state = styled(c.State, sBad)
		}
		cpu, mem := "", ""
		if c.State == "running" {
			cpu, mem = pct(c.CPU), human(c.Mem)
		}
		return []cell{plain(c.Name), state, plain(cpu), plain(mem), plain(c.Status), plain(c.Image)}
	}, 2, h)
	return lines
}

func (m *model) servicesView(h int) []string {
	if m.svcErr != "" && len(m.services) == 0 {
		m.rows = 0
		return []string{"", "  systemd is not available: " + sDim.Render(m.svcErr)}
	}
	rows := m.serviceRows()
	cols := []column{{"UNIT", 38, false}, {"ACTIVE", 10, false}, {"SUB", 10, false}, {"DESCRIPTION", 0, false}}
	lines, _ := m.table(cols, len(rows), func(i int) []cell {
		s := rows[i]
		var a cell
		switch s.Active {
		case "active":
			a = styled(s.Active, sOK)
		case "failed":
			a = styled(s.Active, sBad)
		default:
			a = styled(s.Active, sDim)
		}
		return []cell{plain(s.Unit), a, plain(s.Sub), plain(s.Description)}
	}, 2, h)
	if m.failedOnly && len(rows) == 0 {
		lines = append(lines, "", "  "+sOK.Render("No failed services."))
	}
	return lines
}

func (m *model) disksView(h int) []string {
	ios := len(m.ios) + 3
	th := min(len(m.mounts)+1, h-ios)
	ls := m.list()
	ms := append([]sys.Mount(nil), m.mounts...)
	sortMounts(ms, ls.sortCol, ls.desc)
	cols := []column{{"MOUNT", 0, false}, {"DEVICE", 22, false}, {"FS", 6, false}, {"SIZE", 7, true}, {"USED", 7, true}, {"AVAIL", 7, true}, {"USE", 26, false}}
	lines, _ := m.table(cols, len(ms), func(i int) []cell {
		mt := ms[i]
		f := 0.0
		if mt.Size > 0 {
			f = float64(mt.Used) / float64(mt.Size)
		}
		return []cell{plain(mt.Path), plain(mt.Device), plain(mt.FSType), plain(human(mt.Size)), plain(human(mt.Used)), plain(human(mt.Avail)),
			plain(bar(f, 20) + fitRight(fmt.Sprintf("%.0f%%", f*100), 5))}
	}, 2, th)
	lines = append(lines, "", sHead.Render(fit(fmt.Sprintf(" %-12s %14s %14s", "DISK I/O", "READ", "WRITE"), m.w)))
	for _, d := range m.ios {
		lines = append(lines, fmt.Sprintf(" %-12s %14s %14s", d.Name, rate(d.Read), rate(d.Write)))
	}
	return lines
}

func sortMounts(ms []sys.Mount, col int, desc bool) {
	less := func(a, b sys.Mount) bool {
		switch col {
		case 1:
			return a.Device < b.Device
		case 2:
			return a.FSType < b.FSType
		case 3:
			return a.Size < b.Size
		case 4:
			return a.Used < b.Used
		case 5:
			return a.Avail < b.Avail
		case 6:
			return frac(a) < frac(b)
		default:
			return a.Path < b.Path
		}
	}
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0; j-- {
			x, y := ms[j], ms[j-1]
			if desc {
				x, y = y, x
			}
			if !less(x, y) {
				break
			}
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}

func frac(m sys.Mount) float64 {
	if m.Size == 0 {
		return 0
	}
	return float64(m.Used) / float64(m.Size)
}

func (m *model) viewerView(v *viewer, y0, h int, hint string) []string {
	lines := []string{sHead.Render(fit(" "+v.title+"  "+sDim.Render(hint), m.w))}
	vis := h - 1
	m.rowsY, m.rows = y0+1, vis
	off := v.offset
	if off < 0 || off > len(v.lines)-vis {
		off = max(0, len(v.lines)-vis)
	}
	for i := off; i < len(v.lines) && i < off+vis; i++ {
		lines = append(lines, v.lines[i])
	}
	if len(v.lines) == 0 {
		lines = append(lines, sDim.Render("  (empty)"))
	}
	return lines
}

func (m *model) setupView(h int) []string {
	y := 2
	var l []string
	if m.compErr != "" {
		return []string{"", "  " + sBad.Render(m.compErr)}
	}
	missing := 0
	for _, c := range m.comps {
		if !c.Installed {
			missing++
		}
	}
	all := " Install all missing (a) "
	st := sButton
	if missing == 0 || m.installing != "" {
		st = sButtonD
	}
	intro := fmt.Sprintf(" %d of %d in place  ", len(m.comps)-missing, len(m.comps))
	l = append(l, intro+st.Render(all)+sDim.Render("   click a button or press Enter on a row"))
	x := ansi.StringWidth(intro)
	m.btnHits = append(m.btnHits, hit{x, x + ansi.StringWidth(all), y, -1})

	logH := 0
	if len(m.installLog) > 0 {
		logH = max(6, (h-1)/2)
	}
	th := min(len(m.comps)+1, h-1-logH)
	cols := []column{{"", 2, false}, {"COMPONENT", 26, false}, {"STATE", 0, false}, {"ACTION", 12, false}}
	lines, xs := m.table(cols, len(m.comps), func(i int) []cell {
		c := m.comps[i]
		icon, state := styled("✓", sOK), styled(c.Detail, sDim)
		if !c.Installed {
			icon, state = styled("✗", sWarn), styled(c.Detail, sWarn)
		}
		btn := " Install "
		bst := sButton
		if c.Installed {
			btn, bst = " Re-run ", sButtonD
		}
		if m.installing != "" {
			bst = sButtonD
		}
		return []cell{icon, plain(c.Title), state, styled(btn, bst)}
	}, y+1, th)
	l = append(l, lines...)
	ls := m.list()
	for r := 0; r < m.rows && ls.offset+r < len(m.comps); r++ {
		m.btnHits = append(m.btnHits, hit{xs[3], xs[3] + 9, m.rowsY + r, ls.offset + r})
	}

	if logH > 0 {
		title := " Log"
		switch {
		case m.installing != "":
			title += " · " + m.installing + " " + sWarn.Render("running…")
		case m.installOK != nil && *m.installOK:
			title += " · " + sOK.Render("finished ✓")
		case m.installOK != nil:
			title += " · " + sBad.Render("failed ✗")
		}
		for len(l) < h-logH {
			l = append(l, "")
		}
		l = append(l, sHead.Render(fit(title, m.w)))
		rest := h - len(l)
		start := max(0, len(m.installLog)-rest)
		for _, s := range m.installLog[start:] {
			l = append(l, " "+s)
		}
	}
	return l
}
