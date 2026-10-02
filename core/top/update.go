package top

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
	case tickMsg:
		m.sample()
		return m, tick(m.interval)
	case slowTickMsg:
		cmds := []tea.Cmd{slowTick(), m.loadContainers(), m.loadServices()}
		if m.tab == tLogs {
			cmds = append(cmds, m.loadJournal())
		}
		if m.tab == tShield {
			cmds = append(cmds, m.loadShield())
		}
		if m.viewer != nil && m.viewer.offset < 0 && m.viewer.reload != nil {
			cmds = append(cmds, m.viewer.reload())
		}
		return m, tea.Batch(cmds...)
	case containersMsg:
		m.containers, m.dockerErr = msg.c, ""
		if msg.err != nil {
			m.dockerErr = msg.err.Error()
		}
	case servicesMsg:
		m.services, m.svcErr = msg.s, ""
		if msg.err != nil {
			m.svcErr = msg.err.Error()
		}
	case journalMsg:
		m.journal.lines = msg
	case compsMsg:
		m.comps, m.compErr = msg.c, ""
		if msg.err != nil {
			m.compErr = msg.err.Error()
		}
	case viewerMsg:
		if m.viewer != nil {
			m.viewer.lines = msg.lines
			if msg.err != nil {
				m.viewer.lines = []string{"error: " + msg.err.Error()}
			}
		}
	case updateMsg:
		m.upd = msg
	case updateTickMsg:
		return m, tea.Batch(m.checkUpdate(), updateTick())
	case shieldMsg:
		m.shield.shieldMsg, m.shield.loaded = msg, true
	case shieldDoneMsg:
		m.shield.busy = ""
		m.say(msg.text)
		return m, m.loadShield()
	case actionMsg:
		m.say(msg.text)
		return m, tea.Batch(m.loadContainers(), m.loadServices())
	case installLineMsg:
		m.installLog = append(m.installLog, string(msg))
		if len(m.installLog) > 5000 {
			m.installLog = m.installLog[len(m.installLog)-5000:]
		}
	case installDoneMsg:
		ok := msg.err == nil
		m.installOK = &ok
		if ok {
			m.say(m.installing + ": done")
		} else {
			m.say(m.installing + " failed: " + msg.err.Error())
		}
		m.installing = ""
		return m, m.loadComps()
	case tea.KeyMsg:
		return m, m.onKey(msg)
	case tea.MouseMsg:
		return m, m.onMouse(msg)
	}
	return m, nil
}

func (m *model) setTab(t tab) tea.Cmd {
	if t == m.tab {
		return nil
	}
	m.tab, m.filter, m.filtering = t, "", false
	switch t {
	case tLogs:
		return m.loadJournal()
	case tSetup:
		return m.loadComps()
	case tShield:
		return m.loadShield()
	}
	return nil
}

func (m *model) list() *listState { return m.lists[m.tab] }

// move shifts the cursor by d and keeps it visible.
func (m *model) move(d int) {
	ls, n := m.list(), m.rowCount()
	if ls == nil || n == 0 {
		return
	}
	ls.cursor += d
	if ls.cursor < 0 {
		ls.cursor = 0
	}
	if ls.cursor >= n {
		ls.cursor = n - 1
	}
	rows := m.rows
	if rows < 1 {
		rows = 1
	}
	if ls.cursor < ls.offset {
		ls.offset = ls.cursor
	}
	if ls.cursor >= ls.offset+rows {
		ls.offset = ls.cursor - rows + 1
	}
}

// scrollViewer moves a log view; offset -1 means "follow the end".
func (m *model) scrollViewer(v *viewer, d int) {
	h := m.rows
	if h < 1 {
		h = 1
	}
	maxOff := len(v.lines) - h
	if maxOff < 0 {
		maxOff = 0
	}
	off := v.offset
	if off < 0 {
		off = maxOff
	}
	off += d
	if off < 0 {
		off = 0
	}
	if off >= maxOff {
		off = -1
	}
	v.offset = off
}

func (m *model) activeViewer() *viewer {
	if m.viewer != nil {
		return m.viewer
	}
	if m.tab == tLogs {
		return &m.journal
	}
	return nil
}

func (m *model) sortBy(col int) {
	ls := m.list()
	if ls == nil {
		return
	}
	if ls.sortCol == col {
		ls.desc = !ls.desc
	} else {
		ls.sortCol, ls.desc = col, m.tab == tProcs && (col == 2 || col == 3 || col == 4 || col == 5)
	}
}

// activate is Enter / a second click on the selected row.
func (m *model) activate() tea.Cmd {
	switch m.tab {
	case tContainers, tServices:
		m.openLogs()
		if m.viewer != nil {
			return m.viewer.reload()
		}
	case tSetup:
		if ls := m.list(); ls.cursor < len(m.comps) {
			m.install(m.comps[ls.cursor])
		}
	}
	return nil
}

func (m *model) onKey(k tea.KeyMsg) tea.Cmd {
	key := k.String()
	if key == "ctrl+c" {
		return tea.Quit
	}
	if c := m.confirm; c != nil {
		switch key {
		case "y", "Y", "enter":
			m.confirm = nil
			return c.yes()
		case "n", "N", "esc", "q":
			m.confirm = nil
		}
		return nil
	}
	if in := m.input; in != nil {
		switch k.Type {
		case tea.KeyEsc:
			m.input = nil
		case tea.KeyEnter:
			m.input = nil
			return in.submit(strings.TrimSpace(in.value))
		case tea.KeyBackspace:
			if r := []rune(in.value); len(r) > 0 {
				in.value = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			in.value += string(k.Runes)
		}
		return nil
	}
	if m.filtering {
		switch k.Type {
		case tea.KeyEsc:
			m.filter, m.filtering = "", false
		case tea.KeyEnter:
			m.filtering = false
		case tea.KeyBackspace:
			if r := []rune(m.filter); len(r) > 0 {
				m.filter = string(r[:len(r)-1])
			}
		case tea.KeyRunes, tea.KeySpace:
			m.filter += string(k.Runes)
		}
		if ls := m.list(); ls != nil {
			ls.cursor, ls.offset = 0, 0
		}
		return nil
	}
	if v := m.activeViewer(); v != nil {
		switch key {
		case "esc", "q":
			if m.viewer != nil {
				m.viewer = nil
				return nil
			}
		case "up":
			m.scrollViewer(v, -1)
			return nil
		case "down":
			m.scrollViewer(v, 1)
			return nil
		case "pgup":
			m.scrollViewer(v, -m.rows)
			return nil
		case "pgdown", " ":
			m.scrollViewer(v, m.rows)
			return nil
		case "home", "g":
			v.offset = 0
			return nil
		case "end", "G":
			v.offset = -1
			return nil
		case "r":
			if m.viewer != nil {
				return m.viewer.reload()
			}
			return m.loadJournal()
		}
		if m.viewer != nil {
			return nil
		}
	}
	switch key {
	case "q":
		return tea.Quit
	case "1", "2", "3", "4", "5", "6", "7", "8":
		return m.setTab(tab(key[0] - '1'))
	case "tab", "right":
		return m.setTab((m.tab + 1) % tab(len(tabNames)))
	case "shift+tab", "left":
		return m.setTab((m.tab + tab(len(tabNames)) - 1) % tab(len(tabNames)))
	case "/":
		if m.tab == tProcs || m.tab == tContainers || m.tab == tServices || m.tab == tShield {
			m.filtering, m.filter = true, ""
		}
	case "esc":
		m.filter = ""
	case "up":
		m.move(-1)
	case "down":
		m.move(1)
	case "pgup":
		m.move(-m.rows)
	case "pgdown":
		m.move(m.rows)
	case "home":
		m.move(-1 << 30)
	case "end":
		m.move(1 << 30)
	case "enter":
		return m.activate()
	case "o":
		if ls := m.list(); ls != nil {
			m.sortBy((ls.sortCol + 1) % 8)
		}
	case "O":
		if ls := m.list(); ls != nil {
			ls.desc = !ls.desc
		}
	case "k", "f9":
		if m.tab == tProcs {
			m.killSelected()
		}
	case "r":
		switch m.tab {
		case tShield:
			return m.loadShield()
		case tContainers:
			m.containerAction("restart")
		case tServices:
			m.serviceRestart()
		case tSetup:
			return m.loadComps()
		}
	case "s":
		if m.tab == tContainers {
			m.containerAction("toggle")
		}
		if m.tab == tShield {
			return m.shieldButton(btnService)
		}
	case "e", "m", "b", "w", "u", "R", "d", "delete":
		if m.tab == tShield {
			switch key {
			case "e":
				return m.shieldButton(btnEdge)
			case "m":
				return m.shieldButton(btnMode)
			case "b":
				return m.shieldButton(btnBan)
			case "w":
				return m.shieldButton(btnAllow)
			case "u":
				return m.shieldButton(btnBotURL)
			case "R":
				return m.shieldButton(btnReport)
			default:
				m.shieldDelete()
			}
		}
	case "f":
		if m.tab == tServices {
			m.failedOnly = !m.failedOnly
			m.lists[tServices].cursor, m.lists[tServices].offset = 0, 0
		}
	case "i":
		if m.tab == tSetup {
			return m.activate()
		}
		if m.tab == tShield {
			return m.shieldButton(btnBotIP)
		}
	case "a":
		if m.tab == tSetup {
			m.installMissing()
		}
		if m.tab == tShield {
			return m.shieldButton(btnAsk)
		}
	case "l":
		if m.tab == tContainers || m.tab == tServices {
			return m.activate()
		}
	}
	return nil
}

func in(h hit, x, y int) bool { return y == h.y && x >= h.x0 && x < h.x1 }

func (m *model) onMouse(e tea.MouseMsg) tea.Cmd {
	if m.confirm != nil {
		if e.Action == tea.MouseActionPress && e.Button == tea.MouseButtonLeft {
			for _, h := range m.confirmHits {
				if in(h, e.X, e.Y) {
					c := m.confirm
					m.confirm = nil
					if h.idx == 1 {
						return c.yes()
					}
					return nil
				}
			}
		}
		return nil
	}
	if e.Button == tea.MouseButtonWheelUp || e.Button == tea.MouseButtonWheelDown {
		d := 3
		if e.Button == tea.MouseButtonWheelUp {
			d = -3
		}
		if v := m.activeViewer(); v != nil {
			m.scrollViewer(v, d)
		} else {
			m.move(d)
		}
		return nil
	}
	if e.Action != tea.MouseActionPress || e.Button != tea.MouseButtonLeft {
		return nil
	}
	for _, h := range m.tabHits {
		if in(h, e.X, e.Y) {
			m.viewer = nil
			return m.setTab(tab(h.idx))
		}
	}
	if m.tab == tShield && m.viewer == nil {
		for _, h := range m.shield.hits {
			if in(h, e.X, e.Y) {
				return m.shieldButton(h.idx)
			}
		}
	}
	for _, h := range m.btnHits {
		if in(h, e.X, e.Y) {
			if h.idx < 0 {
				m.installMissing()
			} else if h.idx < len(m.comps) {
				m.lists[tSetup].cursor = h.idx
				m.install(m.comps[h.idx])
			}
			return nil
		}
	}
	if m.viewer != nil {
		return nil
	}
	for _, h := range m.headHits {
		if in(h, e.X, e.Y) {
			m.sortBy(h.idx)
			return nil
		}
	}
	if ls := m.list(); ls != nil && e.Y >= m.rowsY && e.Y < m.rowsY+m.rows {
		i := ls.offset + e.Y - m.rowsY
		if i < m.rowCount() {
			if i == ls.cursor {
				return m.activate()
			}
			ls.cursor = i
		}
	}
	return nil
}
