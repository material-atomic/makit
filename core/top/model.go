package top

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/material-atomic/makit/core/sys"
)

type tab int

const (
	tOverview tab = iota
	tProcs
	tContainers
	tServices
	tDisks
	tLogs
	tSetup
)

var tabNames = []string{"Overview", "Processes", "Containers", "Services", "Disks", "Logs", "Setup"}

const histLen = 240

type procRow struct {
	sys.Proc
	CPU, MemPct float64
}

type netRow struct {
	Name   string
	Rx, Tx float64 // bytes/s
}

type ioRow struct {
	Name        string
	Read, Write float64 // bytes/s
}

// listState is the cursor/scroll/sort of one table.
type listState struct {
	cursor, offset int
	sortCol        int
	desc           bool
}

type viewer struct {
	title  string
	lines  []string
	offset int // first visible line; -1 = follow the end
	reload func() tea.Cmd
}

type confirmBox struct {
	text string
	yes  func() tea.Cmd
}

type hit struct{ x0, x1, y, idx int }

type model struct {
	w, h     int
	root     sys.Root
	makit    string
	interval time.Duration
	isRoot   bool
	tab      tab

	host              sys.Host
	mem               sys.Mem
	cpuPrev, cpuCur   sys.CPUTimes
	corePrev, coreCur []sys.CPUTimes
	cpuHist           []float64
	users             map[int]string
	procs             []procRow
	procTicks         map[int]uint64
	nets              []netRow
	netPrev           map[string]sys.NetDev
	rxHist, txHist    []float64
	mounts            []sys.Mount
	ios               []ioRow
	ioPrev            map[string]sys.DiskIO
	lastSample        time.Time

	docker     *sys.Docker
	containers []sys.Container
	dockerErr  string
	services   []sys.Service
	svcErr     string
	failedOnly bool
	journal    viewer
	comps      []sys.Component
	compErr    string

	installing string
	installLog []string
	installOK  *bool

	lists     map[tab]*listState
	filter    string
	filtering bool
	viewer    *viewer
	confirm   *confirmBox
	flash     string
	flashAt   time.Time

	// Mouse hit regions, filled while rendering.
	tabHits     []hit
	headHits    []hit
	rowsY, rows int
	btnHits     []hit
	confirmHits []hit
}

func newModel(root, makit string, interval time.Duration) *model {
	m := &model{root: sys.Root(root), makit: makit, interval: interval, isRoot: os.Geteuid() == 0,
		procTicks: map[int]uint64{}, netPrev: map[string]sys.NetDev{}, ioPrev: map[string]sys.DiskIO{},
		docker: sys.NewDocker("/var/run/docker.sock"), lists: map[tab]*listState{}}
	m.users = m.root.Users()
	m.lists[tProcs] = &listState{sortCol: 2, desc: true}
	for _, t := range []tab{tContainers, tServices, tDisks, tSetup} {
		m.lists[t] = &listState{}
	}
	m.journal = viewer{title: "System journal", offset: -1}
	m.sample()
	return m
}

// ---- messages

type tickMsg time.Time
type slowTickMsg time.Time
type containersMsg struct {
	c   []sys.Container
	err error
}
type servicesMsg struct {
	s   []sys.Service
	err error
}
type journalMsg []string
type compsMsg struct {
	c   []sys.Component
	err error
}
type viewerMsg struct {
	lines []string
	err   error
}
type actionMsg struct{ text string }
type installLineMsg string
type installDoneMsg struct{ err error }

func tick(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}
func slowTick() tea.Cmd {
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg { return slowTickMsg(t) })
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(tick(m.interval), m.loadContainers(), m.loadServices(), m.loadComps(), slowTick())
}

func (m *model) loadContainers() tea.Cmd {
	return func() tea.Msg { c, err := m.docker.Containers(); return containersMsg{c, err} }
}
func (m *model) loadServices() tea.Cmd {
	return func() tea.Msg { s, err := sys.Services(); return servicesMsg{s, err} }
}
func (m *model) loadJournal() tea.Cmd {
	return func() tea.Msg { l, _ := sys.Journal("", 500); return journalMsg(l) }
}
func (m *model) loadComps() tea.Cmd {
	if m.makit == "" {
		return func() tea.Msg { return compsMsg{nil, fmt.Errorf("makit CLI not found (run as: makit top)")} }
	}
	return func() tea.Msg { c, err := sys.Components(m.makit); return compsMsg{c, err} }
}

// ---- sampling (cheap /proc reads, done on every tick)

func (m *model) sample() {
	now := time.Now()
	dt := now.Sub(m.lastSample).Seconds()
	first := m.lastSample.IsZero()
	m.lastSample = now
	m.host = m.root.ReadHost()
	m.mem, _ = m.root.ReadMem()

	m.cpuPrev, m.corePrev = m.cpuCur, m.coreCur
	m.cpuCur, m.coreCur, _ = m.root.ReadCPU()
	if !first {
		m.cpuHist = push(m.cpuHist, sys.Usage(m.cpuPrev, m.cpuCur)*100)
	}

	ncpu := float64(len(m.coreCur))
	if ncpu == 0 {
		ncpu = 1
	}
	dTotal := float64(m.cpuCur.Total() - m.cpuPrev.Total())
	procs, _ := m.root.ReadProcs(m.users)
	ticks := make(map[int]uint64, len(procs))
	rows := make([]procRow, 0, len(procs))
	for _, p := range procs {
		r := procRow{Proc: p}
		if prev, ok := m.procTicks[p.PID]; ok && dTotal > 0 && p.Ticks >= prev {
			r.CPU = float64(p.Ticks-prev) / (dTotal / ncpu) * 100 // 100 = one full core, like htop
		}
		if m.mem.Total > 0 {
			r.MemPct = float64(p.RSS) / float64(m.mem.Total) * 100
		}
		ticks[p.PID] = p.Ticks
		rows = append(rows, r)
	}
	m.procTicks, m.procs = ticks, rows

	nets, _ := m.root.ReadNet()
	m.nets = m.nets[:0]
	var rx, tx float64
	for _, n := range nets {
		r := netRow{Name: n.Name}
		if p, ok := m.netPrev[n.Name]; ok && dt > 0 && n.RxBytes >= p.RxBytes && n.TxBytes >= p.TxBytes {
			r.Rx, r.Tx = float64(n.RxBytes-p.RxBytes)/dt, float64(n.TxBytes-p.TxBytes)/dt
		}
		m.netPrev[n.Name] = n
		rx, tx = rx+r.Rx, tx+r.Tx
		m.nets = append(m.nets, r)
	}
	if !first {
		m.rxHist, m.txHist = push(m.rxHist, rx), push(m.txHist, tx)
	}

	m.mounts = m.root.ReadMounts()
	dios, _ := m.root.ReadDiskIO()
	m.ios = m.ios[:0]
	for _, d := range dios {
		r := ioRow{Name: d.Name}
		if p, ok := m.ioPrev[d.Name]; ok && dt > 0 && d.ReadSectors >= p.ReadSectors && d.WriteSectors >= p.WriteSectors {
			r.Read, r.Write = float64(d.ReadSectors-p.ReadSectors)*512/dt, float64(d.WriteSectors-p.WriteSectors)*512/dt
		}
		m.ioPrev[d.Name] = d
		m.ios = append(m.ios, r)
	}
}

func push(h []float64, v float64) []float64 {
	h = append(h, v)
	if len(h) > histLen {
		h = h[len(h)-histLen:]
	}
	return h
}

func (m *model) say(s string) { m.flash, m.flashAt = s, time.Now() }

// ---- table data (sorted + filtered) shared by view and actions

func (m *model) match(s ...string) bool {
	if m.filter == "" {
		return true
	}
	f := strings.ToLower(m.filter)
	for _, x := range s {
		if strings.Contains(strings.ToLower(x), f) {
			return true
		}
	}
	return false
}

func (m *model) procRows() []procRow {
	ls := m.lists[tProcs]
	out := make([]procRow, 0, len(m.procs))
	for _, p := range m.procs {
		if m.match(p.Cmd, p.User, fmt.Sprint(p.PID)) {
			out = append(out, p)
		}
	}
	less := func(a, b procRow) bool {
		switch ls.sortCol {
		case 0:
			return a.PID < b.PID
		case 1:
			return a.User < b.User
		case 2:
			return a.CPU < b.CPU
		case 3, 4:
			return a.RSS < b.RSS
		case 5:
			return a.Threads < b.Threads
		case 6:
			return a.State < b.State
		default:
			return a.Cmd < b.Cmd
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ls.desc {
			return less(out[j], out[i])
		}
		return less(out[i], out[j])
	})
	return out
}

func (m *model) containerRows() []sys.Container {
	ls := m.lists[tContainers]
	var out []sys.Container
	for _, c := range m.containers {
		if m.match(c.Name, c.Image, c.State) {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ls.desc {
			a, b = b, a
		}
		switch ls.sortCol {
		case 1:
			return a.State < b.State
		case 2:
			return a.CPU < b.CPU
		case 3:
			return a.Mem < b.Mem
		case 4:
			return a.Status < b.Status
		case 5:
			return a.Image < b.Image
		default:
			return a.Name < b.Name
		}
	})
	return out
}

func (m *model) serviceRows() []sys.Service {
	ls := m.lists[tServices]
	var out []sys.Service
	for _, s := range m.services {
		if (!m.failedOnly || s.Active == "failed") && m.match(s.Unit, s.Description) {
			out = append(out, s)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if ls.desc {
			a, b = b, a
		}
		switch ls.sortCol {
		case 1:
			return a.Active < b.Active
		case 2:
			return a.Sub < b.Sub
		case 3:
			return a.Description < b.Description
		default:
			return a.Unit < b.Unit
		}
	})
	return out
}

func (m *model) rowCount() int {
	switch m.tab {
	case tProcs:
		return len(m.procRows())
	case tContainers:
		return len(m.containerRows())
	case tServices:
		return len(m.serviceRows())
	case tDisks:
		return len(m.mounts)
	case tSetup:
		return len(m.comps)
	}
	return 0
}

// ---- actions

func (m *model) needRoot() bool {
	if !m.isRoot {
		m.say("needs root — run: sudo makit top")
	}
	return !m.isRoot
}

func (m *model) ask(text string, yes func() tea.Cmd) { m.confirm = &confirmBox{text, yes} }

func (m *model) killSelected() {
	rows := m.procRows()
	ls := m.lists[tProcs]
	if ls.cursor >= len(rows) {
		return
	}
	p := rows[ls.cursor]
	m.ask(fmt.Sprintf("Send SIGTERM to %d (%s)?", p.PID, trunc(p.Cmd, 40)), func() tea.Cmd {
		if err := syscall.Kill(p.PID, syscall.SIGTERM); err != nil {
			m.say("kill failed: " + err.Error())
		} else {
			m.say(fmt.Sprintf("SIGTERM sent to %d", p.PID))
		}
		return nil
	})
}

func (m *model) containerAction(action string) {
	rows := m.containerRows()
	ls := m.lists[tContainers]
	if ls.cursor >= len(rows) || m.needRoot() {
		return
	}
	c := rows[ls.cursor]
	if action == "toggle" {
		action = "stop"
		if c.State != "running" {
			action = "start"
		}
	}
	m.ask(fmt.Sprintf("%s container %s?", strings.ToUpper(action[:1])+action[1:], c.Name), func() tea.Cmd {
		return func() tea.Msg {
			if err := m.docker.Action(c.ID, action); err != nil {
				return actionMsg{action + " " + c.Name + " failed: " + err.Error()}
			}
			return actionMsg{action + " " + c.Name + ": done"}
		}
	})
}

func (m *model) serviceRestart() {
	rows := m.serviceRows()
	ls := m.lists[tServices]
	if ls.cursor >= len(rows) || m.needRoot() {
		return
	}
	s := rows[ls.cursor]
	m.ask("Restart "+s.Unit+"?", func() tea.Cmd {
		return func() tea.Msg {
			if err := sys.ServiceAction(s.Unit, "restart"); err != nil {
				return actionMsg{"restart " + s.Unit + " failed: " + err.Error()}
			}
			return actionMsg{"restarted " + s.Unit}
		}
	})
}

func (m *model) openLogs() {
	switch m.tab {
	case tContainers:
		rows := m.containerRows()
		if ls := m.lists[tContainers]; ls.cursor < len(rows) {
			c := rows[ls.cursor]
			m.openViewer("Logs · "+c.Name, func() tea.Msg { l, err := m.docker.Logs(c.ID, 1000); return viewerMsg{l, err} })
		}
	case tServices:
		rows := m.serviceRows()
		if ls := m.lists[tServices]; ls.cursor < len(rows) {
			s := rows[ls.cursor]
			m.openViewer("Journal · "+s.Unit, func() tea.Msg { l, err := sys.Journal(s.Unit, 1000); return viewerMsg{l, err} })
		}
	}
}

func (m *model) openViewer(title string, load tea.Cmd) {
	v := &viewer{title: title, offset: -1}
	v.reload = func() tea.Cmd { return load }
	m.viewer = v
}

func (m *model) install(c sys.Component) {
	if m.installing != "" {
		m.say("an install is already running: " + m.installing)
		return
	}
	if m.needRoot() || m.makit == "" {
		return
	}
	verb := "Install"
	if c.Installed {
		verb = "Re-run"
	}
	m.ask(fmt.Sprintf("%s %s? (runs: makit %s)", verb, c.Title, c.Command), func() tea.Cmd {
		m.installing, m.installLog, m.installOK = c.Title, []string{"$ makit " + c.Command}, nil
		cmd := c.Command
		return func() tea.Msg {
			go func() {
				err := sys.RunMakit(m.makit, cmd, func(l string) { prog.Send(installLineMsg(l)) })
				prog.Send(installDoneMsg{err})
			}()
			return nil
		}
	})
}

func (m *model) installMissing() {
	var miss []sys.Component
	for _, c := range m.comps {
		if !c.Installed {
			miss = append(miss, c)
		}
	}
	if len(miss) == 0 {
		m.say("everything is in place")
		return
	}
	if m.installing != "" || m.needRoot() {
		return
	}
	titles := make([]string, len(miss))
	for i, c := range miss {
		titles[i] = c.Title
	}
	m.ask("Install all missing: "+strings.Join(titles, ", ")+"?", func() tea.Cmd {
		m.installing, m.installLog, m.installOK = "missing components", nil, nil
		return func() tea.Msg {
			go func() {
				var err error
				for _, c := range miss {
					prog.Send(installLineMsg("$ makit " + c.Command))
					if err = sys.RunMakit(m.makit, c.Command, func(l string) { prog.Send(installLineMsg(l)) }); err != nil {
						break
					}
				}
				prog.Send(installDoneMsg{err})
			}()
			return nil
		}
	})
}

func trunc(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}
