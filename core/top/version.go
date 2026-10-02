package top

import (
	"errors"
	"os/exec"
	"regexp"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/material-atomic/makit/core/sys"
)

// The version line: green when this makit is the latest release, yellow with the new version when there is one
// (makit upgrade installs it). The check is `makit upgrade --check` — one source of truth with the CLI — at start
// and every 6 hours.

type updState int

const (
	updUnknown updState = iota // not checked yet, or GitHub unreachable
	updCurrent
	updNewer
)

type updateMsg struct {
	state  updState
	latest string
}
type updateTickMsg struct{}

var latestRe = regexp.MustCompile(`→ (v[0-9][0-9A-Za-z.\-]*)`)

func (m *model) checkUpdate() tea.Cmd {
	if m.makit == "" {
		return nil
	}
	return func() tea.Msg {
		var out []string
		err := sys.RunMakitArgs(m.makit, []string{"upgrade", "--check"}, func(l string) { out = append(out, l) })
		var ee *exec.ExitError
		switch {
		case err == nil:
			return updateMsg{state: updCurrent}
		case errors.As(err, &ee) && ee.ExitCode() == 10:
			for _, l := range out {
				if mm := latestRe.FindStringSubmatch(l); mm != nil {
					return updateMsg{state: updNewer, latest: mm[1]}
				}
			}
			return updateMsg{state: updNewer}
		}
		return updateMsg{state: updUnknown}
	}
}

func updateTick() tea.Cmd {
	return tea.Tick(6*time.Hour, func(time.Time) tea.Msg { return updateTickMsg{} })
}

// versionLabel is shown at the right of the tabs line, or in the status bar when the screen is narrow.
func (m *model) versionLabel() string {
	v := "makit " + Version
	switch m.upd.state {
	case updCurrent:
		return sOK.Render("● " + v)
	case updNewer:
		next := "newer"
		if m.upd.latest != "" {
			next = m.upd.latest
		}
		return sWarn.Render("▲ " + v + " → " + next + " · run makit upgrade")
	}
	return sDim.Render(v)
}
