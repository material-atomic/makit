// Package top is the `makit top` terminal dashboard (mouse + keyboard). Linux only.
package top

import (
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

// Version is shown in the status bar.
var Version = "dev"

// prog lets background work (installs) stream messages into the UI.
var prog *tea.Program

// Run starts the dashboard; makit is the path of the makit CLI used for the Setup tab.
func Run(makit string, interval time.Duration) error {
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}
	prog = tea.NewProgram(newModel("/", makit, interval), tea.WithAltScreen(), tea.WithMouseCellMotion())
	_, err := prog.Run()
	return err
}
