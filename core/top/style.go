package top

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

var (
	cAccent = lipgloss.Color("39")  // blue
	cOK     = lipgloss.Color("42")  // green
	cWarn   = lipgloss.Color("214") // amber
	cBad    = lipgloss.Color("203") // red
	cDim    = lipgloss.Color("244")

	sBold    = lipgloss.NewStyle().Bold(true)
	sDim     = lipgloss.NewStyle().Foreground(cDim)
	sAccent  = lipgloss.NewStyle().Foreground(cAccent).Bold(true)
	sOK      = lipgloss.NewStyle().Foreground(cOK)
	sWarn    = lipgloss.NewStyle().Foreground(cWarn)
	sBad     = lipgloss.NewStyle().Foreground(cBad)
	sTabOn   = lipgloss.NewStyle().Background(cAccent).Foreground(lipgloss.Color("231")).Bold(true)
	sTabOff  = lipgloss.NewStyle().Foreground(lipgloss.Color("250"))
	sHead    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252")).Background(lipgloss.Color("237"))
	sSel     = lipgloss.NewStyle().Background(lipgloss.Color("24")).Foreground(lipgloss.Color("231"))
	sButton  = lipgloss.NewStyle().Background(cAccent).Foreground(lipgloss.Color("231")).Bold(true)
	sButtonD = lipgloss.NewStyle().Background(lipgloss.Color("238")).Foreground(lipgloss.Color("250"))
	sBar     = lipgloss.NewStyle().Background(lipgloss.Color("236"))
)

// fit pads or truncates s (may contain ANSI) to exactly w cells.
func fit(s string, w int) string {
	if w <= 0 {
		return ""
	}
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
	if ansi.StringWidth(s) > w {
		s = ansi.Truncate(s, w, "…")
	}
	return s + strings.Repeat(" ", w-ansi.StringWidth(s))
}

func fitRight(s string, w int) string {
	if ansi.StringWidth(s) > w {
		return ansi.Truncate(s, w, "…")
	}
	return strings.Repeat(" ", w-ansi.StringWidth(s)) + s
}

func levelStyle(frac float64) lipgloss.Style {
	switch {
	case frac >= 0.85:
		return sBad
	case frac >= 0.6:
		return sWarn
	default:
		return sOK
	}
}

// bar draws a usage bar of w cells.
func bar(frac float64, w int) string {
	if w < 1 {
		return ""
	}
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	n := int(frac*float64(w) + 0.5)
	return levelStyle(frac).Render(strings.Repeat("█", n)) + sDim.Render(strings.Repeat("░", w-n))
}

var sparks = []rune("▁▂▃▄▅▆▇█")

// spark renders the last w values scaled to max (or to their own max when max <= 0).
func spark(vals []float64, w int, max float64) string {
	if w <= 0 {
		return ""
	}
	if len(vals) > w {
		vals = vals[len(vals)-w:]
	}
	if max <= 0 {
		for _, v := range vals {
			if v > max {
				max = v
			}
		}
	}
	var b strings.Builder
	b.WriteString(strings.Repeat(" ", w-len(vals)))
	for _, v := range vals {
		i := 0
		if max > 0 {
			i = int(v / max * float64(len(sparks)-1))
		}
		if i < 0 {
			i = 0
		}
		if i >= len(sparks) {
			i = len(sparks) - 1
		}
		b.WriteRune(sparks[i])
	}
	return b.String()
}

func human(b uint64) string {
	const k = 1024
	if b < k {
		return fmt.Sprintf("%dB", b)
	}
	v, units := float64(b), "KMGTPE"
	i := -1
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	if v >= 100 {
		return fmt.Sprintf("%.0f%c", v, units[i])
	}
	return fmt.Sprintf("%.1f%c", v, units[i])
}

func rate(bps float64) string { return human(uint64(bps)) + "/s" }

func dur(d time.Duration) string {
	d = d.Round(time.Minute)
	days, h, m := int(d.Hours())/24, int(d.Hours())%24, int(d.Minutes())%60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	default:
		return fmt.Sprintf("%dm", m)
	}
}

func pct(f float64) string { return fmt.Sprintf("%.1f", f) }
