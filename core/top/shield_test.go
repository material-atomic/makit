package top

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"github.com/material-atomic/makit/core/shield"
)

// The Shield tab renders both switches, counters, the buttons with their click regions and the lists.
func TestShieldTabView(t *testing.T) {
	m := newModel("/", "", 0)
	m.w, m.h, m.tab = 130, 24, tShield
	cfg := &shield.Config{Mode: "block", Ask: true, Edge: false}
	m.shield = shieldState{loaded: true, shieldMsg: shieldMsg{configured: true, service: "active", cfg: cfg,
		status: &gateStatus{Mode: "block", Ask: true, Block: 12, Lists: 1000000, Allow: 2,
			Stats: map[string]int64{"allowed": 12431, "blocked": 120, "limited": 30}},
		rows: []shieldRow{
			{"allow", "203.0.113.10/32", "permanent", "manual", "office", []string{"shield", "unallow", "203.0.113.10/32"}},
			{"ban", "85.204.70.96/32", "until 05-22 14:24", "score:critical", "score 200: path-wordpress+40", []string{"shield", "unban", "85.204.70.96/32"}},
			{"bot url", "https://partner.example/ips.txt", "every 6h", "partner", "1 024 ranges · 2h ago", nil},
		}}}
	out := ansi.Strip(m.View())
	t.Log("\n" + out)
	for _, want := range []string{"7 Shield", "8 Setup", "● running", "Ask  ● ON", "Edge ○ off", "makit checks and blocks in front",
		"+ Ban IP · b", "+ Bot URL · u", "blocked 120", "listed 1 000 000", "85.204.70.96/32", "partner.example"} {
		if !strings.Contains(out, want) {
			t.Errorf("view lacks %q", want)
		}
	}
	if len(m.shield.hits) < 8 {
		t.Errorf("button regions: %d", len(m.shield.hits))
	}
	// Typing into the ban input shows in the status line.
	m.shieldButton(btnBan)
	m.input.value = "198.51.100.7 24h scanner"
	if out := ansi.Strip(m.View()); !strings.Contains(out, "Ban: 198.51.100.7 24h scanner") {
		t.Errorf("input line missing:\n%s", out)
	}
	// Not set up: one button to turn it on.
	m.input = nil
	m.shield = shieldState{loaded: true}
	if out := ansi.Strip(m.View()); !strings.Contains(out, "Turn on (observe)") {
		t.Errorf("not-configured view:\n%s", out)
	}
}
