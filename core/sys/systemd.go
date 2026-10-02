package sys

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

type Service struct{ Unit, Load, Active, Sub, Description string }

func run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// ParseUnits reads `systemctl list-units --plain --no-legend` output.
func ParseUnits(out string) []Service {
	var s []Service
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 || !strings.HasSuffix(f[0], ".service") {
			continue
		}
		s = append(s, Service{f[0], f[1], f[2], f[3], strings.Join(f[4:], " ")})
	}
	return s
}

func Services() ([]Service, error) {
	out, err := run(5*time.Second, "systemctl", "list-units", "--type=service", "--all", "--plain", "--no-legend", "--no-pager")
	if err != nil && out == "" {
		return nil, err
	}
	return ParseUnits(out), nil
}

func ServiceAction(unit, action string) error {
	out, err := run(60*time.Second, "systemctl", action, unit)
	if err != nil && strings.TrimSpace(out) != "" {
		return &cmdErr{strings.TrimSpace(out)}
	}
	return err
}

// Journal returns the last n lines of the system journal, or of one unit.
func Journal(unit string, n int) ([]string, error) {
	args := []string{"--no-pager", "-o", "short-iso", "-n", itoa(n)}
	if unit != "" {
		args = append(args, "-u", unit)
	}
	out, err := run(10*time.Second, "journalctl", args...)
	if err != nil && out == "" {
		return nil, err
	}
	return splitLines(out), nil
}

type cmdErr struct{ s string }

func (e *cmdErr) Error() string { return e.s }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
