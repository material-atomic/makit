package sys

import (
	"bufio"
	"encoding/json"
	"io"
	"os/exec"
	"strings"
)

// Component is one entry of `makit list --json`.
type Component struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Command     string `json:"command"`
	Description string `json:"description"`
	Installed   bool   `json:"installed"`
	Detail      string `json:"detail"`
}

// Components asks the makit CLI (single source of truth for checks).
func Components(makit string) ([]Component, error) {
	out, err := exec.Command(makit, "list", "--json").Output()
	if err != nil {
		return nil, err
	}
	var c []Component
	return c, json.Unmarshal(out, &c)
}

// RunMakit starts `makit <command…>` and streams its combined output line by line to fn; returns the exit error.
func RunMakit(makit, command string, fn func(line string)) error {
	cmd := exec.Command(makit, strings.Fields(command)...)
	pr, pw := io.Pipe()
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			fn(StripANSI(sc.Text()))
		}
		close(done)
	}()
	err := cmd.Wait()
	pw.Close()
	<-done
	return err
}

// StripANSI removes colour escape sequences.
func StripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && (s[j] < 0x40 || s[j] > 0x7e) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// RunMakitArgs is RunMakit with arguments kept as given (values with spaces, such as a ban reason).
func RunMakitArgs(makit string, args []string, fn func(line string)) error {
	cmd := exec.Command(makit, args...)
	out, err := cmd.CombinedOutput()
	for _, l := range strings.Split(strings.TrimRight(string(out), "\n"), "\n") {
		if l != "" {
			fn(StripANSI(l))
		}
	}
	return err
}
