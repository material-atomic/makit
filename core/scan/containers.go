package scan

import (
	"fmt"
	"strings"

	"github.com/material-atomic/makit/core/sys"
)

// containerTargets resolves names/ids to filesystems readable from the host (/proc/<pid>/root) — no docker exec.
func containerTargets(d *sys.Docker, names []string, all bool) ([]target, error) {
	list, err := d.Containers()
	if err != nil {
		return nil, fmt.Errorf("Docker API not reachable (%v) — is Docker running, are you root?", err)
	}
	var pick []sys.Container
	if all {
		for _, c := range list {
			if c.State == "running" {
				pick = append(pick, c)
			}
		}
	}
	for _, n := range names {
		found := false
		for _, c := range list {
			if c.Name == n || strings.HasPrefix(c.ID, n) {
				if c.State != "running" {
					return nil, fmt.Errorf("container %s is %s: start it to scan its filesystem from the host", c.Name, c.State)
				}
				pick, found = append(pick, c), true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("no container named %q", n)
		}
	}
	var out []target
	for _, c := range pick {
		var ins struct {
			State  struct{ Pid int }
			Config struct{ WorkingDir string }
		}
		if err := d.Get("/containers/"+c.ID+"/json", &ins); err != nil || ins.State.Pid == 0 {
			return nil, fmt.Errorf("inspect %s: %v", c.Name, err)
		}
		var changes []struct {
			Path string
			Kind int // 0 modified, 1 added, 2 deleted
		}
		_ = d.Get("/containers/"+c.ID+"/changes", &changes)
		t := target{name: "container:" + c.Name, root: fmt.Sprintf("/proc/%d/root", ins.State.Pid), workdir: ins.Config.WorkingDir}
		for _, ch := range changes {
			if ch.Kind != 2 {
				t.changed = append(t.changed, ch.Path)
			}
		}
		out = append(out, t)
	}
	return out, nil
}
