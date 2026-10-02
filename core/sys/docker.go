package sys

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Docker talks to the Engine API over its unix socket (no CLI, no SDK).
type Docker struct {
	c    *http.Client
	mu   sync.Mutex
	prev map[string][2]uint64 // container id → {cpu total, system total}
}

func NewDocker(sock string) *Docker {
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	return &Docker{c: &http.Client{Transport: tr, Timeout: 5 * time.Second}, prev: map[string][2]uint64{}}
}

type Container struct {
	ID, Name, Image, State, Status, Ports string
	CPU                                   float64 // share of all CPUs × cores (100 = one core)
	Mem, MemLimit                         uint64
}

func (d *Docker) get(path string, v any) error {
	res, err := d.c.Get("http://docker" + path)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("docker %s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(res.Body).Decode(v)
}

// Containers lists all containers, with CPU and memory for running ones.
func (d *Docker) Containers() ([]Container, error) {
	var raw []struct {
		ID     string `json:"Id"`
		Names  []string
		Image  string
		State  string
		Status string
		Ports  []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}
	if err := d.get("/containers/json?all=1", &raw); err != nil {
		return nil, err
	}
	out := make([]Container, len(raw))
	var wg sync.WaitGroup
	for i, c := range raw {
		ports := []string{}
		for _, p := range c.Ports {
			if p.PublicPort > 0 && !strings.Contains(p.IP, ":") {
				ports = append(ports, fmt.Sprintf("%s:%d→%d", p.IP, p.PublicPort, p.PrivatePort))
			}
		}
		sort.Strings(ports)
		name := c.ID[:12]
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		out[i] = Container{ID: c.ID, Name: name, Image: c.Image, State: c.State, Status: c.Status, Ports: strings.Join(ports, " ")}
		if c.State == "running" {
			wg.Add(1)
			go func(i int) { defer wg.Done(); d.stats(&out[i]) }(i)
		}
	}
	wg.Wait()
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func (d *Docker) stats(c *Container) {
	var s struct {
		CPU struct {
			Usage struct {
				Total uint64 `json:"total_usage"`
			} `json:"cpu_usage"`
			System uint64 `json:"system_cpu_usage"`
			Online int    `json:"online_cpus"`
		} `json:"cpu_stats"`
		Mem struct {
			Usage uint64            `json:"usage"`
			Limit uint64            `json:"limit"`
			Stats map[string]uint64 `json:"stats"`
		} `json:"memory_stats"`
	}
	if d.get("/containers/"+c.ID+"/stats?stream=false&one-shot=true", &s) != nil {
		return
	}
	c.Mem, c.MemLimit = s.Mem.Usage, s.Mem.Limit
	if f := s.Mem.Stats["inactive_file"]; f > 0 && f < c.Mem { // what `docker stats` shows (cgroup v2)
		c.Mem -= f
	}
	d.mu.Lock()
	p, ok := d.prev[c.ID]
	d.prev[c.ID] = [2]uint64{s.CPU.Usage.Total, s.CPU.System}
	d.mu.Unlock()
	if ok && s.CPU.System > p[1] && s.CPU.Usage.Total >= p[0] {
		n := s.CPU.Online
		if n == 0 {
			n = 1
		}
		c.CPU = float64(s.CPU.Usage.Total-p[0]) / float64(s.CPU.System-p[1]) * float64(n) * 100
	}
}

// Action posts start/stop/restart for a container.
func (d *Docker) Action(id, action string) error {
	res, err := d.c.Post("http://docker/containers/"+id+"/"+action, "application/json", nil)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode >= 300 && res.StatusCode != http.StatusNotModified {
		b, _ := io.ReadAll(res.Body)
		return fmt.Errorf("%s: %s", res.Status, strings.TrimSpace(string(b)))
	}
	return nil
}

// Logs returns the last lines of a container's output (stdout + stderr).
func (d *Docker) Logs(id string, tail int) ([]string, error) {
	res, err := d.c.Get(fmt.Sprintf("http://docker/containers/%s/logs?stdout=1&stderr=1&tail=%d", id, tail))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	return splitLines(DemuxLogs(b)), nil
}

// DemuxLogs strips Docker's 8-byte stream headers (non-TTY containers); TTY output passes through.
func DemuxLogs(b []byte) string {
	if len(b) < 8 || (b[0] != 1 && b[0] != 2) || b[1] != 0 || b[2] != 0 || b[3] != 0 {
		return string(b)
	}
	var sb strings.Builder
	for len(b) >= 8 {
		n := int(binary.BigEndian.Uint32(b[4:8]))
		b = b[8:]
		if n > len(b) {
			n = len(b)
		}
		sb.Write(b[:n])
		b = b[n:]
	}
	return sb.String()
}

func splitLines(s string) []string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// Get decodes any Engine API GET endpoint (e.g. /containers/<id>/json).
func (d *Docker) Get(path string, v any) error { return d.get(path, v) }
