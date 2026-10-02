// Package sys reads machine state straight from /proc and friends (Linux), with no external tools.
// Every reader takes a root so tests can point it at fixture trees.
package sys

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Root is the filesystem root readers use ("/" in production).
type Root string

func (r Root) path(p string) string { return filepath.Join(string(r), p) }

func (r Root) lines(p string) ([]string, error) {
	f, err := os.Open(r.path(p))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

func (r Root) read(p string) string {
	b, _ := os.ReadFile(r.path(p))
	return strings.TrimSpace(string(b))
}

func u64(s string) uint64 { v, _ := strconv.ParseUint(s, 10, 64); return v }

// CPUTimes are cumulative jiffies from /proc/stat.
type CPUTimes struct{ User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal uint64 }

func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}
func (c CPUTimes) Busy() uint64 { return c.Total() - c.Idle - c.IOWait }

// Usage is the busy share (0..1) between two samples.
func Usage(prev, cur CPUTimes) float64 {
	dt := float64(cur.Total() - prev.Total())
	if dt <= 0 || cur.Total() < prev.Total() {
		return 0
	}
	return float64(cur.Busy()-prev.Busy()) / dt
}

// ReadCPU returns the aggregate line and one entry per core.
func (r Root) ReadCPU() (total CPUTimes, cores []CPUTimes, err error) {
	ls, err := r.lines("proc/stat")
	if err != nil {
		return
	}
	for _, l := range ls {
		f := strings.Fields(l)
		if len(f) < 9 || !strings.HasPrefix(f[0], "cpu") {
			continue
		}
		t := CPUTimes{u64(f[1]), u64(f[2]), u64(f[3]), u64(f[4]), u64(f[5]), u64(f[6]), u64(f[7]), u64(f[8])}
		if f[0] == "cpu" {
			total = t
		} else {
			cores = append(cores, t)
		}
	}
	return
}

// Mem is in bytes.
type Mem struct{ Total, Available, Free, Buffers, Cached, SwapTotal, SwapFree uint64 }

func (m Mem) Used() uint64     { return m.Total - m.Available }
func (m Mem) SwapUsed() uint64 { return m.SwapTotal - m.SwapFree }

func (r Root) ReadMem() (Mem, error) {
	ls, err := r.lines("proc/meminfo")
	if err != nil {
		return Mem{}, err
	}
	var m Mem
	for _, l := range ls {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v := u64(f[1]) * 1024
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			m.Total = v
		case "MemAvailable":
			m.Available = v
		case "MemFree":
			m.Free = v
		case "Buffers":
			m.Buffers = v
		case "Cached":
			m.Cached = v
		case "SwapTotal":
			m.SwapTotal = v
		case "SwapFree":
			m.SwapFree = v
		}
	}
	if m.Available == 0 { // kernels before 3.14
		m.Available = m.Free + m.Buffers + m.Cached
	}
	return m, nil
}

type Host struct {
	Hostname, Kernel, OS string
	Uptime               time.Duration
	Load                 [3]float64
	Running, Total       int
}

func (r Root) ReadHost() Host {
	h := Host{Hostname: r.read("proc/sys/kernel/hostname"), Kernel: r.read("proc/sys/kernel/osrelease")}
	if f := strings.Fields(r.read("proc/uptime")); len(f) > 0 {
		s, _ := strconv.ParseFloat(f[0], 64)
		h.Uptime = time.Duration(s) * time.Second
	}
	if f := strings.Fields(r.read("proc/loadavg")); len(f) >= 4 {
		for i := 0; i < 3; i++ {
			h.Load[i], _ = strconv.ParseFloat(f[i], 64)
		}
		if a, b, ok := strings.Cut(f[3], "/"); ok {
			h.Running, _ = strconv.Atoi(a)
			h.Total, _ = strconv.Atoi(b)
		}
	}
	for _, l := range strings.Split(r.read("etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			h.OS = strings.Trim(v, `"`)
		}
	}
	return h
}

// NetDev counters are cumulative bytes.
type NetDev struct {
	Name             string
	RxBytes, TxBytes uint64
}

func (r Root) ReadNet() ([]NetDev, error) {
	ls, err := r.lines("proc/net/dev")
	if err != nil {
		return nil, err
	}
	var out []NetDev
	for _, l := range ls {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		f := strings.Fields(rest)
		if len(f) < 9 || name == "lo" || strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "br-") {
			continue
		}
		out = append(out, NetDev{name, u64(f[0]), u64(f[8])})
	}
	return out, nil
}

// DiskIO counters are cumulative sectors (512 B) per whole disk.
type DiskIO struct {
	Name                      string
	ReadSectors, WriteSectors uint64
}

func (r Root) ReadDiskIO() ([]DiskIO, error) {
	ls, err := r.lines("proc/diskstats")
	if err != nil {
		return nil, err
	}
	var out []DiskIO
	for _, l := range ls {
		f := strings.Fields(l)
		if len(f) < 10 {
			continue
		}
		n := f[2]
		if strings.HasPrefix(n, "loop") || strings.HasPrefix(n, "ram") || strings.HasPrefix(n, "dm-") {
			continue
		}
		// Whole disks only: sda, vda, nvme0n1 (not sda1, nvme0n1p1).
		if _, err := os.Stat(r.path("sys/block/" + n)); err != nil {
			continue
		}
		out = append(out, DiskIO{n, u64(f[5]), u64(f[9])})
	}
	return out, nil
}
