package sys

import (
	"os"
	"strconv"
	"strings"
)

// Proc is one process from /proc/<pid>.
type Proc struct {
	PID, PPID int
	Name, Cmd string
	User      string
	State     byte
	Ticks     uint64 // utime + stime
	RSS       uint64 // bytes
	Threads   int
}

// Users maps uid → name from /etc/passwd.
func (r Root) Users() map[int]string {
	m := map[int]string{}
	ls, _ := r.lines("etc/passwd")
	for _, l := range ls {
		f := strings.Split(l, ":")
		if len(f) > 2 {
			if id, err := strconv.Atoi(f[2]); err == nil {
				m[id] = f[0]
			}
		}
	}
	return m
}

var pageSize = uint64(os.Getpagesize())

func (r Root) ReadProcs(users map[int]string) ([]Proc, error) {
	ents, err := os.ReadDir(r.path("proc"))
	if err != nil {
		return nil, err
	}
	out := make([]Proc, 0, len(ents))
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if p, ok := r.readProc(pid, users); ok {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r Root) readProc(pid int, users map[int]string) (Proc, bool) {
	dir := "proc/" + strconv.Itoa(pid) + "/"
	stat := r.read(dir + "stat")
	// The command name is in parentheses and may contain spaces or ')'.
	open, close := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || close < open {
		return Proc{}, false
	}
	f := strings.Fields(stat[close+1:])
	if len(f) < 22 {
		return Proc{}, false
	}
	p := Proc{PID: pid, Name: stat[open+1 : close], State: f[0][0]}
	p.PPID, _ = strconv.Atoi(f[1])
	p.Ticks = u64(f[11]) + u64(f[12])
	p.Threads, _ = strconv.Atoi(f[17])
	p.RSS = u64(f[21]) * pageSize
	if cmd := r.read(dir + "cmdline"); cmd != "" {
		p.Cmd = strings.TrimSpace(clean(strings.ReplaceAll(cmd, "\x00", " ")))
	} else {
		p.Cmd = "[" + p.Name + "]"
	}
	for _, l := range strings.Split(r.read(dir+"status"), "\n") {
		if v, ok := strings.CutPrefix(l, "Uid:"); ok {
			if fs := strings.Fields(v); len(fs) > 0 {
				uid, _ := strconv.Atoi(fs[0])
				if p.User = users[uid]; p.User == "" {
					p.User = fs[0]
				}
			}
			break
		}
	}
	return p, true
}

// clean replaces control characters (newlines in argv, escapes) so one process is one screen line.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
}
