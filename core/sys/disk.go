package sys

import (
	"strings"
	"syscall"
)

// Mount is a real filesystem with its usage in bytes.
type Mount struct {
	Device, Path, FSType string
	Size, Used, Avail    uint64
}

var skipFS = map[string]bool{"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true, "devpts": true, "cgroup": true,
	"cgroup2": true, "overlay": true, "squashfs": true, "securityfs": true, "debugfs": true, "tracefs": true, "mqueue": true,
	"pstore": true, "bpf": true, "autofs": true, "hugetlbfs": true, "fusectl": true, "configfs": true, "binfmt_misc": true,
	"nsfs": true, "ramfs": true, "rpc_pipefs": true, "efivarfs": true, "fuse.lxcfs": true}

// ParseMounts lists real filesystems from /proc/mounts content, one entry per device.
func ParseMounts(lines []string) []Mount {
	seen := map[string]bool{}
	var out []Mount
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || skipFS[f[2]] || seen[f[0]] || strings.HasPrefix(f[1], "/var/lib/docker/") || strings.HasPrefix(f[1], "/snap/") {
			continue
		}
		seen[f[0]] = true
		out = append(out, Mount{Device: f[0], Path: strings.ReplaceAll(f[1], `\040`, " "), FSType: f[2]})
	}
	return out
}

func (r Root) ReadMounts() []Mount {
	ls, _ := r.lines("proc/mounts")
	ms := ParseMounts(ls)
	for i := range ms {
		var st syscall.Statfs_t
		if syscall.Statfs(r.path(ms[i].Path), &st) == nil {
			bs := uint64(st.Bsize)
			ms[i].Size = st.Blocks * bs
			ms[i].Avail = st.Bavail * bs
			ms[i].Used = (st.Blocks - st.Bfree) * bs
		}
	}
	return ms
}
