# Kernel settings

A few kernel switches make local privilege escalation and information leaks harder. They cost nothing on a server.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-KERNEL-SYSCTL | One or more baseline settings below are missing (one finding listing them). |

| Setting | Value | Why |
| --- | --- | --- |
| `kernel.kptr_restrict` | 2 | Hide kernel addresses from users (defeats exploit address leaks). |
| `kernel.dmesg_restrict` | 1 | Only root reads the kernel log. |
| `kernel.yama.ptrace_scope` | 1 | Processes cannot attach to non-child processes (credential theft from memory). |
| `fs.protected_symlinks` / `fs.protected_hardlinks` | 1 | Block classic /tmp symlink attacks. |
| `fs.protected_fifos` / `fs.protected_regular` | 2 | Same, for FIFOs and files in sticky directories. |
| `fs.suid_dumpable` | 0 | No core dumps of setuid programs (they may contain secrets). |
| `net.ipv4.conf.all.rp_filter` | 1 or 2 | Drop spoofed source addresses. makit sets 2 (loose): strict mode can drop valid traffic on hosts with several interfaces (public + VPC). |
| `net.ipv4.conf.all.accept_redirects` / `send_redirects` | 0 | Ignore ICMP redirects (traffic hijacking). |
| `net.ipv4.conf.all.accept_source_route` | 0 | Ignore source-routed packets. |
| `net.ipv4.tcp_syncookies` | 1 | Survive SYN floods. |

`net.ipv4.ip_forward` is left alone: Docker needs it.

## Fix

```bash
makit harden            # writes these to /etc/sysctl.d/90-makit.conf and applies them
makit sysctl kernel.kptr_restrict=2     # or one by one
```
