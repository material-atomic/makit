# Server security with makit

One page per topic: why it matters, what `makit scan` checks (rule ids), how to fix it by hand, and the makit command
that fixes it for you. Every finding of `makit scan` links to its page; on a server, read it with `makit docs <topic>`.

| Topic | Rules | Fix with |
| --- | --- | --- |
| [SSH access](ssh.md) | MK-SSH-*, MK-PERSIST-SSH-KEYS | `makit ssh`, `makit harden` |
| [Firewall](firewall.md) | MK-FW-* | `makit firewall` |
| [Docker and the firewall](docker-ports.md) | MK-NET-PUBLIC-SERVICE, MK-DOCKER-UFW | `makit firewall --docker` |
| [Outbound traffic (egress)](egress.md) | MK-EGRESS-OPEN | `makit firewall --docker --egress …` |
| [Container hardening](containers.md) | MK-DOCKER-* | your compose file |
| [Security updates](updates.md) | MK-UPDATES-* | `makit updates`, `makit system-upgrade` |
| [Vulnerable dependencies](dependencies.md) | MK-VULN | upgrade, rebuild, redeploy |
| [Kernel settings](kernel.md) | MK-KERNEL-SYSCTL | `makit harden` |
| [Temporary directories](mounts.md) | MK-HOST-TMP-EXEC | `makit harden` |
| [fail2ban](fail2ban.md) | MK-F2B-* | `makit harden` |
| [AppArmor](apparmor.md) | MK-APPARMOR-OFF | `makit harden` |
| [Secrets](secrets.md) | MK-SECRET-PERMS | `chmod 600` |
| [Logging and auditing](logging.md) | MK-LOG-* | `makit harden` |
| [Malware indicators](malware.md) | MK-PROC-*, MK-FILE-*, MK-NET-*, catalog rules | [incident response](incident-response.md) |
| [Persistence](persistence.md) | MK-PERSIST-* | [incident response](incident-response.md) |
| [Scheduled scans](scheduled-scans.md) | — | `makit schedule scan` |
| [Request shield](shield.md) | MK-HTTP-* | `makit shield on` |
| [Backups](backups.md) | — | your backup tool |
| [Cloud and code accounts](accounts.md) | — | provider settings |
| [Incident response](incident-response.md) | — | — |

Order of work on a new server: `makit init` (includes `harden`) → `makit firewall --docker` → review
[containers](containers.md) and [secrets](secrets.md) → `makit schedule scan daily` → set up [backups](backups.md).
