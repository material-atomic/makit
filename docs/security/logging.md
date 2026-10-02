# Logging and auditing

After a compromise the first question is "what happened?", and attackers delete local logs. Two things answer it:
an audit trail of what was executed, and logs that leave the server.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-LOG-AUDITD | auditd is not running: there is no record of executed programs. |
| MK-LOG-REMOTE | No log shipping found (rsyslog forwarding, systemd-journal-upload, Vector, Fluent Bit, Promtail, Grafana Agent/Alloy, Datadog…). Informational. |

## Fix

```bash
makit harden     # installs auditd and records every program started from /tmp, /var/tmp and /dev/shm
ausearch -k makit_tmp_exec -i | tail     # who ran what from a temporary directory
```

The rules are in `/etc/audit/rules.d/makit.rules`. They also cover changes to `/etc/passwd`, `/etc/shadow`, sudoers,
SSH configuration and cron (`ausearch -k makit_identity`, `makit_sshd`, `makit_cron`).

For remote logs, ship the journal and container logs to a service you trust (Grafana Cloud, Better Stack, a
self-hosted Loki/OpenSearch on another machine). Keep at least 30 days.
