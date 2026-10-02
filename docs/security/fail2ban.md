# fail2ban

fail2ban reads authentication logs and bans IPs that keep failing — cheap protection against password guessing and
log noise, even with key-only SSH.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-F2B-INACTIVE | fail2ban is not running (on a host with an SSH server). |
| MK-F2B-NO-SSHD | fail2ban runs without an `sshd` jail. |

## Fix

```bash
makit harden     # installs fail2ban, enables the sshd jail (journal backend, 5 tries, 1h ban), restarts it
fail2ban-client status sshd          # who is banned
fail2ban-client set sshd unbanip 203.0.113.7
```

The jail lives in `/etc/fail2ban/jail.d/makit.conf`. Add your office IP to `ignoreip` there if colleagues share it.
