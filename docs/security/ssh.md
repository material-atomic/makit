# SSH access

Most server takeovers start with SSH: password guessing, leaked passwords, or a key nobody remembers adding.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-SSH-PASSWORD | `PasswordAuthentication` is on: anyone can try passwords. |
| MK-SSH-ROOT-PASSWORD | `PermitRootLogin yes`: root can log in with a password. |
| MK-SSH-WEAK-SETTINGS | Many auth tries allowed, long login grace time, or X11 forwarding on. |
| MK-PERSIST-SSH-KEYS | Lists authorized keys; *low* when the file changed in the last 7 days. |

makit reads the **effective** configuration (`sshd -T`), so drop-in files and their order are taken into account.

## Fix

```bash
ssh-copy-id root@SERVER     # from your computer, first
makit ssh                   # key-only login (skipped while root has no key, so you cannot lock yourself out)
makit harden                # MaxAuthTries 4, LoginGraceTime 30, X11Forwarding no
```

By hand, in `/etc/ssh/sshd_config.d/00-local.conf` (sshd keeps the **first** value it reads; `50-cloud-init.conf`
often sets `PasswordAuthentication yes`, so a file sorting before it wins):

```
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
```

Then `sshd -t && systemctl reload ssh`, and check with `sshd -T | grep -E 'passwordauth|permitroot'`.

## Going further

- Allow SSH only from your office/VPN IP (`ufw allow from 203.0.113.0/24 to any port 22`), or reach the server
  through WireGuard/Tailscale and close port 22 to the internet.
- Review `~/.ssh/authorized_keys` regularly; remove keys of people who left.
- [fail2ban](fail2ban.md) bans repeated failures.
