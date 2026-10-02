# Firewall

A server should accept connections only on the ports it serves. Everything else (databases, admin panels, debug
ports) must be unreachable from the internet.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-FW-INACTIVE | ufw is not active (and no other firewall rules are loaded). |
| MK-NET-PUBLIC-SERVICE | A database/admin port listens on all interfaces — see [Docker and the firewall](docker-ports.md). |

## Fix

```bash
makit firewall                       # deny incoming, allow 22/tcp 80/tcp 443/tcp 443/udp + your SSH port
makit firewall 22/tcp 443/tcp        # or exactly the ports you need
```

Existing rules are kept; the port sshd listens on is always allowed, so you cannot lock yourself out.

## Two layers

Add the provider's firewall in front (DigitalOcean Cloud Firewall, Hetzner Firewall, AWS security groups) with the same
ports. It still protects you if a host rule is wrong — in particular if Docker publishes a port that ufw does not see.

## Docker

Ports published by Docker bypass ufw. Read [Docker and the firewall](docker-ports.md) before trusting `ufw status`.
