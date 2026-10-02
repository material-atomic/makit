# Docker and the firewall

`ports: - "5432:5432"` in a compose file makes Postgres reachable **from the internet**, even with ufw denying
everything: Docker writes its own iptables rules, and traffic to containers never passes ufw's input rules.

## What makit checks

| Rule | Finding |
| --- | --- |
| MK-NET-PUBLIC-SERVICE | A database/cache/admin port (5432, 3306, 6379, 27017, 9200, 8123, 11211, 2375…) listens on all interfaces, on the host or published by a container. 2375/2376 (Docker API) is critical: it is root on the host. |
| MK-DOCKER-UFW | Docker is installed and nothing filters traffic to containers (`DOCKER-USER` chain empty). |

## Fix

1. Publish internal services on localhost only, or not at all (containers reach each other by name):

   ```yaml
   ports:
     - "127.0.0.1:5432:5432"   # reachable from the host only (backups, psql)
   ```

2. Make ufw filter container traffic:

   ```bash
   makit firewall --docker                     # route traffic to containers through ufw; allow 80/443 by default
   makit firewall --docker 80/tcp 443/tcp 8443/tcp
   ```

   makit adds the `DOCKER-USER` rules (the well-known *ufw-docker* approach) to `/etc/ufw/after.rules` between
   `# BEGIN makit docker` / `# END makit docker`, and allows the listed ports with `ufw route allow`. Container ↔
   container and host ↔ container traffic is unaffected. Ports are the **container** ports (after Docker's mapping).

3. Keep the provider firewall as a second layer ([firewall](firewall.md)).
