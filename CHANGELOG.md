# Changelog

## v0.5.0
- `makit shield`: IP gate for web traffic with its own block set (IP/CIDR, expiry; no ipset) and allowlist.
  - Ask mode: Caddy `forward_auth` / nginx `auth_request` call `/check` (`makit shield snippet caddy|nginx`).
  - Edge mode: makit in front of Caddy/nginx — TLS (ACME TLS-ALPN, Cloudflare Origin Certificate or files), blocked
    direct visitors disconnected at accept, real client IP forwarded; `tcp://` passthrough with optional PROXY v1.
  - Cloudflare-aware: `CF-Connecting-IP` trusted only from Cloudflare ranges (refreshed daily); spoofing ignored.
  - HTTP rules in the catalog (`security/http/`): secret/admin probing, path traversal, scanner user agents,
    React2Shell pattern — with automatic bans.
  - Request snapshots (no bodies, cookies or credentials), `log`, `status`, `check`; optional nftables kernel set.
  - `on` / `off` (pass, proxies keep working) / `uninstall`; lock-out guards for your SSH address and Cloudflare.
- Guide: docs/security/shield.md. Setup tab: request shield.

## v0.4.0
- Security guides in `docs/security/` (one page per topic); every finding links its page for the running version,
  and `makit docs <topic|RULE-ID>` shows it offline.
- `makit scan` checks configuration too (posture): SSH, firewall, exposed services, Docker vs ufw, egress, container
  privileges/socket/root/tmp, updates, kernel, mounts, fail2ban, AppArmor, auditd, log shipping, secret permissions.
  `--only malware,posture,vulns`.
- `makit harden`: kernel sysctls, /dev/shm noexec (`--tmp-noexec` for /tmp), SSH limits, fail2ban sshd jail,
  AppArmor, auditd rules. Part of `makit init` (`--no-harden` to skip).
- `makit firewall --docker` (published container ports follow ufw) and `--egress PORTS` (containers may connect out
  only to those ports); `makit init` enables `--docker` when Docker is installed.
- `makit schedule scan daily|weekly|hourly|off [--webhook=URL]`: scheduled scans, reports in /var/log/makit/scans,
  webhook alerts; consent recorded once.
- Catalog: new React2Shell sample hash; `doc` field on checks and rules.
- Setup tab: server hardening, Docker firewall, scheduled scan.
- Tests: posture and documentation-link tests; e2e covers a misconfigured container; CI proves the egress policy on
  real VMs (HTTPS passes, HTTP is rejected) and runs a scheduled scan.

## v0.3.0
- Security catalog in `security/`: built-in check severities, detection rules (YAML) and vulnerabilities (OSV JSON),
  read from the bundled copy, the newest one from this repository (`makit rules update`) and `--rules DIR`.
  Findings name their rule (`MK-…`) and references. `makit scan --list-rules` / `makit rules list`.
- Vulnerable packages are matched against OSV advisories (npm, including pnpm stores).
- `makit upgrade [--check]` checks GitHub for a newer makit and installs it after asking (`self-update` still works).
- **Breaking:** the apt upgrade command is now `makit system-upgrade` (was `makit upgrade` in v0.2.0).
- Tests: catalog and fixture-filesystem scan tests in Go; `tests/scan-e2e.sh` replays a compromise in Docker.
- `--iocs` / `--list-iocs` are replaced by `--rules` / `--list-rules`.

## v0.2.0
- `makit top`: terminal dashboard with mouse support — overview, processes, containers, services, disks, logs, and a
  Setup tab that shows what is installed and installs missing parts with a live log.
- `makit scan`: read-only malware check of the host and containers (asks for consent first; never changes anything),
  with indicators from the CVE-2025-55182 (React2Shell) attack analysis.
- `makit list [--json]`, `makit upgrade [--full] [--autoremove]`.
- Prebuilt `makit-core` (linux amd64/arm64) installed and checksum-verified by install.sh.
- MIT license.

## v0.1.0
- First release: `init`, `upgrade`, `base`, `swap`, `sysctl`, `docker`, `volume`, `firewall`, `updates`, `ssh`,
  `status`, `self-update`, and the pinned-version installer.
