# Changelog

## v0.5.0
- `makit shield`: a gate for web traffic, in front of every request.
  - Its own IP set (IP/CIDR with expiry, a hash table per prefix length — no ipset): ~180 ns per lookup with
    1,000,000 entries; bulk lists (`import`, millions of entries); an allowlist that always wins.
  - Two independent switches: **ask** (Caddy `forward_auth` / nginx `auth_request` call `/check`; `snippet
    caddy|nginx`) and **edge** (makit in front: TLS via ACME TLS-ALPN, Cloudflare Origin Certificate or files; blocked
    direct visitors dropped at accept; `tcp://` passthrough with optional PROXY v1). Modes block / observe / pass.
  - Cloudflare-aware: `CF-Connecting-IP` trusted only from Cloudflare ranges (refreshed daily).
  - HTTP rules (`security/http/`): secret/admin probes, path traversal, scanners, React2Shell — automatic bans.
  - Request scoring (`security/scoring/http.yaml`, online and overridable): probes, XSS in the URL, SQL injection,
    Log4Shell, command injection, raw requests (RDP/TLS on the HTTP port), floods; values decoded first; per-IP
    escalation and bursts; actions per level. Profiles (WordPress, PHP), overrides in `shield.yaml`,
    `makit shield customize` for your own copy in `/etc/makit/security`.
  - Bots, crawlers and AI agents (`security/bots/agents.yaml`): search engines, AI search/assistants/crawlers/agents
    (Web Bot Auth), SEO, link previews, monitors, libraries, headless browsers. Verified against published ranges or
    forward-confirmed reverse DNS (fake Googlebots caught). Your policy per category or agent: allow, log, block,
    ban, `limit N/window` (429). Bot score for undeclared automation. Your own bot IP sources: URLs refreshed on a
    schedule, typed IPs (`bots source add`, `bots ip add`). `bots robots` writes robots.txt lines. GoesBot and
    goes.vn webhooks are allowed by default.
  - Batch reports every 5 minutes (`report:`): per suspicious IP with level, readable signals, paths, statuses and
    the action taken; saved to `/var/log/makit/shield/reports`, sent through `makit notify` when worth it.
  - `makit shield analyze FILE` scores nginx/Caddy access logs with the same policy (`--follow --ban --notify`).
  - Automatic bans apply at once and are saved in batches (no disk write in the request path); optional nftables
    kernel set; request snapshots; lock-out guards for your SSH address and Cloudflare.
- `makit notify`: Telegram, Slack, Google Chat, Discord, Microsoft Teams, ntfy, webhooks, email; per-channel minimum
  level, no duplicate floods. Scheduled scans and shield reports use it.
- `makit top`: Shield tab — ask and edge switches, mode, counters, bans, allowlist, bot IPs and sources with inline
  inputs, latest reports. Setup moves to tab 8. A version line: green when up to date, yellow with the newer
  release and `makit upgrade` when there is one.
- `benchmark/`: reproducible benchmarks (`benchmark/run.sh`, Docker only) — per-step decision cost and end-to-end
  latency with and without makit. A browser request costs ~9 µs to decide; makit adds well under 1 ms (p50).
- Catalog: `/etc/makit/security` for your own files (never overwritten by `makit rules update`).
- Guides: docs/security/shield.md, bots.md, notifications.md. README leads with what makit is now.

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
