# Changelog

## v0.6.0
- Colour in the terminal: help pages, `makit status`, `makit docs` (guides rendered with headings and code
  highlighted), `makit shield` lists, logs, reports, `analyze`, `sites` and `bots`, `makit notify` and the
  `makit scan` report. `makit shield status` prints a readable summary at a terminal (`--json` for the raw counters,
  as before when piped). Colour is off when output is not a terminal, with `NO_COLOR` or `TERM=dumb`, and on
  anywhere with `FORCE_COLOR`; saved and sent reports never carry colour codes.
- `makit shield`: the client IP behind a load balancer is read from the right of `X-Forwarded-For` — trusted proxies
  are skipped and the first address that is not one is the visitor, so a client can no longer choose its own IP by
  sending the header (every header line counts; at most 16 hops). `trusted_proxies` presets `aws-alb`, `vpc` and
  `loopback` next to `cloudflare`. A trusted proxy is never banned automatically, and `makit shield ban` refuses a
  range that overlaps one. `/check` without `X-Makit-Peer` takes the asking proxy from the right-most entry, not the
  left-most one a visitor wrote.
- `makit shield` edge listeners read PROXY protocol v1 and v2 (`accept_proxy_protocol: true`) from trusted proxies only —
  an AWS NLB or HAProxy in front keeps TLS at makit and makit still sees the visitor. Bans apply at accept, before
  TLS; a visitor's own PROXY line is never believed; headers are read off the accept loop with a 5 s limit; TLVs are
  skipped; malformed headers are dropped and counted.
- `makit shield config check [FILE|-] [--json]`: every error that would stop the gate loading a config, and every setting
  that loads but does nothing or harm — a misspelt key with the right name suggested, wrong value kinds, two listeners
  on a port, wildcard ACME names, trusted ranges anyone is in, `kernel_block` behind a load balancer, unknown notify
  channels, rules/scoring/bot settings the catalog rejects — with line numbers. `--replay LOG` runs a real access
  log through the current and the new config and lists what changes, by rule, with likely false positives (a browser
  the app answered 2xx/3xx) first; nothing is written. `makit shield edit` saves only a file that passes; the gate
  logs the warnings when it reloads.
- `makit shield`: `/metrics` (Prometheus: decisions by site, verdict and rule, a decision-latency histogram, bans by cause,
  events, set sizes, reloads, Go memory), `/healthz` and `/readyz` on the admin address. ~32 ns per request, no
  allocation, striped counters (same cost on 1 and 8 cores). `/status` reads the config in force (it raced with
  reloads before).
- `makit shield` cluster: replicas behind a load balancer share bans, unbans, allow entries, rate limits and request
  scores (`cluster:` with `listen`, `peers` — static or `dns:` for a headless Service — and a shared secret). Limits use
  windows aligned on the clock and add the other replicas' counts, so `limit 60/1m` stays 60 for the cluster; a scan
  spread over pods escalates as on one. A decision never waits on the network: the request path costs the same with and
  without a cluster (6.3–6.6 µs, 18 allocations). Messages are HMAC-signed with a time and sequence number; forged,
  old and replayed ones are refused. New replicas copy the bans of a running one. Peers in `makit shield status` and
  `/metrics`.

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
    schedule, typed IPs (`bots source add`, `bots ip add`). `bots robots` writes robots.txt lines.
  - Batch reports every 5 minutes (`report:`): per suspicious IP with level, readable signals, paths, statuses and
    the action taken; saved to `/var/log/makit/shield/reports`, sent through `makit notify` when worth it.
  - Sites: one server, many domains. The top of `shield.yaml` is the global policy; `sites:` sets per-domain
    mode, ban scope (server or site), allowlist, rules, scoring, bot policy, reports and notification channels —
    site values override the global ones where both are set. `ban/allow --site`, `makit shield sites`,
    `check --host`, `report --site`.
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
