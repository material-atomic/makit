# Changelog

## Unreleased
- `makit shield` reads the visitor from the fields every proxy writes — `X-Forwarded-For`, else `Forwarded`, else
  `X-Real-IP` — walking back through `trusted_proxies`, whatever is in front: Cloudflare, CloudFront, Fastly, a
  DigitalOcean or AWS load balancer, or several. A provider's own header (`CF-Connecting-IP`) is no longer read:
  every proxy behind the provider passes it on as received, so with a load balancer between Cloudflare and the
  server, a client that skipped Cloudflare chose its own address with it — and got any address it named banned (an
  office, Googlebot) instead of its own. `client_ip_header` is no longer read (`config check` says so).
- Ask mode needs no header of makit's: the asking proxy appends the address it got the request from to
  `X-Forwarded-For`, as proxies do (nginx `$proxy_add_x_forwarded_for`; the Caddy snippet's
  `header_up X-Forwarded-For "{http.request.header.X-Forwarded-For}, {remote_host}"`, since Caddy replaces the chain
  unless it trusts its peer). `X-Makit-Peer` and `X-Makit-Client` are no longer read. **Paste the new snippet**
  (`makit shield snippet caddy|nginx`): with an old one, the visitor behind a CDN is the CDN's address. makit's
  `X-Makit-Client` and `X-Makit-Verdict` answers only tell the infrastructure the request went through makit; what
  the app sees is the proxy's to set.
- `makit shield`: the gate answers this machine at any of its own addresses, not only loopback and private ones. With
  `admin: 172.17.0.1:9180` and docker0 down (nothing on Docker's default bridge), a request from the host leaves
  through lo and Docker's `MASQUERADE` rewrites its source to eth0's public address: the gate refused it, and
  `makit shield status` failed with "invalid character 'o' in literal false". A host Caddy or nginx asking that
  address was refused the same way. Other machines cannot use this: the kernel drops packets from outside that carry
  one of its own addresses.
- An upgrade takes effect at once: the shield's systemd unit runs `/opt/makit/current`, not the folder of the version
  that wrote it, and `install.sh` — what `makit upgrade` runs — restarts a running gate on the new version after
  checking its config with the new binary (a config the new version refuses leaves the old gate running). New:
  `makit shield restart`.
- A fake Googlebot (Bingbot, Applebot: any crawler with published ranges and reverse DNS) can no longer slip past
  `bots.policy.spoofed` by making its own reverse DNS fail. Outside the operator's ranges, reverse DNS only rescues a
  new address; a timeout or SERVFAIL — its operator's choice — left it "unknown" for 10 minutes, never spoofed. It is
  now spoofed, and asked again after 10 minutes (not 24 hours) so a real crawler whose DNS was briefly down recovers.
- `makit shield status` and `makit top` never send the admin address's requests through `http_proxy`. A non-JSON
  answer is reported with its HTTP status and first line, and the gate's refusal names the address it refused.
- `tests/server-e2e.sh`: a fresh VPS end to end (terrarium's linux-server: systemd, Docker inside, eth0 with the public
  address first) — install the release, `makit init`, the shield with its admin on Docker's bridge, then upgrade to the
  checkout and check the gate runs it, answers the CLI, and allows a visitor and blocks a probe asked from a container.
  `install.sh` takes `MAKIT_FROM=DIR` to install a build's release files, checksums verified the same way.

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
- `makit shield snippet envoy-gateway|istio|envoy|traefik|ingress-nginx`: gateways in Kubernetes ask makit before every
  request (Envoy Gateway SecurityPolicy + ReferenceGrant, Istio CUSTOM provider, the Envoy ext_authz filter, Traefik
  forwardAuth, ingress-nginx auth-url), passing every header makit reads. `/check` understands Envoy's
  `/check/<path>` and ingress-nginx's `X-Original-URL`. `/status` and `/metrics` answer only private callers, like
  `/check`.
- makit in Kubernetes: the `makit-shield` image (20 MB, distroless, non-root, read-only root filesystem; amd64 and
  arm64; signed keyless with cosign, SBOM and provenance attached; chart pushed to `oci://ghcr.io/material-atomic/charts`),
  the Helm chart `deploy/helm/makit-shield` (2+ replicas sharing one shield, cluster secret generated once and kept,
  headless Service for peers, PodDisruptionBudget, NetworkPolicy on the cluster port, optional ServiceMonitor,
  `/readyz` and `/healthz` probes) and plain manifests `deploy/kubernetes/makit-shield.yaml`. `shield.yaml` comes from a
  ConfigMap mounted as a directory, so `helm upgrade` applies it live without restarting pods. New guide: Kubernetes
  and cloud load balancers (`makit docs kubernetes`). `tests/k8s-e2e.sh` checks it on kind: 3 replicas, CLI and
  automatic bans enforced everywhere, live config, `limit 10/1m` letting 11 of 30 requests through across replicas
  (27 with `cluster:` off).
- `makit shield analyze` and `config check --replay` read AWS ALB access logs (`--format alb` or detected), `.gz` files
  and directories of them, as S3 delivers them. Logs that keep only the User-Agent (ALB, nginx) no longer get
  header-based bot signals in replay — a browser was scored for headers the log never had.
- `makit shield` pushes its live bans to AWS WAF IP sets (`aws_waf:`, every 30 s, `makit shield waf sync [--dry-run]`),
  so the ALB or CloudFront drops that traffic first. Only the named IP sets are written, only when they differ, by one
  replica of a cluster; never a range overlapping an allow entry or a trusted proxy, site-only bans, or ranges wider
  than /8 / /32; beyond 10,000 addresses the newest bans win. Credentials from the AWS chain (EKS Pod Identity, IRSA,
  instance role); the chart has a ServiceAccount to annotate.
- Cluster sync every 250 ms by default (was 1 s): between two syncs a limit can be exceeded by about rate × interval.
- Catalog files starting with a dot are skipped: a catalog copied from a Mac carries AppleDouble `._*.yaml` files, and one
  of them stopped the gate with a YAML error. `makit top` says the Setup tab is tab 8 (it said 7 since the Shield tab
  came in). `makit --help`: aligned columns, and what makit is now.
- Bans, unbans and allow entries reach the other replicas at once instead of at the next sync: ~2 ms on average
  (was a full sync interval), batched at most every 20 ms under a flood.
- Config playground on makit.sh (`playground.html`): presets (single site, many domains, behind Cloudflare, behind a load
  balancer in Kubernetes, makit in front), blocks for every part of `shield.yaml` and a builder for `notify.yaml`, the
  YAML editable both ways, exports as a file, a ConfigMap, Helm values or a Secret. Checked by makit's own config
  check compiled to WebAssembly with the bundled catalog (~14 ms a check), so the messages are the CLI's; nothing
  leaves the browser and secrets stay placeholders. `tests/playground.sh` checks the WebAssembly in CI.

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
