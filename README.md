# makit

[![ci](https://github.com/material-atomic/makit/actions/workflows/ci.yml/badge.svg)](https://github.com/material-atomic/makit/actions/workflows/ci.yml)

Security for Linux servers you run yourself — find what is wrong, block what attacks, and set up new servers safely.
One command-line tool (`makit`), MIT-licensed, for Ubuntu and Debian.

| | What makit does |
| --- | --- |
| **Check** — `makit scan` | Read-only security check of the host and every Docker container (with your consent): malware and miner indicators, suspicious processes and connections, persistence, vulnerable npm packages (OSV), and posture — SSH, firewall, Docker ports, updates, kernel, secrets. Every finding links to a guide. |
| **Protect** — `makit shield` | A gate in front of your web traffic: its own IP set (millions of entries, no ipset), allowlist, Cloudflare-aware client IPs, HTTP rules, request scoring (probes, XSS, SQL injection…), bots/crawlers/AI agents verified and handled by your policy, rate limits, automatic bans. Works with Caddy/nginx asking it, or in front of them. |
| **Alert** — `makit notify`, `makit schedule` | Scheduled scans and ban reports to Telegram, Slack, Google Chat, Discord, Teams, ntfy, webhooks or email. |
| **Set up and harden** — `makit init` | A fresh server in one command: upgrades, swap, Docker, firewall (Docker ports included), automatic updates, kernel and SSH hardening, fail2ban, AppArmor, auditd — idempotent, with `--dry-run`. |
| **Watch** — `makit top` | A terminal dashboard: system, processes, containers, services, logs, setup. |

The threat knowledge — rules, scoring sets, the bot catalog, vulnerabilities — is data in [`security/`](security/),
updated with `makit rules update` and overridable per server. What the shield costs per request is measured in
[`benchmark/`](benchmark/), reproducible with one command.

Install (as root):

```bash
curl -fsSL https://makit.sh/install.sh | sh
```

A given version: `curl -fsSL https://makit.sh/install.sh | sh -s -- v0.5.0` (or `https://makit.sh/v0.5.0/install.sh`).
Website and guides: [makit.sh](https://makit.sh).

Set up a new server — preview first, then apply:

```bash
makit init --dry-run
makit init
```

`makit init` runs, in order: system upgrade and base packages → swap → kernel settings → Docker → (optional)
block-storage volume → firewall (with Docker-published ports behind ufw) → automatic security updates → hardening
(kernel, /dev/shm, fail2ban, AppArmor, auditd) → key-only SSH. Every step checks what is
already done, so running it again is harmless. Every command accepts `--dry-run`.

## Commands

| Command | What it does |
| --- | --- |
| `makit init [options]` | Everything below, in a safe order. `makit init --help` lists the options. |
| `makit system-upgrade [--full] [--autoremove]` | `apt-get update` + `upgrade` (or `dist-upgrade` with `--full`), non-interactive, keeps your config files, warns when a reboot is required. |
| `makit base` | `makit system-upgrade`, then installs curl, git, rsync, ufw, fail2ban, unattended-upgrades, jq… |
| `makit swap [SIZE\|auto]` | Creates `/swapfile` (auto: 2G below 2 GB of RAM, 4G up to 16 GB, none above) and sets `vm.swappiness=10`. Never resizes an existing swap file. |
| `makit sysctl KEY=VALUE… \| opensearch` | Persists kernel settings in `/etc/sysctl.d/90-makit.conf` and applies them. `opensearch` = `vm.max_map_count=262144`. |
| `makit docker` | Docker Engine + Compose plugin from download.docker.com; caps container logs at 3 × 20 MB (only if `/etc/docker/daemon.json` does not exist yet). |
| `makit volume DEVICE\|auto MOUNTPOINT [--docker] [--format]` | Mounts a block-storage volume (DigitalOcean, Hetzner, GCP, AWS EBS) by UUID with `nofail`. `--docker` keeps Docker's named volumes on it and makes Docker wait for the mount. `--format` creates ext4 only on an empty device, after asking. |
| `makit firewall [PORT/PROTO…] [--docker] [--egress PORTS\|off]` | ufw: deny incoming except the given ports (default 22/tcp 80/tcp 443/tcp 443/udp) **plus every port sshd listens on**; existing rules are kept. `--docker` puts Docker-published ports behind ufw; `--egress "443/tcp"` lets containers connect out only to those ports (+ DNS). |
| `makit updates` | Unattended security upgrades (reboots stay manual). |
| `makit harden [--tmp-noexec]` | Kernel hardening sysctls, `/dev/shm` noexec, SSH limits, fail2ban sshd jail, AppArmor, auditd rules for programs run from temporary directories. |
| `makit ssh` | Disables SSH password login, root keeps key login. **Skipped if root has no authorized key.** |
| `makit status` | Read-only summary: RAM, swap, disks, Docker, firewall, SSH, kernel settings, pending reboot. |
| `makit list [--json]` | Each part makit manages and whether it is in place (the Setup tab uses this). |
| `makit top` | Terminal dashboard with mouse support — see below. |
| `makit scan [options]` | Read-only security check of the host and/or containers — see below. |
| `makit rules list\|update\|path` | The security catalog `scan` uses; `update` fetches the newest one from this repository. |
| `makit schedule scan daily\|weekly\|hourly\|off [--webhook=URL]` | Scheduled read-only scans (systemd timer) with a webhook alert when something MEDIUM or worse is found. Consent is asked once. |
| `makit shield on\|off\|ban\|allow\|list\|log\|snippet …` | IP gate for web traffic — its own block set and allowlist, Cloudflare-aware, HTTP rules with automatic bans, request snapshots. Caddy/nginx ask it, or it sits in front of them — see below. |
| `makit docs [topic\|RULE-ID]` | The [security guides](docs/security/README.md), offline: what each finding means and how to fix it. |
| `makit upgrade [--check] [vX.Y.Z]` | Checks GitHub for a newer makit and installs it after asking (`--check` only reports: exit 10 when an update exists). `self-update` is an alias. |
| `makit version`, `makit -v`, `makit --version` | Prints the installed version. |

Global options: `--dry-run` (change nothing), `--yes` (confirm prompts, e.g. `--format` without a terminal).

### Example: a Docker host with OpenSearch and a DigitalOcean volume

```bash
makit init --sysctl opensearch --volume auto --mount /mnt/data --docker-volumes --format
```

## makit top

A terminal dashboard, no htop needed. Mouse: click tabs, click column headers to sort, scroll with the wheel, click a
row to select it (click again to open), click buttons. Keyboard: `1`–`8`, arrows, `/` to filter, `q` to quit. The version line on the right is green when makit is up to date and yellow when
a newer release exists (`makit upgrade` installs it; checked at start and every 6 hours).

| Tab | Shows | Actions (asks first, needs root) |
| --- | --- | --- |
| Overview | CPU per core + history, memory, swap, network, disks, top processes, health summary | — |
| Processes | All processes: CPU%, memory, threads, state, command | `k` send SIGTERM |
| Containers | Docker containers with CPU and memory | logs, restart, start/stop |
| Services | systemd services (`f` failed only) | journal, restart |
| Disks | Usage per filesystem, read/write per disk | — |
| Logs | System journal (follows the end) | — |
| Shield | The gate: service, **Ask** (Caddy/nginx ask makit) and **Edge** (makit checks and blocks in front) as separate switches, mode, counters; bans, allowlist, bot IPs and bot IP sources | turn on/off, toggle ask/edge/mode, + Ban IP, + Allow IP, + Bot IP, + Bot URL (typed inline), remove, latest reports |
| Setup | Everything `makit init` manages, ✓/✗ per item | Install / re-run with a live log, "install all missing" |

## makit scan

A **read-only** security check: a search for malware dropped on a server or inside containers — for example the Go backdoor dropped
through CVE-2025-55182 (React2Shell) as `/tmp/vim`, started with `nohup` and then deleted
([analysis](https://github.com/ngvcanh/CVE-2025-55182-Attack-Analysis)).

```bash
makit scan                              # the host (all processes, including those in containers)
makit scan --container web             # one container's filesystem, seen from the host — no docker exec
makit scan --all-containers --host      # everything
makit scan --json --consent > report.json   # automation: --consent replaces the interactive confirmation
```

Before anything is read, makit lists what it will look at and asks you to type `yes`. **It never modifies, deletes,
moves, quarantines, executes or uploads anything** — it prints findings with evidence and suggested next steps.

What it looks for (every finding links its [guide](docs/security/README.md); `makit docs <rule>` shows it offline):

- **Processes** running a deleted executable (run-then-`rm`), from `/tmp`, `/dev/shm` or a hidden directory, from memory
  only (memfd), disguised as kernel threads (`[kworker/0:1]`) or named like a system tool they are not.
- **Network** connections to known-bad IPs, to common miner/backdoor ports, or from those suspicious processes.
- **Files** in temporary and home directories: unexpected or hidden executables, SHA256 matches with known malware,
  Go binaries with backdoor traits (HTTP + SOCKS5 + TLS/ChaCha20), downloader scripts (`wget … -O /tmp/…; chmod +x;
  nohup`); in containers, every file added or changed since the image (`docker diff`).
- **Persistence**: cron, systemd units, `rc.local`, `/etc/ld.so.preload`, shell profiles, recently changed SSH keys.
- **Entry points**: installed packages affected by advisories in the catalog (e.g. Next.js / React for CVE-2025-55182).
- **Configuration**: SSH password login, firewall, databases/admin ports reachable from the internet, Docker ports
  bypassing ufw, containers that are privileged / have the Docker socket / run as root / have an executable `/tmp`,
  pending security updates, kernel settings, `/dev/shm`, fail2ban, AppArmor, auditd, log shipping, `.env` permissions.

`makit scan --only malware|posture|vulns` runs a subset.

Everything it knows — indicators, patterns, severities, vulnerabilities (OSV format) — is data in
[`security/`](security/README.md), read from the bundled catalog, the newest one from this repository
(`makit rules update`) and your own (`--rules DIR`). Each finding names its rule (`MK-…`) and references (CVE ids).
Exit status: `0` nothing above LOW, `1` MEDIUM or worse, `2` error, `3` consent not given.

## makit shield

Blocks visitors by IP before they reach your app, with its own set (IPs/CIDRs with expiry — no ipset) and an
allowlist that always wins. Behind Cloudflare it uses the visitor's IP from `CF-Connecting-IP`, but only when the
connection really comes from Cloudflare; a direct visitor faking the header is judged on its own IP. HTTP rules from the
catalog ban scanners, secret probing, path traversal and the React2Shell exploitation pattern automatically.

```bash
makit shield on                    # --observe to only log what would be blocked
makit shield snippet caddy         # Caddy/nginx ask makit before every request (forward_auth / auth_request)
makit shield ban 198.51.100.7 --for 24h
makit shield allow 192.0.2.10
makit shield log --blocked
```

Or put makit in front of Caddy/nginx (it terminates TLS and forwards to localhost). Guide:
[docs/security/shield.md](docs/security/shield.md).

Every request is also scored (probes, XSS and SQL injection in the URL, scanners, floods — the scoring set is
[online in this repo](security/scoring/http.yaml) and you can override it per server). Bots, crawlers and AI agents are
recognised and verified (a fake Googlebot is caught), and you choose per category or per bot:

```bash
makit shield bots set ai-crawler block      # no AI training crawlers
makit shield bots set gptbot "limit 30/1m"  # …or let one in slowly
makit shield customize scoring              # your own copy of the scoring set in /etc/makit/security
```

One server, many domains: the top of `shield.yaml` is the global policy and `sites:` overrides it per domain (mode,
bans for the site only or the whole server, bot policy, scoring profiles, rules, report channels).

Guide: [docs/security/bots.md](docs/security/bots.md).

## makit notify

Alerts for bans and scan findings on Telegram, Slack, Google Chat, Discord, Microsoft Teams, ntfy, webhooks or email:

```bash
makit notify add telegram --name ops --token BOT_TOKEN --chat-id CHAT_ID
makit notify test
```

Guide: [docs/security/notifications.md](docs/security/notifications.md).

## Safety

- **No lock-out.** `makit ssh` only disables passwords when root has a key in `/root/.ssh/authorized_keys`, validates
  the config with `sshd -t` before reloading (and reverts if invalid), then checks the effective setting with `sshd -T`.
  Its drop-in is `sshd_config.d/00-makit.conf`: sshd keeps the first value it reads, so a `99-…` file would lose to
  cloud-init's `50-cloud-init.conf`. The firewall always allows the port sshd actually listens on.
- **No data loss.** Volumes are formatted only with `--format`, only when they have no filesystem, and only after a
  confirmation. Existing swap files and `daemon.json` are left untouched.
- **Docker and ufw.** Ports published by Docker bypass ufw. Bind internal services to `127.0.0.1` in compose
  (`"127.0.0.1:5432:5432"`); publish only what must be public.

## Verify before running

`makit.sh/install.sh` only picks the version and runs that release's own `install.sh` from GitHub, which checks the
source and the `makit-core` binary against the release's `SHA256SUMS` before installing. To read everything first,
take the release's installer straight from GitHub (pinned to a tag, never `main`):

```bash
curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/v0.5.0/install.sh -o install.sh
less install.sh
bash install.sh
```

The installer puts each version in `/opt/makit/<version>`, points `/opt/makit/current` at it and links
`/usr/local/bin/makit`.

## Requirements

Ubuntu 20.04+ or Debian 11+ (or derivatives), amd64 or arm64, run as root.

## License

MIT — free for any use.

## Development

```bash
tests/smoke.sh          # makit in throwaway ubuntu:24.04 and debian:12 containers
tests/scan-e2e.sh       # replays a React2Shell-style compromise in Docker and checks every finding of makit scan
scripts/build.sh        # gofmt + vet + tests, then makit-core for linux/amd64 and arm64 into dist/
scripts/release.sh X.Y.Z    # bump, tag, push, build and publish the GitHub release
docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable -x -s bash bin/makit lib/common.sh lib/cmd/*.sh install.sh
```

CI (GitHub Actions) runs all of the above on every push, plus `makit init` for real — twice — on Ubuntu 22.04 and
24.04 VMs, then checks with `makit list` that every part is in place.

Shell commands are one file each in `lib/cmd/` defining `cmd_<name>`; `bin/makit` dispatches to them. `makit top` and
`makit scan` live in `core/` (Go, no cgo): `core/sys` reads `/proc` and the Docker socket, `core/top` is the dashboard,
`core/scan` the scanner.

## Roadmap

- Security first: more sources for the catalog (osv.dev, GitHub advisories), more package ecosystems (dpkg, pip, Go
  binaries), a Scan tab in `makit top`, scheduled scans with alerts.
- Monitoring: a small agent and ready-made images for metrics, logs and alerts.
