# makit

Bootstrap a fresh Ubuntu or Debian server with one command, safely and repeatably.

```bash
curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/v0.1.0/install.sh | bash
makit init --dry-run     # see what would change
makit init               # do it
```

`makit init` runs, in order: system upgrade and base packages → swap → kernel settings → Docker → (optional)
block-storage volume → firewall → automatic security updates → key-only SSH. Every step checks what is
already done, so running it again is harmless. Every command accepts `--dry-run`.

## Commands

| Command | What it does |
| --- | --- |
| `makit init [options]` | Everything below, in a safe order. `makit init --help` lists the options. |
| `makit upgrade [--full] [--autoremove]` | `apt-get update` + `upgrade` (or `dist-upgrade` with `--full`), non-interactive, keeps your config files, warns when a reboot is required. |
| `makit base` | `makit upgrade`, then installs curl, git, rsync, ufw, fail2ban, unattended-upgrades, jq… |
| `makit swap [SIZE\|auto]` | Creates `/swapfile` (auto: 2G below 2 GB of RAM, 4G up to 16 GB, none above) and sets `vm.swappiness=10`. Never resizes an existing swap file. |
| `makit sysctl KEY=VALUE… \| opensearch` | Persists kernel settings in `/etc/sysctl.d/90-makit.conf` and applies them. `opensearch` = `vm.max_map_count=262144`. |
| `makit docker` | Docker Engine + Compose plugin from download.docker.com; caps container logs at 3 × 20 MB (only if `/etc/docker/daemon.json` does not exist yet). |
| `makit volume DEVICE\|auto MOUNTPOINT [--docker] [--format]` | Mounts a block-storage volume (DigitalOcean, Hetzner, GCP, AWS EBS) by UUID with `nofail`. `--docker` keeps Docker's named volumes on it and makes Docker wait for the mount. `--format` creates ext4 only on an empty device, after asking. |
| `makit firewall [PORT/PROTO…]` | ufw: deny incoming except the given ports (default 22/tcp 80/tcp 443/tcp 443/udp) **plus every port sshd listens on**. Existing rules are kept. |
| `makit updates` | Unattended security upgrades (reboots stay manual). |
| `makit ssh` | Disables SSH password login, root keeps key login. **Skipped if root has no authorized key.** |
| `makit status` | Read-only summary: RAM, swap, disks, Docker, firewall, SSH, kernel settings, pending reboot. |
| `makit self-update [vX.Y.Z]` | Installs another release (default: latest). |

Global options: `--dry-run` (change nothing), `--yes` (confirm prompts, e.g. `--format` without a terminal).

### Example: a Docker host with OpenSearch and a DigitalOcean volume

```bash
makit init --sysctl opensearch --volume auto --mount /mnt/data --docker-volumes --format
```

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

Pin a version (never `main`) and, if you like, check the release tarball:

```bash
curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/v0.1.0/install.sh -o install.sh
less install.sh
MAKIT_SHA256=<sha256 from the release notes> bash install.sh
```

The installer puts each version in `/opt/makit/<version>`, points `/opt/makit/current` at it and links
`/usr/local/bin/makit`.

## Requirements

Ubuntu 20.04+ or Debian 11+ (or derivatives), amd64 or arm64, run as root.

## Development

```bash
tests/smoke.sh      # runs makit in throwaway ubuntu:24.04 and debian:12 containers
docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:stable -x -s bash bin/makit lib/common.sh lib/cmd/*.sh install.sh
```

Each command is one file in `lib/cmd/` defining `cmd_<name>`; `bin/makit` dispatches to it.

## Roadmap

- `makit top`: a built-in terminal dashboard (CPU, memory, disks, containers, services, logs) — no htop needed.
- Monitoring: a small agent and ready-made images for metrics, logs and alerts.
