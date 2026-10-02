# Changelog

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
