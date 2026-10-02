# makit security catalog

Everything `makit scan` knows about threats lives here as data, not code: the built-in checks' severities, detection
rules (indicators, patterns, ports) and vulnerabilities. Adding a rule or an advisory never needs a new makit binary.

```
security/
  index.yaml        catalog name, source and schema version
  rules/
    builtin.yaml    severity / on-off of the checks implemented in makit-core (MK-PROC-…, MK-FILE-…, …)
    *.yaml          detection rules
  vulns/
    *.json          vulnerabilities in OSV format
```

## Sources

`makit scan` reads catalogs in this order; a later source replaces entries with the same id:

1. `/opt/makit/<version>/security` — this directory, shipped with the installed makit.
2. `/var/lib/makit/security` — the newest catalog from this repository: `makit rules update [branch|tag]`
   (downloaded, loaded once to validate, then swapped in; a broken or too-new catalog never replaces a working one).
3. `makit scan --rules DIR` — your own catalogs (same layout).

`makit rules list` shows what is in use; `makit rules path` the directories.

## Rules (`rules/*.yaml`)

```yaml
id: MK-R2S                       # unique; a later source with the same id replaces this rule
title: React2Shell (CVE-2025-55182) backdoor and dropper
severity: critical               # optional: severity of every finding of this rule
refs: [CVE-2025-55182]           # vulnerability ids / aliases this rule relates to
sources: [https://…]             # where the indicators come from
indicators:                      # exact matches
  sha256:  [{ value: 0f0f…, note: … }]   # any executable or running process image
  ips:     [{ value: 45.76.155.14, note: … }]   # established/connecting TCP sockets
  strings: [{ value: 45.76.155.14, note: … }]   # command lines, scripts, start-up entries
  paths:   [{ value: /tmp/vim, note: … }]       # files and process executables
patterns:                        # RE2 regular expressions applied to scripts and start-up entries
  - { id: nohup-tmp, regex: '(?i)nohup\s+/(tmp|var/tmp|dev/shm)/' }
min_matches: 2                   # patterns needed in an ordinary file (1 in start-up entries)
ports:                           # remote TCP ports worth a finding
  - { value: 14444, note: monero mining }
```

## Built-in checks (`rules/builtin.yaml`)

The logic (deleted executables, kernel-thread disguise, hidden executables, …) is in makit-core; this file sets each
check's `severity` (`info`, `low`, `medium`, `high`, `critical`), its `title`, or `disabled: true`.

## Vulnerabilities (`vulns/*.json`)

[OSV format](https://ossf.github.io/osv-schema/) — the format of osv.dev and the GitHub Advisory Database — so an
advisory can be copied in unchanged. makit uses `id`, `aliases`, `summary`, `references`, `database_specific.severity`
and `affected[].package` + `versions` / `ranges` (`SEMVER` with `introduced`, `fixed`, `last_affected`).

Installed packages are checked for the ecosystems makit inventories today: **npm** (`node_modules`, including pnpm's
`.pnpm` store) in common app directories, a container's working directory and `--path` directories.

## Contributing

1. Add or edit a file; keep ids stable (`MK-…` for makit rules, the CVE/GHSA id for vulnerabilities).
2. `scripts/build.sh` runs the Go tests, which load this catalog (`TestCatalogLoadsRepository`) and scan a fake
   compromised filesystem (`TestScanFixture`).
3. `tests/scan-e2e.sh` replays a compromise in Docker and checks every expected finding.
4. Bump `schema` in `index.yaml` only for breaking format changes (older makit versions then refuse the catalog and
   ask for `makit upgrade`).
