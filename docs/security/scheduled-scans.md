# Scheduled scans

A scan you run once tells you about today. A daily scan with an alert tells you within a day.

```bash
makit schedule scan daily --webhook https://hooks.slack.com/services/…   # asks for consent once
makit schedule scan weekly --all-containers
makit schedule status
makit schedule scan off
```

- A systemd timer runs `makit scan --consent --json` (host, plus containers with `--all-containers`).
- Reports are kept in `/var/log/makit/scans/` (last 30).
- When the worst finding is **medium or worse**, makit posts a short summary to the webhook (Slack, Discord, or any
  URL accepting JSON `{"text": …}`) and writes it to the journal (`journalctl -t makit-scan`).
- Consent: `makit schedule scan` asks you to type `yes` once and records who agreed and when in
  `/etc/makit/scan-consent`. Scheduled runs refuse to start without it. `makit schedule scan off` removes both.
- Before each run, `makit rules update` refreshes the catalog (skipped quietly when offline).
