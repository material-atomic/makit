# Security policy

makit runs as root on servers and sits in front of web traffic, so security reports get priority.

## Reporting a vulnerability

Email **security@makit.sh** — please do not open a public issue. Include what you found, the makit version
(`makit version`), and how to reproduce it. English or Vietnamese is fine.

- We answer within 3 working days, and keep you informed until it is fixed.
- A fix is released as a new version; the release notes credit you unless you prefer otherwise.
- Please give us reasonable time (up to 90 days) to release a fix before publishing details.

## In scope

- The makit CLI and `makit-core` (scan, shield, notify, top), the installer (`install.sh`, `https://makit.sh/install.sh`)
  and the security catalog in `security/`.
- Ways to bypass the shield (rules, scoring, bot verification, allow/ban logic), lock-outs, privilege or file-permission
  problems, and anything that makes `makit scan` change, delete or upload data.

Wrong or missing detections in the catalog (a missed malware hash, a false positive in a scoring signal) are welcome
as regular issues or pull requests.

## Supported versions

The latest release. Upgrade with `makit upgrade`.
