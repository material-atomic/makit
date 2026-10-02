# Cloud and code accounts

Whoever owns your cloud or GitHub account owns every server, no exploit needed.

- **2FA everywhere** (hardware key or authenticator app, not SMS): cloud provider, registrar/DNS, GitHub, container
  registry, email of the admins.
- **Scoped tokens**: API tokens with the smallest scope and an expiry; one per purpose; revoke when unused.
- **Separate accounts** per person (no shared login), removed on departure.
- **Billing and activity alerts** (new droplets, firewall changes, unusual traffic) to more than one person.
- **Registry**: private images, pull tokens read-only on servers.
- **DNS**: lock the domain at the registrar (transfer lock) — a hijacked domain gets valid TLS certificates.
