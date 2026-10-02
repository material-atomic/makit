# Roadmap

Where makit is going next. There are no dates: a version ships when it is done and tested. Plans change with what
people need, so if something here matters to you — or is missing — say so in an
[issue](https://github.com/material-atomic/makit/issues) or write to hello@makit.sh.

## Now — v0.5.x

Fixes and small additions on top of v0.5.0.

- **Client IP behind load balancers.** Read `X-Forwarded-For` from the right: skip the addresses of your trusted
  proxies and take the first one that is not, so a client cannot choose its own IP by sending the header itself.
  (`CF-Connecting-IP` holds a single address and is not affected.)
- **Presets for `trusted_proxies`**: `aws-alb` / `vpc` alongside `cloudflare`, so the right ranges are one word away.

## Next — v0.6: clusters, cloud load balancers and a config playground

makit started on single servers. v0.6 brings the request shield to clusters behind a cloud load balancer
(AWS ALB/NLB first), where the load balancer keeps TLS and makit decides on every request behind it — and makes
its configuration easier to write, with a playground on makit.sh.

- **makit in Kubernetes.** An official container image of `makit-core`, a Helm chart and plain manifests,
  health and readiness checks, configuration from a ConfigMap.
- **Ingress controllers ask makit.** Ready-made setups for ingress-nginx (`auth-url`) and Traefik (`forwardAuth`),
  the same ask mode Caddy and nginx use today.
- **One ban list for every replica.** Bans, allowlists and bot sources shared between makit instances, so an IP
  banned by one pod is banned by all.
- **Guide: behind a cloud load balancer.** How to keep the real client IP (ALB headers, NLB proxy protocol or IP
  targets), which ranges to trust, and why the kernel layer stays off there.
- **Config playground on makit.sh.** Build `shield.yaml` and `notify.yaml` in the browser instead of from a blank
  file: start from a preset (single site, many domains, behind Cloudflare, behind a load balancer), add blocks —
  sites, allowlists, rules, scoring levels, bot policies, rate limits, notification channels — and see the
  resulting YAML as you go. Checked against the same schema makit uses, then exported as a file to copy to
  `/etc/makit/` or as a Kubernetes ConfigMap. Nothing leaves your browser; secrets such as webhook URLs stay
  placeholders unless you type them.
- **`makit shield config check`.** Validates a config file on the server before it is loaded, with the same
  messages as the playground, so a pasted file never takes the shield down.

## Later

- **Push bans to the edge.** Sync makit's bans to AWS WAF IP sets, so bad traffic stops at the load balancer
  without reaching the cluster; then Cloudflare Lists and Google Cloud Armor.
- **Load balancer logs.** `makit shield analyze` for AWS ALB access logs, scored with the same policy.
- **Scan what runs in the cluster.** `makit scan` for pods and images: the container checks it already runs on
  Docker hosts.
- **More vulnerability sources** for the catalog: osv.dev and GitHub advisories next to the makit repository.
- **More package ecosystems** for `makit scan`: dpkg, pip and Go binaries next to npm.
- **A Scan tab in `makit top`**: findings of the last scan, re-run from the dashboard.
- **Monitoring**: a small agent and ready-made images for metrics, logs and alerts.

## Not planned

- Replacing your cloud load balancer or its WAF — makit works with them, not instead of them.
- Hardening managed Kubernetes nodes (EKS on Amazon Linux or Bottlerocket): `makit init` and the host checks stay
  for Ubuntu and Debian servers you run yourself.
- Favouring any crawler or vendor in the bot catalog: every policy stays yours.

## Shipped

- **v0.5.0** — the request shield (own IP set, rules, scoring, bots and AI agents, sites, batch reports, log
  analysis), notifications, the Shield tab in `makit top`, reproducible benchmarks.
  See the [changelog](https://github.com/material-atomic/makit/blob/main/CHANGELOG.md) for every release.
