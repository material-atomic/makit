# Roadmap

Where makit is going next. There are no dates: a version ships when it is done and tested. Plans change with what
people need, so if something here matters to you — or is missing — say so in an
[issue](https://github.com/material-atomic/makit/issues) or write to hello@makit.sh.

## Next — v0.6: clusters, cloud load balancers and a config playground

makit started on single servers. v0.6 brings the request shield to clusters behind a cloud load balancer
(AWS ALB/NLB first), where the load balancer keeps TLS and makit decides on every request behind it — and makes
its configuration easier to write, with a playground on makit.sh. A cluster must not be easier to get through than
one server: every limit, score and ban holds across all replicas, and every claim below ships with its benchmark
and an end-to-end test on a real cluster.

### The real client IP

- **`X-Forwarded-For` read from the right.** Skip the addresses of your trusted proxies and take the first one that
  is not, so a client cannot choose its own IP by sending the header itself. (`CF-Connecting-IP` holds a single
  address and is not affected.) Presets for `trusted_proxies`: `aws-alb` / `vpc` alongside `cloudflare`.
- **PROXY protocol v1 and v2 in.** The edge listener reads the PROXY header an AWS NLB (or HAProxy) sends, only from
  addresses you trust, so makit sees the client behind a TCP load balancer without TLS ending there.

### Running in a cluster

- **makit in Kubernetes.** An official container image of `makit-core` — signed (cosign) with an SBOM, checked the
  same way the installer checks release binaries — a Helm chart and plain manifests, health and readiness checks,
  configuration from a ConfigMap, reloaded without a restart and kept on the last good version when a new one fails.
- **Ingress and gateways ask makit.** Ready-made setups for Envoy `ext_authz` (Envoy Gateway, Istio, Contour —
  the Gateway API path Kubernetes recommends now that ingress-nginx is retired), Traefik `forwardAuth` and, for
  clusters that still run it, ingress-nginx `auth-url`: the same ask mode Caddy and nginx use today.
- **One shield across every replica.** Bans, allowlists and bot sources are shared, so an IP banned by one pod is
  banned by all — and so are rate limits and request scores: behind N replicas, `limit 60/1m` stays 60 a minute, not
  60×N, and a scan spread across pods escalates as if it hit one. Replicas exchange counts in the background; a
  decision still never waits on the network.
- **Metrics.** A Prometheus `/metrics` endpoint: decisions by rule and action, decision latency, bans, how far each
  replica's shared counts lag behind the others.

### At the load balancer

- **Push bans to AWS WAF.** makit's bans synced to an AWS WAF IP set, so bad traffic stops at the load balancer
  without reaching the cluster; the allowlist always wins there too.
- **Load balancer logs.** `makit shield analyze` for AWS ALB access logs, scored with the same policy — try makit on
  real traffic before it sits in front of any.
- **Guide: behind a cloud load balancer.** How to keep the real client IP (ALB headers, NLB proxy protocol or IP
  targets), which ranges to trust, how replicas share state, and why the kernel layer stays off there.

### Configuration you can trust

- **Config playground on makit.sh.** Build `shield.yaml` and `notify.yaml` in the browser instead of from a blank
  file: start from a preset (single site, many domains, behind Cloudflare, behind a load balancer), add blocks —
  sites, allowlists, rules, scoring levels, bot policies, rate limits, notification channels — and see the
  resulting YAML as you go. Checked against the same schema makit uses, then exported as a file to copy to
  `/etc/makit/` or as a Kubernetes ConfigMap. Nothing leaves your browser; secrets such as webhook URLs stay
  placeholders unless you type them.
- **`makit shield config check`.** Validates a config file on the server before it is loaded, with the same
  messages as the playground, so a pasted file never takes the shield down.
- **`makit shield config check --replay LOG`.** Runs a new config against a real access log next to the current one
  and lists what changes: which requests would now be blocked, limited or let through, and by which rule — a false
  positive found before it reaches a visitor.

### Proof

- Benchmarks for the cluster paths, in `benchmark/` like the rest: the cost of an ingress asking makit, decision
  latency with shared counters, and how long a ban takes to reach every replica — with the machine, inputs and
  method stated, and the results shown as terminal recordings in the README and on makit.sh.
- End-to-end tests on a real cluster (kind in CI, then EKS behind an ALB and an NLB): forged `X-Forwarded-For`,
  a scan spread across replicas, a ban from one pod enforced by all.

## Later

- **Push bans to more edges.** Cloudflare Lists and Google Cloud Armor, after AWS WAF.
- **More load balancer logs.** Google Cloud and Azure load balancers next to AWS ALB.
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
