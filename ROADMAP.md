# Roadmap

Where makit is going next. There are no dates: a version ships when it is done and tested. Plans change with what
people need, so if something here matters to you — or is missing — say so in an
[issue](https://github.com/material-atomic/makit/issues) or write to hello@makit.sh.

## Next — v0.8: more edges, and what runs in the cluster

v0.6 put the shield in front of clusters and v0.7 made it read any infrastructure in front; v0.8 takes its bans to
more edges and looks inside what runs there.

- **Push bans to more edges.** Cloudflare Lists and Google Cloud Armor, after AWS WAF.
- **More load balancer logs.** Google Cloud and Azure load balancers next to AWS ALB.
- **Scan what runs in the cluster.** `makit scan` for pods and images: the container checks it already runs on
  Docker hosts.
- **More vulnerability sources** for the catalog: osv.dev and GitHub advisories next to the makit repository.
- **More package ecosystems** for `makit scan`: dpkg, pip and Go binaries next to npm.
- **A Scan tab in `makit top`**: findings of the last scan, re-run from the dashboard.
- **Monitoring**: a small agent and ready-made images for metrics, logs and alerts.

## Later

- **Contour asks makit** over gRPC ext_authz: a gRPC endpoint next to `/check`.
- **End-to-end on EKS**: the kind tests repeated on a real AWS cluster behind an ALB and an NLB, in CI.

## Not planned

- Replacing your cloud load balancer or its WAF — makit works with them, not instead of them.
- Hardening managed Kubernetes nodes (EKS on Amazon Linux or Bottlerocket): `makit init` and the host checks stay
  for Ubuntu and Debian servers you run yourself.
- Favouring any crawler or vendor in the bot catalog: every policy stays yours.

## Shipped

- **v0.7.0** — the shield behind any CDN or load balancer: the visitor read from `X-Forwarded-For` (or `Forwarded`)
  walked back through `trusted_proxies`, never from a provider's header such as `CF-Connecting-IP` that a client
  could send past a load balancer; ask mode needs no header of makit's. Exploits carried in headers stopped by
  catalog rules named by CVE (Next.js middleware bypass, Spring Cloud Function, Struts, F5, Fortinet, Rails, Symfony;
  Shellshock scored); a fake crawler can no longer dodge the spoofed policy by making its reverse DNS fail; upgrades
  restart the gate on the new version. Checked end to end behind terrarium's Cloudflare and load balancer stand-ins.
- **v0.6.0** — the shield for clusters behind cloud load balancers: the client IP read from the right of
  `X-Forwarded-For` and from PROXY protocol, a signed container image and Helm chart, Envoy Gateway / Istio / Envoy /
  Traefik / ingress-nginx asking makit, replicas sharing bans, rate limits and scores (a ban reaches every pod in
  ~2 ms; `limit 60/1m` holds for the cluster), Prometheus metrics, bans pushed to AWS WAF, ALB log analysis,
  `makit shield config check --replay`, and the config playground on makit.sh.
- **v0.5.0** — the request shield (own IP set, rules, scoring, bots and AI agents, sites, batch reports, log
  analysis), notifications, the Shield tab in `makit top`, reproducible benchmarks.
  See the [changelog](https://github.com/material-atomic/makit/blob/main/CHANGELOG.md) for every release.
