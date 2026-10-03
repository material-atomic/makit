# Kubernetes and cloud load balancers

On one server, makit sits in front of Caddy or nginx. In a cluster, the cloud load balancer keeps TLS and spreads
requests over a gateway (Envoy Gateway, Istio, Traefik, ingress-nginx); makit runs as a small Deployment that the
gateway asks before every request, and its replicas share what they learn.

```
visitor → AWS ALB / NLB → gateway pods ──ask /check──→ makit-shield (2+ replicas, sharing bans, limits, scores)
                                  └──────────────────→ your app (only if makit said yes)
```

## Install

```bash
helm install shield oci://ghcr.io/material-atomic/charts/makit-shield -n makit --create-namespace
# or from a checkout:   helm install shield deploy/helm/makit-shield -n makit --create-namespace
# or without Helm:      deploy/kubernetes/makit-shield.yaml (see its first lines)
```

The chart runs two replicas of `ghcr.io/material-atomic/makit-shield` (20 MB, distroless, non-root, read-only root
filesystem, no capabilities), a Service for `/check` and `/metrics`, a headless Service the replicas find each other
through, a shared secret for them (generated once and kept), a PodDisruptionBudget and a NetworkPolicy that lets only
makit pods reach the cluster port. `shield.yaml` is `config:` in the values; it starts in `observe` mode.

Verify the image before you run it — every release is signed in GitHub Actions, without a long-lived key:

```bash
cosign verify ghcr.io/material-atomic/makit-shield:0.6.0 \
  --certificate-identity-regexp '^https://github.com/material-atomic/makit/.github/workflows/image.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
docker buildx imagetools inspect ghcr.io/material-atomic/makit-shield:0.6.0 --format '{{ json .SBOM }}'   # the SBOM
```

## Make the gateway ask

```bash
makit shield snippet envoy-gateway --service shield-makit-shield --namespace makit --gateway eg --gateway-namespace default
makit shield snippet istio | traefik | ingress-nginx | envoy
```

Each snippet passes on every header makit reads — Envoy-based gateways send only a handful unless told — and fails
open, so a makit outage never takes the site down. See [the shield guide](shield.md#gateways-in-kubernetes-ask-makit).

## The visitor's IP

The load balancer and the gateway each add the address they saw to `X-Forwarded-For`. makit reads it **from the
right**, skipping your trusted proxies, so the visitor's own `X-Forwarded-For` is never believed:

```yaml
config:
  trusted_proxies: [vpc]        # or the subnets of the load balancer and the gateway pods: [10.0.0.0/16]
```

| In front | What reaches the gateway | What to set |
| --- | --- | --- |
| AWS ALB | `X-Forwarded-For: …, <visitor>` from the ALB's private address | `trusted_proxies: [aws-alb]` or the ALB subnets |
| AWS NLB, IP targets | the visitor's own address (client IP preservation) | nothing |
| AWS NLB, instance targets / PROXY protocol | a PROXY v2 header | let the gateway read it (Envoy Gateway `ClientTrafficPolicy` `proxyProtocol`), or, with makit at the edge, `accept_proxy_protocol: true` |
| Cloudflare → ALB | `X-Forwarded-For: …, <visitor>, <Cloudflare>` from the ALB | `trusted_proxies: [cloudflare, aws-alb]` |

Trust only what can reach makit: anything in `trusted_proxies` may name its own client. Narrow `vpc` to the load
balancer's and gateway's subnets when other workloads share the VPC. [More on the walk from the right.](shield.md#the-visitors-address-behind-a-cdn-a-load-balancer-or-both)

## Replicas share one shield

Requests from one visitor land on any replica. The chart turns on `cluster:`: replicas send each other their bans,
allow entries, rate-limit counts and scores four times a second, so an IP banned by one pod is banned by all, `limit 60/1m`
holds for the whole cluster, and a scan spread over pods escalates as on one — while every decision is still made
from local memory, never waiting on the network. Messages are signed with the shared secret; forged and replayed ones
are refused. [How it works and what it costs.](shield.md#several-replicas-behind-one-load-balancer)

Measured on a kind cluster with 3 replicas (`tests/k8s-e2e.sh`): a ban made with the CLI on one pod and an automatic
ban from a probe on another are enforced by all three within seconds; with `limit 10/1m` and 30 requests spread over
the 3 replicas, 11 got through with `cluster:` on (`sync: 1s`) and 27 with it off.

## Stop bans at the load balancer: AWS WAF

With `aws_waf:`, makit keeps an AWS WAF IP set equal to its live bans; a rule in the web ACL on the ALB (or CloudFront)
blocks those addresses before they reach the cluster at all — no gateway hop, no pod, no `/check`.

```yaml
config:
  aws_waf:
    region: us-east-2
    scope: REGIONAL                  # ALB, API Gateway; CLOUDFRONT for CloudFront (us-east-1)
    ipv4: { name: makit-bans-v4, id: 1a2b3c4d-… }
    ipv6: { name: makit-bans-v6, id: 5e6f7a8b-… }   # optional
    every: 30s
```

1. Create the IP sets (`aws wafv2 create-ip-set --name makit-bans-v4 --scope REGIONAL --ip-address-version IPV4
   --addresses []`, and the same with `IPV6`) and a **block** rule in your web ACL that references them — after any
   rule that allows your own traffic.
2. Give the makit pods `wafv2:GetIPSet` and `wafv2:UpdateIPSet` on those two IP sets only (EKS Pod Identity or IRSA on
   the chart's ServiceAccount; any credential the AWS SDK finds works).
3. `makit shield waf sync --dry-run` shows what would change; the gate then syncs every 30 seconds.

makit writes only those IP sets and only when they differ; one replica writes (the cluster agrees which). Never
pushed: a range that overlaps an allow entry or a trusted proxy — at the edge that would block every visitor behind
it — bans for one site only (a web ACL covers every site), and ranges wider than /8 (IPv4) or /32 (IPv6). An IP set
holds at most 10,000 addresses: beyond that the newest bans win, and `waf sync` says how many were left out. Expired
bans leave the IP set at the next sync. `/metrics` has the addresses in each set and the failed syncs.

## Config changes

Edit `config:` and `helm upgrade`: the pods load the new `shield.yaml` without a restart, as soon as the kubelet
updates the ConfigMap (up to about a minute). A file that does not load is not applied — the pods keep the previous
policy and log why — and `makit shield config check` (or the playground on makit.sh) tells you before. Changing
`cluster:` restarts the pods.

```bash
kubectl -n makit exec deploy/shield-makit-shield -- makit-core shield config check
kubectl -n makit exec deploy/shield-makit-shield -- makit-core shield status
kubectl -n makit exec deploy/shield-makit-shield -- makit-core shield ban 203.0.113.7 --for 24h   # reaches every replica
```

## Watching it

`/metrics` on port 9180 (Prometheus; `serviceMonitor.enabled: true` with the Prometheus Operator): decisions by verdict
and rule, decision latency, bans, peers and how far each is behind. `/readyz` keeps a pod out of rotation until its
policy is loaded. Batch reports go through `makit notify` — put your `notify.yaml` in a Secret and set
`notify.existingSecret`.

## What stays off in a cluster

- **The kernel layer** (`kernel_block`): behind a load balancer the node's kernel only ever sees the load balancer's
  addresses, never a visitor's. `makit shield config check` warns when it is on with private trusted proxies.
- **Host hardening** (`makit init`, `makit scan` of the host): managed nodes (EKS on Amazon Linux or Bottlerocket) are
  the provider's to harden. Scanning pods and images is on the [roadmap](../../ROADMAP.md).
