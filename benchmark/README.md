# makit benchmarks

makit shield sits in front of every request, so what it costs must be measured, published and reproducible. This
directory is how: one command, Docker as the only requirement, a report you can compare with ours.

```bash
git clone https://github.com/material-atomic/makit && cd makit
benchmark/run.sh               # micro + http, about 4 minutes
benchmark/run.sh micro         # only the Go benchmarks
benchmark/run.sh http -c 64 -d 30s --list 5000000
```

On GitHub: the `benchmark` workflow runs the same on a Linux runner and attaches the report (Actions → benchmark →
Run workflow).

The report is written to `results/<date>-<arch>-<cpus>cpu.md`. Run it on the kind of server you deploy to and send
a pull request with that file: [`results/`](results/) collects them.

## What is measured

**Decision cost** (`micro`) — Go benchmarks of each step the gate takes, with a production-like policy: a
1,000,000-entry block list, 100 bans, the catalog's HTTP rules, the attack scoring set, the bot catalog with Googlebot's
ranges, the bot score, and 100,000 distinct visitors so per-IP state is realistic.

| Benchmark | What it is |
| --- | --- |
| `Decide/browser` | a normal page view from a browser: every check runs and lets it through (the common case) |
| `Decide/browser-via-cloudflare` | same, client IP taken from `CF-Connecting-IP` of a trusted proxy |
| `Decide/listed-ip-1M` | a visitor in the 1M-entry list: blocked by the set lookup |
| `Decide/attack-xss`, `probe-dotenv` | an attack found by scoring, a probe caught by a rule |
| `Decide/googlebot-verified` | the real Googlebot (published ranges): let through without rules or scores |
| `Decide/undeclared-bot` | a script pretending to be Chrome: caught by the bot score |
| `DecideParallel` | `Decide/browser` on every core at once |
| `CheckEndpoint` | one Caddy `forward_auth` / nginx `auth_request` call, including writing the request snapshot |
| `ClientIPChain` | the visitor read from a 3-hop `X-Forwarded-For` (Cloudflare → load balancer), right to left |
| `DecideCluster/single`, `/cluster` | the same decisions alone and as a replica sharing limits and scores |
| `LimiterShared/single`, `/cluster` | one rate-limit count, alone and keeping the delta for the other replicas |
| `MetricsObserve` | counting one decision for `/metrics`, on 8 cores at once |
| `ClusterBanPropagation` | a ban on one of 3 replicas until the 2 others enforce it (ms/ban, worst) |
| `MatchMillion`, `BotIPIndex1M` | one lookup in a 1M-entry IP set (block list, bot IP index) |

**Request latency** (`http`) — real HTTP through containers ([compose.yaml](compose.yaml)):

```
load ──► app                                  baseline
load ──► makit (edge) ──► app                 makit in front
load ──► Caddy ──► app                        baseline for ask mode
load ──► Caddy ──forward_auth──► makit
           └──► app                           ask mode
load ──► Envoy ──► app                        baseline for a gateway
load ──► Envoy ──ext_authz──► makit
           └──► app                           what Envoy Gateway and Istio do
```

The app is Caddy answering a fixed page, so only the proxy path is measured. makit runs in `block` mode with
everything on, and writes a snapshot of every request to disk. The load generator ([load/](load/), plain Go, no
dependencies) keeps fixed keep-alive connections, records the latency of every request (no sampling) and sends
browser-like headers with visitor IPs spread over 100,000 addresses. The attack runs send XSS, secret probes, SQL
injection, Log4Shell and path traversal: makit answers them itself (403) and bans the senders.

## What the numbers have already caught

The benchmarks are not decoration: the first runs found three problems, fixed before release.

| Found | Before | After |
| --- | --- | --- |
| Go's regexp has no DFA: case-insensitive alternations cost ~30 µs on every User-Agent | 148 µs per browser request | 9 µs (literal prefilters, per-User-Agent memo, fields decoded once) |
| Every automatic ban rewrote `state.json` inside the request | O(n²) disk writes under a botnet | bans active in memory at once, saved once a second in one batch |
| The edge proxy kept 2 idle connections to the upstream | 1,664 req/s, p99 142 ms, 502 errors | 25,000–30,000 req/s, +0.6–0.8 ms p50, no errors |

## Reading the results

- Compare runs within one report: "added" is makit's cost on the same path. Absolute numbers depend on the machine.
- Docker Desktop (macOS, Windows) runs containers in a VM and routes every hop through its network: latencies are
  higher than on a Linux server. Publish Linux results from real servers when you can.
- Latency percentiles matter more than requests per second: p99 is what your slowest visitors feel.
- Tail latencies on Docker Desktop vary between runs (in our runs, ask mode's added p99 ranged from 2 to 14 ms):
  run twice, and trust Linux servers over laptops.
