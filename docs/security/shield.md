# Request shield

`makit shield` decides, for every request, whether the visitor may reach your app: its own **block set** (IPs and
CIDRs, with expiry — no ipset needed), an **allowlist** that always wins, and **HTTP rules** that ban scanners and
exploit attempts automatically. Every decision is recorded as a request snapshot.

## Two ways to use it

**1. Caddy/nginx ask makit (recommended).** Your proxy keeps TLS and HTTP/3 and calls makit before each request.

```bash
makit shield on                    # or: makit shield on --observe  (log what would be blocked, block nothing)
makit shield snippet caddy         # or nginx — paste it, reload the proxy
```

Caddy (`import makit_shield` in each site):

```
(makit_shield) {
	forward_auth 127.0.0.1:9180 {
		uri /check
		header_up X-Makit-Peer {remote_host}
		header_up X-Makit-Client {http.request.header.CF-Connecting-IP}
		copy_headers X-Makit-Client
	}
}
```

Caddy in Docker cannot reach the host's 127.0.0.1: set `admin: 172.17.0.1:9180` (the host's bridge address) in
`/etc/makit/shield.yaml` and use that address in the snippet (`makit shield snippet caddy --addr 172.17.0.1:9180`).
`/check` only answers callers on loopback or private networks.

**2. makit in front of Caddy/nginx.** makit owns ports 80/443, terminates TLS (Let's Encrypt via TLS-ALPN, a
Cloudflare Origin Certificate, or your files) and forwards allowed requests to the service on localhost. Blocked direct
visitors are disconnected right after the TCP handshake. Configure `listeners` in `/etc/makit/shield.yaml`
(`makit shield edit`); move Caddy/nginx to `127.0.0.1:8080`. HTTP/3 is not offered in this mode.

`tcp://` upstreams pass any TCP service through after the IP check (with a PROXY v1 header when
`proxy_protocol: true`).

### Gateways in Kubernetes ask makit

The same ask mode works for the gateway in front of a cluster. `makit shield snippet` prints a ready setup:

| Gateway | Command | How it asks |
| --- | --- | --- |
| Envoy Gateway (Gateway API) | `makit shield snippet envoy-gateway --gateway NAME --gateway-namespace NS` | `SecurityPolicy` `extAuth.http` + a `ReferenceGrant` |
| Istio | `makit shield snippet istio` | `envoyExtAuthzHttp` provider + `AuthorizationPolicy` `CUSTOM` |
| Envoy | `makit shield snippet envoy` | the `ext_authz` HTTP filter |
| Traefik | `makit shield snippet traefik` | `forwardAuth` middleware |
| ingress-nginx | `makit shield snippet ingress-nginx` | `auth-url` annotation (`?deny=403`: nginx passes only 401/403 on) |

Envoy-based gateways send the auth service only a few headers unless told otherwise; the snippets list every header
makit reads (`X-Forwarded-For`, `User-Agent`, `Accept-*`, `Sec-Fetch-Mode`, `Sec-CH-UA`, `Next-Action`, the Web Bot
Auth signature headers, Cloudflare's) — without them a real browser would score like a script. Envoy asks on
`/check/<original path>`; ingress-nginx sends the original URL in `X-Original-URL`; both are read as the visitor's
request. The snippets fail open (`failOpen: true`, `failure_mode_allow`): if makit is unreachable, traffic goes on
rather than the site going down — run two or more replicas with `/readyz`. ingress-nginx is retired upstream (no fixes
after March 2026): prefer Envoy Gateway. Contour asks over gRPC only, which makit does not speak yet.

In Kubernetes the admin address listens on the pod's address (`admin: 0.0.0.0:9180`); `/check`, `/status` and
`/metrics` still answer only callers on private networks.

## Behind Cloudflare

Behind Cloudflare every connection comes from a Cloudflare IP; the visitor's IP is in the `CF-Connecting-IP` header.
makit uses that header **only when the connection really comes from Cloudflare** (`trusted_proxies: [cloudflare]`,
ranges refreshed daily from cloudflare.com/ips). A direct visitor sending a fake header is judged on its own IP.

Also lock the origin so it only accepts web traffic from Cloudflare (provider firewall, or `ufw allow from <range>`),
otherwise attackers can skip Cloudflare by hitting the server IP.

## Behind a load balancer or other proxies

A load balancer (AWS ALB, HAProxy, a second nginx) passes the visitor in `X-Forwarded-For`, a list every proxy
appends to: `<whatever the visitor sent>, <visitor as the first proxy saw it>, <next proxy>…`. The left part is
written by the visitor, so makit reads the list **from the right**: it skips the addresses of your trusted proxies and
takes the first one that is not. A visitor who sends `X-Forwarded-For: 192.0.2.10` (an allowlisted address, or a
random one to dodge a ban) is still judged on its real address.

```yaml
client_ip_header: X-Forwarded-For
trusted_proxies: [aws-alb]          # or your load balancer's subnets: [10.0.1.0/24, 10.0.2.0/24]
```

| `trusted_proxies` | Trusts |
| --- | --- |
| `cloudflare` | Cloudflare's published ranges, refreshed daily. |
| `aws-alb`, `vpc` | The private ranges a VPC uses (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7). AWS publishes no range for load balancer nodes: they take addresses in your subnets. List those subnets instead when other machines in the VPC can reach makit directly — anything trusted may name its own client. |
| `loopback` | 127.0.0.0/8 and ::1, for a proxy on the same machine. |
| CIDRs | Anything else, e.g. `203.0.113.0/28` for your own proxies. |

Presets and CIDRs combine: `[cloudflare, aws-alb]` reads a chain Cloudflare → ALB → makit correctly. Every line of the
header counts (a visitor cannot hide behind a second `X-Forwarded-For` line), and the walk stops after 16 hops.

A trusted proxy is never banned automatically — a ban on it would block every visitor it carries — and
`makit shield ban` refuses a range that overlaps one (`--force` to insist). When Traefik `forwardAuth` or
ingress-nginx `auth-url` asks makit without an `X-Makit-Peer` header, the asking proxy's own hop is the right-most
`X-Forwarded-For` entry. Measured cost: ~270 ns and no allocation to resolve a three-hop chain against Cloudflare
and the VPC ranges (`go test ./shield -bench ClientIPChain`, Apple M1).

### PROXY protocol (AWS NLB, HAProxy)

A TCP load balancer does not touch HTTP, so there is no header to read: with PROXY protocol it puts the visitor's
address in front of the connection instead. Turn it on for the listener behind it:

```yaml
edge: true
trusted_proxies: [aws-alb]          # the NLB's subnets
listeners:
  - name: web
    listen: ":443"
    upstream: http://127.0.0.1:8080
    accept_proxy_protocol: true     # v1 and v2; enable "Proxy protocol v2" on the NLB target group
    tls: { acme: [example.com] }
```

The header is read **only from trusted proxies**: from anyone else the bytes go on untouched, so a visitor who sends
its own `PROXY TCP4 <address>` line gets a broken request, never a new address. A trusted peer that sends no header
(a TCP health check) and the `LOCAL` command keep the connection's own address; TLVs such as the AWS VPC endpoint id
are skipped. The visitor is checked against bans and lists right after the header, before TLS. Headers are read off
the accept loop with a 5-second limit, so a stalled connection cannot hold up the others; malformed headers are
dropped and counted as `proxy-protocol-error` in `makit shield status`. With an NLB that preserves client IPs (IP
targets, no PROXY protocol), the connection already comes from the visitor and nothing needs to be set.

## Several replicas behind one load balancer

Behind a load balancer, requests from one visitor land on any replica. Each replica alone would count only its share:
a rate limit of 60 a minute would let 60 × N through, and a scan spread over the pods would never escalate. With
`cluster:` the replicas share what they learn:

```yaml
cluster:
  listen: ":9181"                                   # inside the cluster only
  peers: ["dns:makit-shield-headless.makit.svc.cluster.local:9181"]   # or host:port, one per replica
  # secret: MAKIT_CLUSTER_SECRET in the environment (a Kubernetes Secret), or secret_file: /etc/makit/cluster.key
  sync: 1s
```

- **Bans, unbans and allow entries** — automatic ones and those made with `makit shield ban/allow` on any replica —
  reach every replica within about one sync interval (≈0.4 s in tests with `sync: 100ms`).
- **Rate limits** count across replicas: windows are aligned on the clock, and each replica adds the others' counts to
  its own, so `limit 60/1m` stays 60 a minute for the whole cluster, give or take one sync interval of requests.
- **Request scores** add up across replicas (suspicious requests, bursts), so a scan spread over the pods escalates
  and is banned as if it hit one.
- A replica that starts copies the bans and allow entries of a running one first.

**A decision never waits on the network.** Each replica decides from its own memory; changes travel in the background.
Measured: deciding a request costs the same with and without a cluster (6.3–6.6 µs, 18 allocations, on the shared
benchmark — `go test ./shield -bench DecideCluster`, Apple M1). If a peer cannot be reached, list changes wait for it
(up to 200,000) and counts are dropped: they matter only for the current window.

**What an attacker inside the network cannot do.** Every message is signed (HMAC-SHA256 with the shared secret, at
least 32 characters: `openssl rand -hex 32`) over its time and body and carries a sequence number. A forged message,
one older than 30 seconds, or a replayed one is refused and counted — otherwise anyone who reaches port 9181 could
inflate a visitor's count to get it banned, or unban an attacker. Clocks must agree within 30 seconds (NTP; every
cloud provides it). The listen port carries ban lists in clear text: keep it inside the cluster (a NetworkPolicy
allowing only the makit pods).

Peers listed by `dns:` are looked up every 15 seconds, so pods that come and go are followed; a replica finds its own
address in the list and leaves it out. `makit shield status` lists the peers and how far each is behind; `/metrics`
has `makit_shield_cluster_peer_sync_age_seconds` and the refused messages. Changing `cluster:` needs a restart.

## The set and the allowlist

```bash
makit shield ban 198.51.100.7 --for 24h --reason "credential stuffing"
makit shield ban 203.0.113.0/24
makit shield unban 198.51.100.7
makit shield allow 192.0.2.10 --reason office      # never blocked (or `allow:` in shield.yaml)
makit shield list
makit shield check --peer 104.16.1.1 --client 198.51.100.7 --uri /admin    # what would happen?
```

Lists live in `/var/lib/makit/shield/state.json`; the running gate picks up changes within two seconds. makit refuses
to ban your own SSH address or a Cloudflare range (that would block every proxied visitor) unless you add `--force`.

## Rules

HTTP rules come from the catalog (`security/http/*.yaml`), match method, path, user agent and headers, and ban the
client for `ban_for`:

| Rule | Bans |
| --- | --- |
| MK-HTTP-PROBE | Requests for `/.env`, `/.git/`, database dumps, `wp-login.php`, phpMyAdmin… (24h) |
| MK-HTTP-TRAVERSAL | `../` and system-file requests (24h) |
| MK-HTTP-SCANNER | sqlmap, nikto, nuclei, masscan… user agents (24h) |
| MK-HTTP-R2S | Scripted `POST` with a `Next-Action` header — the React2Shell exploitation pattern (7 days) |

A server that hosts WordPress should override MK-HTTP-PROBE (copy it into your own catalog with `disabled: true` or
without the WordPress paths) — see [the catalog](../../security/README.md).

## Scoring

Rules ban on one unmistakable request. Scoring catches the rest: every request gets points from the signals it
matches, and each IP keeps a score over a window. The scoring set is part of the online catalog
([`security/scoring/http.yaml`](../../security/scoring/http.yaml)) and updates with `makit rules update`.

- **Request score** — the sum of the signals that match (each counted once, capped at 200). Values are decoded first
  (URL encoding up to three layers, HTML entities, NUL bytes), so `%253Cscript%253E` is seen as `<script>`.
- **IP score** — the highest request score in the window (10 minutes), plus escalation (+30 for every 5 suspicious
  requests) and bursts (30 client errors, or 600 requests, in the window).
- **Levels and actions** — low ≥30 and medium ≥50 are logged, high ≥80 bans for 1 hour, critical ≥100 bans for 24
  hours. In `observe` mode nothing is banned. Bursts by status (many 4xx) only count where the status is known: in
  log analysis.

Signals cover probes (`.env`, `.git`, cloud keys, backups, admin panels), path traversal, XSS in the URL (script
tags, event handlers, `javascript:`/`data:` URLs, DOM sinks), SQL injection, Log4Shell, command injection, PHP
wrappers, scanner user agents, raw IP hosts, RDP or TLS spoken to an HTTP port, and the React2Shell pattern.

Compared with the `nginx.score.json` it started from: one explicit model (signals add up, IPs keep a window)
instead of mixed per-request and per-IP points; case-insensitive patterns on decoded values instead of raw
substrings; no points for ordinary traffic (status 200, `POST`, `.php` on a PHP site, search words such as "curl");
WordPress and PHP paths sit in profiles you switch on for servers that run them; IP addresses live in shield lists,
not in the scoring file; status codes only count in log analysis and as bursts; the SQL injection pattern catches
quoted forms such as `' or '1'='1`; every signal has a readable label for reports; and XSS, SQL injection,
Log4Shell, React2Shell, command injection, raw IP hosts and request floods were added.

### Changing the scoring on your server

From the smallest change to the largest:

```yaml
# /etc/makit/shield.yaml
scoring:
  profiles: { wordpress: true }        # this server runs WordPress: do not score wp-* paths
  actions: { medium: block, high: "ban 6h" }
  disable: [host-ip-literal]           # signal ids to ignore
  # enabled: false                     # no scoring at all
```

To edit the signals themselves, copy the catalog's file and change your copy:

```bash
makit shield customize scoring        # → /etc/makit/security/scoring/http.yaml
```

Files under `/etc/makit/security` override the bundled and downloaded catalog and are never overwritten by
`makit rules update`; the running gate reloads them within two seconds. `makit shield customize bots` and
`makit shield customize rules` do the same for the bot catalog and the HTTP rules. To keep a scoring file somewhere
else (a git repo of your own, for example), point to it: `scoring: { file: /srv/ops/makit/http-scoring.yaml }`.

## Bots, crawlers and AI agents

Known bots are recognised and verified, and you decide per category or per bot: allow, log, block, ban or rate
limit. Clients that hide what they are get a separate bot score. See [Bots, crawlers and AI agents](bots.md).

## Sites (one server, many domains)

Everything at the top of `shield.yaml` is the **global** policy. Under `sites:`, each domain lists only what differs;
a request is decided by the site its Host matches (`Host` in edge mode, `X-Forwarded-Host` in ask mode, `$host` /
Caddy's host in logs), and by the global policy otherwise.

```yaml
# global
mode: block
bots: { policy: { ai-crawler: block } }
ban_scope: server

sites:
  - name: blogcode
    match: [blogcode.vn, "*.blogcode.vn"]
    ban_scope: site                       # an attacker of this site is banned here only
    allow: [203.0.113.0/24]               # on top of the global allowlist
    rules: { disable: [MK-HTTP-PROBE] }
    scoring: { profiles: { wordpress: true } }
    bots: { policy: { ai-crawler: allow } }   # overrides the global ai-crawler: block
    report: { notify: [blog-telegram] }   # this site's reports go to these channels only
  - match: [shop.example.com]
    mode: observe
```

How a site overrides the global settings:

| Setting | Rule |
| --- | --- |
| `mode`, `ban_scope`, `report.min_level` | the site's value replaces the global one |
| `bots.policy`, `scoring.actions`, `scoring.profiles`, `bots.score.actions` | merged key by key; the site wins where both set a key |
| `rules.disable`, `scoring.disable`, `bots.score.disable` | the site's list replaces the global list |
| `allow` | added to the global allowlist (your office stays allowed everywhere) |

Shared by every site: the IP set and bulk lists, server-wide bans, Cloudflare ranges, bot verification. Per site:
everything above, its own bans (`ban_scope: site`, or `makit shield ban IP --site blogcode`), its allowlist entries
(`makit shield allow IP --site blogcode`), rate limits, and batch reports (saved under `reports/<site>/`, `makit
shield report --site blogcode`). An IP's history (escalation, bursts) is shared across sites, except on sites with
`ban_scope: site`, where what it does there stays there. `makit shield sites` shows what each site changes; `makit
shield check --host blogcode.vn …` shows a decision for one.

## Batch reports and alerts

The gate sums up what it saw every five minutes, without anyone running a command: totals, then one block per
suspicious IP with its level and score, what it did in plain words, sample paths, the statuses it got, and what makit
did about it. Known bots handled by your policy are one line; ordinary visitors are only counted.

```
makit shield · blogcode.vn · 2026-05-21 14:40–14:45 UTC
511 requests · 3 suspicious IPs · 1 banned · blocked 2 · limited 2 · critical 2 · high 1

[CRITICAL 170] 91.238.181.96 · 1 req · blocked 1
   malformed or empty request line · RDP scan on the HTTP port · no User-Agent
   (empty or binary request line) · status 403×1

[CRITICAL 115] 85.204.70.96 · 5 req · banned until 05-22 14:40 UTC (score:critical)
   WordPress probing ×5 · no User-Agent ×5
   /wp1/wp-includes/wlwmanifest.xml, /cms/wp-includes/wlwmanifest.xml, +3 · status 500×5

[HIGH] 203.0.113.50 · 1 req · blocked 1
   fake Googlebot

bots: GPTBot 4 (verified, 2 denied) · Googlebot 1 (fake, 1 denied)

⚠ your app answered 5xx to 5 suspicious requests — unknown paths should return 404, not an error
```

Each report is appended to `/var/log/makit/shield/reports/<date>.txt` (and `.jsonl` for tools), kept 30 days, and
sent through [`makit notify`](notifications.md) when it contains something at `report.min_level` or above, a ban, or
a fake bot — one message per window, never one per request or per ban. `makit shield report [-n 3]` prints the latest.

```yaml
report:
  every: 5m          # 1m or more; "off" for no reports
  min_level: high    # low, medium, high, critical
  keep_days: 30
```

## Analysing logs

The same policy can read the access logs you already have — to see what the gate would do before turning it on, to
look back at an incident, or instead of the gate: `--follow --ban --notify` turns a log into bans and alerts without
anything in the request path.

```bash
makit shield analyze /var/log/nginx/access.log                 # batch reports, nothing changed
makit shield analyze /var/log/caddy/access.log --batch 10m --json
makit shield analyze /var/log/nginx/access.log --follow --ban --notify --quiet
zcat /var/log/nginx/access.log.2.gz | makit shield analyze -
```

nginx's `combined` format works; to know the visitor behind Cloudflare and the site, log two more fields:

```nginx
log_format makit '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent" "$http_cf_connecting_ip" "$host"';
access_log /var/log/nginx/access.log makit;
```

Caddy's JSON access log is read as is, request headers included (cookies and authorization are ignored). Status
codes count in log analysis (many 4xx, the app answering 5xx to probes), and claimed bots are verified by reverse DNS
(`--verify=false` for speed). Without `--ban` nothing is written; with it, bans go to the same list the gate uses.

**AWS Application Load Balancer** access logs are read too — as delivered to S3, one gzipped file per node every five
minutes. Point `analyze` (or `config check --replay`) at a file or at a directory of them:

```bash
aws s3 sync s3://my-alb-logs/AWSLogs/123456789012/elasticloadbalancing/us-east-2/2026/10/03/ ./alb
makit shield analyze ./alb --verify=false            # every .log.gz in name order, i.e. in time
makit shield config check new.yaml --replay ./alb    # what a new config would change, on real traffic
```

The ALB is the edge, so its `client:port` is the visitor (behind CloudFront or Cloudflare it is theirs, and the log
has nothing more: analyse the gateway's log there). The log records the User-Agent and no other header, so
header-based bot signals are not applied to it (nor to nginx's) — a browser is never scored for headers the log
did not keep.

## Checking a config before it is loaded

`makit shield edit` opens a copy of `shield.yaml` and saves it only when nothing in it is wrong; a file you write
yourself, paste from the playground or ship with Ansible can be checked the same way:

```bash
makit shield config check                       # /etc/makit/shield.yaml
makit shield config check new.yaml              # or - for stdin
makit shield config check new.yaml --json       # for CI
```

It reports, with the line:

- **errors** — the gate would refuse the file, or a setting does nothing: YAML syntax, a misspelt key (`trusted_proxy:`
  is ignored by the gate, so the check says so and suggests `trusted_proxies`), a value of the wrong kind, an allow
  entry that is not an IP, two listeners on one port, a wildcard in `acme`, a missing certificate file, a trusted range
  anyone is in (`0.0.0.0/0`), a site without `match`, and anything the rules, scoring set or bot catalog reject (an
  unknown action or level);
- **warnings** — it loads, but probably not as meant: `kernel_block` behind a load balancer, `client_ip_header`
  without trusted proxies, `accept_proxy_protocol` with nothing trusted, an admin address reachable from outside,
  `mode: pass`, a report sent to a `makit notify` channel that does not exist.

Exit status 1 when there is an error. The running gate never loads a file it cannot read (it keeps the previous
policy) and logs the same warnings when it reloads one.

### What would a new config block? `--replay`

```bash
makit shield config check new.yaml --replay /var/log/nginx/access.log
```

runs every request of a real access log through the current config and the new one and lists what changes:
requests and clients that go from allowed to blocked or limited and back, the rules responsible, and examples. Both
are enforced for the comparison (observe mode reads as block), bans are kept in memory and last in log time, bots are
checked against the downloaded ranges without DNS — nothing is written, banned or sent. A newly stopped request from a
browser that the app answered with 2xx or 3xx is flagged as a **likely false positive**: look at those before loading
the file. `--against FILE` compares with another config than `/etc/makit/shield.yaml`; `--format nginx|caddy` when the
log is not recognised.

## Snapshots

Each decision is a JSON line in `/var/log/makit/shield/requests.jsonl` (rotated): time, client IP, peer, proxy,
verdict, rule, method, host, URI, user agent, referer, Cloudflare country and ray, status, duration. Bodies, cookies
and authorization headers are never recorded.

```bash
makit shield log -n 100
makit shield log --blocked
makit shield status          # live counters: mode, switches, list sizes, requests by verdict (--json for tools)
```

## Metrics and health

The admin address (`admin:`, `127.0.0.1:9180` by default) also serves:

| Path | What |
| --- | --- |
| `/metrics` | Prometheus text format: decisions by site, verdict and rule (`makit_shield_decisions_total`), decision latency (`makit_shield_decision_seconds` histogram), automatic bans by cause, gate events (connections dropped at accept, PROXY header errors), set sizes, config reloads and their result, Go memory and goroutines. |
| `/healthz` | `ok` while the process answers. |
| `/readyz` | 200 once a policy is loaded and, with `edge` on, the listeners started; 503 before — a pod that is not ready gets no traffic. |

Labels come from the config and the catalog (site names, rule and bot ids), never from a request, so the number of
series stays bounded. Counting costs ~32 ns per request with no allocation, also with 8 cores counting at once
(counters are striped across cache lines; `go test ./shield -bench MetricsObserve -cpu 1,8`, Apple M1). Keep the
admin address private: `makit shield config check` warns when it is not.

## Kernel layer (optional)

`kernel_block: true` mirrors the block set into an nftables table (`inet makit_shield`, sets with per-entry timeouts,
checked in prerouting before Docker's NAT). Use it to cover ports makit does not see (SSH, mail) or floods. Private,
loopback and very wide ranges never go into the kernel set.

## On and off

```bash
makit shield on        # block
makit shield off       # allow everything; the gate keeps answering so proxies keep working
makit shield uninstall # stop it (remove the snippet from Caddy/nginx first)
```

If the gate is not running while a proxy still asks it, the proxy answers 502: keep the service running (it restarts
automatically) or remove the snippet before `uninstall`.
