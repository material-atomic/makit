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

## Behind Cloudflare

Behind Cloudflare every connection comes from a Cloudflare IP; the visitor's IP is in the `CF-Connecting-IP` header.
makit uses that header **only when the connection really comes from Cloudflare** (`trusted_proxies: [cloudflare]`,
ranges refreshed daily from cloudflare.com/ips). A direct visitor sending a fake header is judged on its own IP.

Also lock the origin so it only accepts web traffic from Cloudflare (provider firewall, or `ufw allow from <range>`),
otherwise attackers can skip Cloudflare by hitting the server IP.

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

## Snapshots

Each decision is a JSON line in `/var/log/makit/shield/requests.jsonl` (rotated): time, client IP, peer, proxy,
verdict, rule, method, host, URI, user agent, referer, Cloudflare country and ray, status, duration. Bodies, cookies
and authorization headers are never recorded.

```bash
makit shield log -n 100
makit shield log --blocked
makit shield status          # live counters
```

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
