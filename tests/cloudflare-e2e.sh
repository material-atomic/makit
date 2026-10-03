#!/usr/bin/env bash
# Behind Cloudflare, end to end: visitor → Cloudflare → origin (Caddy in Docker asks makit) → app, with this checkout
# installed on a VPS-like server.
#
#   terrarium start linux-server cloudflare && tests/cloudflare-e2e.sh
#
# terrarium's cloudflare service is the edge: it sits at 172.64.0.10, inside Cloudflare's published 172.64.0.0/13, and
# sends what Cloudflare sends (CF-Connecting-IP, X-Forwarded-For, CF-IPCountry, CF-Ray…). A test visitor says who it is
# with X-Terrarium-Client-IP. The origin is reached on the "internet" network, whose other half (172.72.0.0/16) is
# the rest of the internet — where an attacker who skips Cloudflare comes from.
#
# Checks, with a config shaped like a real one (observe overall, an admin site that blocks):
#   the visitor's address is the one Cloudflare names, and the app receives it;
#   a probe on the blocking site is stopped and banned; on the observing site it is only logged;
#   a fake Googlebot is caught (it does not come from Google's ranges);
#   a client that skips Cloudflare and forges CF-Connecting-IP and X-Forwarded-For is judged on its real address.
# SKIP_INIT=1 when makit init already ran on the server; KEEP=1 leaves the setup in place.
# shellcheck disable=SC2016,SC2015  # $ in single quotes expands on the server; ok() cannot fail
set -euo pipefail
cd "$(dirname "$0")/.."
box=${1:-terrarium-linux-server}
edge=${EDGE:-http://localhost:8088}
ver=v$(cat VERSION)-test
. tests/lib/server.sh
need_server
docker inspect -f '{{.State.Running}}' terrarium-cloudflare 2>/dev/null | grep -q true || fail "terrarium-cloudflare is not running (terrarium start cloudflare)"

step "makit (this checkout) on the origin"
on 'command -v makit >/dev/null' || on 'curl -fsSL https://makit.sh/install.sh | sh' | tail -1
[[ ${SKIP_INIT:-} == 1 ]] || init_server
install_checkout "$ver"
on 'install -D -m 640 /dev/stdin /etc/makit/shield.yaml' <<'YAML'
mode: observe
ask: true
admin: 172.17.0.1:9180
trusted_proxies: [cloudflare]
ban_scope: server
bots:
  policy: { spoofed: block }
sites:
  - { name: app, match: [app.example.com] }
  - { name: admin, match: [admin.example.com], mode: block }
YAML
on 'makit shield config check /etc/makit/shield.yaml' | tail -1
on 'ufw allow from 172.16.0.0/12 to 172.17.0.1 port 9180 proto tcp' >/dev/null
on 'makit shield on --observe' >/dev/null
on 'makit shield restart' >/dev/null 2>&1 || true

step "the origin: Caddy in Docker, asking makit before every request"
on 'mkdir -p /srv/origin && cat > /srv/origin/Caddyfile' <<'CADDY'
{
	auto_https off
}
(shield_on) {
	forward_auth 172.17.0.1:9180 {
		uri /check
		header_up X-Forwarded-For "{http.request.header.X-Forwarded-For}, {remote_host}"
		copy_headers X-Makit-Client
	}
}
http://app.example.com, http://admin.example.com {
	import shield_on
	respond "{host}: the visitor is {http.request.header.X-Makit-Client}" 200
}
CADDY
on 'docker rm -f origin-caddy >/dev/null 2>&1; docker network inspect web >/dev/null 2>&1 || docker network create web >/dev/null
    docker run -d --name origin-caddy --network web -p 80:80 -v /srv/origin/Caddyfile:/etc/caddy/Caddyfile:ro caddy:2-alpine >/dev/null'
for _ in $(seq 1 30); do on 'curl -s -o /dev/null -w "%{http_code}" -H "Host: app.example.com" http://127.0.0.1/' 2>/dev/null | grep -q '^[0-9]' && break; sleep 1; done
ok "origin up: $(on 'docker ps --filter name=origin-caddy --format "{{.Image}} {{.Status}}"')"
cf_addr=$(docker inspect -f '{{(index .NetworkSettings.Networks "terrarium-internet").IPAddress}}' terrarium-cloudflare)
on 'grep -qx "172.64.0.0/13" /var/lib/makit/shield/cloudflare.txt' && ok "Cloudflare's edge is $cf_addr, inside 172.64.0.0/13 of the list makit downloaded from cloudflare.com/ips" \
  || fail "172.64.0.0/13 is not in makit's Cloudflare list: $(on 'head -3 /var/lib/makit/shield/cloudflare.txt')"

browser=(-H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36'
  -H 'Accept: text/html,application/xhtml+xml' -H 'Accept-Language: vi-VN,vi;q=0.9' -H 'Accept-Encoding: gzip, br'
  -H 'Sec-CH-UA: "Chromium";v="140"' -H 'Sec-Fetch-Mode: navigate' -H 'Sec-Fetch-Site: none' -H 'Sec-Fetch-Dest: document')
# visit HOST CLIENT_IP PATH [curl args…]: through the Cloudflare edge, as a visitor from CLIENT_IP; prints the status.
visit() { local host=$1 ip=$2 path=$3; shift 3; curl -s -o /tmp/makit-cf-body -w '%{http_code}' -H "Host: $host" -H "X-Terrarium-Client-IP: $ip" "$@" "$edge$path"; }
last_log() { sleep 0.3; on "makit shield log -n ${1:-1}"; }

step "through Cloudflare"
code=$(visit app.example.com 203.0.113.50 / "${browser[@]}")
[[ $code == 200 ]] && ok "a visitor's page view: 200" || fail "a visitor's page view: $code"
grep -q 'the visitor is 203.0.113.50' /tmp/makit-cf-body && ok "the app is told the visitor is 203.0.113.50 (X-Makit-Client)" || fail "app saw: $(cat /tmp/makit-cf-body)"
last_log | grep -q '203.0.113.50.*via' && ok "makit logged 203.0.113.50 via Cloudflare: $(last_log | tr -s ' ' | cut -c1-110)" || { last_log; fail "makit did not take the visitor from CF-Connecting-IP"; }

code=$(visit admin.example.com 203.0.113.9 /.env)
[[ $code == 403 ]] && ok "a probe for /.env on the blocking site: 403" || fail "a probe on admin: $code"
for _ in $(seq 1 10); do on 'makit shield list' | grep -q 203.0.113.9 && break; sleep 0.5; done
on 'makit shield list' | grep -q 203.0.113.9 && ok "203.0.113.9 banned: $(on 'makit shield list' | grep 203.0.113.9 | tr -s ' ' | cut -c1-90)" || fail "no ban for 203.0.113.9"

code=$(visit app.example.com 203.0.113.10 /wp-login.php)
[[ $code == 200 ]] && ok "a probe on the observing site goes through (observe): 200" || fail "observe site answered $code"
last_log | grep -q '203.0.113.10' && ok "and is logged: $(last_log | tr -s ' ' | cut -c1-110)" || fail "observe site: not logged"

for _ in $(seq 1 60); do on 'ls /var/lib/makit/shield/bots/ 2>/dev/null' | grep -qi google && break; sleep 1; done
# A request never waits for a reverse DNS answer: the first one from a new address is "pending" — it gets none of a
# verified crawler's privileges (rules and the attack score still apply) — and the spoofed policy follows once the
# answer is in, milliseconds later.
googlebot=(-H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
visit admin.example.com 203.0.113.77 / "${googlebot[@]}" >/dev/null
last_log | grep -q 'bot-verified' && fail "a fake Googlebot was treated as the real one: $(last_log)"
code=$(visit admin.example.com 203.0.113.77 /.env "${googlebot[@]}")
[[ $code == 403 ]] && ok "a fake Googlebot is not trusted while it is checked: /.env still 403" || fail "pending fake Googlebot /.env: $code"
on 'makit shield unban 203.0.113.77' >/dev/null 2>&1 || true
sleep 1
code=$(visit admin.example.com 203.0.113.78 / "${googlebot[@]}")
for _ in 1 2 3 4 5 6 7 8 9 10; do sleep 0.3; code=$(visit admin.example.com 203.0.113.78 / "${googlebot[@]}"); [[ $code == 403 ]] && break; done
[[ $code == 403 ]] && ok "once reverse DNS says it is not Google: blocked as spoofed ($(last_log | grep -o 'bot:spoofed' | head -1))" || fail "fake Googlebot after DNS: $code ($(last_log))"

step "skipping Cloudflare: straight to the origin with a forged CF-Connecting-IP and X-Forwarded-For"
code=$(docker run --rm --network terrarium-internet curlimages/curl:8.10.1 -s -o /dev/null -w '%{http_code}' \
  -H 'Host: admin.example.com' -H 'CF-Connecting-IP: 66.249.66.1' -H 'X-Forwarded-For: 66.249.66.1, 172.64.0.10' \
  http://linux-server.internet/.git/config)
line=$(last_log)
[[ $code == 403 ]] && ok "blocked: $code" || fail "the forged request answered $code"
grep -q '66.249.66.1' <<<"$line" && fail "makit believed the forged headers: $line"
grep -q '172.72.' <<<"$line" && ok "judged on its real address, not 66.249.66.1: $(tr -s ' ' <<<"$line" | cut -c1-110)" || fail "log: $line"

on 'makit shield unban 203.0.113.9; makit shield unban 203.0.113.78' >/dev/null 2>&1 || true
[[ ${KEEP:-} == 1 ]] || on 'docker rm -f origin-caddy >/dev/null 2>&1; makit shield off >/dev/null 2>&1 || true'
printf '\n\033[32mcloudflare end to end: ok\033[0m\n'
