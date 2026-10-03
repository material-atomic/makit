#!/usr/bin/env bash
# A fresh VPS, end to end: install the released makit, makit init, turn the shield on with the gate's admin address on
# Docker's bridge (172.17.0.1, as a gate that Caddy in a container asks), then upgrade to this checkout the way
# `makit upgrade` does — and check that the gate runs the new version and answers the CLI.
#
#   tests/server-e2e.sh [CONTAINER]        default: terrarium-linux-server (terrarium start linux-server)
#
# The server must look like a real droplet: systemd as PID 1, Docker able to run inside, eth0 with the public address
# first (terrarium's linux-server does all three). On such a server, with docker0 down, a request from the host to
# 172.17.0.1 leaves through lo and Docker's MASQUERADE gives it eth0's public address — which makit v0.6.0 refused.
# FROM=vX.Y.Z picks the release to start from (default v0.6.0); KEEP=1 leaves the server as the test left it.
# shellcheck disable=SC2016,SC2015  # $ in single quotes expands on the server; ok() cannot fail
set -euo pipefail
cd "$(dirname "$0")/.."
box=${1:-terrarium-linux-server}
from=${FROM:-v0.6.0}
ver=v$(cat VERSION)-test
. tests/lib/server.sh
need_server
on 'test ! -e /opt/makit' || fail "$box already has makit — this test starts from a new server: terrarium remove linux-server --data --yes && terrarium start linux-server"

step "makit $from from makit.sh, as on a new server"
on "curl -fsSL https://makit.sh/install.sh | sh -s -- $from" | tail -1
init_server
on 'ip -br link show docker0 | grep -q DOWN' && ok "docker0 is down (nothing runs on Docker's default bridge)"

step "the shield, with its admin address on Docker's bridge"
on 'install -D -m 640 /dev/stdin /etc/makit/shield.yaml' <<'YAML'
mode: block
ask: true
admin: 172.17.0.1:9180
trusted_proxies: [cloudflare]
YAML
on 'makit shield config check /etc/makit/shield.yaml' | tail -1
on 'ufw allow from 172.16.0.0/12 to 172.17.0.1 port 9180 proto tcp' >/dev/null
on 'makit shield on' | tail -1
# At a terminal v0.6.0 printed "invalid character 'o' in literal false"; without one it prints the gate's answer.
before=$(on 'makit shield status' 2>&1 || true)
if grep -q "forbidden\|invalid character 'o'" <<<"$before"; then
  ok "$from: makit shield status fails as it did on the server (the gate refuses the host's own address)"
else
  echo "$before" | tail -2; [[ $from == v0.6.0 ]] && fail "$from did not reproduce the forbidden status"
fi
ok "the old unit runs $(on "systemctl show -p ExecStart --value makit-shield | sed 's/.*path=\\([^ ;]*\\).*/\\1/'")"

step "upgrade to this checkout ($ver), the way makit upgrade installs a release"
install_checkout "$ver"

step "after the upgrade"
exec_start=$(on "systemctl show -p ExecStart --value makit-shield")
grep -q "/opt/makit/current/libexec/makit-core" <<<"$exec_start" && ok "the unit runs /opt/makit/current, not a version's folder" || fail "unit: $exec_start"
running=$(on 'readlink -f /proc/$(systemctl show -p MainPID --value makit-shield)/exe')
[[ $running == "/opt/makit/$ver/libexec/makit-core" ]] && ok "the gate runs the new binary ($running)" || fail "the gate runs $running"
status=$(on 'makit shield status' 2>&1) || { echo "$status"; fail "makit shield status failed"; }
grep -q "${ver#v}" <<<"$status" && ok "makit shield status answers, version ${ver#v}" || { echo "$status"; fail "status does not show ${ver#v}"; }

step "a proxy in a container asks the gate, as Caddy will"
on 'docker network inspect goes >/dev/null 2>&1 || docker network create goes >/dev/null'
ask() { on "docker run --rm --network goes curlimages/curl:8.10.1 -s -o /dev/null -w '%{http_code}' $* http://172.17.0.1:9180/check"; }
code=$(ask "-H 'X-Forwarded-For: 198.51.100.20' -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Uri: /' -H 'X-Forwarded-Host: goes.vn' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36' -H 'Accept: text/html' -H 'Accept-Language: vi' -H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: navigate'")
[[ $code == 200 ]] && ok "a visitor's page view: 200" || fail "a visitor's page view: $code"
code=$(ask "-H 'X-Forwarded-For: 203.0.113.9' -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Uri: /.env' -H 'X-Forwarded-Host: goes.vn'")
[[ $code == 403 ]] && ok "a probe for /.env: 403" || fail "a probe for /.env: $code"
on 'makit shield log -n 2' | tail -2
# The gate saves automatic bans once a second: wait until this one is in the list before taking it out.
for _ in 1 2 3 4 5 6 7 8 9 10; do on 'makit shield list' | grep -q 203.0.113.9 && break; sleep 0.5; done
on 'makit shield unban 203.0.113.9' >/dev/null && ok "the probe's automatic ban is listed and can be lifted"

[[ ${KEEP:-} == 1 ]] || on 'makit shield uninstall >/dev/null 2>&1; docker network rm goes >/dev/null 2>&1 || true'
printf '\n\033[32mserver end to end: ok\033[0m\n'
