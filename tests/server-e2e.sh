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
ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*"; exit 1; }
on() { docker exec -i "$box" bash -lc "$*"; }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

docker inspect -f '{{.State.Running}}' "$box" 2>/dev/null | grep -q true || fail "$box is not running (terrarium start linux-server)"
on 'systemctl is-system-running --wait' >/dev/null 2>&1 || true
[[ $(on 'ip -4 -o addr show dev eth0 | awk "{print \$4}" | head -1') != 172.* ]] || fail "$box: eth0's first address is private — not laid out like a VPS"

step "makit $from from makit.sh, as on a new server"
on "curl -fsSL https://makit.sh/install.sh | sh -s -- $from" | tail -1
on 'makit init --yes --swap none'   # a container cannot swapon; the rest runs for real > /tmp/makit-e2e-init.log 2>&1 || { tail -20 /tmp/makit-e2e-init.log; fail "makit init failed"; }
ok "makit init done"
on 'ip -br link show docker0 | grep -q DOWN' && ok "docker0 is down (nothing runs on Docker's default bridge)"

step "the shield, with its admin address on Docker's bridge"
on 'install -D -m 640 /dev/stdin /etc/makit/shield.yaml' <<'YAML'
mode: block
ask: true
admin: 172.17.0.1:9180
trusted_proxies: [cloudflare]
client_ip_header: CF-Connecting-IP
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
rel=$(mktemp -d)
mkdir "$rel/makit-$ver"
git ls-files -co --exclude-standard | grep -v '^site/\|^docs/img/' | tar -cf - -T - | tar -xf - -C "$rel/makit-$ver"
echo "${ver#v}" > "$rel/makit-$ver/VERSION"
tar -czf "$rel/makit-$ver.tar.gz" -C "$rel" "makit-$ver"
arch=$(on 'uname -m' | sed 's/x86_64/amd64/; s/aarch64/arm64/')
(cd core && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -ldflags "-s -w -X main.version=${ver#v}" -o "$rel/makit-core-linux-$arch" .)
(cd "$rel" && shasum -a 256 "makit-$ver.tar.gz" "makit-core-linux-$arch" > SHA256SUMS)
on 'rm -rf /tmp/makit-release && mkdir -p /tmp/makit-release'
for f in SHA256SUMS "makit-$ver.tar.gz" "makit-core-linux-$arch"; do docker cp "$rel/$f" "$box:/tmp/makit-release/$f"; done
rm -r "$rel"
# install.sh of the version being installed is the one makit upgrade runs:
docker cp install.sh "$box:/tmp/makit-release/install.sh"
on "MAKIT_VERSION=$ver MAKIT_FROM=/tmp/makit-release bash /tmp/makit-release/install.sh" | tail -3

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
code=$(ask "-H 'X-Makit-Peer: 198.51.100.20' -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Uri: /' -H 'X-Forwarded-Host: goes.vn' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/140.0 Safari/537.36' -H 'Accept: text/html' -H 'Accept-Language: vi' -H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: navigate'")
[[ $code == 200 ]] && ok "a visitor's page view: 200" || fail "a visitor's page view: $code"
code=$(ask "-H 'X-Makit-Peer: 203.0.113.9' -H 'X-Forwarded-Method: GET' -H 'X-Forwarded-Uri: /.env' -H 'X-Forwarded-Host: goes.vn'")
[[ $code == 403 ]] && ok "a probe for /.env: 403" || fail "a probe for /.env: $code"
on 'makit shield log -n 2' | tail -2
# The gate saves automatic bans once a second: wait until this one is in the list before taking it out.
for _ in 1 2 3 4 5 6 7 8 9 10; do on 'makit shield list' | grep -q 203.0.113.9 && break; sleep 0.5; done
on 'makit shield unban 203.0.113.9' >/dev/null && ok "the probe's automatic ban is listed and can be lifted"

[[ ${KEEP:-} == 1 ]] || on 'makit shield uninstall >/dev/null 2>&1; docker network rm goes >/dev/null 2>&1 || true'
printf '\n\033[32mserver end to end: ok\033[0m\n'
