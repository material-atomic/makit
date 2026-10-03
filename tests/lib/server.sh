# shellcheck shell=bash
# Shared by the end-to-end tests that run on a VPS-like server (terrarium's linux-server): run commands on it, set it
# up the way a new server is, and install this checkout the way `makit upgrade` installs a release.
# shellcheck disable=SC2016  # $ in single quotes expands on the server
: "${box:?set box to the server container before sourcing tests/lib/server.sh}"

ok() { printf '  \033[32m✓\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗ %s\033[0m\n' "$*"; exit 1; }
step() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }
on() { docker exec -i "$box" bash -lc "$*"; }

# need_server: $box runs, has booted, and looks like a droplet (eth0's first address is not a private one).
need_server() {
  docker inspect -f '{{.State.Running}}' "$box" 2>/dev/null | grep -q true || fail "$box is not running (terrarium start linux-server)"
  on 'systemctl is-system-running --wait' >/dev/null 2>&1 || true
  [[ $(on 'ip -4 -o addr show dev eth0 | awk "{print \$4}" | head -1') != 172.* ]] || fail "$box: eth0's first address is private — not laid out like a VPS"
}

# init_server: makit init as on a new server (a container cannot swapon; everything else runs for real).
init_server() {
  on 'makit init --yes --swap none' > /tmp/makit-e2e-init.log 2>&1 || { tail -20 /tmp/makit-e2e-init.log; fail "makit init failed (log: /tmp/makit-e2e-init.log)"; }
  ok "makit init done"
}

# install_checkout VERSION: this checkout as release files (source tarball, makit-core for the server's architecture,
# SHA256SUMS), installed with this checkout's install.sh — what `makit upgrade` runs for a release.
install_checkout() {
  local ver=$1 rel arch f
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
  docker cp install.sh "$box:/tmp/makit-release/install.sh"
  on "MAKIT_VERSION=$ver MAKIT_FROM=/tmp/makit-release bash /tmp/makit-release/install.sh" | tail -3
}
