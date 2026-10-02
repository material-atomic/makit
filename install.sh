#!/usr/bin/env bash
# Installs makit on a server:
#   curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/v0.4.0/install.sh | bash
# Env: MAKIT_VERSION (tag to install, default below), MAKIT_SHA256 (checksum of the source tarball; by default it is
# read from the release's SHA256SUMS, which also covers the makit-core binaries).
set -euo pipefail

MAKIT_VERSION=${MAKIT_VERSION:-v0.4.0}
MAKIT_REPO=${MAKIT_REPO:-material-atomic/makit}
PREFIX=/opt/makit

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo -i, or ssh root@host)." >&2; exit 1; }
command -v curl >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
rel="https://github.com/$MAKIT_REPO/releases/download/$MAKIT_VERSION"
echo "Downloading makit $MAKIT_VERSION…"
curl -fsSL "$rel/SHA256SUMS" -o "$tmp/SHA256SUMS" || : > "$tmp/SHA256SUMS"
curl -fsSL "https://codeload.github.com/$MAKIT_REPO/tar.gz/refs/tags/$MAKIT_VERSION" -o "$tmp/makit.tgz"
sum=${MAKIT_SHA256:-$(awk -v f="makit-$MAKIT_VERSION.tar.gz" '$2 == f {print $1}' "$tmp/SHA256SUMS")}
if [[ -n $sum ]]; then
  echo "$sum  $tmp/makit.tgz" | sha256sum -c --quiet - || { echo "Source checksum mismatch — not installing." >&2; exit 1; }
else
  echo "warning: $MAKIT_VERSION publishes no source checksum — installing unverified source (set MAKIT_SHA256 to check)" >&2
fi
dest="$PREFIX/$MAKIT_VERSION"
mkdir -p "$dest/libexec"
tar -xzf "$tmp/makit.tgz" -C "$dest" --strip-components=1
chmod +x "$dest/bin/makit"

# makit-core (makit top / makit scan): prebuilt per architecture, verified against the release's SHA256SUMS.
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) arch='' ;; esac
if [[ -n $arch ]] && grep -q " makit-core-linux-$arch\$" "$tmp/SHA256SUMS" && curl -fsSL "$rel/makit-core-linux-$arch" -o "$tmp/makit-core-linux-$arch"; then
  (cd "$tmp" && grep " makit-core-linux-$arch\$" SHA256SUMS | sha256sum -c --quiet -) || { echo "makit-core checksum mismatch — not installing." >&2; exit 1; }
  install -m 0755 "$tmp/makit-core-linux-$arch" "$dest/libexec/makit-core"
else
  echo "warning: no makit-core for $(uname -m) in $MAKIT_VERSION — 'makit top' and 'makit scan' will be unavailable" >&2
fi

ln -sfn "$dest" "$PREFIX/current"
ln -sfn "$PREFIX/current/bin/makit" /usr/local/bin/makit
echo "Installed: $(/usr/local/bin/makit version)  →  next: makit init --dry-run"
