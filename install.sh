#!/usr/bin/env bash
# Installs makit on a server:
#   curl -fsSL https://raw.githubusercontent.com/material-atomic/makit/v0.1.0/install.sh | bash
# Env: MAKIT_VERSION (tag to install, default below), MAKIT_SHA256 (optional checksum of the release tarball).
set -euo pipefail

MAKIT_VERSION=${MAKIT_VERSION:-v0.1.0}
MAKIT_REPO=${MAKIT_REPO:-material-atomic/makit}
PREFIX=/opt/makit

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo -i, or ssh root@host)." >&2; exit 1; }
command -v curl >/dev/null || { apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl ca-certificates; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
url="https://codeload.github.com/$MAKIT_REPO/tar.gz/refs/tags/$MAKIT_VERSION"
echo "Downloading makit $MAKIT_VERSION…"
curl -fsSL "$url" -o "$tmp/makit.tgz"
if [[ -n ${MAKIT_SHA256:-} ]]; then
  echo "$MAKIT_SHA256  $tmp/makit.tgz" | sha256sum -c --quiet - || { echo "Checksum mismatch — not installing." >&2; exit 1; }
fi
mkdir -p "$PREFIX/$MAKIT_VERSION"
tar -xzf "$tmp/makit.tgz" -C "$PREFIX/$MAKIT_VERSION" --strip-components=1
chmod +x "$PREFIX/$MAKIT_VERSION/bin/makit"
ln -sfn "$PREFIX/$MAKIT_VERSION" "$PREFIX/current"
ln -sfn "$PREFIX/current/bin/makit" /usr/local/bin/makit
echo "Installed: $(/usr/local/bin/makit version)  →  next: makit init --dry-run"
