#!/usr/bin/env bash
# Builds the config playground's WebAssembly (makit's config check + the security catalog) into dist/playground/:
#   makit-check.wasm, wasm_exec.js (from the same Go toolchain). Upload both next to playground.html on makit.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:-$(cat VERSION)}
out=dist/playground
mkdir -p "$out"
rm -rf core/cmd/playground/catalog && mkdir -p core/cmd/playground/catalog
cp -R security core/cmd/playground/catalog/security
trap 'rm -rf core/cmd/playground/catalog' EXIT
(cd core && GOOS=js GOARCH=wasm go build -trimpath -ldflags "-s -w -X github.com/material-atomic/makit/core/shield.Version=$version" \
  -o "../$out/makit-check.wasm" ./cmd/playground)
cp "$(cd core && go env GOROOT)/lib/wasm/wasm_exec.js" "$out/"
gzip -9 -k -f "$out/makit-check.wasm"
ls -la "$out"
