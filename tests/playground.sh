#!/usr/bin/env bash
# Builds the config playground's WebAssembly and checks it answers like makit shield config check (needs Go, Node).
set -euo pipefail
cd "$(dirname "$0")/.."
scripts/playground.sh "${1:-dev}" >/dev/null
node tests/playground-check.mjs "$(cd core && go env GOROOT)" dist/playground/makit-check.wasm
