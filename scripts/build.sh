#!/usr/bin/env bash
# Builds makit-core for linux/amd64 and linux/arm64 into dist/ (+ SHA256SUMS), using the golang Docker image —
# or the Go installed here with MAKIT_BUILD=local (same flags; static, -trimpath).
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:-$(cat VERSION)}
mkdir -p dist && rm -f dist/makit-core-linux-* dist/SHA256SUMS
steps="
  gofmt -l . | (! grep .) || { echo 'gofmt needed'; exit 1; }
  go vet ./... && go test ./...
  for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=\$arch go build -trimpath -ldflags '-s -w -X main.version=$version' -o \$OUT/makit-core-linux-\$arch .
  done"
if [[ ${MAKIT_BUILD:-docker} == local ]]; then
  (cd core && OUT="$PWD/../dist" sh -euc "$steps")
else
  docker run --rm -e OUT=/out -v "$PWD:/repo" -v "$PWD/dist:/out" -w /repo/core golang:1 sh -euc "$steps"
fi
(cd dist && shasum -a 256 makit-core-linux-* > SHA256SUMS && cat SHA256SUMS)
