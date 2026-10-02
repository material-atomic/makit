#!/usr/bin/env bash
# Builds makit-core for linux/amd64 and linux/arm64 into dist/ (+ SHA256SUMS), using the golang Docker image.
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:-$(cat VERSION)}
mkdir -p dist && rm -f dist/makit-core-linux-* dist/SHA256SUMS
docker run --rm -v "$PWD/core:/src" -v "$PWD/dist:/out" -w /src golang:1 sh -euc "
  gofmt -l . | (! grep .) || { echo 'gofmt needed'; exit 1; }
  go vet ./... && go test ./...
  for arch in amd64 arm64; do
    CGO_ENABLED=0 GOOS=linux GOARCH=\$arch go build -trimpath -ldflags '-s -w -X main.version=$version' -o /out/makit-core-linux-\$arch .
  done"
(cd dist && shasum -a 256 makit-core-linux-* > SHA256SUMS && cat SHA256SUMS)
