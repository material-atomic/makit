#!/usr/bin/env bash
# Smoke test inside a throwaway container: tests/smoke.sh  (runs ubuntu:24.04 and debian:12).
# Containers have no systemd/ufw, so those steps run with --dry-run; apt, files and sysctl run for real.
set -euo pipefail
cd "$(dirname "$0")/.."
for img in ubuntu:24.04 debian:12; do
  echo "=== $img"
  docker run --rm -v "$PWD:/opt/makit-src:ro" "$img" bash -euo pipefail -c '
    m=/opt/makit-src/bin/makit
    $m version
    $m --help > /tmp/h; head -3 /tmp/h
    $m --dry-run init --sysctl opensearch --volume auto --docker-volumes 2>&1 | tail -5 || true
    $m --dry-run init --no-ssh-harden > /tmp/dry.log 2>&1; grep -c "\[dry-run\]" /tmp/dry.log
    $m base >/dev/null && echo "base: ok"
    $m --dry-run upgrade --full --autoremove | tail -3
    $m sysctl opensearch vm.swappiness=10 2>&1 | tail -2
    grep -c "" /etc/sysctl.d/90-makit.conf
    $m sysctl vm.swappiness=20 >/dev/null 2>&1; grep swappiness /etc/sysctl.d/90-makit.conf
    $m --dry-run swap 2G | tail -3
    $m --dry-run firewall 8080/tcp | tail -4
    $m ssh 2>&1 | tail -2
    $m volume /dev/null /mnt/x 2>&1 | tail -1 || true
    $m bogus 2>&1 | tail -1 || true
    $m status > /tmp/st; head -4 /tmp/st
  '
done
