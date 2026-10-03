#!/usr/bin/env bash
# makit benchmarks — anyone can run them; Docker is the only requirement.
#
#   benchmark/run.sh [micro|http|all] [-c CONNECTIONS] [-d DURATION] [--list N]
#
#   micro   Go benchmarks of each step of a decision (set lookups with 1M entries, scoring, bots, /check)
#   http    end-to-end latency: the app alone vs. makit in front (edge); Caddy and Envoy alone vs. asking makit (ask)
#
# The report goes to benchmark/results/<date>-<arch>-<cpus>cpu.md. Everything runs in containers of the
# "makit-bench" compose project, on its own network, with no host ports; it is removed at the end.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$here")
mode=all conc=32 dur=15s list=1000000
while [[ $# -gt 0 ]]; do
  case $1 in
    micro|http|all) mode=$1 ;;
    -c) conc=$2; shift ;;
    -d) dur=$2; shift ;;
    --list) list=$2; shift ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
command -v docker >/dev/null || { echo "Docker is required" >&2; exit 1; }

arch=$(docker info --format '{{.Architecture}}')
ncpu=$(docker info --format '{{.NCPU}}')
mem=$(( $(docker info --format '{{.MemTotal}}') / 1024 / 1024 / 1024 ))
os=$(docker info --format '{{.OperatingSystem}} · kernel {{.KernelVersion}}')
version=$(cat "$repo/VERSION")
commit=$(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)
dirty=$(git -C "$repo" status --porcelain 2>/dev/null | grep -q . && echo " (uncommitted changes)" || true)
mkdir -p "$here/.bin" "$here/results"
out="$here/results/$(date -u +%Y-%m-%d)-$arch-${ncpu}cpu.md"

go_run() { # the Go toolchain in a container, with a cache that survives runs
  docker run --rm -m 4g -v "$repo:/repo" -v makit-bench-gocache:/root/.cache -v makit-bench-gomod:/go/pkg/mod \
    -e CGO_ENABLED=0 -w /repo golang:1 sh -c "$1"
}
cpu_model() { # the host's CPU (inside Docker Desktop's VM an ARM core only shows a part number)
  if [[ $(uname -s) == Darwin ]]; then
    printf '%s (macOS host, Docker Desktop VM)' "$(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
  elif grep -q -m1 'model name' /proc/cpuinfo 2>/dev/null; then
    grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//'
  else
    lscpu 2>/dev/null | sed -n 's/^Model name: *//p' | head -1
  fi
}

{
  echo "# makit $version benchmark — $(date -u '+%Y-%m-%d %H:%M UTC')"
  echo
  echo "| | |"
  echo "| --- | --- |"
  echo "| makit | $version, commit \`$commit\`$dirty |"
  echo "| Machine | $arch, $ncpu CPUs, ${mem} GiB for Docker, $(cpu_model) |"
  echo "| Docker host | $os |"
  echo "| Command | \`benchmark/run.sh $mode -c $conc -d $dur --list $list\` |"
  echo
} > "$out"

if [[ $mode == micro || $mode == all ]]; then
  echo "▸ micro benchmarks (about a minute)…"
  raw=$(go_run "cd core && go test -run '^\$' -bench . -benchmem -benchtime 2s ./shield 2>&1")
  {
    echo "## Decision cost (Go benchmarks)"
    echo
    echo "Each line is one step of what the gate does for a request, with a production-like policy: 1,000,000 listed"
    echo "IPs, catalog rules, attack scoring, bot catalog and bot score, 100,000 distinct visitors."
    echo
    echo "| Benchmark | Time per op | Memory per op | Allocations |"
    echo "| --- | ---: | ---: | ---: |"
    awk '/^Benchmark/ {
      name=$1; sub(/-[0-9]+$/, "", name); sub(/^Benchmark/, "", name)
      t=$3
      if (t+0 >= 1000000) { tt=sprintf("%.2f ms", t/1000000) } else if (t+0 >= 1000) { tt=sprintf("%.2f µs", t/1000) } else { tt=sprintf("%.0f ns", t) }
      b=""; a=""
      for (i=5; i<=NF; i++) { if ($(i+1)=="B/op") b=$i" B"; else if ($(i+1)=="allocs/op") a=$i }
      printf "| %s | %s | %s | %s |\n", name, tt, b, a
    }' <<<"$raw"
    echo
    echo "<details><summary>Raw output</summary>"
    echo
    echo '```'
    echo "$raw"
    echo '```'
    echo
    echo "</details>"
    echo
  } >> "$out"
fi

if [[ $mode == http || $mode == all ]]; then
  echo "▸ building makit-core and the load generator…"
  go_run "cd core && go build -trimpath -o /repo/benchmark/.bin/makit-core . && cd ../benchmark/load && go build -trimpath -o ../.bin/load ."
  compose=(docker compose -f "$here/compose.yaml")
  cleanup() { "${compose[@]}" --profile load down -v --remove-orphans >/dev/null 2>&1 || true; }
  trap cleanup EXIT
  cleanup
  rm -f "$here/.bin/http.jsonl"
  echo "▸ starting the stack (makit loads a $list-entry block list)…"
  LIST_SIZE=$list "${compose[@]}" up -d app makit proxy envoy >/dev/null
  "${compose[@]}" run --rm load wait http://app:80/ http://makit:9180/status http://makit:8080/ http://proxy:81/ http://proxy:82/ \
    http://envoy:83/ http://envoy:84/
  load() { "${compose[@]}" run --rm load run -out /bench/.bin/http.jsonl -c "$conc" -d "$dur" "$@" >/dev/null; }
  echo "▸ app directly"; load -name "app" -url http://app:80/
  echo "▸ makit edge → app"; load -name "makit edge → app" -baseline "app" -url http://makit:8080/
  echo "▸ Caddy → app"; load -name "Caddy → app" -url http://proxy:81/
  echo "▸ Caddy asking makit → app"; load -name "Caddy + makit ask → app" -baseline "Caddy → app" -url http://proxy:82/
  echo "▸ Envoy → app"; load -name "Envoy → app" -url http://envoy:83/
  echo "▸ Envoy ext_authz asking makit → app"; load -name "Envoy + makit ext_authz → app" -baseline "Envoy → app" -url http://envoy:84/
  echo "▸ attacks through makit edge"; load -name "makit edge, attack traffic" -profile attack -baseline "app" -url http://makit:8080/
  echo "▸ attacks through Caddy asking makit"; load -name "Caddy + makit ask, attack traffic" -profile attack -baseline "Caddy → app" -url http://proxy:82/
  echo "▸ attacks through Envoy asking makit"; load -name "Envoy + makit ext_authz, attack traffic" -profile attack -baseline "Envoy → app" -url http://envoy:84/
  status=$("${compose[@]}" exec -T makit wget -qO- http://127.0.0.1:9180/status 2>/dev/null || echo '{}')
  {
    echo "## Request latency (HTTP, end to end)"
    echo
    echo "$conc keep-alive connections for $dur per run, after a 3 s warm-up. Visitors are spread over 100,000 IPs"
    echo "(CF-Connecting-IP through a trusted proxy). Every makit decision runs the full policy and writes a request"
    echo "snapshot to disk. \"Added\" is the difference with the same path without makit. Attack traffic is XSS,"
    echo "secret probes, SQL injection, Log4Shell and path traversal: makit answers 403 itself and bans the IPs."
    echo
    "${compose[@]}" run --rm load report /bench/.bin/http.jsonl
    echo
    echo "Gate counters at the end: \`$status\`"
    echo
  } >> "$out"
fi

cat >> "$out" <<'EOF2'
## Reading these numbers

- Docker on macOS or Windows adds a virtual machine and its network to every hop: absolute latencies there are
  higher than on a Linux server, and tail latencies (p99, p99.9) vary from one run to the next — run twice before
  drawing conclusions from them.
- The app answers a fixed page, so the runs measure the proxy path, not an application.
- Run it on your own server (`benchmark/run.sh`) and open a pull request with the file from `benchmark/results/`
  to add your machine to the comparison.
EOF2
echo "report: $out"
