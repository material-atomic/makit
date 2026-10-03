#!/usr/bin/env bash
# makit-shield in a real Kubernetes cluster (kind): build the image, install the Helm chart with 3 replicas, then check
# what the cluster mode promises, from a pod inside the cluster:
#   1. a ban made with the CLI on one replica is enforced by every replica;
#   2. an automatic ban (a probe on one replica) is enforced by every replica;
#   3. a visitor who is not banned passes everywhere, and a forged left-most X-Forwarded-For changes nothing;
#   4. a shield.yaml change reaches the running pods without a restart;
#   5. a rate limit holds across replicas: limit 10/1m lets about 10 of 30 requests through (27-30 without cluster).
# Needs docker, kind, kubectl and helm. KEEP=1 keeps the cluster afterwards.
set -euo pipefail
cd "$(dirname "$0")/.."
name=makit-e2e ns=makit image=ghcr.io/material-atomic/makit-shield:e2e
fail=0
check() { # check DESCRIPTION EXPECTED ACTUAL
  if [[ $2 == "$3" ]]; then echo "  ✓ $1"; else echo "  ✗ $1: got $3, want $2"; fail=1; fi
}
cleanup() { [[ ${KEEP:-0} == 1 ]] || kind delete cluster --name "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

kind get clusters 2>/dev/null | grep -qx "$name" || kind create cluster --name "$name" --wait 120s
docker build -q -f deploy/image/Dockerfile --build-arg VERSION=e2e -t "$image" . >/dev/null
kind load docker-image "$image" --name "$name" >/dev/null
kubectl create namespace "$ns" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
helm upgrade --install shield deploy/helm/makit-shield -n "$ns" --set image.tag=e2e --set replicaCount=3 \
  --set config.mode=block --wait --timeout 180s >/dev/null
kubectl -n "$ns" run c --image=curlimages/curl:8.10.1 --restart=Never --command -- sleep 3600 >/dev/null 2>&1 || true
kubectl -n "$ns" wait --for=condition=Ready pod/c --timeout=120s >/dev/null
sleep 3 # the replicas find each other (first sync)

# shellcheck disable=SC2207 # pod names and IPs have no spaces
pods=($(kubectl -n "$ns" get pods -l app.kubernetes.io/name=makit-shield -o jsonpath='{.items[*].metadata.name}'))
# shellcheck disable=SC2207
ips=($(kubectl -n "$ns" get pods -l app.kubernetes.io/name=makit-shield -o jsonpath='{.items[*].status.podIP}'))
ask() { # ask POD_IP CLIENT PATH [UA]: the status /check answers for a visitor CLIENT behind a forged left-most address
  kubectl -n "$ns" exec c -- curl -s -o /dev/null -w '%{http_code}' -H "X-Forwarded-For: 192.0.2.1, $2" \
    -H "X-Forwarded-Uri: $3" -H "User-Agent: ${4:-Mozilla/5.0 (X11; Linux x86_64) Chrome/126}" -H 'Accept: text/html' \
    -H 'Accept-Language: en' -H 'Accept-Encoding: gzip' -H 'Sec-Fetch-Mode: navigate' "http://$1:9180/check"
}
everywhere() { local out=""; for ip in "${ips[@]}"; do out+="$(ask "$ip" "$1" "$2") "; done; echo "${out% }"; }
all() { local out=""; for _ in "${ips[@]}"; do out+="$1 "; done; echo "${out% }"; }

echo "== ${#pods[@]} replicas: ${ips[*]}"
peers=$(kubectl -n "$ns" exec "${pods[0]}" -- makit-core shield status --json | grep -o '"addr"' | wc -l | tr -d ' ')
check "each replica sees the other two" 2 "$peers"

echo "== 1. a CLI ban on one replica"
kubectl -n "$ns" exec "${pods[0]}" -- makit-core shield ban 203.0.113.50 --reason e2e >/dev/null
sleep 4
check "blocked by every replica" "$(all 403)" "$(everywhere 203.0.113.50 /)"

echo "== 2. an automatic ban on one replica"
ask "${ips[1]}" 203.0.113.60 /.env >/dev/null
sleep 2
check "the prober is blocked by every replica" "$(all 403)" "$(everywhere 203.0.113.60 /)"

echo "== 3. everyone else"
check "a clean visitor passes everywhere (the forged 192.0.2.1 on the left is ignored)" "$(all 200)" "$(everywhere 198.51.100.20 /)"

echo "== 4. a config change, live"
before=$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=makit-shield -o jsonpath='{.items[*].metadata.uid}')
helm upgrade shield deploy/helm/makit-shield -n "$ns" --reuse-values \
  --set-json 'config.bots={"policy":{"library":"limit 10/1m"}}' >/dev/null
live=0
for i in $(seq 1 60); do
  n=0
  for p in "${pods[@]}"; do
    kubectl -n "$ns" exec "$p" -- makit-core shield bots list 2>/dev/null | grep -q 'library.*limit 10/1m' && n=$((n + 1))
  done
  if [[ $n == "${#pods[@]}" ]]; then live=1; echo "  (on every replica after ~$((i * 3)) s)"; break; fi
  sleep 3
done
check "the new policy is live on every replica" 1 "$live"
check "without restarting them" "$before" "$(kubectl -n "$ns" get pods -l app.kubernetes.io/name=makit-shield -o jsonpath='{.items[*].metadata.uid}')"

echo "== 5. a rate limit across replicas"
allowed=$(kubectl -n "$ns" exec c -- sh -c "ok=0; i=0; for ip in $(printf '%s ' "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}" "${ips[@]}"); do
  c=\$(curl -s -o /dev/null -w '%{http_code}' -H 'X-Forwarded-For: 198.51.100.77' -H 'X-Forwarded-Uri: /' -H 'User-Agent: curl/8.10' http://\$ip:9180/check)
  [ \"\$c\" = 200 ] && ok=\$((ok+1)); sleep 0.1; done; echo \$ok")
echo "  limit 10/1m, 30 requests round-robin over ${#pods[@]} replicas at ~10/s: $allowed let through"
check "about 10 (at most one sync interval over), not 30" 1 "$(( allowed >= 10 && allowed <= 13 ))"

if [[ $fail == 0 ]]; then echo "PASS"; else echo "FAIL"; exit 1; fi
