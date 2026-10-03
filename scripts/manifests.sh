#!/usr/bin/env bash
# Renders deploy/kubernetes/makit-shield.yaml from the Helm chart (defaults, namespace makit, the cluster secret made
# by hand so none is committed). Run after changing the chart.
set -euo pipefail
cd "$(dirname "$0")/.."
{
  echo "# makit-shield, plain manifests (rendered from deploy/helm/makit-shield with defaults; namespace makit)."
  echo "# First: kubectl create namespace makit"
  echo "#        kubectl -n makit create secret generic makit-shield-cluster --from-literal=secret=\$(openssl rand -hex 32)"
  echo "# Then:  kubectl apply -n makit -f makit-shield.yaml"
  echo "# Regenerate: scripts/manifests.sh"
  helm template makit deploy/helm/makit-shield -n makit --set cluster.existingSecret=makit-shield-cluster | grep -v '^# Source:'
} > deploy/kubernetes/makit-shield.yaml
echo "wrote deploy/kubernetes/makit-shield.yaml"
