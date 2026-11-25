#!/usr/bin/env bash
# Creates a local kind cluster with Calico, so NetworkPolicies are enforced.
# Requires: docker, kind, kubectl.
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-kubeplumb}"
# Check https://github.com/projectcalico/calico/releases for the current version.
CALICO_VERSION="${CALICO_VERSION:-v3.29.1}"

cat <<EOF | kind create cluster --name "${CLUSTER_NAME}" --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
nodes:
  - role: control-plane
  - role: worker
EOF

kubectl apply -f "https://raw.githubusercontent.com/projectcalico/calico/${CALICO_VERSION}/manifests/calico.yaml"
kubectl -n kube-system rollout status daemonset/calico-node --timeout=300s
kubectl wait --for=condition=Ready nodes --all --timeout=300s

echo "Cluster kind-${CLUSTER_NAME} is ready."
