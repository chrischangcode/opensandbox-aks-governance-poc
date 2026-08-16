#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

namespace="${OPENSANDBOX_NAMESPACE:-opensandbox}"
assignment_namespace="${ASSIGNMENT_NAMESPACE:-aks-sandbox-system}"
server_image="${OPENSANDBOX_SERVER_IMAGE:?set OPENSANDBOX_SERVER_IMAGE to a digest-pinned server image reference}"
server_image="$("$repo_root/scripts/require-image-digest.sh" "$server_image" OPENSANDBOX_SERVER_IMAGE)"
kata_nodepool="${KATA_NODEPOOL_NAME:?set KATA_NODEPOOL_NAME to the AKS Kata agent-pool name}"
ingress_mode="${OPENSANDBOX_INGRESS_MODE:-gateway}"
gateway_address="${OPENSANDBOX_GATEWAY_ADDRESS:-127.0.0.1:8081}"
gateway_route_mode="${OPENSANDBOX_GATEWAY_ROUTE_MODE:-header}"

config_file="$(mktemp)"
manifest_file="$(mktemp)"
batchsandbox_file="$(mktemp)"
cleanup() {
  rm -f "$config_file" "$manifest_file" "$batchsandbox_file"
}
trap cleanup EXIT

kubectl create namespace "$namespace" --dry-run=client -o yaml |
  kubectl apply -f -

if ! kubectl -n "$namespace" get secret opensandbox-server >/dev/null 2>&1; then
  api_key="$(openssl rand -hex 32)"
  kubectl -n "$namespace" create secret generic opensandbox-server \
    --from-literal=api-key="$api_key"
  unset api_key
fi

sed \
  -e "s|__NAMESPACE__|$namespace|g" \
  -e "s|__INGRESS_MODE__|$ingress_mode|g" \
  -e "s|__INGRESS_GATEWAY_ADDRESS__|gateway.address = \"$gateway_address\"|g" \
  -e "s|__INGRESS_GATEWAY_ROUTE_MODE__|gateway.route.mode = \"$gateway_route_mode\"|g" \
  deploy/opensandbox-server/config/sandbox.toml >"$config_file"

kubectl -n "$namespace" create configmap opensandbox-server-config \
  --from-file="sandbox.toml=$config_file" \
  --dry-run=client -o yaml |
  kubectl apply -f -
sed "s|__KATA_NODEPOOL_NAME__|$kata_nodepool|g" \
  deploy/opensandbox-server/k8s/batchsandbox-template.yaml >"$batchsandbox_file"
kubectl -n "$namespace" create configmap opensandbox-batchsandbox-template \
  --from-file="batchsandbox-template.yaml=$batchsandbox_file" \
  --dry-run=client -o yaml |
  kubectl apply -f -

sed \
  -e "s|__NAMESPACE__|$namespace|g" \
  -e "s|__SERVER_IMAGE__|$server_image|g" \
  deploy/opensandbox-server/k8s/opensandbox-server.yaml >"$manifest_file"
kubectl apply -f "$manifest_file"

api_key="$(
  kubectl -n "$namespace" get secret opensandbox-server \
    -o jsonpath='{.data.api-key}' |
    base64 --decode
)"
kubectl create namespace "$assignment_namespace" --dry-run=client -o yaml |
  kubectl apply -f -
kubectl -n "$assignment_namespace" create secret generic assignmentd-opensandbox-api \
  --from-literal=api-key="$api_key" \
  --dry-run=client -o yaml |
  kubectl apply -f -
unset api_key

kubectl -n "$namespace" rollout status deployment/opensandbox-server --timeout=300s
echo "OpenSandbox deployed in namespace $namespace with persistent SQLite state."
