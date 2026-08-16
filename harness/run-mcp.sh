#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"

forward_pids=()
forward_port=""
cleanup() {
  for pid in "${forward_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT INT TERM

start_random_forward() {
  local remote_port="$1"
  shift
  local log_file
  log_file="$(mktemp)"
  kubectl --kubeconfig "$KUBECONFIG" --address 127.0.0.1 port-forward "$@" \
    ":${remote_port}" >"$log_file" 2>&1 &
  forward_pids+=("$!")
  local pid="${forward_pids[-1]}"
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log_file" >&2
      rm -f "$log_file"
      exit 1
    fi
    forward_port="$(
      sed -n 's/^Forwarding from 127\.0\.0\.1:\([0-9][0-9]*\) .*/\1/p' "$log_file" |
        head -1
    )"
    if [[ -n "$forward_port" ]] &&
      timeout 1 bash -c "</dev/tcp/127.0.0.1/$forward_port" 2>/dev/null; then
      rm -f "$log_file"
      return
    fi
    sleep 0.2
  done
  cat "$log_file" >&2
  rm -f "$log_file"
  echo "Port-forward to remote port $remote_port did not become ready" >&2
  exit 1
}

start_random_forward 8080 -n aks-sandbox-system svc/assignmentd
export ASSIGNMENTD_URL="http://127.0.0.1:${forward_port}/opensandbox"
export CREDENTIAL_BROKER_URL="http://127.0.0.1:${forward_port}/broker"

start_random_forward 8080 -n opensandbox svc/opensandbox-server
export OPEN_SANDBOX_DOMAIN="127.0.0.1:${forward_port}"

if timeout 1 bash -c "</dev/tcp/127.0.0.1/8081" 2>/dev/null; then
  echo "Local port 8081 is occupied; refusing to trust an unrelated listener" >&2
  exit 1
fi
kubectl --kubeconfig "$KUBECONFIG" --address 127.0.0.1 port-forward \
  -n opensandbox svc/opensandbox-ingress-gateway 8081:80 >/tmp/opensandbox-governance-ingress.log 2>&1 &
forward_pids+=("$!")
for _ in {1..50}; do
  if timeout 1 bash -c "</dev/tcp/127.0.0.1/8081" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if ! timeout 1 bash -c "</dev/tcp/127.0.0.1/8081" 2>/dev/null; then
  cat /tmp/opensandbox-governance-ingress.log >&2
  exit 1
fi

if [[ -z "${OPEN_SANDBOX_API_KEY:-}" ]]; then
  encoded="$(
    kubectl --kubeconfig "$KUBECONFIG" -n opensandbox \
      get secret opensandbox-server -o jsonpath='{.data.api-key}'
  )"
  if [[ -z "$encoded" ]]; then
    echo "OpenSandbox API key secret is unavailable" >&2
    exit 1
  fi
  export OPEN_SANDBOX_API_KEY
  OPEN_SANDBOX_API_KEY="$(printf '%s' "$encoded" | base64 --decode)"
fi

exec uv run --quiet --project "$repo_root/harness" \
  python "$repo_root/harness/server.py"
