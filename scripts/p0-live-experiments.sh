#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

assignment_namespace="${ASSIGNMENT_NAMESPACE:-aks-sandbox-system}"
workload_namespace="${WORKLOAD_NAMESPACE:-opensandbox}"
lifecycle_url="${LIFECYCLE_URL:-}"
authz_address="${AUTHZ_ADDRESS:-}"
manage_forwards="${MANAGE_PORT_FORWARDS:-true}"
template_name="${SANDBOX_TEMPLATE:-python-kata-web-reader-v1}"
output_dir="${P0_OUTPUT_DIR:-$repo_root/demo-output/p0-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$output_dir"

token=""
sandbox_id=""
assignment_name=""
pod_name=""
forward_pids=()
forward_port=""

cleanup() {
  if [[ -n "$sandbox_id" && -n "$token" ]]; then
    curl -fsS -X DELETE \
      -H "Authorization: Bearer $token" \
      "$lifecycle_url/sandboxes/$sandbox_id" >/dev/null 2>&1 || true
  fi
  for pid in "${forward_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
}
trap cleanup EXIT

start_random_forward() {
  local remote_port="$1"
  local log_file
  log_file="$(mktemp)"
  kubectl -n "$assignment_namespace" port-forward svc/assignmentd \
    ":$remote_port" >"$log_file" 2>&1 &
  forward_pids+=("$!")
  local pid="${forward_pids[-1]}"
  for _ in {1..50}; do
    if ! kill -0 "$pid" 2>/dev/null; then
      cat "$log_file" >&2
      rm -f "$log_file"
      return 1
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
  return 1
}

start_managed_forwards() {
  for pid in "${forward_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  forward_pids=()
  start_random_forward 8080
  lifecycle_url="http://127.0.0.1:$forward_port/opensandbox"
  start_random_forward 9001
  authz_address="127.0.0.1:$forward_port"
}

if [[ "$manage_forwards" == "true" ]]; then
  start_managed_forwards
else
  lifecycle_url="${lifecycle_url:?set LIFECYCLE_URL when MANAGE_PORT_FORWARDS=false}"
  authz_address="${authz_address:?set AUTHZ_ADDRESS when MANAGE_PORT_FORWARDS=false}"
fi

assert_status() {
  local want="$1"
  local actual="$2"
  local label="$3"
  if [[ "$actual" != "$want" ]]; then
    echo "$label: got HTTP $actual, want $want" >&2
    exit 1
  fi
  printf 'PASS %-42s HTTP %s\n' "$label" "$actual"
}

echo "==> Caller authentication and idempotency"
token="$(kubectl -n "$assignment_namespace" create token assignmentd-harness \
  --audience aks-sandbox-lifecycle --duration 1h)"
wrong_token="$(kubectl -n "$assignment_namespace" create token assignmentd-harness \
  --audience wrong-audience --duration 10m)"

status="$(curl -sS -o /dev/null -w '%{http_code}' "$lifecycle_url/sandboxes")"
assert_status 401 "$status" "missing caller token rejected"

status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $wrong_token" "$lifecycle_url/sandboxes")"
assert_status 401 "$status" "wrong token audience rejected"

body="$(
  jq -n --arg template "$template_name" '{
    image: {uri: "attacker.invalid/forged:latest"},
    snapshotId: "forged-snapshot",
    entrypoint: ["sh", "-c", "sleep infinity"],
    resourceLimits: {cpu: "99", memory: "99Gi"},
    volumes: [{name: "forged"}],
    metadata: {"demo": "p0-live"},
    extensions: {
      "aks-sandbox.azure.com/template": $template,
      "aks-sandbox.azure.com/capabilityProfile": "forged"
    }
  }'
)"
status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $token" \
  -H "Content-Type: application/json" \
  --data "$body" "$lifecycle_url/sandboxes")"
assert_status 400 "$status" "missing idempotency key rejected"

idempotency_key="p0-live-$(date -u +%s)-$RANDOM"
curl -fsS \
  -H "Authorization: Bearer $token" \
  -H "Idempotency-Key: $idempotency_key" \
  -H "Content-Type: application/json" \
  --data "$body" "$lifecycle_url/sandboxes" |
  tee "$output_dir/create-response.json" >/dev/null
sandbox_id="$(jq -er '.id' "$output_dir/create-response.json")"

for _ in {1..180}; do
  assignment_name="$(
    kubectl -n "$assignment_namespace" get sandboxassignments \
      -l "aks-sandbox.azure.com/opensandbox-id=$sandbox_id" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  if [[ -n "$assignment_name" ]]; then
    ready="$(
      kubectl -n "$assignment_namespace" get sandboxassignment "$assignment_name" \
        -o json |
        jq -r '.status.conditions // [] | map(select(.type == "Ready")) | first.status // ""'
    )"
    if [[ "$ready" == "True" ]]; then
      break
    fi
  fi
  sleep 2
done
if [[ -z "$assignment_name" || "$ready" != "True" ]]; then
  echo "sandbox assignment did not become ready" >&2
  exit 1
fi

assignment_json="$(
  kubectl -n "$assignment_namespace" get sandboxassignment "$assignment_name" -o json
)"
pod_name="$(jq -er '.status.podRef.name' <<<"$assignment_json")"
logical_tenant="$(jq -er '.spec.logicalTenant' <<<"$assignment_json")"
resolved_template="$(jq -er '.spec.templateRef.name' <<<"$assignment_json")"
if [[ "$resolved_template" != "$template_name" || "$logical_tenant" != "tenant-a" ]]; then
  echo "trusted template boundary was not persisted" >&2
  exit 1
fi
if kubectl -n "$workload_namespace" get pod "$pod_name" -o json |
  jq -e '.spec.containers | any(.image == "attacker.invalid/forged:latest")' >/dev/null; then
  echo "forged image reached the sandbox Pod" >&2
  exit 1
fi
echo "PASS forged workload shape overwritten by immutable template"

retry_id="$(
  curl -fsS \
    -H "Authorization: Bearer $token" \
    -H "Idempotency-Key: $idempotency_key" \
    -H "Content-Type: application/json" \
    --data "$body" "$lifecycle_url/sandboxes" |
    jq -er '.id'
)"
if [[ "$retry_id" != "$sandbox_id" ]]; then
  echo "idempotent retry returned a different sandbox" >&2
  exit 1
fi
echo "PASS same idempotency key replayed the original sandbox"

different_body="$(jq '.metadata.demo = "different-intent"' <<<"$body")"
status="$(curl -sS -o /dev/null -w '%{http_code}' \
  -H "Authorization: Bearer $token" \
  -H "Idempotency-Key: $idempotency_key" \
  -H "Content-Type: application/json" \
  --data "$different_body" "$lifecycle_url/sandboxes")"
assert_status 409 "$status" "idempotency key intent conflict rejected"

echo "==> Replica and restart recovery"
victim="$(
  kubectl -n "$assignment_namespace" get pod -l app=assignmentd \
    -o jsonpath='{.items[0].metadata.name}'
)"
kubectl -n "$assignment_namespace" delete pod "$victim" --wait=false >/dev/null
kubectl -n "$assignment_namespace" rollout status deployment/assignmentd --timeout=180s >/dev/null
if [[ "$manage_forwards" == "true" ]]; then
  start_managed_forwards
fi
retry_id="$(
  curl -fsS \
    -H "Authorization: Bearer $token" \
    -H "Idempotency-Key: $idempotency_key" \
    -H "Content-Type: application/json" \
    --data "$body" "$lifecycle_url/sandboxes" |
    jq -er '.id'
)"
[[ "$retry_id" == "$sandbox_id" ]]
echo "PASS lifecycle replay survived assignmentd replica replacement"

kubectl -n "$workload_namespace" rollout restart deployment/opensandbox-server >/dev/null
kubectl -n "$workload_namespace" rollout status deployment/opensandbox-server --timeout=300s >/dev/null
status="$(curl -sS -o "$output_dir/get-after-restart.json" -w '%{http_code}' \
  -H "Authorization: Bearer $token" "$lifecycle_url/sandboxes/$sandbox_id")"
assert_status 200 "$status" "OpenSandbox metadata survived server restart"

echo "==> Forced egress and per-sandbox attribution"
kubectl apply -f deploy/governance/k8s/forced-egress-networkpolicy.yaml >/dev/null
sleep 10
container_name="$(
  kubectl -n "$workload_namespace" get pod "$pod_name" \
    -o jsonpath='{.spec.containers[0].name}'
)"
if kubectl -n "$workload_namespace" exec "$pod_name" -c "$container_name" -- \
  python -c 'import socket; socket.create_connection(("1.1.1.1",443),3)' \
  >"$output_dir/direct-tcp.txt" 2>&1; then
  echo "direct TCP egress unexpectedly succeeded" >&2
  exit 1
fi
echo "PASS direct TCP internet denied"

if kubectl -n "$workload_namespace" exec "$pod_name" -c "$container_name" -- \
  python -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"x",("1.1.1.1",53)); s.recvfrom(64)' \
  >"$output_dir/direct-udp.txt" 2>&1; then
  echo "direct UDP egress unexpectedly received a response" >&2
  exit 1
fi
echo "PASS direct UDP/DNS path denied"

if kubectl -n "$workload_namespace" exec "$pod_name" -c "$container_name" -- \
  python -c 'import socket; socket.getaddrinfo("example.com",443)' \
  >"$output_dir/direct-dns.txt" 2>&1; then
  echo "sandbox DNS unexpectedly succeeded" >&2
  exit 1
fi
echo "PASS sandbox DNS exfiltration path denied"

go run ./cmd/egress-probe \
  --assignment "$assignment_name" \
  --address "$authz_address" \
  --backend external-web \
  --method GET \
  --target https://example.com/docs |
  tee "$output_dir/mediated-allow.txt"
grep -q 'allowed:    true' "$output_dir/mediated-allow.txt"

go run ./cmd/egress-probe \
  --assignment "$assignment_name" \
  --address "$authz_address" \
  --backend external-web \
  --method GET \
  --target https://example.com/admin |
  tee "$output_dir/mediated-deny.txt"
grep -q 'allowed:    false' "$output_dir/mediated-deny.txt"

latest_event="$(
  kubectl -n "$assignment_namespace" get sandboxegressevents \
    --sort-by=.metadata.creationTimestamp -o json |
    jq -c --arg assignment "$assignment_name" \
      '[.items[] | select(.spec.assignmentRef.name == $assignment)] | last'
)"
expected_pod_uid="$(jq -er '.status.podRef.uid' <<<"$assignment_json")"
actual_pod_uid="$(jq -er '.spec.podUid' <<<"$latest_event")"
if [[ "$actual_pod_uid" != "$expected_pod_uid" ]]; then
  echo "egress event Pod UID attribution mismatch" >&2
  exit 1
fi
echo "$latest_event" | jq >"$output_dir/latest-egress-event.json"
echo "PASS mediated decision attributed to exact assignment and Pod UID"

echo "P0 live experiments passed; evidence: $output_dir"
