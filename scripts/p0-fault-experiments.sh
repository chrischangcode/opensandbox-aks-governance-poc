#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

assignment_namespace="${ASSIGNMENT_NAMESPACE:-aks-sandbox-system}"
output_dir="${P0_FAULT_OUTPUT_DIR:-$repo_root/demo-output/p0-fault-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$output_dir"

forward_pids=()
sandbox_ids=()
role_backup="$(mktemp)"

restore_audit_permission() {
  if ! kubectl auth can-i create sandboxegressevents.aks-sandbox.azure.com \
    -n "$assignment_namespace" \
    --as "system:serviceaccount:$assignment_namespace:assignmentd" |
    grep -qx yes; then
    kubectl -n "$assignment_namespace" patch role assignmentd --type=json \
      -p='[{"op":"add","path":"/rules/9/verbs/0","value":"create"}]' >/dev/null
  fi
}

cleanup() {
  local exit_code=$?
  kubectl apply -f "$role_backup" >/dev/null 2>&1 || true
  restore_audit_permission || true
  local token
  token="$(kubectl -n "$assignment_namespace" create token assignmentd-harness \
    --audience aks-sandbox-lifecycle --duration 10m 2>/dev/null || true)"
  for sandbox_id in "${sandbox_ids[@]}"; do
    if [[ -n "$token" && -n "$sandbox_id" ]]; then
      curl -fsS -X DELETE \
        -H "Authorization: Bearer $token" \
        "http://127.0.0.1:19180/opensandbox/sandboxes/$sandbox_id" \
        >/dev/null 2>&1 || true
    fi
  done
  for pid in "${forward_pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  rm -f "$role_backup"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

start_forward() {
  local port="$1"
  local target="$2"
  local remote_port="$3"
  local log_file="$output_dir/port-forward-${port}.log"
  kubectl -n "$assignment_namespace" port-forward "$target" "$port:$remote_port" \
    >"$log_file" 2>&1 &
  forward_pids+=("$!")
  for _ in {1..50}; do
    if timeout 1 bash -c "</dev/tcp/127.0.0.1/$port" 2>/dev/null; then
      return
    fi
    sleep 0.2
  done
  cat "$log_file" >&2
  return 1
}

create_sandbox() {
  local port="$1"
  local key="$2"
  local output="$3"
  local token="$4"
  curl -sS -o "$output" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $token" \
    -H "Idempotency-Key: $key" \
    -H "Content-Type: application/json" \
    --data '{"extensions":{"aks-sandbox.azure.com/template":"python-kata-web-reader-v1"}}' \
    "http://127.0.0.1:$port/opensandbox/sandboxes"
}

wait_for_assignment() {
  local sandbox_id="$1"
  local assignment_name=""
  for _ in {1..90}; do
    assignment_name="$(
      kubectl -n "$assignment_namespace" get sandboxassignments \
        -l "aks-sandbox.azure.com/opensandbox-id=$sandbox_id" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
    )"
    if [[ -n "$assignment_name" ]] &&
      [[ -n "$(kubectl -n "$assignment_namespace" get sandboxassignment "$assignment_name" \
        -o jsonpath='{.status.podRef.name}' 2>/dev/null || true)" ]]; then
      printf '%s' "$assignment_name"
      return
    fi
    sleep 2
  done
  return 1
}

wait_for_zero_assignments() {
  for _ in {1..90}; do
    if [[ "$(kubectl -n "$assignment_namespace" get sandboxassignments \
      -o jsonpath='{.items}' 2>/dev/null)" == "[]" ]]; then
      return
    fi
    sleep 2
  done
  echo "sandbox assignments did not drain before the next experiment" >&2
  return 1
}

kubectl -n "$assignment_namespace" get role assignmentd -o yaml >"$role_backup"
start_forward 19180 svc/assignmentd 8080
start_forward 19101 svc/assignmentd 9001
wait_for_zero_assignments

token="$(
  kubectl -n "$assignment_namespace" create token assignmentd-harness \
    --audience aks-sandbox-lifecycle --duration 30m
)"

echo "==> Audit persistence outage fails closed"
audit_body="$output_dir/audit-create.json"
audit_status="$(create_sandbox 19180 "audit-fault-$(date +%s)" "$audit_body" "$token")"
[[ "$audit_status" == "200" || "$audit_status" == "202" ]]
audit_sandbox="$(jq -r .id "$audit_body")"
sandbox_ids+=("$audit_sandbox")
audit_assignment="$(wait_for_assignment "$audit_sandbox")"

go run ./cmd/egress-probe \
  --assignment "$audit_assignment" \
  --address 127.0.0.1:19101 \
  --backend external-web \
  --method GET \
  --target https://example.com/docs |
  tee "$output_dir/audit-before.txt"
grep -q 'allowed:    true' "$output_dir/audit-before.txt"

kubectl -n "$assignment_namespace" patch role assignmentd --type=json \
  -p='[{"op":"remove","path":"/rules/9/verbs/0"}]' >/dev/null
sleep 2
go run ./cmd/egress-probe \
  --assignment "$audit_assignment" \
  --address 127.0.0.1:19101 \
  --backend external-web \
  --method GET \
  --target https://example.com/docs |
  tee "$output_dir/audit-after.txt"
grep -q 'allowed:    false' "$output_dir/audit-after.txt"
restore_audit_permission

curl -fsS -X DELETE \
  -H "Authorization: Bearer $token" \
  "http://127.0.0.1:19180/opensandbox/sandboxes/$audit_sandbox" >/dev/null
sandbox_ids=()

wait_for_zero_assignments

echo "==> Distributed tenant admission serializes across replicas"
mapfile -t assignmentd_pods < <(
  kubectl -n "$assignment_namespace" get pods -l app=assignmentd \
    -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}'
)
[[ "${#assignmentd_pods[@]}" -ge 2 ]]
start_forward 19280 "pod/${assignmentd_pods[0]}" 8080
start_forward 19281 "pod/${assignmentd_pods[1]}" 8080

pids=()
for i in {1..6}; do
  port=19280
  if ((i % 2 == 0)); then
    port=19281
  fi
  (
    create_sandbox "$port" "concurrent-${i}-$(date +%s%N)" \
      "$output_dir/concurrent-${i}.json" "$token" \
      >"$output_dir/concurrent-${i}.status"
  ) &
  pids+=("$!")
done
for pid in "${pids[@]}"; do
  wait "$pid"
done

accepted=0
rejected=0
for i in {1..6}; do
  status="$(cat "$output_dir/concurrent-${i}.status")"
  case "$status" in
    200|202)
      accepted=$((accepted + 1))
      sandbox_id="$(jq -r .id "$output_dir/concurrent-${i}.json")"
      sandbox_ids+=("$sandbox_id")
      ;;
    403|429)
      rejected=$((rejected + 1))
      ;;
    *)
      echo "unexpected concurrent create status $status" >&2
      cat "$output_dir/concurrent-${i}.json" >&2
      exit 1
      ;;
  esac
done
printf 'accepted=%d\nrejected=%d\n' "$accepted" "$rejected" |
  tee "$output_dir/concurrent-summary.txt"
[[ "$accepted" -eq 4 && "$rejected" -eq 2 ]]

echo "==> Controller recovers an ambiguous post-create operation"
recovery_sandbox="${sandbox_ids[0]}"
recovery_assignment="$(wait_for_assignment "$recovery_sandbox")"
kubectl -n "$assignment_namespace" annotate sandboxassignment "$recovery_assignment" \
  aks-sandbox.azure.com/opensandbox-id- >/dev/null
kubectl -n "$assignment_namespace" label sandboxassignment "$recovery_assignment" \
  aks-sandbox.azure.com/opensandbox-id- >/dev/null
for _ in {1..60}; do
  recovered="$(
    kubectl -n "$assignment_namespace" get sandboxassignment "$recovery_assignment" \
      -o jsonpath='{.metadata.annotations.aks-sandbox\.azure\.com/opensandbox-id}' \
      2>/dev/null || true
  )"
  if [[ "$recovered" == "$recovery_sandbox" ]]; then
    break
  fi
  sleep 1
done
[[ "$recovered" == "$recovery_sandbox" ]]
printf 'assignment=%s\nrecoveredSandbox=%s\n' \
  "$recovery_assignment" "$recovered" |
  tee "$output_dir/recovery-summary.txt"

echo "P0 fault experiments passed; evidence: $output_dir"
