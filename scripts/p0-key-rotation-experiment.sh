#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

namespace="${ASSIGNMENT_NAMESPACE:-aks-sandbox-system}"
workload_namespace="${WORKLOAD_NAMESPACE:-opensandbox}"
output_dir="${P0_ROTATION_OUTPUT_DIR:-$repo_root/demo-output/p0-rotation-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$output_dir"

forward_pid=""
sandbox_id=""
original_key="$(
  kubectl -n "$namespace" get secret assignmentd-credential-broker \
    -o jsonpath='{.data.signing-key}' |
    base64 --decode
)"

cleanup() {
  local exit_code=$?
  if [[ -n "$sandbox_id" && -n "$forward_pid" ]]; then
    token="$(
      kubectl -n "$namespace" create token assignmentd-harness \
        --audience aks-sandbox-lifecycle --duration 10m 2>/dev/null || true
    )"
    curl -fsS -X DELETE \
      -H "Authorization: Bearer $token" \
      "http://127.0.0.1:19480/opensandbox/sandboxes/$sandbox_id" \
      >/dev/null 2>&1 || true
  fi
  kubectl -n "$namespace" create secret generic assignmentd-credential-broker \
    --from-literal=signing-key="$original_key" \
    --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null 2>&1 || true
  kubectl -n "$namespace" set env deployment/assignmentd \
    ASSIGNMENTD_BROKER_SIGNING_KEY_ID- \
    ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY- \
    ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY_ID- >/dev/null 2>&1 || true
  kubectl -n "$namespace" rollout restart deployment/assignmentd >/dev/null 2>&1 || true
  kubectl -n "$namespace" rollout status deployment/assignmentd \
    --timeout=180s >/dev/null 2>&1 || true
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2>/dev/null || true
  fi
  unset original_key
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

start_forward() {
  if [[ -n "$forward_pid" ]]; then
    kill "$forward_pid" 2>/dev/null || true
  fi
  kubectl -n "$namespace" port-forward svc/assignmentd 19480:8080 \
    >"$output_dir/port-forward.log" 2>&1 &
  forward_pid="$!"
  for _ in {1..50}; do
    if timeout 1 bash -c '</dev/tcp/127.0.0.1/19480' 2>/dev/null; then
      return
    fi
    sleep 0.2
  done
  cat "$output_dir/port-forward.log" >&2
  return 1
}

echo "==> Issue a credential under the old signing key ID"
kubectl -n "$namespace" set env deployment/assignmentd \
  ASSIGNMENTD_BROKER_SIGNING_KEY_ID=old >/dev/null
kubectl -n "$namespace" rollout status deployment/assignmentd --timeout=180s >/dev/null
start_forward

lifecycle_token="$(
  kubectl -n "$namespace" create token assignmentd-harness \
    --audience aks-sandbox-lifecycle --duration 30m
)"
sandbox_id="$(
  curl -fsS -X POST \
    -H "Authorization: Bearer $lifecycle_token" \
    -H "Idempotency-Key: rotation-$(date +%s%N)" \
    -H "Content-Type: application/json" \
    --data '{"extensions":{"aks-sandbox.azure.com/template":"python-kata-web-reader-v1"}}' \
    http://127.0.0.1:19480/opensandbox/sandboxes |
    jq -r .id
)"

assignment_name=""
pod_name=""
for _ in {1..90}; do
  assignment_name="$(
    kubectl -n "$namespace" get sandboxassignments \
      -l "aks-sandbox.azure.com/opensandbox-id=$sandbox_id" \
      -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true
  )"
  if [[ -n "$assignment_name" ]]; then
    pod_name="$(
      kubectl -n "$namespace" get sandboxassignment "$assignment_name" \
        -o jsonpath='{.status.podRef.name}' 2>/dev/null || true
    )"
  fi
  [[ -n "$pod_name" ]] && break
  sleep 2
done
[[ -n "$pod_name" ]]

pod_uid="$(kubectl -n "$workload_namespace" get pod "$pod_name" -o jsonpath='{.metadata.uid}')"
pod_ip="$(kubectl -n "$workload_namespace" get pod "$pod_name" -o jsonpath='{.status.podIP}')"
service_account="$(
  kubectl -n "$workload_namespace" get pod "$pod_name" \
    -o jsonpath='{.spec.serviceAccountName}'
)"
identity_token="$(
  kubectl -n "$workload_namespace" create token "$service_account" \
    --audience aks-sandbox-capability-gateway \
    --duration 10m \
    --bound-object-kind Pod \
    --bound-object-name "$pod_name" \
    --bound-object-uid "$pod_uid"
)"
credential="$(
  jq -n \
    --arg token "$identity_token" \
    --arg task "rotation-$(date -u +%Y%m%dT%H%M%SZ)" \
    '{
      identityToken: $token,
      backend: "external-web",
      method: "GET",
      host: "example.com",
      path: "/docs",
      taskId: $task,
      ttlSeconds: 900
    }' |
    curl -fsS -X POST \
      -H "Content-Type: application/json" \
      --data-binary @- \
      http://127.0.0.1:19480/broker/v1/credentials |
    jq -r .credential
)"
[[ -n "$credential" ]]
credential_kid="$(
  python3 -c 'import base64,json,sys; part=sys.argv[1].split(".")[0]; print(json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))["kid"])' \
    "$credential"
)"
[[ "$credential_kid" == "old" ]]

echo "==> Rotate to a new key while retaining the old key for grace"
new_key="$(openssl rand -hex 32)"
kubectl -n "$namespace" create secret generic assignmentd-credential-broker \
  --from-literal=signing-key="$new_key" \
  --dry-run=client -o yaml |
  kubectl apply -f - >/dev/null
kubectl -n "$namespace" set env deployment/assignmentd \
  ASSIGNMENTD_BROKER_SIGNING_KEY_ID=new \
  ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY="$original_key" \
  ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY_ID=old >/dev/null
kubectl -n "$namespace" rollout restart deployment/assignmentd >/dev/null
kubectl -n "$namespace" rollout status deployment/assignmentd --timeout=180s >/dev/null
start_forward

configured_previous="$(
  kubectl -n "$namespace" get deployment assignmentd -o json |
    jq -r '.spec.template.spec.containers[0].env[]
      | select(.name == "ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY")
      | .value'
)"
[[ "$configured_previous" == "$original_key" ]]
configured_current_id="$(
  kubectl -n "$namespace" get deployment assignmentd -o json |
    jq -r '.spec.template.spec.containers[0].env[]
      | select(.name == "ASSIGNMENTD_BROKER_SIGNING_KEY_ID")
      | .value'
)"
configured_previous_id="$(
  kubectl -n "$namespace" get deployment assignmentd -o json |
    jq -r '.spec.template.spec.containers[0].env[]
      | select(.name == "ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY_ID")
      | .value'
)"
printf 'credentialKid=%s\ncurrentKeyId=%s\npreviousKeyId=%s\n' \
  "$credential_kid" "$configured_current_id" "$configured_previous_id" \
  >"$output_dir/rotation-config.txt"

grace_status="$(
  curl -sS -o "$output_dir/grace-response.json" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $credential" \
    http://127.0.0.1:19480/broker/v1/verify
)"
[[ "$grace_status" == "200" ]]

echo "==> Remove the old key and reject the stale credential"
kubectl -n "$namespace" set env deployment/assignmentd \
  ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY- \
  ASSIGNMENTD_BROKER_PREVIOUS_SIGNING_KEY_ID- >/dev/null
kubectl -n "$namespace" rollout restart deployment/assignmentd >/dev/null
kubectl -n "$namespace" rollout status deployment/assignmentd --timeout=180s >/dev/null
start_forward

stale_status="$(
  curl -sS -o "$output_dir/stale-response.txt" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $credential" \
    http://127.0.0.1:19480/broker/v1/verify
)"
[[ "$stale_status" == "401" ]]
printf 'graceStatus=%s\nstaleStatus=%s\nassignment=%s\nsandbox=%s\n' \
  "$grace_status" "$stale_status" "$assignment_name" "$sandbox_id" |
  tee "$output_dir/summary.txt"

unset credential identity_token lifecycle_token new_key
echo "P0 key rotation experiment passed; evidence: $output_dir"
