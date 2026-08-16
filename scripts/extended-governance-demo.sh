#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
export PATH="$HOME/.local/bin:$PATH"

assignment_namespace="aks-sandbox-system"
workload_namespace="opensandbox"
run_snapshot="${RUN_SNAPSHOT:-true}"
opencode_model="${OPENCODE_MODEL:-opencode/big-pickle}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
task_prefix="extended-${timestamp,,}"
output_dir="${EXTENDED_DEMO_OUTPUT_DIR:-$repo_root/demo-output/$timestamp-extended}"
mkdir -p "$output_dir"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

cleanup_task_evidence() {
  local plural="$1"
  local task_id="$2"
  kubectl -n "$assignment_namespace" get "$plural" -o json 2>/dev/null |
    jq -r --arg task "$task_id" '.items[] | select(.spec.taskId == $task) | .metadata.name' |
    while IFS= read -r name; do
      if [[ -n "$name" ]]; then
        kubectl -n "$assignment_namespace" delete "$plural" "$name" --ignore-not-found >/dev/null
      fi
    done
}

for command in kubectl go jq openssl opencode grep; do
  require_command "$command"
done

validation_task="${task_prefix}-validation"
credential_task="${task_prefix}-credential"
snapshot_task="${task_prefix}-snapshot"

cleanup() {
  local exit_code=$?
  cleanup_task_evidence sandboxvalidationruns "$validation_task" || exit_code=1
  cleanup_task_evidence sandboxcredentialevents "$credential_task" || exit_code=1
  cleanup_task_evidence sandboxcredentialevents "$snapshot_task" || exit_code=1
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo "==> Applying extended governance APIs and policies"
kubectl apply -f deploy/governance/k8s/crds.yaml
kubectl apply -f deploy/governance/k8s/capability-bundles.yaml
kubectl apply -f deploy/governance/k8s/sandbox-templates.yaml
kubectl apply -f deploy/governance/k8s/tenant-policies.yaml
kubectl apply -f deploy/governance/k8s/sandbox-serviceaccount.yaml

echo "==> Ensuring the broker has a generated signing key"
if ! kubectl -n "$assignment_namespace" get secret assignmentd-credential-broker >/dev/null 2>&1; then
  signing_key="$(openssl rand -hex 32)"
  kubectl -n "$assignment_namespace" create secret generic assignmentd-credential-broker \
    --from-literal=signing-key="$signing_key" \
    --dry-run=client -o yaml |
    kubectl apply -f - >/dev/null
  unset signing_key
fi

if ! kubectl -n "$assignment_namespace" get deployment assignmentd \
  -o json |
  jq -e '.spec.template.spec.containers[0].env | any(.name == "ASSIGNMENTD_BROKER_SIGNING_KEY")' \
  >/dev/null; then
  kubectl -n "$assignment_namespace" patch deployment assignmentd --type=json -p='[
    {
      "op":"add",
      "path":"/spec/template/spec/containers/0/env/-",
      "value":{
        "name":"ASSIGNMENTD_BROKER_SIGNING_KEY",
        "valueFrom":{
          "secretKeyRef":{
            "name":"assignmentd-credential-broker",
            "key":"signing-key"
          }
        }
      }
    }
  ]' >/dev/null
fi
kubectl -n "$assignment_namespace" rollout restart deployment/assignmentd >/dev/null
kubectl -n "$assignment_namespace" rollout status deployment/assignmentd --timeout=180s

echo "==> Cluster readiness contract"
go run ./cmd/sandbox-doctor --output json |
  tee "$output_dir/doctor.json"
jq -e '.ready == true' "$output_dir/doctor.json" >/dev/null

echo "==> Tenant admission budgets"
kubectl -n "$assignment_namespace" get sandboxtenantpolicies \
  -o custom-columns='NAME:.metadata.name,TENANT:.spec.logicalTenant,NAMESPACE:.spec.workloadNamespace,CONCURRENT:.spec.maxConcurrentSandboxes,LIFETIME:.spec.maxLifetimeSeconds,ACCESS:.spec.maxAccessRequestDurationSeconds,CPU:.spec.maxCpu,MEMORY:.spec.maxMemory' |
  tee "$output_dir/tenant-policies.txt"

echo "==> Automatic test selection and hashed validation evidence"
opencode run \
  --agent sandbox-only \
  --model "$opencode_model" \
  "Use validate_change with template python-kata-reader-v2, task ID ${validation_task}, repository https://github.com/chrischangcode/opensandbox-aks-governance-poc, source revision demo-${timestamp}, and changed paths [internal/assignment/authz/checker.go]. Report the selected command, sandbox and Pod identity, result hashes, and cleanup." |
  tee "$output_dir/validation.txt"
! grep -Fq '✗ sandbox_governance_validate_change' "$output_dir/validation.txt"
kubectl -n "$assignment_namespace" get sandboxvalidationruns -o json |
  jq -e --arg task "$validation_task" \
    '[.items[] | select(.spec.taskId == $task and .status.state == "Succeeded" and .status.cleanedUp == true)] | length == 1' \
    >/dev/null

echo "==> Brokered short-lived credential with revocation"
opencode run \
  --agent sandbox-only \
  --model "$opencode_model" \
  "Use exercise_brokered_credential with template python-kata-web-reader-v1, task ID ${credential_task}, backend external-web, method GET, target https://example.com/docs, and TTL 300. Do not expose the credential. Report issuance scope, use, revocation, replay denial, and cleanup." |
  tee "$output_dir/credential.txt"
! grep -Fq '✗ sandbox_governance_exercise_brokered_credential' "$output_dir/credential.txt"
kubectl -n "$assignment_namespace" get sandboxcredentialevents -o json |
  jq -e --arg task "$credential_task" \
    '[.items[] | select(.spec.taskId == $task) | .spec.action] as $actions |
      ($actions | index("issued") != null) and
      ($actions | index("used") != null) and
      ($actions | index("revoked") != null)' \
    >/dev/null

if [[ "$run_snapshot" == "true" ]]; then
  echo "==> Snapshot pause/resume with state continuity and authority rotation"
  opencode run \
    --agent sandbox-only \
    --model "$opencode_model" \
    "Use snapshot_pause_resume with template python-kata-web-reader-v1, task ID ${snapshot_task}, backend external-web, method GET, and target https://example.com/docs. Report preserved state, old and new Pod UIDs, rejection of the pre-snapshot credential, and cleanup." |
    tee "$output_dir/snapshot.txt"
  ! grep -Fq '✗ sandbox_governance_snapshot_pause_resume' "$output_dir/snapshot.txt"
  kubectl -n "$assignment_namespace" get sandboxcredentialevents -o json |
    jq -e --arg task "$snapshot_task" \
      '[.items[] | select(.spec.taskId == $task and .spec.action == "issued")] | length == 1' \
      >/dev/null
fi

echo "==> Durable credential-free evidence"
kubectl -n "$assignment_namespace" get sandboxvalidationruns \
  -o custom-columns='NAME:.metadata.name,STATE:.status.state,TASK:.spec.taskId,REVISION:.spec.sourceRevision,SANDBOX:.spec.sandboxId,CLEANED:.status.cleanedUp' |
  tee "$output_dir/validation-evidence.txt"
kubectl -n "$assignment_namespace" get sandboxcredentialevents \
  -o custom-columns='TIME:.spec.timestamp,ACTION:.spec.action,TASK:.spec.taskId,SANDBOX:.spec.sandboxId,TARGET:.spec.host,EXPIRES:.spec.expiresAt' |
  tee "$output_dir/credential-audit.txt"

echo "Extended governance demonstration completed. Evidence: $output_dir"
