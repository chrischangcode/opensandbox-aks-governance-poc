#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

pause=true
case "${1:-}" in
  "")
    ;;
  --no-pause)
    pause=false
    ;;
  *)
    echo "usage: $0 [--no-pause]" >&2
    exit 2
    ;;
esac

export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
export PATH="$HOME/.local/bin:$PATH"

assignment_namespace="aks-sandbox-system"
workload_namespace="opensandbox"
assignment_port="${ASSIGNMENT_PORT:-19080}"
authz_port="${AUTHZ_PORT:-19001}"
requester_port="${REQUESTER_PORT:-18081}"
admin_port="${ADMIN_PORT:-18082}"
opencode_model="${OPENCODE_MODEL:-opencode/big-pickle}"
capture_screenshots="${CAPTURE_SCREENSHOTS:-true}"
run_opencode="${RUN_OPENCODE:-true}"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
run_suffix="$(printf '%s' "$timestamp" | tr '[:upper:]' '[:lower:]')"
output_dir="${LIVE_DEMO_OUTPUT_DIR:-$repo_root/demo-output/$timestamp}"
mkdir -p "$output_dir"

pids=()
sandbox_id=""
assignment_name=""
pod_name=""
event_name=""
allowed_event=""
request_name=""
bundle_sandbox_id=""
bundle_assignment_name=""
bundle_pod_name=""
bundle_event_name=""
bundle_sandbox_cleaned=false
admin_bundle_name="demo-web-reader-$run_suffix"
admin_template_name="demo-python-web-reader-$run_suffix"
admin_bundle_created=false
admin_template_created=false

delete_sandbox_and_wait() {
  local id="$1"
  local pod="$2"
  if ! curl -fsS -X DELETE \
    "http://127.0.0.1:${assignment_port}/opensandbox/sandboxes/${id}" \
    >/dev/null 2>&1; then
    kubectl -n "$assignment_namespace" delete sandboxassignments \
      -l "aks-sandbox.azure.com/opensandbox-id=${id}" \
      --ignore-not-found >/dev/null 2>&1 || true
  fi
  for _ in {1..90}; do
    assignment_exists=false
    workload_exists=false
    pod_exists=false
    if kubectl -n "$assignment_namespace" get sandboxassignments \
      -l "aks-sandbox.azure.com/opensandbox-id=${id}" \
      -o name 2>/dev/null | grep -q .; then
      assignment_exists=true
    fi
    if kubectl -n "$workload_namespace" get batchsandbox "$id" \
      >/dev/null 2>&1; then
      workload_exists=true
    fi
    if [[ -n "$pod" ]] &&
      kubectl -n "$workload_namespace" get pod "$pod" \
        >/dev/null 2>&1; then
      pod_exists=true
    fi
    if [[ "$assignment_exists" == "false" &&
      "$workload_exists" == "false" &&
      "$pod_exists" == "false" ]]; then
      echo "Cleanup confirmed for $id: assignment, workload, and Pod are absent."
      return 0
    fi
    sleep 1
  done
  echo "Cleanup did not complete for sandbox $id" >&2
  return 1
}

cleanup() {
  local exit_code=$?
  if [[ -n "$sandbox_id" ]]; then
    delete_sandbox_and_wait "$sandbox_id" "$pod_name" || exit_code=1
  fi
  if [[ -n "$bundle_sandbox_id" && "$bundle_sandbox_cleaned" != "true" ]]; then
    delete_sandbox_and_wait \
      "$bundle_sandbox_id" "$bundle_pod_name" || exit_code=1
  fi
  if [[ -n "$request_name" ]]; then
    kubectl -n "$assignment_namespace" delete sandboxaccessrequest \
      "$request_name" --ignore-not-found >/dev/null 2>&1 || exit_code=1
  fi
  for event in "$event_name" "$allowed_event" "$bundle_event_name"; do
    if [[ -n "$event" ]]; then
      kubectl -n "$assignment_namespace" delete sandboxegressevent \
        "$event" --ignore-not-found >/dev/null 2>&1 || exit_code=1
    fi
  done
  if [[ "$admin_template_created" == "true" ]]; then
    kubectl -n "$assignment_namespace" delete sandboxtemplate \
        "$admin_template_name" --ignore-not-found >/dev/null 2>&1 || exit_code=1
  fi
  if [[ "$admin_bundle_created" == "true" ]]; then
    kubectl -n "$assignment_namespace" delete capabilitybundle \
        "$admin_bundle_name" --ignore-not-found >/dev/null 2>&1 || exit_code=1
  fi
  for pid in "${pids[@]}"; do
    kill "$pid" 2>/dev/null || true
  done
  wait "${pids[@]}" 2>/dev/null || true
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

port_is_open() {
  timeout 1 bash -c "</dev/tcp/127.0.0.1/$1" 2>/dev/null
}

require_free_port() {
  if port_is_open "$1"; then
    echo "local port $1 is already occupied" >&2
    exit 1
  fi
}

start_background() {
  local name="$1"
  shift
  "$@" >"$output_dir/${name}.log" 2>&1 &
  pids+=("$!")
}

wait_for_port() {
  local port="$1"
  local name="$2"
  for _ in {1..60}; do
    if port_is_open "$port"; then
      return
    fi
    sleep 0.5
  done
  echo "$name did not open port $port; see $output_dir/${name}.log" >&2
  exit 1
}

wait_for_http() {
  local url="$1"
  local name="$2"
  for _ in {1..60}; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return
    fi
    sleep 0.5
  done
  echo "$name did not become ready at $url" >&2
  exit 1
}

url_encode() {
  jq -sRr @uri
}

create_from_template() {
  local template_name="$1"
  local template
  local body
  template="$(
    kubectl -n "$assignment_namespace" get sandboxtemplate \
      "$template_name" -o json
  )"
  if [[ "$(jq -r '.spec.enabled' <<<"$template")" != "true" ]]; then
    echo "sandbox template $template_name is disabled" >&2
    return 1
  fi
  body="$(
    jq '{
      image: {uri: .spec.image},
      entrypoint: .spec.entrypoint,
      timeout: .spec.timeoutSeconds,
      resourceLimits: .spec.resources,
      metadata: {
        "aks-sandbox.azure.com/demo": "live-replay",
        "aks-sandbox.azure.com/template": .metadata.name
      },
      extensions: {
        "aks-sandbox.azure.com/capabilityProfile": .spec.capabilityBundleRef.name
      }
    }' <<<"$template"
  )"
  curl -fsS \
    -H 'Content-Type: application/json' \
    --data "$body" \
    "http://127.0.0.1:${assignment_port}/opensandbox/sandboxes" |
    jq -er '.id'
}

wait_for_assignment() {
  local id="$1"
  local assignment_json
  local ready
  for _ in {1..180}; do
    assignment_json="$(
      kubectl -n "$assignment_namespace" get sandboxassignments \
        -l "aks-sandbox.azure.com/opensandbox-id=${id}" \
        -o json
    )"
    ready="$(
      jq -r '
        .items[0].status.conditions // []
        | map(select(.type == "Ready"))
        | first.status // empty
      ' <<<"$assignment_json"
    )"
    if [[ "$ready" == "True" ]]; then
      printf '%s' "$assignment_json"
      return
    fi
    sleep 1
  done
  echo "sandbox assignment did not become ready for $id" >&2
  return 1
}

capture_page() {
  local url="$1"
  local file="$2"
  local full_page="${3:-true}"
  local height="${4:-1000}"
  if [[ "$capture_screenshots" != "true" ]]; then
    return
  fi
  require_command npx
  local args=(
    playwright screenshot
    --browser chromium
    --viewport-size="1440,${height}"
    --wait-for-timeout=2000
  )
  if [[ "$full_page" == "true" ]]; then
    args+=(--full-page)
  fi
  npx --yes "${args[@]}" "$url" "$output_dir/$file" \
    >"$output_dir/${file%.png}-capture.log" 2>&1 || {
      echo "Screenshot failed; run 'npx playwright install chromium' first." >&2
      exit 1
    }
  test -s "$output_dir/$file"
}

for command in kubectl curl jq go timeout grep sed column; do
  require_command "$command"
done
if [[ "$run_opencode" == "true" ]]; then
  require_command opencode
fi

for port in "$assignment_port" "$authz_port" "$requester_port" "$admin_port"; do
  require_free_port "$port"
done

echo "==> Verifying cluster prerequisites"
kubectl get runtimeclass kata-optimized
kubectl -n "$assignment_namespace" get deployment assignmentd >/dev/null
kubectl -n "$workload_namespace" get service opensandbox-server >/dev/null

echo "==> Applying immutable governance definitions"
kubectl apply -f deploy/governance/k8s/crds.yaml
kubectl apply -f deploy/governance/k8s/capability-bundles.yaml
kubectl apply -f deploy/governance/k8s/sandbox-templates.yaml
kubectl apply -f deploy/governance/k8s/sandbox-serviceaccount.yaml
kubectl rollout status deployment/assignmentd \
  -n "$assignment_namespace" --timeout=180s

echo "==> Starting loopback-only services"
start_background assignment-port-forward \
  kubectl --address 127.0.0.1 port-forward \
  -n "$assignment_namespace" svc/assignmentd \
  "${assignment_port}:8080" "${authz_port}:9001"
wait_for_port "$assignment_port" assignment-port-forward
wait_for_port "$authz_port" assignment-port-forward

start_background requester-dashboard \
  go run ./cmd/aks-sandbox-dashboard \
  --dev-auth \
  --dev-name "POC Requester" \
  --dev-object-id 00000000-0000-4000-8000-000000000010 \
  --dev-roles OpenSandbox.User \
  --listen "127.0.0.1:${requester_port}" \
  --redirect-uri "http://127.0.0.1:${requester_port}/dashboard/auth/redirect/" \
  --kubeconfig "$KUBECONFIG" \
  --opensandbox-namespace "$workload_namespace" \
  --lifecycle-endpoint "http://127.0.0.1:${assignment_port}/opensandbox" \
  --capability-profile team-a-reader \
  --cookie-secure=false

start_background admin-dashboard \
  go run ./cmd/aks-sandbox-dashboard \
  --dev-auth \
  --dev-name "POC Administrator" \
  --dev-object-id 00000000-0000-4000-8000-000000000020 \
  --dev-roles OpenSandbox.Admin \
  --listen "127.0.0.1:${admin_port}" \
  --redirect-uri "http://127.0.0.1:${admin_port}/dashboard/auth/redirect/" \
  --kubeconfig "$KUBECONFIG" \
  --opensandbox-namespace "$workload_namespace" \
  --lifecycle-endpoint "http://127.0.0.1:${assignment_port}/opensandbox" \
  --capability-profile team-a-reader \
  --cookie-secure=false

wait_for_http "http://127.0.0.1:${requester_port}/dashboard/" requester-dashboard
wait_for_http "http://127.0.0.1:${admin_port}/dashboard/admin" admin-dashboard

printf '\nRequester: http://127.0.0.1:%s/dashboard/\n' "$requester_port"
printf 'Access:    http://127.0.0.1:%s/dashboard/access\n' "$requester_port"
printf 'Admin:     http://127.0.0.1:%s/dashboard/admin\n\n' "$admin_port"

echo "==> Pre-encoding an exact capability through the administrator page"
admin_page="$(
  curl -fsS "http://127.0.0.1:${admin_port}/dashboard/admin"
)"
admin_csrf="$(
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' <<<"$admin_page" |
    head -1
)"
if [[ -z "$admin_csrf" ]]; then
  echo "administrator CSRF token was not found" >&2
  exit 1
fi
if kubectl -n "$assignment_namespace" get capabilitybundle \
  "$admin_bundle_name" >/dev/null 2>&1; then
  echo "demo capability bundle name already exists: $admin_bundle_name" >&2
  exit 1
fi
admin_bundle_created=true
encoded_csrf="$(printf '%s' "$admin_csrf" | url_encode)"
capability_body="csrf=${encoded_csrf}&name=${admin_bundle_name}&displayName=Live%20demo%20approved%20web%20reader&logicalTenant=tenant-a&team=web-readers&permissionLevel=reader&egressRules=external-web%20GET%20https%3A%2F%2Fexample.com%2Fdocs&allowedCommands="
capability_status="$(
  printf '%s' "$capability_body" |
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Origin: http://127.0.0.1:${admin_port}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- \
    "http://127.0.0.1:${admin_port}/dashboard/admin/bundles"
)"
if [[ "$capability_status" != "303" ]]; then
  echo "capability creation returned HTTP $capability_status" >&2
  exit 1
fi
unset admin_page admin_csrf encoded_csrf capability_body capability_status
kubectl -n "$assignment_namespace" get capabilitybundle \
  "$admin_bundle_name" >/dev/null

admin_page="$(
  curl -fsS "http://127.0.0.1:${admin_port}/dashboard/admin"
)"
admin_csrf="$(
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' <<<"$admin_page" |
    head -1
)"
if [[ -z "$admin_csrf" ]]; then
  echo "administrator CSRF token was not found" >&2
  exit 1
fi
if kubectl -n "$assignment_namespace" get sandboxtemplate \
  "$admin_template_name" >/dev/null 2>&1; then
  echo "demo sandbox template name already exists: $admin_template_name" >&2
  exit 1
fi
admin_template_created=true
encoded_csrf="$(printf '%s' "$admin_csrf" | url_encode)"
template_body="csrf=${encoded_csrf}&name=${admin_template_name}&displayName=Live%20demo%20Python%20web%20reader&description=Admin-created%20Kata%20sandbox%20with%20exact%20pre-authorized%20egress.&image=python%40sha256%3A876416ecde9aca2bcc90e1fb0c7a9500bbf749f5788b70f82d4c5a5c2357f8b4&entrypoint=%5B%22tail%22%2C%22-f%22%2C%22%2Fdev%2Fnull%22%5D&capabilityBundle=${admin_bundle_name}&cpu=500m&memory=512Mi&timeoutSeconds=1800&enabled=true"
template_status="$(
  printf '%s' "$template_body" |
  curl -sS -o /dev/null -w '%{http_code}' \
    -H "Origin: http://127.0.0.1:${admin_port}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- \
    "http://127.0.0.1:${admin_port}/dashboard/admin/templates"
)"
if [[ "$template_status" != "303" ]]; then
  echo "template creation returned HTTP $template_status" >&2
  exit 1
fi
unset admin_page admin_csrf encoded_csrf template_body template_status
kubectl -n "$assignment_namespace" get sandboxtemplate \
  "$admin_template_name" >/dev/null
echo "capability bundle CRD: $admin_bundle_name"
echo "sandbox template CRD:  $admin_template_name"

echo "==> Approved template"
kubectl -n "$assignment_namespace" get sandboxtemplates \
  -o custom-columns='NAME:.metadata.name,CAPABILITY:.spec.capabilityBundleRef.name,IMAGE:.spec.image,ENABLED:.spec.enabled'

if [[ "$run_opencode" == "true" ]]; then
  echo "==> OpenCode MCP connection"
  opencode mcp list | tee "$output_dir/opencode-mcp.txt"

  echo "==> Allowed OpenCode command in a fresh Kata sandbox"
  opencode run \
    --agent sandbox-only \
    --model "$opencode_model" \
    "List approved templates, then use python-kata-reader-v1 to run exactly: uname -a && python --version. Report the sandbox ID, assignment, capability bundle, runtime class, output, and confirmed cleanup." \
    | tee "$output_dir/opencode-allowed.txt"
  grep -q "kata-optimized" "$output_dir/opencode-allowed.txt"
  grep -Eq 'cleanedUp[`"]?:[[:space:]]*true' \
    "$output_dir/opencode-allowed.txt"

  echo "==> Denied OpenCode command"
  opencode run \
    --agent sandbox-only \
    --model "$opencode_model" \
    "Using python-kata-reader-v1, try to run exactly: id. Do not substitute another command. Report whether the capability boundary allowed it." \
    | tee "$output_dir/opencode-denied.txt"
  grep -q "command is not allowed by the capability bundle" \
    "$output_dir/opencode-denied.txt"
fi

echo "==> Template-provided egress requires no access request"
bundle_sandbox_id="$(create_from_template "$admin_template_name")"
bundle_assignment_json="$(wait_for_assignment "$bundle_sandbox_id")"
bundle_assignment_name="$(
  jq -er '.items[0].metadata.name' <<<"$bundle_assignment_json"
)"
bundle_pod_name="$(
  jq -er '.items[0].status.podRef.name' <<<"$bundle_assignment_json"
)"
echo "sandbox: $bundle_sandbox_id"
echo "assignment: $bundle_assignment_name"
sleep 3
go run ./cmd/egress-probe \
  --assignment "$bundle_assignment_name" \
  --address "127.0.0.1:${authz_port}" \
  --backend external-web \
  --target https://example.com/docs \
  | tee "$output_dir/egress-template-allowed.txt"
grep -q "allowed:    true" "$output_dir/egress-template-allowed.txt"

for _ in {1..30}; do
  bundle_event_name="$(
    kubectl -n "$assignment_namespace" get sandboxegressevents -o json |
      jq -r --arg sandbox "$bundle_sandbox_id" '
        [.items[]
          | select(.spec.sandboxId == $sandbox)
          | select(.spec.allowed == true)
          | select(.spec.decisionSource == "bundle")
          | select((.spec.accessRequestName // "") == "")]
        | sort_by(.metadata.creationTimestamp)
        | last.metadata.name // empty
      '
  )"
  [[ -n "$bundle_event_name" ]] && break
  sleep 1
done
if [[ -z "$bundle_event_name" ]]; then
  echo "bundle-authorized egress event was not persisted" >&2
  exit 1
fi
bundle_request_count="$(
  kubectl -n "$assignment_namespace" get sandboxaccessrequests -o json |
    jq --arg assignment "$bundle_assignment_name" '
      [.items[] | select(.spec.assignmentRef.name == $assignment)] | length
    '
)"
if [[ "$bundle_request_count" != "0" ]]; then
  echo "bundle-authorized sandbox unexpectedly has an access request" >&2
  exit 1
fi
echo "decision source: bundle"
echo "access requests: 0"
delete_sandbox_and_wait "$bundle_sandbox_id" "$bundle_pod_name"
bundle_sandbox_cleaned=true

echo "==> Creating the request-gated egress sandbox"
sandbox_id="$(create_from_template python-kata-reader-v1)"
echo "sandbox: $sandbox_id"
assignment_json="$(wait_for_assignment "$sandbox_id")"
assignment_name="$(jq -er '.items[0].metadata.name' <<<"$assignment_json")"
pod_name="$(jq -er '.items[0].status.podRef.name' <<<"$assignment_json")"
echo "assignment: $assignment_name"

capture_page \
  "http://127.0.0.1:${requester_port}/dashboard/" \
  requester-dashboard.png

echo "==> Initial attributed egress decision"
go run ./cmd/egress-probe \
  --assignment "$assignment_name" \
  --address "127.0.0.1:${authz_port}" \
  --backend external-web \
  --target https://example.com/docs \
  | tee "$output_dir/egress-denied.txt"
grep -q "allowed:    false" "$output_dir/egress-denied.txt"

for _ in {1..30}; do
  event_name="$(
    kubectl -n "$assignment_namespace" get sandboxegressevents -o json |
      jq -r --arg sandbox "$sandbox_id" '
        [.items[]
          | select(.spec.sandboxId == $sandbox)
          | select(.spec.backend == "external-web")
          | select(.spec.method == "GET")
          | select(.spec.host == "example.com")
          | select(.spec.path == "/docs")
          | select(.spec.allowed == false)]
        | sort_by(.metadata.creationTimestamp)
        | last.metadata.name // empty
      '
  )"
  [[ -n "$event_name" ]] && break
  sleep 1
done
if [[ -z "$event_name" ]]; then
  echo "denied egress event was not persisted" >&2
  exit 1
fi
echo "denied event: $event_name"

capture_page \
  "http://127.0.0.1:${requester_port}/dashboard/access" \
  access-governance.png

echo "==> Requesting exact temporary access through the requester page"
requester_page="$(
  curl -fsS "http://127.0.0.1:${requester_port}/dashboard/access"
)"
requester_csrf="$(
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' <<<"$requester_page" |
    head -1
)"
if [[ -z "$requester_csrf" ]]; then
  echo "requester CSRF token was not found" >&2
  exit 1
fi
request_body="csrf=${requester_csrf}&eventName=${event_name}&durationMinutes=30&reason=Temporary%20access%20needed%20for%20the%20governed%20demonstration."
printf '%s' "$request_body" |
  curl -fsS -L \
    -H "Origin: http://127.0.0.1:${requester_port}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- \
    "http://127.0.0.1:${requester_port}/dashboard/access/requests" \
    >/dev/null
unset request_body requester_csrf

for _ in {1..30}; do
  request_name="$(
    kubectl -n "$assignment_namespace" get sandboxaccessrequests -o json |
      jq -r --arg assignment "$assignment_name" '
        [.items[]
          | select(.spec.assignmentRef.name == $assignment)
          | select(.spec.backend == "external-web")
          | select(.spec.method == "GET")
          | select(.spec.host == "example.com")
          | select(.spec.path == "/docs")]
        | sort_by(.metadata.creationTimestamp)
        | last.metadata.name // empty
      '
  )"
  [[ -n "$request_name" ]] && break
  sleep 1
done
if [[ -z "$request_name" ]]; then
  echo "access request was not created" >&2
  exit 1
fi
echo "access request: $request_name"

echo "==> Approving 15 minutes through the administrator page"
admin_page="$(
  curl -fsS "http://127.0.0.1:${admin_port}/dashboard/admin"
)"
admin_csrf="$(
  sed -n 's/.*name="csrf" value="\([^"]*\)".*/\1/p' <<<"$admin_page" |
    head -1
)"
if [[ -z "$admin_csrf" ]]; then
  echo "administrator CSRF token was not found" >&2
  exit 1
fi
approval_body="csrf=${admin_csrf}&durationMinutes=15&decisionReason=Approved%20for%20the%20exact%20demonstration%20target%20only."
printf '%s' "$approval_body" |
  curl -fsS -L \
    -H "Origin: http://127.0.0.1:${admin_port}" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-binary @- \
    "http://127.0.0.1:${admin_port}/dashboard/admin/requests/${request_name}/approve" \
    >/dev/null
unset approval_body admin_csrf

state="$(
  kubectl -n "$assignment_namespace" get sandboxaccessrequest "$request_name" \
    -o jsonpath='{.status.state}'
)"
if [[ "$state" != "Approved" ]]; then
  echo "access request state is $state, expected Approved" >&2
  exit 1
fi

echo "==> Repeating the exact egress decision"
go run ./cmd/egress-probe \
  --assignment "$assignment_name" \
  --address "127.0.0.1:${authz_port}" \
  --backend external-web \
  --target https://example.com/docs \
  | tee "$output_dir/egress-allowed.txt"
grep -q "allowed:    true" "$output_dir/egress-allowed.txt"

for _ in {1..30}; do
  allowed_event="$(
    kubectl -n "$assignment_namespace" get sandboxegressevents -o json |
      jq -r --arg sandbox "$sandbox_id" --arg request "$request_name" '
        [.items[]
          | select(.spec.sandboxId == $sandbox)
          | select(.spec.allowed == true)
          | select(.spec.decisionSource == "access-request")
          | select(.spec.accessRequestName == $request)]
        | sort_by(.metadata.creationTimestamp)
        | last.metadata.name // empty
      '
  )"
  [[ -n "$allowed_event" ]] && break
  sleep 1
done
if [[ -z "$allowed_event" ]]; then
  echo "allowed egress event was not persisted" >&2
  exit 1
fi
echo "allowed event: $allowed_event"

echo "==> Attributed egress telemetry"
kubectl -n "$assignment_namespace" get sandboxegressevents -o json |
  jq -r --arg sandbox "$sandbox_id" --arg bundleSandbox "$bundle_sandbox_id" '
    ["TIME", "SANDBOX", "TENANT", "TEAM", "TARGET", "PATH", "ALLOWED", "SOURCE", "REQUEST"],
    (.items
      | map(select(
          .spec.sandboxId == $sandbox or
          .spec.sandboxId == $bundleSandbox
        ))
      | sort_by(.metadata.creationTimestamp)[]
      | [
          .spec.timestamp,
          .spec.sandboxId,
          .spec.logicalTenant,
          .spec.team,
          .spec.host,
          .spec.path,
          (.spec.allowed | tostring),
          .spec.decisionSource,
          (.spec.accessRequestName // "<none>")
        ])
    | @tsv
  ' |
  column -t -s $'\t' \
  | tee "$output_dir/egress-events.txt"

capture_page \
  "http://127.0.0.1:${admin_port}/dashboard/admin#create-capability-boundary" \
  admin-capabilities.png \
  false \
  700
capture_page \
  "http://127.0.0.1:${admin_port}/dashboard/admin#approved-templates" \
  admin-templates.png \
  false \
  430
capture_page \
  "http://127.0.0.1:${admin_port}/dashboard/admin#access-requests" \
  admin-approvals.png \
  false \
  280
capture_page \
  "http://127.0.0.1:${admin_port}/dashboard/admin#recent-egress-events" \
  egress-telemetry.png \
  false \
  520

cat <<EOF

Live demonstration complete.

Sandbox:       $sandbox_id
Assignment:    $assignment_name
Access request: $request_name
Admin bundle:   $admin_bundle_name
Admin template: $admin_template_name
Artifacts:     $output_dir

Requester: http://127.0.0.1:${requester_port}/dashboard/
Access:    http://127.0.0.1:${requester_port}/dashboard/access
Admin:     http://127.0.0.1:${admin_port}/dashboard/admin
EOF

if [[ "$pause" == "true" && -t 0 ]]; then
  echo
  read -r -p "Press Enter to delete the demo sandbox and stop local services..."
fi
