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
output_dir="${LIVE_DEMO_OUTPUT_DIR:-$repo_root/demo-output/$timestamp}"
mkdir -p "$output_dir"

pids=()
sandbox_id=""
assignment_name=""
pod_name=""
event_name=""
allowed_event=""
request_name=""

cleanup() {
  local exit_code=$?
  if [[ -n "$sandbox_id" ]]; then
    curl -fsS -X DELETE \
      "http://127.0.0.1:${assignment_port}/opensandbox/sandboxes/${sandbox_id}" \
      >/dev/null 2>&1 || true
    cleanup_confirmed=false
    for _ in {1..90}; do
      assignment_exists=false
      workload_exists=false
      pod_exists=false
      if kubectl -n "$assignment_namespace" get sandboxassignments \
        -l "aks-sandbox.azure.com/opensandbox-id=${sandbox_id}" \
        -o name 2>/dev/null | grep -q .; then
        assignment_exists=true
      fi
      if kubectl -n "$workload_namespace" get batchsandbox "$sandbox_id" \
        >/dev/null 2>&1; then
        workload_exists=true
      fi
      if [[ -n "$pod_name" ]] &&
        kubectl -n "$workload_namespace" get pod "$pod_name" \
          >/dev/null 2>&1; then
        pod_exists=true
      fi
      if [[ "$assignment_exists" == "false" &&
        "$workload_exists" == "false" &&
        "$pod_exists" == "false" ]]; then
        cleanup_confirmed=true
        break
      fi
      sleep 1
    done
    if [[ "$cleanup_confirmed" == "true" ]]; then
      echo "Cleanup confirmed: assignment, workload, and Pod are absent."
    else
      echo "Cleanup did not complete for sandbox $sandbox_id" >&2
      exit_code=1
    fi
  fi
  if [[ -n "$request_name" ]]; then
    kubectl -n "$assignment_namespace" delete sandboxaccessrequest \
      "$request_name" --ignore-not-found >/dev/null 2>&1 || exit_code=1
  fi
  for event in "$event_name" "$allowed_event"; do
    if [[ -n "$event" ]]; then
      kubectl -n "$assignment_namespace" delete sandboxegressevent \
        "$event" --ignore-not-found >/dev/null 2>&1 || exit_code=1
    fi
  done
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
    "List approved templates, then run exactly: uname -a && python --version. Report the sandbox ID, assignment, capability bundle, runtime class, output, and confirmed cleanup." \
    | tee "$output_dir/opencode-allowed.txt"
  grep -q "kata-optimized" "$output_dir/opencode-allowed.txt"
  grep -Eq 'cleanedUp[`"]?:[[:space:]]*true' \
    "$output_dir/opencode-allowed.txt"

  echo "==> Denied OpenCode command"
  opencode run \
    --agent sandbox-only \
    --model "$opencode_model" \
    "Try to run exactly: id. Do not substitute another command. Report whether the capability boundary allowed it." \
    | tee "$output_dir/opencode-denied.txt"
  grep -q "command is not allowed by the capability bundle" \
    "$output_dir/opencode-denied.txt"
fi

echo "==> Creating the persistent egress-demonstration sandbox"
create_body="$(
  jq -n '{
    image: {uri: "python@sha256:876416ecde9aca2bcc90e1fb0c7a9500bbf749f5788b70f82d4c5a5c2357f8b4"},
    entrypoint: ["tail", "-f", "/dev/null"],
    timeout: 1800,
    resourceLimits: {cpu: "500m", memory: "512Mi"},
    metadata: {
      "aks-sandbox.azure.com/demo": "live-replay"
    },
    extensions: {
      "aks-sandbox.azure.com/capabilityProfile": "team-a-reader"
    }
  }'
)"
create_response="$(
  curl -fsS \
    -H 'Content-Type: application/json' \
    --data "$create_body" \
    "http://127.0.0.1:${assignment_port}/opensandbox/sandboxes"
)"
sandbox_id="$(jq -er '.id' <<<"$create_response")"
echo "sandbox: $sandbox_id"

for _ in {1..180}; do
  assignment_json="$(
    kubectl -n "$assignment_namespace" get sandboxassignments \
      -l "aks-sandbox.azure.com/opensandbox-id=${sandbox_id}" \
      -o json
  )"
  assignment_name="$(jq -r '.items[0].metadata.name // empty' <<<"$assignment_json")"
  pod_name="$(jq -r '.items[0].status.podRef.name // empty' <<<"$assignment_json")"
  ready="$(
    jq -r '
      .items[0].status.conditions // []
      | map(select(.type == "Ready"))
      | first.status // empty
    ' <<<"$assignment_json"
  )"
  if [[ -n "$assignment_name" && "$ready" == "True" ]]; then
    break
  fi
  sleep 1
done
if [[ -z "$assignment_name" || "$ready" != "True" ]]; then
  echo "sandbox assignment did not become ready" >&2
  exit 1
fi
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
  jq -r --arg sandbox "$sandbox_id" '
    ["TIME", "SANDBOX", "TENANT", "TEAM", "TARGET", "PATH", "ALLOWED", "SOURCE", "REQUEST"],
    (.items
      | map(select(.spec.sandboxId == $sandbox))
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
  "http://127.0.0.1:${admin_port}/dashboard/admin#approved-templates" \
  admin-templates.png \
  false \
  800
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
Artifacts:     $output_dir

Requester: http://127.0.0.1:${requester_port}/dashboard/
Access:    http://127.0.0.1:${requester_port}/dashboard/access
Admin:     http://127.0.0.1:${admin_port}/dashboard/admin
EOF

if [[ "$pause" == "true" && -t 0 ]]; then
  echo
  read -r -p "Press Enter to delete the demo sandbox and stop local services..."
fi
