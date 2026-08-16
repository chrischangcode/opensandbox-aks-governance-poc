# OpenSandbox AKS Governance POC

This POC runs [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) on AKS with Kata VM isolation, then adds:

- per-sandbox egress authorization telemetry;
- logical tenants, teams, and permission levels;
- immutable capability boundaries;
- temporary access requests tied to one exact sandbox incarnation;
- fail-closed tenant admission budgets;
- readiness diagnostics and exact policy-impact simulation;
- sandbox-only validation with durable hashed evidence;
- short-lived broker authority bound to the current Pod identity;
- snapshot pause/resume with state continuity and authority rotation;
- requester and administrator pages; and
- approval, expiry, audit retention, and stale-request fencing.

It extends the public [AKS Kata example](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/examples/aks-kata.md). The POC uses one Azure tenant and simulates multiple logical tenants inside it.

> [!WARNING]
> The local development login is intentionally restricted to a loopback address. It is for port-forwarded POC use only. Do not expose it through an ingress or load balancer.

## See it in action

[Open the visual live-demo report](docs/live-demo-report.md), including the
architecture, exact redacted commands, terminal transcripts, implemented
service boundaries, and replay steps. The
[remaining P0 service work](docs/p0-service-boundary-findings.md) contains only
the unresolved or partially proven work required for an Azure service.

| Running Kata sandbox | Administrator capability editor |
|---|---|
| ![Running governed sandbox](docs/assets/requester-dashboard.png) | ![Administrator capability editor](docs/assets/admin-capabilities.png) |

## Prerequisites

- An Azure subscription where you can create AKS, ACR, role assignments, and resource groups
- Azure CLI, `kubectl`, Helm 3, Docker, GNU Make, Go 1.26+, `uv`, `jq`, and `envsubst`
- An AKS region and VM SKU that support `KataMshvVmIsolation`

## Files

| Path | Purpose |
|---|---|
| `infra/` | Disposable AKS, ACR, system-pool, and Kata-pool infrastructure |
| `deploy/opensandbox-server/` | OpenSandbox lifecycle server, ingress gateway, and Kata template |
| `deploy/governance/k8s/` | Governance CRDs, RBAC, assignment service, and sample boundaries |
| `cmd/assignmentd/` | Assignment lifecycle facade and egress authorization service |
| `cmd/aks-sandbox-dashboard/` | Requester and administrator pages |
| `cmd/egress-probe/` | Sends an attributed authorization decision for a live sandbox |
| `docs/live-demo-report.md` | Captured OpenCode, Kata, cleanup, and egress approval evidence |

## 1. Deploy OpenSandbox on AKS

Select the intended subscription, then run the baseline deployment:

```bash
az account set --subscription <subscription-id>
make all
```

`make local-config` creates `.make.env` with generated resource names and an API key. The file is ignored by Git and must remain local.

Verify Kata isolation:

```bash
kubectl get runtimeclass kata-optimized
kubectl get pods -n opensandbox \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.runtimeClassName}{"\n"}{end}'
```

The Python smoke test should print `runtime class: kata-optimized`.

## 2. Build and deploy governance

Build `assignmentd` in the ACR created by the baseline:

```bash
source .make.env

az acr build \
  --registry "$ACR_NAME" \
  --file deploy/governance/assignmentd.Containerfile \
  --image opensandbox/assignmentd:governance-poc \
  .

export ASSIGNMENTD_IMAGE="$ACR_NAME.azurecr.io/opensandbox/assignmentd:governance-poc"
```

Install the data model, logical boundaries, and sandbox ServiceAccount:

```bash
kubectl create namespace aks-sandbox-system --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -f deploy/governance/k8s/crds.yaml
kubectl apply -f deploy/governance/k8s/capability-bundles.yaml
kubectl apply -f deploy/governance/k8s/sandbox-templates.yaml
kubectl apply -f deploy/governance/k8s/tenant-policies.yaml
kubectl apply -f deploy/governance/k8s/sandbox-serviceaccount.yaml
```

Copy the generated OpenSandbox API key between Kubernetes Secrets without printing it:

```bash
kubectl get secret opensandbox-server -n opensandbox -o json |
  jq 'del(.metadata.annotations,.metadata.creationTimestamp,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)
      | .metadata.name="assignmentd-opensandbox-api"
      | .metadata.namespace="aks-sandbox-system"' |
  kubectl apply -f -

kubectl get secret opensandbox-server -n opensandbox -o json |
  jq 'del(.metadata.annotations,.metadata.creationTimestamp,.metadata.managedFields,.metadata.resourceVersion,.metadata.uid)
      | .metadata.name="opensandbox-api-key"
      | .metadata.namespace="opensandbox"' |
  kubectl apply -f -
```

Deploy the service:

```bash
envsubst '${ASSIGNMENTD_IMAGE}' \
  < deploy/governance/k8s/assignmentd.yaml |
  kubectl apply -f -

kubectl rollout status deployment/assignmentd \
  -n aks-sandbox-system --timeout=180s
```

## 3. Open requester and admin pages

Forward the assignment lifecycle and authorization endpoints:

```bash
kubectl port-forward -n aks-sandbox-system svc/assignmentd \
  19080:8080 19001:9001
```

Run a requester dashboard:

```bash
go run ./cmd/aks-sandbox-dashboard \
  --dev-auth \
  --dev-name "POC Requester" \
  --dev-object-id 00000000-0000-4000-8000-000000000010 \
  --dev-roles OpenSandbox.User \
  --listen 127.0.0.1:18081 \
  --redirect-uri http://127.0.0.1:18081/dashboard/auth/redirect/ \
  --kubeconfig "$HOME/.kube/config" \
  --opensandbox-namespace opensandbox \
  --lifecycle-endpoint http://127.0.0.1:19080/opensandbox \
  --capability-profile team-a-reader \
  --cookie-secure=false
```

Run the administrator dashboard in another terminal:

```bash
go run ./cmd/aks-sandbox-dashboard \
  --dev-auth \
  --dev-name "POC Administrator" \
  --dev-object-id 00000000-0000-4000-8000-000000000020 \
  --dev-roles OpenSandbox.Admin \
  --listen 127.0.0.1:18082 \
  --redirect-uri http://127.0.0.1:18082/dashboard/auth/redirect/ \
  --kubeconfig "$HOME/.kube/config" \
  --opensandbox-namespace opensandbox \
  --lifecycle-endpoint http://127.0.0.1:19080/opensandbox \
  --capability-profile team-a-reader \
  --cookie-secure=false
```

Open:

- Requester: <http://127.0.0.1:18081/dashboard/>
- Access requests: <http://127.0.0.1:18081/dashboard/access>
- Administration: <http://127.0.0.1:18082/dashboard/admin>

The administrator page can create immutable `CapabilityBundle` boundaries from
exact egress entries such as `external-web GET https://example.com/docs`, then
create immutable `SandboxTemplate` revisions by selecting one of those
boundaries. Each template also selects a digest-pinned image, entrypoint,
CPU/memory limit, lifetime, and exact capability-bundle policy revision.
Harnesses can only select enabled templates.

Admin-entered egress rules reject explicit ports, query strings, and fragments
instead of silently widening a grant. Admin-entered commands are exact strings;
the dashboard generates the anchored policy representation automatically.
Validation rules use `path-prefix => exact command`; each selected command must
also be allowed by the exact command policy.

The page is a convenience frontend, not a second configuration store. Every
boundary and template created there is stored as a Kubernetes
`CapabilityBundle` or `SandboxTemplate` custom resource. Platform teams can
define the same resources directly with YAML and manage them through GitOps,
Helm, Kustomize, or another Kubernetes-native workflow.

Tenant limits are Kubernetes-native too:

```bash
kubectl -n aks-sandbox-system get sandboxtenantpolicies
```

`SandboxTenantPolicy` fails closed when no enabled revision exists for the
logical tenant. It limits approved bundle names or prefixes, concurrent
sandboxes, maximum lifetime, CPU, memory, and temporary access duration before
an assignment is created.

Create a sandbox from the requester page and wait for its assignment to become ready:

```bash
kubectl get sandboxassignments -n aks-sandbox-system -w
```

## 4. Demonstrate deny, request, approve, allow

Get the assignment name:

```bash
export ASSIGNMENT="$(
  kubectl get sandboxassignments -n aks-sandbox-system \
    -o jsonpath='{.items[0].metadata.name}'
)"
```

Send an egress authorization check attributed to that sandbox:

```bash
go run ./cmd/egress-probe \
  --assignment "$ASSIGNMENT" \
  --backend external-web \
  --target https://example.com/docs
```

The first result should be `allowed: false`. The decision creates a sanitized `SandboxEgressEvent`.

1. On the requester access page, request access for the denied event.
2. On the administrator page, approve it for a short duration.
3. Run the exact same probe again.

The second result should be `allowed: true`. Confirm attribution and decision source:

```bash
kubectl get sandboxegressevents -n aks-sandbox-system \
  -o custom-columns='TIME:.spec.timestamp,SANDBOX:.spec.sandboxId,TENANT:.spec.logicalTenant,TEAM:.spec.team,TARGET:.spec.host,ALLOWED:.spec.allowed,SOURCE:.spec.decisionSource,REQUEST:.spec.accessRequestName'
```

Changing the backend, method, host, path, assignment UID, or bundle revision does not reuse the approval.

## Egress identity modes

The live POC uses `external-mediator` mode because the upstream OpenSandbox
create path replaces additional containers from the base Pod template. That
means this integration cannot yet reliably retain a trusted egress sidecar next
to the user-controlled sandbox container.

In `external-mediator` mode:

- the sandbox has `automountServiceAccountToken: false` and receives no
  projected Kubernetes token;
- a trusted external probe or gateway requests a short-lived,
  audience-restricted token bound to the exact sandbox Pod;
- `assignmentd` validates the token, Pod, assignment, capability revision,
  destination, and any temporary access grant; and
- the resulting decision and sanitized telemetry are attributed to that
  sandbox.

This proves per-sandbox authorization and attribution, but it does not claim
transparent interception of every network connection made by the sandbox.

For a production data plane, `projected-sidecar` remains the fail-closed
controller default. A mutating admission webhook or equivalent integration
would inject the egress proxy and mount the Pod-bound token only in that trusted
sidecar. The user container would not receive the token. If the sidecar,
projection, or isolation is missing or malformed, the assignment does not
become ready and mediated egress is denied.

## Security model

- Capability bundle specs and assignment specs are immutable.
- Approvals are exact overlays, not mutations of a live capability bundle.
- Authorization uses an audience-restricted token bound to the current Pod UID.
- Authorization fails closed on stale caches, ambiguous state, malformed targets, expired grants, or incarnation mismatch.
- Temporary access and brokered credentials are invalid after pause/resume
  replaces the Pod UID.
- Broker credential values are never persisted in Kubernetes audit resources.
- Validation resources retain output hashes instead of unrestricted logs.
- Tenant admission fails closed when the requested logical tenant has no
  enabled policy revision.
- `assignmentd` runs two API replicas with `RollingUpdate`, a PodDisruptionBudget,
  controller leader election, and per-tenant Kubernetes Leases that serialize
  budget admission across replicas.
- Audit events omit headers, query strings, bodies, credentials, tokens, and source IPs.
- Required authorization audit is synchronous and fail closed: if the audit
  record cannot be persisted, an otherwise valid allow becomes a deny.
- Logical tenants in this POC are governance labels, not Azure tenant or Kubernetes namespace isolation.

The `egress-probe` exercises the same authorization and telemetry path used by an egress gateway. It does not itself forward network packets.

## OpenCode sandbox-only harness

Install OpenCode in the current WSL user profile:

```bash
npm install --prefix "$HOME/.local" -g opencode-ai@latest
export PATH="$HOME/.local/bin:$PATH"
opencode --version
```

This repository includes:

- `opencode.json` — registers the local `sandbox_governance` MCP server;
- `.opencode/agents/sandbox-only.md` — denies every built-in tool and allows
  only the sandbox MCP tools; and
- `harness/run-mcp.sh` — starts required local port-forwards, reads the
  Kubernetes API key Secret without printing it, and starts the MCP server.

Check the MCP connection:

```bash
cd ~/go/opensandbox-aks-governance-poc
opencode mcp list
```

Run a non-interactive demonstration using one of OpenCode's listed models:

```bash
opencode run \
  --agent sandbox-only \
  --model opencode/big-pickle \
  "Use the least-privileged approved template to run: uname -a && python --version"
```

The agent cannot call host `bash`, edit files, browse the web, or launch
subagents. Its only execution tool creates a fresh sandbox through
`assignmentd`, waits for the assignment and Kata Pod to become ready, runs the
command only when the bundle's command policy allows it, captures attribution
evidence, and confirms the assignment, workload, and Pod are gone before
reporting cleanup complete.

The same MCP server also exposes:

- `validate_change`, which maps normalized repository-relative paths to exact
  approved commands and writes a `SandboxValidationRun` containing source,
  sandbox, Pod, command, output-hash, and cleanup evidence;
- `exercise_brokered_credential`, which issues a 1-15 minute exact grant,
  verifies it against live assignment and Pod state, revokes it, and proves
  replay denial without returning the credential; and
- `snapshot_pause_resume`, which writes state, pauses through the governed
  lifecycle facade, resumes onto a fresh Pod UID, confirms filesystem
  continuity, and rejects the pre-snapshot credential.

The current broker uses an internal HMAC-signed POC JWT. It proves bounded
scope, lifetime, revocation, and lifecycle invalidation, but does not yet
exchange the grant for a real GitHub, Azure DevOps, package-feed, Kusto, or AKS
credential.

## Readiness contract

Run the doctor before CI or a live demonstration:

```bash
go run ./cmd/sandbox-doctor
go run ./cmd/sandbox-doctor --output json | jq .
```

Missing Kata capacity, governance APIs, assignment/OpenSandbox services,
ServiceAccount security, or enabled template/bundle/tenant inventory fails
readiness. Missing `ResourceQuota` or `NetworkPolicy` is reported as a warning
so the POC remains runnable while the production gap stays visible.

## Replay the full live demonstration

After deploying OpenSandbox and `assignmentd`, install the optional screenshot
browser once:

```bash
npx playwright install chromium
```

Run the complete presentation:

```bash
./scripts/live-demo.sh
```

The script:

1. Applies the immutable templates and boundaries.
2. Starts loopback-only requester and administrator pages.
3. Runs the allowed and denied OpenCode examples.
4. Creates a Kata sandbox for the egress demonstration.
5. Produces deny, request, approve, and allow decisions through the real pages.
6. Captures screenshots and terminal logs under `demo-output/<timestamp>/`.
7. Pauses so the visual product state can be presented.
8. Runs tenant-budget, validation, credential, snapshot, fault, key-rotation,
   lifecycle, recovery, forced-egress, and attribution scenarios.
9. Removes the temporary forced-egress policies, restores the dashboard
   port-forward, and confirms all ephemeral sandbox resources are gone.

For an unattended replay:

```bash
./scripts/live-demo.sh --no-pause
```

Both commands run the same complete POC; `--no-pause` only removes the
presentation pauses. Set `RUN_OPENCODE=false` to skip the redundant OpenCode
presentation step, `CAPTURE_SCREENSHOTS=false` to skip screenshots, or
`RUN_SNAPSHOT=false` only when the cluster was intentionally installed without
snapshot prerequisites.

The live-demo report is authoritative for proven behavior. Physical tenancy,
regional metadata, transparent egress injection with controlled DNS, Azure
identity and key integration, and managed-service operability remain in
[remaining P0 service work](docs/p0-service-boundary-findings.md).

## Cleanup

Delete governance resources:

```bash
kubectl delete namespace aks-sandbox-system
kubectl delete -f deploy/governance/k8s/sandbox-serviceaccount.yaml --ignore-not-found
kubectl delete -f deploy/governance/k8s/crds.yaml --ignore-not-found
```

Delete the disposable Azure environment:

```bash
make infra-delete
```

## Provenance

The AKS/Kata bootstrap is derived from the public
[`weinong/opensandbox-aks`](https://github.com/weinong/opensandbox-aks) POC and
the upstream
[`OpenSandbox` AKS Kata example](https://github.com/opensandbox-group/OpenSandbox/tree/main/examples/aks-kata).
