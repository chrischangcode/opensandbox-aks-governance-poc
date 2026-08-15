# OpenSandbox AKS Governance POC

This POC runs [OpenSandbox](https://github.com/opensandbox-group/OpenSandbox) on AKS with Kata VM isolation, then adds:

- per-sandbox egress authorization telemetry;
- logical tenants, teams, and permission levels;
- immutable capability boundaries;
- temporary access requests tied to one exact sandbox incarnation;
- requester and administrator pages; and
- approval, expiry, audit retention, and stale-request fencing.

It extends the public [AKS Kata example](https://github.com/opensandbox-group/OpenSandbox/blob/main/docs/examples/aks-kata.md). The POC uses one Azure tenant and simulates multiple logical tenants inside it.

> [!WARNING]
> The local development login is intentionally restricted to a loopback address. It is for port-forwarded POC use only. Do not expose it through an ingress or load balancer.

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

## Security model

- Capability bundle specs and assignment specs are immutable.
- Approvals are exact overlays, not mutations of a live capability bundle.
- Projected sandbox identity is audience-restricted and bound to the current Pod UID.
- Authorization fails closed on stale caches, ambiguous state, malformed targets, expired grants, or incarnation mismatch.
- Audit events omit headers, query strings, bodies, credentials, tokens, and source IPs.
- The asynchronous audit queue cannot turn a valid allow into a deny.
- Logical tenants in this POC are governance labels, not Azure tenant or Kubernetes namespace isolation.

The `egress-probe` exercises the same authorization and telemetry path used by an egress gateway. It does not itself forward network packets.

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
