# P0 managed-service boundary findings

This POC now has an experimentally verified path for the major P0 boundaries
needed to turn OpenSandbox on AKS into an Azure service. It does not claim that
the implementation itself is production-ready: several controls still need to
move into Azure-managed infrastructure, and upstream OpenSandbox still has
single-writer and Pod-template integration limits.

## Result matrix

| P0 boundary | POC result | Production path or remaining work |
|---|---|---|
| Trusted lifecycle input | **Closed in POC.** Callers select an immutable `SandboxTemplate`; image, entrypoint, resources, timeout, capability bundle, and tenant are resolved server-side. Caller snapshots, volumes, credentials, network policy, platform settings, and arbitrary extensions are removed. | Sign and version templates through a managed control plane. Add policy rollout, rollback, and regional propagation. |
| Lifecycle caller authentication | **Closed in POC.** Assignmentd requires a dedicated-audience Kubernetes ServiceAccount token, validates it with TokenReview, binds it through `SandboxPrincipalBinding`, and strips it before proxying upstream. | Use managed workload identity or an Azure-issued service credential, private endpoints, and service-to-service mTLS. |
| Tenant authorization | **Closed for logical tenants.** Request, approval, list, and lifecycle operations are tenant-scoped. Cross-tenant requests return `403`. | Map Azure tenant/subscription/resource identities to service-owned stamps. Logical isolation is not a substitute for separate Azure tenants, subscriptions, or clusters where required. |
| Durable and idempotent create | **Path proven with a remaining edge.** Production creates require `Idempotency-Key`. The deterministic assignment CRD is the operation record; same key and intent replays, different intent returns `409`, and unrecovered pending records expire conservatively. | Store the exact original response and enough immutable template material to replay even after a template is disabled or removed. |
| Distributed admission | **Path proven live.** Two assignmentd replicas serialize tenant admission with Kubernetes Leases. Six simultaneous creates pinned across both replicas admitted exactly four and rejected two at the configured tenant budget. | Replace Kubernetes Leases with a service-grade regional transaction or quota service if admission spans clusters. |
| Ambiguous create recovery | **Path proven live.** Removing the committed sandbox mapping after upstream creation caused the controller to recover it from the matching `BatchSandbox`. | Add explicit operation phases, retry budgets, poison-operation handling, and reconciliation SLOs. |
| Assignment service availability | **Path proven.** Assignmentd runs two API replicas, a single elected controller leader, `RollingUpdate`, and a PodDisruptionBudget. Replay survived replica replacement. | Add zone-aware topology spread, regional failover, overload protection, and tested disaster recovery. |
| OpenSandbox metadata durability | **Partially closed.** SQLite is on an RWO PVC and survived server restart. | Upstream currently supports SQLite only. A managed service needs an external transactional store and active/active lifecycle APIs; PVC-backed `Recreate` is not a regional HA design. |
| Forced egress | **Feasibility proven live.** AKS was moved to Cilium. Assigned sandbox Pods were default-denied and could reach only assignmentd; direct TCP, UDP, DNS, and name resolution failed while the exact mediated request succeeded. | Inject a trusted proxy/sidecar or node data plane, prevent bypass below L7, and add a controlled DNS resolver. The no-DNS proof is secure but not generally usable. |
| Per-sandbox egress attribution | **Closed for the mediated path.** Pod-bound TokenReview identity, Pod UID, assignment UID, capability revision, method, host, and path are checked and audited. The external mediator derives the Pod address from the authenticated identity rather than trusting caller JSON. | The injected data plane must derive source from the trusted connection/proxy metadata and export immutable events to an Azure-owned telemetry pipeline. |
| Fail-closed audit | **Path proven live.** Authorization writes the immutable event synchronously. Removing `create` permission on `SandboxEgressEvent` changed an otherwise allowed request to deny. | Use a replicated durable audit service, define latency/error budgets, and separate security evidence from customer diagnostics. |
| Brokered credentials | **Closed in POC.** Credentials are exact-scope, short-lived, Pod-bound, never returned in reports, and use durable Kubernetes revocations. | Integrate Azure Key Vault/Managed Identity, backend-specific token exchange, hardware-backed service keys, and emergency revocation. |
| Signing-key rotation | **Path proven live.** A credential signed by key ID `old` remained valid after rotation to `new` while the previous key was configured, then returned `401` after grace removal. | Automate rotation, overlap, key distribution, monitoring, and compromise response through a managed key service. |
| Pause/resume | **Path proven live.** Snapshot pause/resume preserved state, replaced the Pod UID, rejected pre-snapshot authority, and cleaned up the old workload. | Define snapshot encryption, portability, retention, consistency, malware scanning, billing, and compatibility guarantees. |
| Harness confinement | **Closed for the demo.** The OpenCode `sandbox-only` agent denies built-in host tools and can execute only through the governance MCP server, which dynamically creates approved sandboxes. | Enforce this outside prompt/configuration using service identity, broker policy, endpoint isolation, and signed harness attestations. |

## Important architecture finding

The live POC uses `external-mediator` identity mode because the upstream
OpenSandbox create path replaces additional containers from its base template.
The sandbox therefore receives no projected Kubernetes credential, and the
harness explicitly invokes assignmentd for governed external operations.

This proves authorization, attribution, audit, revocation, and forced L3/L4
network denial, but it is not the final transparent data plane.
`projected-sidecar` remains the fail-closed production default: a trusted
admission component must inject the proxy and mount the Pod-bound identity only
into that proxy. Missing injection, identity, or policy must leave the sandbox
with no external route.

## Live experiments

The experiments ran on the dedicated AKS Standalone development cluster:

```text
resource group: rg-osb-governance-poc-westus2
cluster:        osb-governance-poc-aks
Kubernetes:     v1.35.6
network policy: Cilium
```

Reproducible commands:

```bash
# Core authentication, immutable-template, idempotency, restart, forced-egress,
# and exact attribution checks.
./scripts/p0-live-experiments.sh

# Fail-closed audit, cross-replica quota serialization, and ambiguous-create
# recovery.
./scripts/p0-fault-experiments.sh

# Signing-key grace and stale-key rejection.
./scripts/p0-key-rotation-experiment.sh

# Validation evidence, broker issue/use/revoke/replay, and snapshot pause/resume.
RUN_SNAPSHOT=true ./scripts/extended-governance-demo.sh
```

Successful evidence:

```text
demo-output/p0-20260816T191432Z
demo-output/p0-fault-20260816T190955Z
demo-output/p0-rotation-20260816T190904Z
demo-output/20260816T191604Z-extended
```

The final assignmentd deployment used:

```text
osbkata0815201155f3e68b.azurecr.io/opensandbox/assignmentd@sha256:7dcf9ba4d539ecc9ea1e60b7b34f24fe07fb2751c68fbfe85b930cc863b95d70
```

The forced-egress NetworkPolicies were removed before the extended OpenCode
replay because `external-mediator` does not transparently proxy `git clone`.
This is intentional evidence of the remaining integration gap: the secure
default-deny proof works, and the governed harness flow works, but both become
simultaneously usable only after the trusted egress data plane is injected.

## Highest-priority work after this POC

1. Replace SQLite/PVC metadata with an external highly available store and
   define regional operation recovery.
2. Implement the injected fail-closed egress proxy plus controlled DNS and
   validate bypass resistance at L3 through L7.
3. Move identity, key management, audit, and telemetry into Azure-managed
   services with private connectivity.
4. Define physical tenancy tiers: shared stamp, dedicated cluster, dedicated
   subscription, and any tenant-specific isolation requirements.
5. Add service SLOs, capacity admission, upgrade/rollback, incident response,
   abuse prevention, compliance retention, billing, and customer support
   workflows.
6. Make templates, capability bundles, tenant policies, and access requests
   first-class Kubernetes CRDs backed by an Azure resource-provider API and
   portal experience.
