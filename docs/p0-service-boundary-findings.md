# Remaining P0 Service Work

This document contains only the service-boundary work that remains unresolved or
partially proven after the OpenSandbox-on-AKS governance POC.

See the README's
[remaining-P0 architecture diagram](../README.md#remaining-p0-azure-service-architecture)
for the target service shape represented by these gaps.

The controls already demonstrated live are documented in
[live-demo-report.md](live-demo-report.md#implemented-service-boundaries). They include
trusted lifecycle templates, authenticated logical-tenant authorization, durable
idempotency and recovery, distributed quota admission, synchronous fail-closed audit,
forced egress, per-sandbox attribution, credential revocation and key rotation, and
snapshot identity rotation.

## Executive summary

The POC now has a credible path for the core Kubernetes enforcement boundaries, but it
is not yet an Azure managed service. The remaining P0 work is concentrated in four
areas:

1. Replace single-cluster POC state and identity components with regional,
   Azure-managed control-plane dependencies.
2. Make transparent, fail-closed egress mediation usable for arbitrary sandbox
   workloads, including controlled DNS.
3. Close lifecycle edge cases around distributed fencing, idempotent replay, ambiguous
   operations, and pause rollback.
4. Define the operational, compliance, abuse, recovery, and billing contracts required
   for a multitenant Azure service.

## Residual P0 gaps

| Area | Current POC boundary | Required service boundary |
|---|---|---|
| Regional lifecycle state | `SandboxAssignment` records and Leases are durable inside one Kubernetes control plane. OpenSandbox metadata uses SQLite on a PVC. | Use an external, highly available regional metadata and operation store with conditional writes, backup/restore, regional failover, and tested disaster recovery. |
| Admission fencing | A per-tenant Lease serializes quota admission across two API replicas. | Fence release by holder identity and object version so a stale holder cannot delete a Lease acquired by another replica. Bound the critical section and define recovery from expired holders. |
| Idempotent replay | Deterministic operation records reject conflicting intent and survive replica replacement. | Detect a matching existing operation inside the serialized admission path before quota rejection. A replay must return the original result even when the tenant is currently at quota. |
| Ambiguous create recovery | The controller repairs missing mappings after an upstream workload becomes visible. | Replace time-only pending-operation deletion with upstream-aware reconciliation. Never delete an operation merely because the controller or upstream API was unavailable, since that can permit duplicate creation. |
| Pause fencing | Governance marks an assignment paused before proxying the upstream pause request. | Roll back or reconcile the pause fence when the upstream pause fails. Define timeout, retry, and ambiguous-result semantics for pause, resume, and delete. |
| Transparent egress | Cilium proves default-deny TCP, UDP, DNS, and direct-address traffic. Exact mediated requests are allowed and attributed. | Inject a mandatory mediation path that upstream OpenSandbox cannot replace, authenticate the sandbox transparently, prevent bypass, and provide a controlled DNS resolver or proxy. |
| Egress identity mode | The live POC uses `external-mediator` because the upstream create path replaces additional template containers. | Make `projected-sidecar`, node interception, or another transparent data plane the production default. The enforcement component must be outside sandbox control and fail closed. |
| Physical tenancy | Logical tenant, team, template, and permission boundaries are enforced in one namespace and cluster. | Define when customers receive namespace, node-pool, cluster, network, key, or regional isolation. Prove cross-tenant resource, network, identity, cache, and telemetry isolation. |
| Azure control-plane identity | Kubernetes TokenReview and ServiceAccount bindings authenticate lifecycle and sandbox callers. | Integrate Microsoft Entra ID, managed identities, workload identity federation, private endpoints, mTLS, certificate rotation, and Azure RBAC without accepting caller-asserted tenant context. |
| Provider credentials | The broker proves exact-scope grants, revocation, replay denial, and signing-key grace. | Exchange grants for short-lived provider credentials through managed identity or provider federation. Store and rotate signing material in an Azure-managed key service and define outage behavior. |
| Audit and telemetry | Required authorization audit is synchronous and fail closed in Kubernetes CRDs. Egress is attributed to assignment and Pod UID. | Export immutable audit and telemetry to a regional durable pipeline with retention, schema versioning, redaction, access control, query SLOs, and cross-region recovery. |
| Snapshot product semantics | Pause/resume preserves workspace state while rotating Pod UID and rejecting stale authority. | Define snapshot consistency, encryption, size limits, retention, portability, deletion, restore compatibility, malware handling, billing, and tenant/key boundaries. |
| Agent harness enforcement | The OpenCode harness demonstrates sandbox-only execution and governed elevation. | Enforce the boundary independently of prompt configuration. Attest the harness, authenticate tool calls, constrain extensions, and ensure host execution cannot be re-enabled by an agent or user. |
| Service operability | Doctor checks, PDB, leader election, replay scripts, and fault experiments exist. | Define SLOs, capacity models, autoscaling, upgrade and rollback safety, regional failover, on-call diagnostics, customer-visible health, quota operations, and incident response. |
| Abuse and compliance | Capability templates and exact elevation reduce accidental access. | Add abuse detection, malware and exfiltration controls, acceptable-use enforcement, legal retention/deletion behavior, compliance evidence, support access controls, and tenant notification workflows. |
| Metering and billing | The POC records assignments, requests, grants, and egress events. | Produce reconciled, tamper-resistant meters for compute, storage, snapshot, network, and premium capabilities, including retries, partial failures, credits, and dispute handling. |

## Second-review lifecycle findings

These implementation issues should be fixed before treating the current control plane as
a reusable service foundation.

### 1. Lease release is not fully fenced

Kubernetes Lease takeover updates the same object, so its UID does not change. A holder
that acquired the Lease earlier can therefore delete the object after another holder has
updated it if release validates only the UID.

The release operation should use holder identity plus `resourceVersion` as a conditional
fence. A stale holder must receive a conflict and leave the newer holder's Lease intact.
Tests should cover expiry, takeover, stale release, and controller restart.

### 2. Replay can be rejected at quota

Quota admission currently occurs before existing-operation detection. If a tenant is at
its limit, replaying an already admitted idempotency key can return `403` rather than the
recorded result.

The serialized path should first look up the deterministic operation, validate the
request hash, and return its state without consuming a new quota slot. Only a genuinely
new operation should run quota admission.

### 3. Time-only pending expiry risks duplicate creation

A pending record can outlive its timeout while the upstream workload already exists but
the assignment controller or upstream API is unavailable. Deleting that record makes the
same idempotency key appear new and can create a duplicate workload.

Pending operations should remain authoritative until reconciliation proves that no
upstream operation or workload exists. If absence cannot be proven, surface an
indeterminate state and continue recovery rather than permitting replacement.

### 4. Failed pause can leave a false governance fence

The governance pause marker is written before the upstream pause request. When that call
fails, the marker remains and can deny credentials even though the workload is still
running.

Use a small operation state machine or compensating update so failure restores the prior
state. Ambiguous timeouts should enter reconciliation rather than being reported as
success or silently left fenced.

## Required Azure-service investigations

### Regional state and recovery

- Evaluate an Azure-managed transactional store for lifecycle operations, assignments,
  idempotency records, template versions, grants, and revocations.
- Define consistency and failure semantics between the regional store, Kubernetes
  control planes, and OpenSandbox runtime state.
- Prove zone loss, cluster replacement, regional failover, backup restore, and
  reconciliation from each source of truth.

### Transparent network data plane

- Prototype a production identity mode that survives upstream template rendering and
  cannot be removed by the sandbox workload.
- Add controlled DNS with policy decisions and attribution for both names and resolved
  addresses.
- Cover HTTP, HTTPS, raw TCP, UDP, redirects, proxies, IPv6, private endpoints, service
  tags, CDN address churn, and long-lived connections.
- Define fail-closed behavior when the policy service, audit sink, DNS service, or
  identity issuer is unavailable.

### Identity, credentials, and private connectivity

- Map Azure subscription, tenant, resource, and principal identities to the internal
  lifecycle principal without trusting request headers.
- Use managed identity federation or provider-native token exchange instead of service
  credentials held by the broker.
- Move signing and encryption keys to an Azure-managed key boundary with rotation,
  revocation, regional availability, and break-glass procedures.
- Prove private-link and customer-network access without creating a cross-tenant routing
  or DNS boundary violation.

### Product and operational contracts

- Define supported isolation tiers and the admin UX for choosing them.
- Specify elevation approval ownership, expiration, emergency revocation, and policy
  propagation SLOs.
- Establish runtime, snapshot, network, audit, and credential SLOs with measurable error
  budgets.
- Define capacity, cost, billing, abuse response, compliance, support, data residency,
  deletion, and incident-notification requirements.

## Reproducing the proven baseline

Run the complete POC:

```bash
./scripts/live-demo.sh --no-pause
```

The replay restores the external-mediator demo path after the forced-egress proof.
See [live-demo-report.md](live-demo-report.md#implemented-service-boundaries) for expected
results and sanitized evidence locations.
