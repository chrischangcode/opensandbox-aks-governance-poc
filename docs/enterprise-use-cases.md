# Enterprise Use Cases for Managed Remote Sandboxes

An AKS-managed sandbox can be more than a remote shell. The useful product
primitive is a short-lived, strongly isolated workspace with an admin-selected
runtime, tools, data connectors, commands, credentials, network destinations,
approval rules, lifetime, and audit policy.

The service could be consumed directly by an engineering organization, or exposed as
a platform API that lets enterprise SaaS builders publish domain-specific sandbox
templates and administration experiences for their own customers.

The examples below are product scenarios, not claims that every named integration
already exists in this POC. The POC demonstrates the common enforcement model:
immutable templates, Kata-isolated execution, exact egress policy, temporary
elevation, Pod-bound authority, per-sandbox attribution, and cleanup.

## 1. Engineering team: governed developer and coding-agent workspaces

### Customer

An engineering organization wants developers and coding agents to work on private
repositories without giving every laptop, CI runner, or agent a standing path to
source code, package registries, test subscriptions, and production systems.

GitHub Codespaces demonstrates demand for isolated, reproducible remote development:
each codespace runs in a separate VM and network, receives an expiring repository
token, and injects development secrets only into authorized environments. GitHub
Actions OIDC similarly shows how an automated workload can exchange a scoped identity
for short-lived cloud credentials instead of storing a permanent secret.

### Sandbox profiles

| Profile | Pre-approved capabilities |
|---|---|
| `pr-reader` | Read one repository and pull request, query approved internal documentation, run static analysis, and post review findings. |
| `pr-author` | Read/write one branch, use approved package registries, run the repository's exact build/test commands, and open a pull request. |
| `integration-debugger` | Read a test namespace and selected logs; no production subscription, cluster-admin, or unrestricted internet access. |

### Example workflow

1. A developer or issue-assigned coding agent creates a sandbox from the team's
   digest-pinned template.
2. The sandbox receives a repository-scoped GitHub App or federated token, not the
   developer's general-purpose credential.
3. Egress is limited to GitHub, Azure Container Registry, Azure Artifacts, approved
   documentation, and specific test endpoints.
4. The command policy permits the repository's build, lint, test, and packaging
   commands. Attempts to run an unapproved deployment or host-management command are
   rejected before execution.
5. If the agent needs a new package feed or temporary access to a test resource, it
   creates an exact, time-limited request that names the tool, target, method, and
   reason. The engineering platform administrator approves or denies it.
6. The sandbox returns a patch or pull request plus hashed test evidence, then is
   deleted. Its credentials and Pod-bound grants cannot be replayed by a later
   sandbox.

### Why the managed sandbox matters

- A repository can define the development environment while the platform team retains
  control over the security boundary.
- Untrusted build scripts and agent-generated commands run inside a Kata VM rather
  than on a developer workstation or shared runner host.
- Different teams can receive different templates without creating bespoke clusters
  or CI systems.
- The same admission, approval, and audit model works for interactive developers,
  pull-request agents, incident diagnostics, and batch validation.

Relevant technologies include [GitHub Codespaces security isolation and expiring
tokens](https://docs.github.com/en/codespaces/reference/security-in-github-codespaces),
the [Development Containers specification](https://containers.dev/), and
[GitHub Actions OIDC short-lived cloud
credentials](https://docs.github.com/en/actions/concepts/security/openid-connect).

## 2. Legal platform: matter-scoped research, discovery, and drafting agents

### Customer

An enterprise legal software provider offers law firms a configurable AI workspace.
Each firm is a tenant, and each client matter is a narrower security boundary. The
provider wants agents to use authoritative research, e-discovery, and document
systems without creating a second, weaker permission model around the firm's data.

This maps to real legal platforms:

- [Lexis APIs](https://www.lexisnexis.com/en-us/products/lexis-api.page) expose
  statutes, case law, regulatory updates, news, and analytics through standardized
  APIs.
- Relativity exposes workspace-level
  [search](https://platform.relativity.com/RelativityOne/Content/BD_Extensibility/Search_Provider_service_in_REST.htm)
  and [export
  APIs](https://platform.relativity.com/RelativityOne/Content/Relativity_Platform/Relativity_Export_SDK/Overview/Relativity_Export_Service_API.htm)
  for e-discovery workflows.
- [NetDocuments AI integrations](https://www.netdocuments.com/legal-ai-integrations/)
  state that MCP access is scoped to the authenticated user and continues to apply
  existing permissions, ethical walls, and DLP rules.
- [NetDocuments ethical
  walls](https://www.netdocuments.com/solutions/ethical-walls/) are an example of the
  conflict and need-to-know controls that the sandbox must preserve rather than
  bypass.

### Sandbox profiles

| Profile | Pre-approved capabilities |
|---|---|
| `matter-research-reader` | Query approved Lexis APIs and the firm's precedent library; no access to unrelated client workspaces and no document writes. |
| `matter-discovery-reader` | Search one Relativity workspace and read only the collections assigned to the authenticated review team. |
| `matter-drafting-writer` | Read firm-approved templates and matter-approved source excerpts, then write drafts only to a designated work-product folder. It cannot browse other client documents. |

### Example workflow

1. A lawyer starts a discovery agent for `Firm A / Client B / Matter 2026-014`.
2. The platform resolves that matter to an immutable sandbox template and connector
   set. The sandbox cannot select a broader firm or client identity.
3. The research connector can call exact Lexis API operations. The discovery connector
   can query only the authorized Relativity workspace. The document connector uses the
   lawyer's existing NetDocuments identity, so ethical walls and DLP remain
   authoritative.
4. Retrieved text is delivered to the agent only for the current task. General web
   browsing, bulk export, unrelated matter search, and arbitrary external upload sites
   are denied.
5. A drafting agent receives selected exhibits, citations, and firm templates. It can
   write a draft to the current matter's work-product folder but cannot read another
   client's case documents merely because it has document-write capability.
6. If the agent needs one sealed exhibit or a larger discovery collection, the request
   is surfaced to the matter owner with the exact resource, purpose, and expiry.
7. Every connector decision is attributed to the firm, matter, sandbox assignment,
   Pod incarnation, user, and policy revision.

### Why the managed sandbox matters

- The legal application vendor can offer configurable AI workflows without placing
  customer documents in a shared, unrestricted agent runtime.
- Research, discovery, and drafting become separate capability profiles instead of
  one overly powerful "legal agent."
- Existing source-system authorization remains the first line of defense; the sandbox
  adds compute, tool, credential, egress, lifetime, and audit boundaries.
- A law firm administrator can pre-encode approved research sources and drafting
  destinations while retaining an explicit exception workflow.

## 3. Healthcare and life sciences: study-scoped clinical research agents

### Customer

A hospital, pharmaceutical sponsor, or contract research organization wants
investigators to use an LLM and Python/R tools to explore clinical cohorts, summarize
trial evidence, and prepare study documents without granting an agent broad access to
the electronic health record or identifiable data from unrelated studies.

[Azure Health Data Services FHIR
service](https://learn.microsoft.com/en-us/azure/healthcare-apis/fhir/) provides a
managed standards-based API for clinical data. Its built-in Azure RBAC roles include
[FHIR Data Reader, Writer, Exporter, and Contributor
roles](https://learn.microsoft.com/en-us/azure/healthcare-apis/configure-azure-rbac).
The
[de-identification
service](https://learn.microsoft.com/en-us/azure/healthcare-apis/deidentification/overview)
can tag, redact, or surrogate PHI in clinical text, supports private endpoints, and
supports managed identity for Azure Storage access. Azure Health Data Services also
supports [Private
Link](https://learn.microsoft.com/en-us/azure/healthcare-apis/configure-private-link)
and documents [network access
controls](https://learn.microsoft.com/en-us/azure/healthcare-apis/network-access-security).

### Sandbox profiles

| Profile | Pre-approved capabilities |
|---|---|
| `study-cohort-reader` | Read/search FHIR through a study-scoping API, invoke de-identification, and analyze approved de-identified datasets with Python/R. |
| `protocol-evidence-writer` | Read approved literature and aggregate study results, then write protocol or report drafts to a controlled study workspace. |
| `data-quality-triage` | Read source and validation errors, write only to a quarantine or correction queue, and never update the production clinical record directly. |

### Example workflow

1. An investigator creates a sandbox for `Study ABC`, cohort version 7.
2. The sandbox receives a managed or federated identity with FHIR Data Reader, not
   Writer or Contributor. A study-scoping API or separately isolated FHIR workspace
   restricts the request to the approved study population.
3. Clinical notes pass through the Azure de-identification service before being
   presented to the model. The sandbox can retain temporary analysis files but cannot
   send source data to public endpoints.
4. Cilium and private connectivity permit only the FHIR/study API,
   de-identification endpoint, approved model endpoint, study storage, and audit sink.
5. The agent can produce cohort counts, code, charts, and a draft report. Export of
   row-level data or access to another study requires a separate admin approval.
6. Pause/resume can preserve a long-running analysis while rotating the Pod identity,
   invalidating old credentials, and maintaining the study's audit chain.

### Important boundary

FHIR Data Reader is a service data-plane role; it does not by itself guarantee
row-level study or patient isolation. A production design must enforce cohort scope in
an application/API layer, a separately isolated data service, or an equivalent
data-level authorization system. The sandbox is defense in depth, not a substitute for
the source system's authorization and clinical governance.

This scenario is for governed research and document workflows. Clinical decision
support or patient-care automation would require separate clinical validation,
regulatory review, human oversight, and product safety controls.

### Why the managed sandbox matters

- Researchers get useful code execution without moving unrestricted PHI onto laptops
  or generic shared agent hosts.
- The model can be constrained to de-identified or cohort-filtered context while the
  source clinical system remains authoritative.
- Read, export, correction, and document-writing privileges become separate templates.
- Network, credential, audit, snapshot, and deletion policy can be reviewed as one
  study-specific control surface.

## Common product pattern

These domains share the same managed-service shape:

| Product concern | Sandbox platform answer |
|---|---|
| Who owns the boundary? | An enterprise administrator publishes immutable templates and policy revisions. |
| What can the agent do? | Exact commands, tools, connectors, credential scopes, and network targets are pre-encoded. |
| How does it ask for more? | The agent creates a narrow request with resource, action, reason, and expiry; an authorized owner decides. |
| How is tenant context preserved? | Caller identity and tenant/matter/study scope are resolved by the control plane, never trusted from agent-supplied fields. |
| How is data leakage limited? | Kata isolation, mandatory egress policy, short-lived credentials, private endpoints, and source-system authorization are combined. |
| How is activity reviewed? | Every decision is tied to an immutable assignment, sandbox incarnation, user/workload identity, policy revision, and audit event. |
| What happens after the task? | The sandbox and temporary grants are deleted; snapshots and retained evidence follow explicit lifecycle policy. |

The differentiator is not merely running containers remotely. It is giving platform
builders a reusable way to turn enterprise policy into concrete, inspectable agent
workspaces without designing a new isolation and approval system for every domain.
