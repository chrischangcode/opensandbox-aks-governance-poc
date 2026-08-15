# Live demonstration report

Date: 2026-08-15

This demonstration used a disposable AKS cluster with an isolated Kata node,
OpenSandbox, the assignment governance service, two loopback-only dashboard
identities, and OpenCode configured as a sandbox-only agent.

No subscription IDs, credentials, API keys, tokens, or private service URLs are
included below.

## Local pages

All pages returned HTTP 200 and remained bound to loopback:

- Requester: <http://127.0.0.1:18081/dashboard/>
- Access requests: <http://127.0.0.1:18081/dashboard/access>
- Administrator: <http://127.0.0.1:18082/dashboard/admin>

The administrator page displayed the enabled immutable template
`python-kata-reader-v1`.

## Administrator-approved template

```text
NAME                    CAPABILITY                 DIGEST-PINNED   ENABLED
python-kata-reader-v1   team-a-harness-reader-v1   true            true
```

The template selects a digest-pinned Python image, the
`team-a-harness-reader-v1` capability bundle, 500m CPU, 512Mi memory, a
30-minute maximum lifetime, and Kata-backed execution.

## OpenCode sandbox-only execution

OpenCode connected to the project MCP server:

```text
MCP Servers
✓ sandbox_governance connected
  bash ./harness/run-mcp.sh
```

The `sandbox-only` agent listed approved templates and invoked
`run_ephemeral` for:

```text
uname -a && python --version
```

The tool returned:

```text
Template:          python-kata-reader-v1
Sandbox ID:        d1f60723-cbdb-43f9-8e54-4f6166b03bb5
Assignment:        assignment-nb9mr
Capability bundle: team-a-harness-reader-v1
Runtime class:     kata-optimized
Exit code:         0
Cleaned up:        true
```

Command output:

```text
Linux d1f60723-cbdb-43f9-8e54-4f6166b03bb5-0 6.6.137.mshv1-1.azl3 #1 SMP Tue May 19 17:02:13 UTC 2026 x86_64 GNU/Linux
Python 3.12.14
```

The MSHV guest kernel and `kata-optimized` runtime class show that the command
ran inside the Kata sandbox rather than on the OpenCode host. A Kubernetes
lookup after the tool returned found no remaining assignment or sandbox for
that ID.

The same agent then attempted the unapproved exact command `id`. The MCP tool
rejected it before sandbox creation:

```text
Error executing tool run_ephemeral: command is not allowed by the capability bundle
```

This verifies that disabling OpenCode's host tools is complemented by a
server-side, fail-closed command policy in the referenced capability bundle.

## Per-sandbox egress attribution and approval

An authorization probe used a short-lived projected token bound to the live
sandbox Pod and requested the exact target `GET https://example.com/docs`.

Initial decision:

```text
assignment: assignment-t2zvg
sandbox:    5c620c38-f2ae-450b-a744-25fa6c8ac01f
target:     GET https://example.com/docs
backend:    external-web
allowed:    false
```

The requester page created `access-5dhhn` from that denied event. The
administrator page approved 15 minutes of access for the exact assignment UID,
bundle revision, backend, method, host, and path.

The identical probe then returned:

```text
assignment: assignment-t2zvg
sandbox:    5c620c38-f2ae-450b-a744-25fa6c8ac01f
target:     GET https://example.com/docs
backend:    external-web
allowed:    true
```

Sanitized telemetry recorded both decisions:

```text
TIME                   SANDBOX                                TENANT     TEAM      TARGET        PATH    ALLOWED   SOURCE           REQUEST
2026-08-15T21:20:32Z   5c620c38-f2ae-450b-a744-25fa6c8ac01f   tenant-a   readers   example.com   /docs   false     deny             <none>
2026-08-15T21:21:05Z   5c620c38-f2ae-450b-a744-25fa6c8ac01f   tenant-a   readers   example.com   /docs   true      access-request   access-5dhhn
```

This proves that an egress decision can be attributed to one immutable sandbox
incarnation and logical tenant/team, and that a temporary admin approval is an
exact overlay rather than a mutation of the base capability bundle.

## Boundary behavior

- Admins define immutable, enabled sandbox templates.
- Template images are digest-pinned and capability references include the exact
  immutable policy revision.
- Harness users can select only those templates.
- OpenCode's sandbox-only agent has no host shell, file-editing, browsing, or
  subagent tools.
- Every allowed harness command creates a fresh governed sandbox; the tool does
  not report cleanup complete until its assignment, workload, and Pod are gone.
- Temporary access cannot be reused when the assignment UID, policy revision,
  backend, HTTP method, normalized host, normalized path, or expiration differs.
- Audit events omit headers, queries, bodies, source IPs, credentials, and
  tokens.
- Logical tenants are demonstrated as governance boundaries; this POC does not
  claim physical Azure tenant isolation.
