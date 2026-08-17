# OpenSandbox Server Deployment

This deployment packages the upstream OpenSandbox lifecycle server for AKS and configures it to create sandboxes with the `kata-optimized` RuntimeClass.

## What It Runs

- OpenSandbox Kubernetes controller, installed from the upstream Helm chart.
- OpenSandbox lifecycle server, built from `Dockerfile`.
- OpenSandbox ingress gateway for browser/WebSocket sandbox endpoints.
- Kubernetes manifests and server configuration for the lifecycle server.

The Makefile installs controller chart `0.2.0` so BatchSandbox pause/resume is available. Pause/resume depends on the `SandboxSnapshot` CRD and `BatchSandbox.spec.pause`; older controller releases do not provide those fields.

## Runtime Configuration

`config/sandbox.toml` uses:

```toml
[runtime]
type = "kubernetes"
execd_image = "opensandbox/execd:v1.0.18"

[kubernetes]
workload_provider = "batchsandbox"
batchsandbox_template_file = "/app/batchsandbox-template.yaml"

[secure_runtime]
type = "kata"
k8s_runtime_class = "kata-optimized"
```

The Bicep template keeps cluster components on a non-Kata Azure Linux system pool and creates a dedicated tainted Kata user pool with `workloadRuntime: 'KataMshvVmIsolation'`, which creates the AKS `kata-vm-isolation` RuntimeClass. `make controller-install` also creates `kata-optimized`, which is identical to `kata-vm-isolation` except for a reduced `32Mi` pod memory overhead. `k8s/batchsandbox-template.yaml` sets the optimized runtime class and targets the Kata pool with a node selector and toleration.

## Pause/Resume Snapshot Configuration

`make controller-install` passes snapshot settings to the controller:

```text
controller.snapshot.registry=$(OPEN_SANDBOX_SNAPSHOT_REGISTRY)
controller.snapshot.snapshotPushSecret=$(OPEN_SANDBOX_SNAPSHOT_SECRET)
controller.snapshot.resumePullSecret=$(OPEN_SANDBOX_SNAPSHOT_SECRET)
controller.snapshot.imageCommitterImage=$(OPEN_SANDBOX_IMAGE_COMMITTER_IMAGE)
```

`make k8s-deploy` creates `OPEN_SANDBOX_SNAPSHOT_SECRET` as a docker-registry secret by default when `OPEN_SANDBOX_SNAPSHOT_REGISTRY` points at this repo's ACR. Otherwise, create an equivalent `kubernetes.io/dockerconfigjson` secret in the sandbox namespace before calling `sandbox pause`, or set `ENABLE_SNAPSHOT_REGISTRY_SECRET=false` to opt out of automatic secret creation.

Deploy from the repository root with `make k8s-deploy`, or run the full workflow with `make all`.

`make image-push` still tags and pushes `$(SERVER_IMAGE)` for convenience, but
`make k8s-deploy` resolves that pushed tag to an immutable ACR digest before it
renders `k8s/opensandbox-server.yaml`.

If you use `scripts/deploy-opensandbox.sh` directly, set
`OPENSANDBOX_SERVER_IMAGE` to a digest-pinned reference first. The helper
below resolves a pushed ACR tag to the required digest form (replace the
repository or tag if you used different values):

```bash
export OPENSANDBOX_SERVER_IMAGE="$(
  ./scripts/resolve-acr-image.sh "$ACR_NAME" "opensandbox-kata-server" "${SERVER_IMAGE_TAG:-latest}" "${SUBSCRIPTION_ID:-}"
)"
./scripts/deploy-opensandbox.sh
```

## Ingress Gateway

By default, `config/sandbox.toml` renders gateway ingress settings so examples can use browser-friendly HTTP/WebSocket endpoints:

```bash
make k8s-deploy
```

The Makefile then renders:

```toml
[ingress]
mode = "gateway"
gateway.address = "127.0.0.1:8081"
gateway.route.mode = "header"
```

It also deploys `k8s/opensandbox-ingress-gateway.yaml`. For local examples, the Makefile port-forwards `svc/opensandbox-ingress-gateway` to `INGRESS_GATEWAY_LOCAL_PORT`, which defaults to `8081`.
