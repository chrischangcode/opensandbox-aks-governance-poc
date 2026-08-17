# OpenSandbox Python Client Example

This example uses the upstream OpenSandbox Python SDK against the OpenSandbox lifecycle server deployed by this repository.

It creates a sandbox, runs commands, writes and reads a file, prints `uname -a`, verifies the sandbox workload uses the `kata-optimized` RuntimeClass, and cleans up the sandbox.

## Prerequisites

- The AKS OpenSandbox server is already deployed with `make k8s-deploy` from the repository root.
- `kubectl` points at the AKS cluster.
- `uv` is available.

## Automated Run

Run the Python SDK example from the repository root after `make k8s-deploy`:

```bash
make python-client-example
```

The target installs SDK dependencies into `.venv` with `uv`, port-forwards the OpenSandbox server and ingress gateway, runs `app.py`, verifies `kata-optimized`, and kills the sandbox when finished.

## Step-By-Step Run

Install the pinned SDK into the repository virtual environment:

```bash
uv venv --allow-existing .venv
uv pip install --python .venv opensandbox==0.1.10
```

Port-forward the OpenSandbox server:

```bash
kubectl -n opensandbox port-forward svc/opensandbox-server 8080:8080
```

Port-forward the OpenSandbox ingress gateway in a second terminal:

```bash
kubectl -n opensandbox port-forward svc/opensandbox-ingress-gateway 8081:80
```

In another terminal, load the API key from the Kubernetes Secret and run the client:

```bash
export OPEN_SANDBOX_API_KEY=$(kubectl -n opensandbox get secret opensandbox-server -o jsonpath='{.data.api-key}' | base64 -d)
OPEN_SANDBOX_DOMAIN=localhost:8080 VERIFY_KATA_WITH_KUBECTL=1 uv run --no-project --python .venv/bin/python python examples/python-client/app.py
```
