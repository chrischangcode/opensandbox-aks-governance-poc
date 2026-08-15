import asyncio
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import httpx
from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from mcp.server.fastmcp import FastMCP
from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig


GROUP = "aks-sandbox.azure.com"
VERSION = "v1alpha1"
TEMPLATE_PLURAL = "sandboxtemplates"
ASSIGNMENT_PLURAL = "sandboxassignments"
BUNDLE_PLURAL = "capabilitybundles"
WORKLOAD_GROUP = "sandbox.opensandbox.io"
WORKLOAD_VERSION = "v1alpha1"
WORKLOAD_PLURAL = "batchsandboxes"

mcp = FastMCP("sandbox_governance")


@dataclass(frozen=True)
class Settings:
    namespace: str
    workload_namespace: str
    assignmentd_url: str
    opensandbox_domain: str
    opensandbox_api_key: str


def settings() -> Settings:
    return Settings(
        namespace=os.getenv("SANDBOX_GOVERNANCE_NAMESPACE", "aks-sandbox-system"),
        workload_namespace=os.getenv("OPEN_SANDBOX_NAMESPACE", "opensandbox"),
        assignmentd_url=os.getenv(
            "ASSIGNMENTD_URL", "http://127.0.0.1:19080/opensandbox"
        ).rstrip("/"),
        opensandbox_domain=os.getenv(
            "OPEN_SANDBOX_DOMAIN", "127.0.0.1:18080"
        ),
        opensandbox_api_key=os.environ["OPEN_SANDBOX_API_KEY"],
    )


def custom_objects() -> client.CustomObjectsApi:
    config.load_kube_config(config_file=os.getenv("KUBECONFIG"))
    return client.CustomObjectsApi()


def core_api() -> client.CoreV1Api:
    config.load_kube_config(config_file=os.getenv("KUBECONFIG"))
    return client.CoreV1Api()


def load_template(name: str) -> dict[str, Any]:
    cfg = settings()
    template = custom_objects().get_namespaced_custom_object(
        GROUP, VERSION, cfg.namespace, TEMPLATE_PLURAL, name
    )
    spec = template["spec"]
    if not spec["enabled"]:
        raise ValueError(f"sandbox template {name!r} is disabled")
    bundle = custom_objects().get_namespaced_custom_object(
        GROUP,
        VERSION,
        cfg.namespace,
        BUNDLE_PLURAL,
        spec["capabilityBundleRef"]["name"],
    )
    actual_revision = policy_revision(bundle["spec"])
    expected_revision = spec["capabilityBundleRef"]["policyRevision"]
    if actual_revision != expected_revision:
        raise ValueError(
            f"sandbox template {name!r} references a stale capability bundle revision"
        )
    enforce_command_policy(bundle, "")
    template["_resolvedCapabilityBundle"] = bundle
    return template


def policy_revision(spec: dict[str, Any]) -> str:
    body = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def enforce_command_policy(bundle: dict[str, Any], command: str) -> None:
    rules = bundle.get("spec", {}).get("harness", {}).get("commandPolicy", [])
    if command == "":
        if not rules:
            raise PermissionError("capability bundle has no harness command policy")
        return
    for rule in rules:
        try:
            matches = re.fullmatch(rule["pattern"], command) is not None
        except re.error as error:
            raise ValueError("capability bundle contains an invalid command pattern") from error
        if not matches:
            continue
        reason = rule.get("reason") or "no reason supplied"
        if rule["decision"] == "allow":
            return
        if rule["decision"] == "require_approval":
            raise PermissionError(f"command requires administrator approval: {reason}")
        raise PermissionError(f"command denied by capability bundle: {reason}")
    raise PermissionError("command is not allowed by the capability bundle")


async def create_sandbox(template: dict[str, Any]) -> str:
    cfg = settings()
    spec = template["spec"]
    body = {
        "image": {"uri": spec["image"]},
        "entrypoint": spec["entrypoint"],
        "timeout": spec["timeoutSeconds"],
        "resourceLimits": spec["resources"],
        "metadata": {
            "aks-sandbox.azure.com/template": template["metadata"]["name"],
            "aks-sandbox.azure.com/harness": "opencode-mcp",
        },
        "extensions": {
            "aks-sandbox.azure.com/capabilityProfile": spec[
                "capabilityBundleRef"
            ]["name"]
        },
    }
    async with httpx.AsyncClient(timeout=300) as http:
        response = await http.post(f"{cfg.assignmentd_url}/sandboxes", json=body)
        response.raise_for_status()
        return response.json()["id"]


async def delete_sandbox(sandbox_id: str) -> None:
    cfg = settings()
    async with httpx.AsyncClient(timeout=120) as http:
        response = await http.delete(
            f"{cfg.assignmentd_url}/sandboxes/{sandbox_id}"
        )
        if response.status_code not in (200, 202, 204, 404):
            response.raise_for_status()


async def wait_for_cleanup(sandbox_id: str, pod_name: str | None) -> bool:
    cfg = settings()
    api = custom_objects()
    core = core_api()
    for _ in range(120):
        assignments = api.list_namespaced_custom_object(
            GROUP,
            VERSION,
            cfg.namespace,
            ASSIGNMENT_PLURAL,
            label_selector=f"aks-sandbox.azure.com/opensandbox-id={sandbox_id}",
        )
        workload_absent = False
        try:
            api.get_namespaced_custom_object(
                WORKLOAD_GROUP,
                WORKLOAD_VERSION,
                cfg.workload_namespace,
                WORKLOAD_PLURAL,
                sandbox_id,
            )
        except ApiException as error:
            if error.status != 404:
                raise
            workload_absent = True
        pod_absent = pod_name is None
        if pod_name is not None:
            try:
                core.read_namespaced_pod(pod_name, cfg.workload_namespace)
            except ApiException as error:
                if error.status != 404:
                    raise
                pod_absent = True
        if not assignments["items"] and workload_absent and pod_absent:
            return True
        await asyncio.sleep(1)
    return False


async def wait_for_assignment(sandbox_id: str) -> dict[str, Any]:
    cfg = settings()
    api = custom_objects()
    for _ in range(90):
        assignments = api.list_namespaced_custom_object(
            GROUP,
            VERSION,
            cfg.namespace,
            ASSIGNMENT_PLURAL,
            label_selector=f"aks-sandbox.azure.com/opensandbox-id={sandbox_id}",
        )
        if assignments["items"]:
            assignment = assignments["items"][0]
            conditions = assignment.get("status", {}).get("conditions", [])
            ready = next(
                (condition for condition in conditions if condition["type"] == "Ready"),
                None,
            )
            if ready and ready["status"] == "True":
                return assignment
            if ready and ready["reason"] not in ("PodPending", "PodNotReady"):
                raise RuntimeError(
                    f"assignment rejected sandbox: {ready['reason']}: {ready['message']}"
                )
        await asyncio.sleep(1)
    raise TimeoutError("sandbox assignment did not become ready")


def execution_output(execution: Any) -> tuple[str, str]:
    stdout = "".join(chunk.text for chunk in execution.logs.stdout)
    stderr = "".join(chunk.text for chunk in execution.logs.stderr)
    return stdout, stderr


@mcp.tool()
def list_templates() -> str:
    """List enabled admin-approved sandbox templates."""
    cfg = settings()
    response = custom_objects().list_namespaced_custom_object(
        GROUP, VERSION, cfg.namespace, TEMPLATE_PLURAL
    )
    templates = []
    for item in response["items"]:
        spec = item["spec"]
        if spec["enabled"]:
            templates.append(
                {
                    "name": item["metadata"]["name"],
                    "displayName": spec["displayName"],
                    "description": spec.get("description", ""),
                    "image": spec["image"],
                    "capabilityBundle": spec["capabilityBundleRef"]["name"],
                    "resources": spec["resources"],
                    "timeoutSeconds": spec["timeoutSeconds"],
                }
            )
    return json.dumps(templates, indent=2)


@mcp.tool()
async def run_ephemeral(template_name: str, command: str) -> str:
    """Run one command in a fresh governed sandbox and always delete it."""
    if not command.strip():
        raise ValueError("command is required")
    template = load_template(template_name)
    enforce_command_policy(template["_resolvedCapabilityBundle"], command)
    cfg = settings()
    sandbox_id = await create_sandbox(template)
    sandbox: Sandbox | None = None
    cleaned_up = False
    pod_name: str | None = None
    try:
        assignment = await wait_for_assignment(sandbox_id)
        pod_name = assignment["status"]["podRef"]["name"]
        pod = core_api().read_namespaced_pod(pod_name, cfg.workload_namespace)
        connection = ConnectionConfig(
            domain=cfg.opensandbox_domain,
            api_key=cfg.opensandbox_api_key,
            request_timeout=timedelta(minutes=5),
            use_server_proxy=False,
        )
        sandbox = await Sandbox.connect(
            sandbox_id, connection_config=connection, connect_timeout=timedelta(minutes=2)
        )
        execution = await sandbox.commands.run(command)
        stdout, stderr = execution_output(execution)
        result = {
            "template": template_name,
            "sandboxId": sandbox_id,
            "assignment": assignment["metadata"]["name"],
            "capabilityBundle": assignment["status"]["resolvedCapabilityBundle"][
                "name"
            ],
            "pod": pod_name,
            "runtimeClass": pod.spec.runtime_class_name,
            "node": pod.spec.node_name,
            "command": command,
            "stdout": stdout,
            "stderr": stderr,
            "exitCode": getattr(execution, "exit_code", None),
        }
    finally:
        if sandbox is not None:
            await sandbox.close()
        await delete_sandbox(sandbox_id)
        cleaned_up = await wait_for_cleanup(sandbox_id, pod_name)
    if not cleaned_up:
        raise RuntimeError(
            "sandbox deletion was requested but Kubernetes cleanup was not confirmed"
        )
    result["cleanedUp"] = cleaned_up
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
