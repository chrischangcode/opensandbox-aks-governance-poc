import asyncio
import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

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
VALIDATION_PLURAL = "sandboxvalidationruns"
WORKLOAD_GROUP = "sandbox.opensandbox.io"
WORKLOAD_VERSION = "v1alpha1"
WORKLOAD_PLURAL = "batchsandboxes"

mcp = FastMCP("sandbox_governance")


@dataclass(frozen=True)
class Settings:
    namespace: str
    workload_namespace: str
    assignmentd_url: str
    broker_url: str
    opensandbox_domain: str
    opensandbox_api_key: str
    assignmentd_token_file: str


def settings() -> Settings:
    return Settings(
        namespace=os.getenv("SANDBOX_GOVERNANCE_NAMESPACE", "aks-sandbox-system"),
        workload_namespace=os.getenv("OPEN_SANDBOX_NAMESPACE", "opensandbox"),
        assignmentd_url=os.getenv(
            "ASSIGNMENTD_URL", "http://127.0.0.1:19080/opensandbox"
        ).rstrip("/"),
        broker_url=os.getenv(
            "CREDENTIAL_BROKER_URL", "http://127.0.0.1:19080/broker"
        ).rstrip("/"),
        opensandbox_domain=os.getenv(
            "OPEN_SANDBOX_DOMAIN", "127.0.0.1:18080"
        ),
        opensandbox_api_key=os.environ["OPEN_SANDBOX_API_KEY"],
        assignmentd_token_file=os.environ["ASSIGNMENTD_TOKEN_FILE"],
    )


def assignmentd_headers() -> dict[str, str]:
    token = open(settings().assignmentd_token_file, encoding="utf-8").read().strip()
    if not token:
        raise RuntimeError("assignmentd caller token is unavailable")
    return {"Authorization": "Bearer " + token}


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
    body = json.dumps(
        spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(body).hexdigest()}"


def exact_command(pattern: str) -> str | None:
    if len(pattern) < 2 or not pattern.startswith("^") or not pattern.endswith("$"):
        return None
    literal: list[str] = []
    body = pattern[1:-1]
    metacharacters = frozenset(r"\.^$*+?{}[]|()")
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\":
            index += 1
            if index >= len(body) or body[index] not in metacharacters:
                return None
            literal.append(body[index])
        elif character in metacharacters:
            return None
        else:
            literal.append(character)
        index += 1
    return "".join(literal)


def enforce_command_policy(bundle: dict[str, Any], command: str) -> None:
    rules = bundle.get("spec", {}).get("harness", {}).get("commandPolicy", [])
    if command == "":
        if not rules:
            raise PermissionError("capability bundle has no harness command policy")
        if any(exact_command(rule["pattern"]) is None for rule in rules):
            raise ValueError("capability bundle contains a non-exact command pattern")
        return
    if len(command) > 2048 or any(character in command for character in "\r\n\x00"):
        raise PermissionError("command exceeds the bounded exact-command policy")
    for rule in rules:
        if exact_command(rule["pattern"]) != command:
            continue
        reason = rule.get("reason") or "no reason supplied"
        if rule["decision"] == "allow":
            return
        if rule["decision"] == "require_approval":
            raise PermissionError(f"command requires administrator approval: {reason}")
        raise PermissionError(f"command denied by capability bundle: {reason}")
    raise PermissionError("command is not allowed by the capability bundle")


def normalize_changed_paths(changed_paths: list[str]) -> list[str]:
    if not changed_paths or len(changed_paths) > 256:
        raise ValueError("changed_paths must contain 1-256 repository-relative paths")
    normalized: list[str] = []
    for value in changed_paths:
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 512
            or value.startswith("/")
            or "\\" in value
            or any(part == ".." for part in value.split("/"))
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError(f"invalid repository-relative changed path: {value!r}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def select_validation_commands(
    bundle: dict[str, Any], changed_paths: list[str]
) -> list[str]:
    paths = normalize_changed_paths(changed_paths)
    rules = bundle.get("spec", {}).get("harness", {}).get("validationRules", [])
    commands: list[str] = []
    for rule in rules:
        prefix = rule.get("pathPrefix")
        command = rule.get("command")
        if not isinstance(prefix, str) or not isinstance(command, str):
            raise ValueError("capability bundle contains a malformed validation rule")
        if prefix != "*" and (
            not prefix
            or prefix.startswith("/")
            or "\\" in prefix
            or ".." in prefix
            or len(prefix) > 512
        ):
            raise ValueError("capability bundle contains an invalid path prefix")
        if prefix == "*" or any(path.startswith(prefix) for path in paths):
            enforce_command_policy(bundle, command)
            if command not in commands:
                commands.append(command)
    if not commands:
        raise PermissionError("no approved validation rule matches the changed paths")
    return commands


def evidence_hash(value: str) -> str:
    return f"sha256:{hashlib.sha256(value.encode('utf-8')).hexdigest()}"


def validate_evidence_identity(
    task_id: str, repository: str, source_revision: str
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", task_id):
        raise ValueError("task_id is invalid")
    for name, value, maximum in (
        ("repository", repository, 512),
        ("source_revision", source_revision, 128),
    ):
        if (
            not value
            or len(value) > maximum
            or value != value.strip()
            or any(ord(character) < 32 for character in value)
        ):
            raise ValueError(f"{name} is invalid")


def parse_broker_target(target: str) -> tuple[str, str]:
    parsed = urlsplit(target)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(
            "target must be an exact HTTPS URL without credentials, port, query, or fragment"
        )
    path = parsed.path or "/"
    if any(ord(character) < 32 for character in path) or len(path) > 2048:
        raise ValueError("target path is invalid")
    return parsed.hostname.lower().rstrip("."), path


def create_bound_identity_token(
    assignment: dict[str, Any], expiration_seconds: int = 600
) -> tuple[str, str]:
    cfg = settings()
    pod_ref = assignment["status"]["podRef"]
    pod = core_api().read_namespaced_pod(
        pod_ref["name"], cfg.workload_namespace
    )
    if str(pod.metadata.uid) != pod_ref["uid"] or not pod.status.pod_ip:
        raise RuntimeError("assignment Pod identity is stale or incomplete")
    response = core_api().create_namespaced_service_account_token(
        name=pod.spec.service_account_name,
        namespace=cfg.workload_namespace,
        body={
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenRequest",
            "spec": {
                "audiences": ["aks-sandbox-capability-gateway"],
                "expirationSeconds": expiration_seconds,
                "boundObjectRef": {
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "name": pod.metadata.name,
                    "uid": str(pod.metadata.uid),
                },
            },
        },
    )
    return response.status.token, pod.status.pod_ip


async def create_sandbox(template: dict[str, Any]) -> str:
    cfg = settings()
    body = {
        "metadata": {
            "aks-sandbox.azure.com/harness": "opencode-mcp",
        },
        "extensions": {
            "aks-sandbox.azure.com/template": template["metadata"]["name"]
        },
    }
    async with httpx.AsyncClient(timeout=300) as http:
        response = await http.post(
            f"{cfg.assignmentd_url}/sandboxes",
            json=body,
            headers={
                **assignmentd_headers(),
                "Idempotency-Key": str(uuid.uuid4()),
            },
        )
        if response.is_error:
            raise RuntimeError(
                f"assignmentd create failed with HTTP {response.status_code}: "
                f"{response.text[:1000]}"
            )
        return response.json()["id"]


async def delete_sandbox(sandbox_id: str) -> None:
    cfg = settings()
    async with httpx.AsyncClient(timeout=120) as http:
        response = await http.delete(
            f"{cfg.assignmentd_url}/sandboxes/{sandbox_id}",
            headers=assignmentd_headers(),
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


async def cleanup_ephemeral(
    sandbox: Sandbox | None, sandbox_id: str, pod_name: str | None
) -> tuple[bool, str]:
    errors: list[str] = []
    if sandbox is not None:
        try:
            await sandbox.close()
        except Exception as error:
            errors.append(f"close failed: {error}")
    try:
        await delete_sandbox(sandbox_id)
    except Exception as error:
        errors.append(f"delete failed: {error}")
    try:
        cleaned_up = await wait_for_cleanup(sandbox_id, pod_name)
    except Exception as error:
        errors.append(f"cleanup verification failed: {error}")
        cleaned_up = False
    if cleaned_up:
        return True, ""
    errors.append("Kubernetes cleanup was not confirmed")
    return False, "; ".join(errors)[:512]


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


async def wait_for_paused(sandbox_id: str, old_pod_name: str) -> None:
    cfg = settings()
    api = custom_objects()
    core = core_api()
    for _ in range(300):
        assignments = api.list_namespaced_custom_object(
            GROUP,
            VERSION,
            cfg.namespace,
            ASSIGNMENT_PLURAL,
            label_selector=f"aks-sandbox.azure.com/opensandbox-id={sandbox_id}",
        )
        paused = False
        if assignments["items"]:
            assignment = assignments["items"][0]
            conditions = assignment.get("status", {}).get("conditions", [])
            ready = next(
                (condition for condition in conditions if condition["type"] == "Ready"),
                None,
            )
            paused = (
                assignment.get("metadata", {})
                .get("annotations", {})
                .get("aks-sandbox.azure.com/paused")
                == "true"
                and ready is not None
                and ready["status"] == "False"
            )
        pod_absent = False
        try:
            core.read_namespaced_pod(old_pod_name, cfg.workload_namespace)
        except ApiException as error:
            if error.status != 404:
                raise
            pod_absent = True
        if paused and pod_absent:
            return
        await asyncio.sleep(1)
    raise TimeoutError("sandbox did not complete snapshot pause")


async def wait_for_resumed(
    sandbox_id: str, old_pod_uid: str
) -> dict[str, Any]:
    cfg = settings()
    api = custom_objects()
    for _ in range(300):
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
            pod_uid = assignment.get("status", {}).get("podRef", {}).get("uid")
            if (
                ready is not None
                and ready["status"] == "True"
                and pod_uid
                and pod_uid != old_pod_uid
            ):
                return assignment
        await asyncio.sleep(1)
    raise TimeoutError("sandbox did not resume with a fresh Pod identity")


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
            template = load_template(item["metadata"]["name"])
            templates.append(
                {
                    "name": item["metadata"]["name"],
                    "displayName": spec["displayName"],
                    "description": spec.get("description", ""),
                    "image": spec["image"],
                    "capabilityBundle": spec["capabilityBundleRef"]["name"],
                    "resources": spec["resources"],
                    "timeoutSeconds": spec["timeoutSeconds"],
                    "validationRules": len(
                        template["_resolvedCapabilityBundle"]
                        .get("spec", {})
                        .get("harness", {})
                        .get("validationRules", [])
                    ),
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
    result: dict[str, Any] | None = None
    failure: Exception | None = None
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
    except Exception as error:
        failure = error
    finally:
        cleaned_up, cleanup_error = await cleanup_ephemeral(
            sandbox, sandbox_id, pod_name
        )
    if cleanup_error:
        raise RuntimeError(cleanup_error) from failure
    if failure is not None:
        raise failure
    if result is None:
        raise RuntimeError("sandbox execution produced no result")
    result["cleanedUp"] = cleaned_up
    return json.dumps(result, indent=2)


@mcp.tool()
async def validate_change(
    template_name: str,
    task_id: str,
    repository: str,
    source_revision: str,
    changed_paths: list[str],
) -> str:
    """Select approved tests, run them only in a sandbox, and persist hashed evidence."""
    validate_evidence_identity(task_id, repository, source_revision)
    template = load_template(template_name)
    bundle = template["_resolvedCapabilityBundle"]
    normalized_paths = normalize_changed_paths(changed_paths)
    commands = select_validation_commands(bundle, normalized_paths)
    cfg = settings()
    sandbox_id = await create_sandbox(template)
    sandbox: Sandbox | None = None
    pod_name: str | None = None
    validation_name: str | None = None
    results: list[dict[str, Any]] = []
    outputs: list[dict[str, Any]] = []
    state = "Failed"
    message = ""
    cleaned_up = False
    failure: Exception | None = None
    status_failure: Exception | None = None
    evidence: dict[str, Any] | None = None
    try:
        assignment = await wait_for_assignment(sandbox_id)
        pod_name = assignment["status"]["podRef"]["name"]
        pod_uid = assignment["status"]["podRef"]["uid"]
        resolved_bundle = assignment["status"]["resolvedCapabilityBundle"]
        started_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        body = {
            "apiVersion": f"{GROUP}/{VERSION}",
            "kind": "SandboxValidationRun",
            "metadata": {
                "generateName": "validation-",
                "namespace": cfg.namespace,
            },
            "spec": {
                "taskId": task_id,
                "repository": repository,
                "sourceRevision": source_revision,
                "changedPaths": normalized_paths,
                "selectedCommands": commands,
                "templateName": template_name,
                "assignmentRef": {
                    "name": assignment["metadata"]["name"],
                    "uid": assignment["metadata"]["uid"],
                },
                "podUid": pod_uid,
                "sandboxId": sandbox_id,
                "capabilityBundleName": resolved_bundle["name"],
                "capabilityBundleRevision": resolved_bundle["policyRevision"],
                "startedAt": started_at,
            },
        }
        created = custom_objects().create_namespaced_custom_object(
            GROUP, VERSION, cfg.namespace, VALIDATION_PLURAL, body
        )
        validation_name = created["metadata"]["name"]
        custom_objects().patch_namespaced_custom_object_status(
            GROUP,
            VERSION,
            cfg.namespace,
            VALIDATION_PLURAL,
            validation_name,
            {"status": {"state": "Running"}},
        )
        pod = core_api().read_namespaced_pod(pod_name, cfg.workload_namespace)
        connection = ConnectionConfig(
            domain=cfg.opensandbox_domain,
            api_key=cfg.opensandbox_api_key,
            request_timeout=timedelta(minutes=5),
            use_server_proxy=False,
        )
        sandbox = await Sandbox.connect(
            sandbox_id,
            connection_config=connection,
            connect_timeout=timedelta(minutes=2),
        )
        for command in commands:
            execution = await sandbox.commands.run(command)
            stdout, stderr = execution_output(execution)
            exit_code = getattr(execution, "exit_code", None)
            if exit_code is None:
                exit_code = -1
            result = {
                "command": command,
                "exitCode": int(exit_code),
                "stdoutSha256": evidence_hash(stdout),
                "stderrSha256": evidence_hash(stderr),
            }
            results.append(result)
            outputs.append(
                {
                    "command": command,
                    "stdout": stdout,
                    "stderr": stderr,
                    "exitCode": int(exit_code),
                }
            )
            if exit_code != 0:
                message = f"validation command exited with status {exit_code}"
                break
        else:
            state = "Succeeded"
        evidence = {
            "validationRun": validation_name,
            "taskId": task_id,
            "repository": repository,
            "sourceRevision": source_revision,
            "template": template_name,
            "sandboxId": sandbox_id,
            "assignment": assignment["metadata"]["name"],
            "pod": pod_name,
            "podUid": pod_uid,
            "runtimeClass": pod.spec.runtime_class_name,
            "commands": outputs,
            "evidence": results,
            "state": state,
        }
    except Exception as error:
        failure = error
        message = str(error)[:512] or type(error).__name__
    finally:
        cleaned_up, cleanup_error = await cleanup_ephemeral(
            sandbox, sandbox_id, pod_name
        )
        if cleanup_error:
            state = "Failed"
            message = "; ".join(part for part in (message, cleanup_error) if part)[
                :512
            ]
        if validation_name is not None:
            completed_at = (
                datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            status = {
                "state": state,
                "completedAt": completed_at,
                "results": results,
                "cleanedUp": cleaned_up,
            }
            if message:
                status["message"] = message
            try:
                custom_objects().patch_namespaced_custom_object_status(
                    GROUP,
                    VERSION,
                    cfg.namespace,
                    VALIDATION_PLURAL,
                    validation_name,
                    {"status": status},
                )
            except Exception as error:
                status_failure = error
    if cleanup_error:
        raise RuntimeError(cleanup_error) from failure
    if status_failure is not None:
        raise status_failure
    if failure is not None:
        raise failure
    if evidence is None:
        raise RuntimeError("validation produced no evidence")
    evidence["cleanedUp"] = True
    return json.dumps(evidence, indent=2)


@mcp.tool()
async def exercise_brokered_credential(
    template_name: str,
    task_id: str,
    backend: str,
    method: str,
    target: str,
    ttl_seconds: int = 300,
) -> str:
    """Issue, use, revoke, and recheck a sandbox-bound short-lived credential."""
    validate_evidence_identity(task_id, "brokered-scope", "brokered-scope")
    if ttl_seconds < 60 or ttl_seconds > 900:
        raise ValueError("ttl_seconds must be between 60 and 900")
    host, path = parse_broker_target(target)
    template = load_template(template_name)
    cfg = settings()
    sandbox_id = await create_sandbox(template)
    pod_name: str | None = None
    cleaned_up = False
    failure: Exception | None = None
    result: dict[str, Any] | None = None
    try:
        assignment = await wait_for_assignment(sandbox_id)
        pod_name = assignment["status"]["podRef"]["name"]
        identity_token, source_address = create_bound_identity_token(assignment)
        async with httpx.AsyncClient(timeout=30) as http:
            issued = await http.post(
                f"{cfg.broker_url}/v1/credentials",
                json={
                    "identityToken": identity_token,
                    "backend": backend,
                    "method": method,
                    "host": host,
                    "path": path,
                    "taskId": task_id,
                    "ttlSeconds": ttl_seconds,
                },
            )
            issued.raise_for_status()
            issuance = issued.json()
            credential = issuance.pop("credential")
            used = await http.post(
                f"{cfg.broker_url}/v1/verify",
                headers={"Authorization": f"Bearer {credential}"},
            )
            used.raise_for_status()
            revoked = await http.post(
                f"{cfg.broker_url}/v1/revoke",
                headers={"Authorization": f"Bearer {credential}"},
            )
            revoked.raise_for_status()
            replay = await http.post(
                f"{cfg.broker_url}/v1/verify",
                headers={"Authorization": f"Bearer {credential}"},
            )
        result = {
            "template": template_name,
            "sandboxId": sandbox_id,
            "assignment": assignment["metadata"]["name"],
            "pod": pod_name,
            "taskId": task_id,
            "issuance": issuance,
            "use": used.json(),
            "revoked": True,
            "replayDenied": replay.status_code == 401,
            "credentialExposed": False,
        }
        if not result["replayDenied"]:
            raise RuntimeError("revoked credential replay was not denied")
    except Exception as error:
        failure = error
    finally:
        cleaned_up, cleanup_error = await cleanup_ephemeral(
            None, sandbox_id, pod_name
        )
    if cleanup_error:
        raise RuntimeError(cleanup_error) from failure
    if failure is not None:
        raise failure
    if result is None:
        raise RuntimeError("credential exercise produced no result")
    result["cleanedUp"] = True
    return json.dumps(result, indent=2)


@mcp.tool()
async def snapshot_pause_resume(
    template_name: str,
    task_id: str,
    backend: str,
    method: str,
    target: str,
) -> str:
    """Pause to a snapshot, resume, preserve state, and reject old authority."""
    validate_evidence_identity(task_id, "snapshot", "snapshot")
    host, path = parse_broker_target(target)
    template = load_template(template_name)
    cfg = settings()
    sandbox_id = await create_sandbox(template)
    sandbox: Sandbox | None = None
    old_pod_name: str | None = None
    cleanup_pod_name: str | None = None
    cleaned_up = False
    failure: Exception | None = None
    result: dict[str, Any] | None = None
    try:
        assignment = await wait_for_assignment(sandbox_id)
        old_pod_name = assignment["status"]["podRef"]["name"]
        cleanup_pod_name = old_pod_name
        old_pod_uid = assignment["status"]["podRef"]["uid"]
        identity_token, source_address = create_bound_identity_token(assignment)
        connection = ConnectionConfig(
            domain=cfg.opensandbox_domain,
            api_key=cfg.opensandbox_api_key,
            request_timeout=timedelta(minutes=5),
            use_server_proxy=False,
        )
        sandbox = await Sandbox.connect(
            sandbox_id,
            connection_config=connection,
            connect_timeout=timedelta(minutes=2),
        )
        marker = f"{task_id}:{old_pod_uid}"
        await sandbox.files.write_file(
            "/tmp/governance-snapshot-marker", marker, mode=600
        )
        async with httpx.AsyncClient(timeout=300) as http:
            issued = await http.post(
                f"{cfg.broker_url}/v1/credentials",
                json={
                    "identityToken": identity_token,
                    "backend": backend,
                    "method": method,
                    "host": host,
                    "path": path,
                    "taskId": task_id,
                    "ttlSeconds": 900,
                },
            )
            issued.raise_for_status()
            credential = issued.json()["credential"]
            await sandbox.close()
            sandbox = None
            paused = await http.post(
                f"{cfg.assignmentd_url}/sandboxes/{sandbox_id}/pause",
                headers=assignmentd_headers(),
            )
            paused.raise_for_status()
            await wait_for_paused(sandbox_id, old_pod_name)
            resumed = await http.post(
                f"{cfg.assignmentd_url}/sandboxes/{sandbox_id}/resume",
                headers=assignmentd_headers(),
            )
            resumed.raise_for_status()
            resumed_assignment = await wait_for_resumed(
                sandbox_id, old_pod_uid
            )
            stale_credential = await http.post(
                f"{cfg.broker_url}/v1/verify",
                headers={"Authorization": f"Bearer {credential}"},
            )
        new_pod_name = resumed_assignment["status"]["podRef"]["name"]
        cleanup_pod_name = new_pod_name
        new_pod_uid = resumed_assignment["status"]["podRef"]["uid"]
        sandbox = await Sandbox.connect(
            sandbox_id,
            connection_config=connection,
            connect_timeout=timedelta(minutes=2),
        )
        restored_marker = await sandbox.files.read_file(
            "/tmp/governance-snapshot-marker"
        )
        if restored_marker != marker:
            raise RuntimeError("snapshot did not preserve the approved marker")
        if stale_credential.status_code != 401:
            raise RuntimeError("pre-snapshot credential remained usable after resume")
        result = {
            "template": template_name,
            "sandboxId": sandbox_id,
            "assignment": resumed_assignment["metadata"]["name"],
            "snapshotStatePreserved": True,
            "oldPod": {"name": old_pod_name, "uid": old_pod_uid},
            "newPod": {"name": new_pod_name, "uid": new_pod_uid},
            "podIdentityRotated": old_pod_uid != new_pod_uid,
            "preSnapshotCredentialRejected": True,
            "credentialExposed": False,
        }
    except Exception as error:
        failure = error
    finally:
        cleaned_up, cleanup_error = await cleanup_ephemeral(
            sandbox, sandbox_id, cleanup_pod_name
        )
    if cleanup_error:
        raise RuntimeError(cleanup_error) from failure
    if failure is not None:
        raise failure
    if result is None:
        raise RuntimeError("snapshot exercise produced no result")
    result["cleanedUp"] = True
    return json.dumps(result, indent=2)


if __name__ == "__main__":
    mcp.run(transport="stdio")
