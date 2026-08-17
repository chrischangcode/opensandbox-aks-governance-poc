import asyncio
import os
import subprocess
from datetime import timedelta

from opensandbox import Sandbox
from opensandbox.config import ConnectionConfig
from opensandbox.models import WriteEntry


def output_text(result) -> str:
    return "".join(part.text for part in (result.logs.stdout or [])).strip()


def kata_pod_exists(namespace: str) -> bool:
    completed = subprocess.run(
        [
            "kubectl",
            "get",
            "pods",
            "--namespace",
            namespace,
            "--output",
            "jsonpath={range .items[*]}{.spec.runtimeClassName}{'\\n'}{end}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return "kata-optimized" in completed.stdout.splitlines()


async def exercise_sandbox() -> None:
    connection = ConnectionConfig(
        domain=os.environ.get("OPEN_SANDBOX_DOMAIN", "localhost:8080"),
        api_key=os.environ.get("OPEN_SANDBOX_API_KEY", "dev-api-key"),
        request_timeout=timedelta(seconds=90),
        use_server_proxy=False,
    )
    sandbox = await Sandbox.create(
        os.environ.get("SANDBOX_IMAGE", "python:3.12-slim"),
        connection_config=connection,
        timeout=timedelta(minutes=10),
        resource={"cpu": "500m", "memory": "512Mi"},
        metadata={"scenario": "governed-aks-kata-smoke"},
    )

    try:
        greeting = await sandbox.commands.run(
            "printf 'hello from governed OpenSandbox on AKS\\n'"
        )
        print(f"command output: {output_text(greeting)}")

        kernel = await sandbox.commands.run("uname -a")
        print(f"sandbox kernel: {output_text(kernel)}")

        marker = "/tmp/governance-poc.txt"
        await sandbox.files.write_files(
            [WriteEntry(path=marker, data="sandbox file API works\n", mode=0o600)]
        )
        print(f"file roundtrip: {await sandbox.files.read_file(marker)}")

        if os.environ.get("VERIFY_KATA_WITH_KUBECTL") == "1":
            namespace = os.environ.get("OPEN_SANDBOX_NAMESPACE", "opensandbox")
            for _ in range(30):
                if kata_pod_exists(namespace):
                    print("runtime class: kata-optimized")
                    break
                await asyncio.sleep(1)
            else:
                raise RuntimeError("sandbox Pod did not use kata-optimized")
    finally:
        await sandbox.kill()


if __name__ == "__main__":
    asyncio.run(exercise_sandbox())
