#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if command -v python3 >/dev/null 2>&1; then
  python_bin=python3
elif command -v python >/dev/null 2>&1; then
  python_bin=python
else
  echo "python3 or python is required" >&2
  exit 1
fi

"$python_bin" - <<'PY'
import json
from pathlib import Path

config = json.loads(Path('opencode.json').read_text(encoding='utf-8'))
enabled = config['mcp']['sandbox_governance']['enabled']
if enabled is not False:
    raise SystemExit('opencode.json must leave sandbox_governance disabled by default')
PY

digest="sha256:$(printf 'a%.0s' {1..64})"
valid_ref="example.azurecr.io/opensandbox/assignmentd@$digest"
invalid_ref="example.azurecr.io/opensandbox/assignmentd:governance-poc"

scripts/require-image-digest.sh "$valid_ref" TEST_IMAGE >/dev/null
if scripts/require-image-digest.sh "$invalid_ref" TEST_IMAGE >/dev/null 2>&1; then
  echo "tag-only image unexpectedly passed digest validation" >&2
  exit 1
fi

rendered="$(ASSIGNMENTD_IMAGE="$valid_ref" scripts/render-assignmentd.sh)"
grep -Fq "image: $valid_ref" <<<"$rendered" || {
  echo "render-assignmentd.sh did not render the digest-pinned image" >&2
  exit 1
}
if grep -Fq '${ASSIGNMENTD_IMAGE}' <<<"$rendered"; then
  echo "render-assignmentd.sh left ASSIGNMENTD_IMAGE unresolved" >&2
  exit 1
fi
if ASSIGNMENTD_IMAGE="$invalid_ref" scripts/render-assignmentd.sh >/dev/null 2>&1; then
  echo "render-assignmentd.sh accepted a tag-only image" >&2
  exit 1
fi

grep -Fq 'disabled by default' README.md || {
  echo 'README.md must document the disabled-by-default OpenCode MCP entry' >&2
  exit 1
}
grep -Fq 'unreviewed branch or pull request' README.md || {
  echo 'README.md must warn against enabling the MCP entry for unreviewed code' >&2
  exit 1
}
grep -Fq './scripts/resolve-acr-image.sh "$ACR_NAME" "opensandbox/assignmentd" "governance-poc"' README.md || {
  echo 'README.md must show digest resolution for assignmentd' >&2
  exit 1
}
grep -Fq './scripts/render-assignmentd.sh |' README.md || {
  echo 'README.md must render assignmentd through the digest-checking helper' >&2
  exit 1
}
grep -Fq 'disabled by default' docs/live-demo-report.md || {
  echo 'docs/live-demo-report.md must document the disabled-by-default MCP entry' >&2
  exit 1
}
grep -Fq './scripts/render-assignmentd.sh |' docs/live-demo-report.md || {
  echo 'docs/live-demo-report.md must render assignmentd through the digest-checking helper' >&2
  exit 1
}
grep -Fq '.mcp.sandbox_governance.enabled' scripts/live-demo.sh || {
  echo 'scripts/live-demo.sh must require an explicit local MCP opt-in' >&2
  exit 1
}
grep -Fq './scripts/resolve-acr-image.sh "$(ACR_NAME)" "$(SERVER_IMAGE_NAME)" "$(SERVER_IMAGE_TAG)"' Makefile || {
  echo 'Makefile must resolve the OpenSandbox server deployment image to a digest' >&2
  exit 1
}
grep -Fq 'require-image-digest.sh' scripts/deploy-opensandbox.sh || {
  echo 'scripts/deploy-opensandbox.sh must require a digest-pinned server image' >&2
  exit 1
}

echo 'publication safety checks passed'
