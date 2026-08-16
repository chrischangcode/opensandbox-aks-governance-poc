#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
assignmentd_image="${ASSIGNMENTD_IMAGE:?set ASSIGNMENTD_IMAGE to a digest-pinned image reference}"
assignmentd_image="$("$repo_root/scripts/require-image-digest.sh" "$assignmentd_image" ASSIGNMENTD_IMAGE)"

sed "s|\${ASSIGNMENTD_IMAGE}|$assignmentd_image|g" \
  "$repo_root/deploy/governance/k8s/assignmentd.yaml"
