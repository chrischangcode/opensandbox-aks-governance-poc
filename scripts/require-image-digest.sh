#!/usr/bin/env bash
set -euo pipefail

if (($# < 1 || $# > 2)); then
  echo "usage: $0 <image-ref> [variable-name]" >&2
  exit 64
fi

image_ref="$1"
variable_name="${2:-IMAGE_REF}"

if [[ ! "$image_ref" =~ ^[^[:space:]]+@sha256:[0-9a-f]{64}$ ]]; then
  echo "$variable_name must be a digest-pinned image reference (example: registry/repository@sha256:...)" >&2
  echo "got: $image_ref" >&2
  exit 1
fi

printf '%s\n' "$image_ref"
