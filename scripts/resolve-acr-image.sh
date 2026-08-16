#!/usr/bin/env bash
set -euo pipefail

if (($# < 3 || $# > 4)); then
  echo "usage: $0 <acr-name> <repository> <tag> [subscription-id]" >&2
  exit 64
fi

acr_name="$1"
repository="$2"
tag="$3"
subscription_id="${4:-}"
subscription_args=()
if [[ -n "$subscription_id" ]]; then
  subscription_args=(--subscription "$subscription_id")
fi

login_server="$(az acr show --name "$acr_name" "${subscription_args[@]}" --query loginServer -o tsv)"
if [[ -z "$login_server" ]]; then
  echo "unable to resolve login server for $acr_name" >&2
  exit 1
fi

digest="$(az acr repository show --name "$acr_name" "${subscription_args[@]}" --image "${repository}:${tag}" --query digest -o tsv)"
if [[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo "unable to resolve immutable digest for ${repository}:${tag} in $acr_name" >&2
  exit 1
fi

printf '%s/%s@%s\n' "$login_server" "$repository" "$digest"
