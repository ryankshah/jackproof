#!/usr/bin/env bash
set -euo pipefail

marker='<!-- jackproof -->'
limit=60000
body_file="$1"
combined="$(mktemp)"

{
  echo "${marker}"
  head -c "${limit}" "${body_file}"
} > "${combined}"

api="repos/${GITHUB_REPOSITORY}/issues"
existing="$(gh api "${api}/${PR_NUMBER}/comments" --paginate --jq ".[] | select(.body | contains(\"${marker}\")) | .id" | head -n 1)"

if [ -n "${existing}" ]; then
  gh api --method PATCH "${api}/comments/${existing}" --field "body=@${combined}" > /dev/null
else
  gh api --method POST "${api}/${PR_NUMBER}/comments" --field "body=@${combined}" > /dev/null
fi
