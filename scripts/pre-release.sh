#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"
release_tag=${1:-${RELEASE_TAG:-}}
if [ -z "$release_tag" ]; then
  echo "usage: $0 <release-tag>" >&2
  exit 2
fi
git check-ref-format "refs/tags/$release_tag"
if git show-ref --verify --quiet "refs/tags/$release_tag"; then
  echo "pre-release: local tag already exists: $release_tag" >&2
  exit 1
fi
if git ls-remote --exit-code --refs origin "refs/tags/$release_tag" >/dev/null 2>&1; then
  echo "pre-release: remote tag already exists: $release_tag" >&2
  exit 1
fi
git diff --check
./scripts/pre-push.sh
if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo 'pre-release: working tree must be clean after qualification' >&2
  git status --short >&2
  exit 1
fi
printf 'pre-release: PASS (%s); publish step intentionally not run\n' "$release_tag"
