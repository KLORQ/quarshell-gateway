#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo_dir"

module=$(sed -n 's/^module //p' go.mod | head -n 1)
[ -n "$module" ] || { echo "pre-push: go.mod has no module directive" >&2; exit 1; }
if [ -z "${GOWORK:-}" ]; then
  workspace="$(dirname "$repo_dir")/go.work"
  if [ -f "$workspace" ] && grep -Fq "./$(basename "$repo_dir")" "$workspace"; then
    export GOWORK="$workspace"
  else
    export GOWORK=off
  fi
fi
export CGO_ENABLED="${CGO_ENABLED:-0}"

printf 'pre-push: %s (GOWORK=%s, CGO_ENABLED=%s)\n' "$module" "$GOWORK" "$CGO_ENABLED"
go_files=$(find . -type f -name '*.go' -not -path './vendor/*' -print -quit)
if [ -n "$go_files" ]; then
  unformatted=$(find . -type f -name '*.go' -not -path './vendor/*' -print0 | xargs -0 gofmt -l)
  if [ -n "$unformatted" ]; then
    printf 'gofmt required:\n%s\n' "$unformatted" >&2
    exit 1
  fi
fi
go mod verify
go test -mod=readonly ./...
go vet -mod=readonly ./...
go build -mod=readonly ./...
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run --timeout=5m ./...
printf 'pre-push: PASS\n'
