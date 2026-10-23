# quarshell-gateway

Gateway server module in the [`quarshell`](https://github.com/KLORQ/quarshell)
workspace. The implementation and remaining compatibility work are tracked in
[`plans/REMAINING.md`](../plans/REMAINING.md).

## Run locally

From the repository root:

```sh
export QUARSHELL_TOKEN="$(openssl rand -hex 32)"
go -C quarshell-gateway run ./cmd/quarshell-gateway \
  --listen 127.0.0.1:7443 \
  --grpc-listen 127.0.0.1:7444 \
  --runtime docker
```

`--data` selects a SQLite state file; without it, state stays in memory.
`--runtime-config` accepts backend configuration as JSON. HTTP API routes and
gRPC calls require the configured token in `Authorization: Bearer` or
`X-Quarshell-Token`, except for HTTP liveness and gRPC `Health`:

```sh
curl --fail http://127.0.0.1:7443/v1/healthz
```

For a VM runtime, the Gateway also accepts `--gateway-public-url` and these
environment-backed options: `QUARSHELL_RUNTIME_INIT_BINARY`,
`QUARSHELL_RUNTIME_SUPERVISOR_BINARY`, `QUARSHELL_RUNTIME_SSHD_BINARY`,
`QUARSHELL_RUNTIME_PROXY_BINARY`, and `QUARSHELL_RUNTIME_POLICY_PATH` (or the
matching `--runtime-*` flags). These paths configure the guest init,
supervisor, SSH daemon, host proxy, and policy passed to the VM backend. The VM
Gateway contract remains fail-closed until the host supervisor and isolation
handshake pass end-to-end acceptance; see `plans/REMAINING.md`.

The liveness response contains only `{"status":"ok"}`. The Docker image listens
on HTTP port `7443` and gRPC port `7444` on all interfaces. The shared token
authenticates gRPC calls as the static `gateway-client` platform administrator;
it does not provide per-user or sandbox identity, and gRPC has no TLS listener.
Keep gRPC bound to loopback or a trusted private network.

## Current scope

The gRPC server implements health/info/current-user, workspace and sandbox lifecycle,
policy chunks, templates, settings, providers, and exposed services. Generation-bound
sandbox token refresh, supervisor control, and loopback relay methods are present;
the complete OpenShell runtime RPC inventory remains partial and some methods fail
closed. See the migration plan for the complete status.

HTTP routes are registered in
[`internal/transport/applicationhttp/server.go`](internal/transport/applicationhttp/server.go).
The protobuf contract and generated clients live in the `quarshell-proto`
module.

## Build the container image

From the repository root:

```sh
docker build --file quarshell-gateway/Dockerfile --tag quarshell-gateway:local .
```

The image build and healthcheck run in the GitHub-hosted Linux workflow. No
container image has been published to a registry yet.
