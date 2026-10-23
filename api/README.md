# Gateway API contract

`openapi.yaml` documents the remaining HTTP contract: health and browser/local
auth bootstrap. OpenShell Gateway RPCs provide sandbox inventory and logs;
provider/config/catalog/workspace management, identity, command execution, and
SSH session management use the native Gateway service. SSH byte streams and supervisor relay remain
transport endpoints outside OpenAPI. The route inventory was reviewed against
`NewHandler` and its mounted handlers on 2026-10-09.

The documented `/healthz` route is the gateway listener's empty-body liveness
response from the pinned OpenShell HTTP contract. Operational endpoints are outside this API document:

| Registered surface | Why it is excluded |
| --- | --- |
| `/readyz` and the health-listener `/healthz` | Optional separate health listener; probe-only endpoints. |
| `/metrics` | Separate Prometheus metrics listener. |
| `/_ws_tunnel` | Edge transport bridge, documented by the relay protocol rather than OpenAPI. It is disabled by default and bridges authenticated edge WebSockets to the normal OpenShell HTTP/2 listener. SSH and supervisor byte streams use OpenShell `ForwardTcp`, `ConnectSupervisor`, and `RelayStream` RPCs. |
| OpenShell RPC and gRPC health methods | The pinned OpenShell Proto contract is authoritative for RPC and runtime lifecycle. |

Documented remaining HTTP paths include OpenShell OIDC configuration and edge-proxy
browser authentication at `/auth/connect`. The latter binds the edge-provided
`CF_Authorization` cookie to a CLI callback port and one-time confirmation code;
the token is sent only after the user clicks the confirmation button. The integration
contract test covers the documented HTTP operations. Security-specific RPC
and relay integration coverage is being migrated from the removed REST
management routes.

Rootfs tar staging is an OpenShell RPC operation. `BeginRootfsTarStaging`
returns a gateway-local path, and callers with access to the gateway
filesystem write the archive there; no rootfs upload REST route is exposed.

Sandbox runtime lifecycle is defined by the pinned OpenShell Proto contract under
`../../tools/upstream/openshell/proto/openshell.proto` in the workspace.

Validate the contract with the same Redocly CLI version used in CI:

```bash
npx --yes @redocly/cli@2.60.0 lint api/openapi.yaml --config api/redocly.yaml
```

Before generating SDKs, compare the generated client with the existing public
Go/Python facades, especially auth, error mapping, YAML, and streaming routes.
Keep runtime lifecycle operations on the pinned OpenShell Proto contract rather
than duplicating them here.

## Native RPC contract

Gateway management uses the pinned OpenShell v0.1.4 RPC contract. The HTTP
surface documented here is limited to health and authentication bootstrap;
there is no first-party Connect management API. The pinned Gateway does not
expose managed inference routes; sandboxes attach providers and call native
endpoints.

The browser console lives in the separate [`quarshell-ui`](https://github.com/KLORQ/quarshell-ui)
repository. It uses OIDC authorization code with PKCE and native OpenShell
Gateway RPCs for sandbox, service, policy-draft, and provider-profile flows.

Native OpenShell `GetSandboxLogs`, `PushSandboxLogs`, and `WatchSandbox` carry
log reads, writes, and resumable sandbox streams. Watch cursors are opaque and
scoped to their issuing Gateway cursor space.

Sandbox create/start/stop/delete, resource versions, service exposures and
result URLs use native OpenShell requests. Lifecycle requests carry OpenShell
`request_id` idempotency values; there is no separate operation lookup API.
Policy draft review uses pinned `GetDraftPolicy`, `ApproveDraftChunk`, and
`RejectDraftChunk` RPCs.

The Go Proto, native gRPC, and Connect clients are imported from
`github.com/KLORQ/quarshell-proto`; the Gateway does not generate copies of the
contract. Generate and validate clients in the protocol module:

```bash
cd ../quarshell-proto
buf lint
buf generate --template buf.gen.yaml
buf generate --template typescript/buf.gen.yaml
npm ci --prefix typescript
npm run build --prefix typescript
```

The TypeScript browser client is consumed by the UI as
`@klorq/control-client`. Gateway integration coverage exercises gRPC and
gRPC-Web against the same handlers.
