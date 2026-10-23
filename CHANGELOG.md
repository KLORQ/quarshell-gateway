# Changelog

## [Unreleased]

### Removed

- Remove the first-party `InferenceService`, route state, and handlers; pinned OpenShell has no managed inference routes.
- Remove the first-party `/debug/loglevel` HTTP route and the `CAUTEM_LOG_LEVEL_ADDR` listener setting, which have no pinned OpenShell counterpart.

### Fixed

- Match the pinned OpenShell `/healthz` contract: GET returns an empty-body liveness response, and other methods receive 405.

### Added

- Register the reserved `openshell/regex` middleware locally, validate its policy configuration, and provide its selected settings to the proxy without a remote gRPC endpoint.
- Export privacy-bounded Gateway HTTP request traces to an optional OTLP/gRPC endpoint configured by `openshell.gateway.otlp`.

### Fixed

- Accept service exposures in Control sandbox creation, validate them before provisioning, and compensate the sandbox create if registration fails.
- Persist and enforce service `STRIP` and `BEARER_PASSTHROUGH` authorization modes for HTTP and WebSocket proxy requests.
- Accept explicit authorization mode on browser-managed service creation; default to `STRIP`.
- Return service authorization mode in Control catalog summaries for the browser UI.
- Persist stable IDs for service records and return them in Gateway endpoint metadata.
- Migrate durable service authorization settings to schema v3, defaulting legacy endpoints to `STRIP`.
- Preserve each service's domain setting across expose, get, list, and store reopen.
- Atomically reject service-name ownership conflicts inside the durable store and remove service records with sandbox deletion.

## [v0.3.0] - 2026-10-16

### Added

- Stream bounded non-interactive VM exec output through the OpenShell stdout/stderr/exit event contract.
- Upload VM rootfs tar archives to authenticated, workspace-bound Gateway staging slots from remote clients.
- Preflight optional backend Gateway-runtime capabilities before consuming one-shot rootfs uploads or persisting sandbox lifecycle state.
- Restore process-local workload argv and environment from the durable sandbox spec before restarting a backend that implements `LaunchSpecRestorer`.

## [v0.2.1] - 2026-10-13

### Fixed

- Build the released Gateway image with the matching `quarshell-cli` v0.2.0 helpers.
- Allow the supervisor to finalize a durably reported main-process exit after sandbox terminal status blocks ordinary supervisor RPCs.

## [v0.2.0] - 2026-10-13

### Added

- Add a same-origin React browser console with OIDC login, sandbox lifecycle, terminal, files, services, and noVNC display sessions.
- Add shared-server workspace quotas, PostgreSQL state storage, backup/restore tooling, and an experimental Agent Sandbox Kubernetes compute path.

### Changed

- Move first-party Control API schemas and generated clients to the published `quarshell-proto` module.
- Deliver Kubernetes policy changes by switching immutable runtime Secret generations and waiting for the supervisor to reconnect.
- Check running Kubernetes runtimes daily and rotate bridge credentials before their 90-day certificates expire.
- Split Gateway RPC, storage, and server handlers into focused source files.

## [v0.1.7] - 2026-10-11

### Changed

- Update quarshell-runtime to v0.1.8 and quarshell-driver to v0.1.7 so gateway builds include the latest sandbox secret-storage and driver fixes.
- Refresh the AWS SDK and Go crypto, network, and system dependencies while keeping the OpenShell API schema aligned with runtime.

## [v0.1.6] - 2026-10-11

### Changed

- Rename the module, runtime identifiers and project references to the `cautem` namespace.

## [v0.1.0-beta.2] - 2026-10-10

### Changed

- Resolve driver v0.1.0-beta.2, providers v0.1.0-beta.1 and runtime v0.1.0-beta.2 from published tags.


## [v0.1.0-beta.2] - 2026-10-10

### Added

- Expose the versioned `cautem.control.v1` management RPC contract with generated Go, Connect and TypeScript clients.
- Add bounded management views, lifecycle operations, logs, inference, services and gateway information over Control RPC.
- Persist operation, audit and policy state with authorization, resource-version checks and idempotency.

### Changed

- Remove legacy REST management routes; retain health and authentication bootstrap endpoints.
- Resolve `quarshell-core` v0.1.0-beta.2 and `slogx` v0.1.0-beta.1 from published tags.

## [v0.1.0-beta.1] - 2026-10-07

### Added

- Add contextual structured logs for gateway relay operations.

### Changed

- Use `quarshell-core` v0.1.0-beta.1 and `quarshell-runtime` v0.1.0-beta.1.
- Update AWS SDK, go-jose, and SPIFFE dependencies to their latest compatible releases.

### Fixed

- Restrict gateway token files with Windows ACLs and run HTTP security integration tests across platforms.
- Wait for the gateway listener before making RPC readiness assertions.

## [v0.1.0-alpha.2] - 2026-10-07

### Added

- Workspace/global provider profile catalog APIs with authorization and resource-version conflict checks.
- Encrypted OAuth refresh material, output token rotation, and lazy credential refresh during sandbox secret resolution.

### Changed

- Align runtime, driver, and slogx with v0.1.0-alpha.2; update Go crypto, gRPC, protobuf, and SPIFFE dependencies.

## [v0.0.2-alpha.1] - 2026-09-28

### Security

- Refuse `allow_unauthenticated` on non-loopback listen addresses.
- Force `security_flagged` on pending proposals so bulk approve cannot clear sensitive rules by client trust.

### Added

- Gateway info exposes `allow_unauthenticated`, KEK `format`, and `migration_needed`.
