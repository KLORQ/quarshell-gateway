# Local Gateway Compose deployment

This Compose file runs the current Go Gateway with a persistent SQLite state
file. Run it from the repository root with Docker Compose installed.

Generate a private token for this local instance, then start the service:

```sh
export QUARSHELL_TOKEN="$(openssl rand -hex 32)"
docker compose -f quarshell-gateway/compose/docker-compose.yml up --build -d
curl --fail http://127.0.0.1:7443/v1/healthz
```

HTTP is bound to `127.0.0.1:7443`; gRPC is bound to `127.0.0.1:7445` on the
host and `7444` inside the container. The `quarshell-gateway-data` volume stores
`/var/lib/openshell/state.db`. `docker compose down` preserves this volume;
`docker compose down --volumes` deletes the local database.

The container does not receive the host Docker socket in the default setup.
On a dedicated Linux machine where the Gateway is trusted to manage host
containers, add the explicit compute overlay:

```sh
docker compose \
  -f quarshell-gateway/compose/docker-compose.yml \
  -f quarshell-gateway/compose/docker-compose.compute.docker.yml \
  up --build -d
```

The optional UI and Dex files are retained from the migration baseline but are
not connected to the current token-authenticated Gateway implementation.
They are not part of this deployment path. Current API coverage and platform
gates are tracked in [`plans/REMAINING.md`](../../plans/REMAINING.md).
