# SPDX-FileCopyrightText: Copyright (c) 2026 the cautem authors
# SPDX-License-Identifier: Apache-2.0
#
# Build from a workspace that has sibling checkouts (CI does this):
#   docker build -f quarshell-gateway/Dockerfile -t quarshell-gateway:local .

FROM golang:1.27-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61 AS build
WORKDIR /src
COPY go.work go.work.sum ./
COPY quarshell-core ./quarshell-core
COPY quarshell-credentials ./quarshell-credentials
COPY quarshell-display ./quarshell-display
COPY quarshell-driver-mxc ./quarshell-driver-mxc
COPY quarshell-driver-vm ./quarshell-driver-vm
COPY quarshell-providers ./quarshell-providers
COPY quarshell-runtime ./quarshell-runtime
COPY quarshell-cli ./quarshell-cli
COPY quarshell-isolation ./quarshell-isolation
COPY quarshell-policy ./quarshell-policy
COPY quarshell-proxy ./quarshell-proxy
COPY quarshell-driver ./quarshell-driver
COPY quarshell-sdk ./quarshell-sdk
COPY quarshell-slogx ./quarshell-slogx
COPY quarshell-prover ./quarshell-prover
COPY quarshell-proto ./quarshell-proto
COPY quarshell-spi ./quarshell-spi
COPY quarshell-supervisor ./quarshell-supervisor
COPY quarshell-telemetry ./quarshell-telemetry
COPY quarshell-gateway ./quarshell-gateway
WORKDIR /src/quarshell-gateway
ARG TARGETARCH
ARG VERSION=0.0.0-dev
RUN set -eu; arch="${TARGETARCH:-$(go env GOARCH)}"; mkdir -p /out/helpers/linux-$arch; \
	CGO_ENABLED=0 go build -ldflags="-X main.gatewayVersion=${VERSION}" -o /out/quarshell-gateway ./cmd/quarshell-gateway; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/quarshell-cli -o /out/helpers/linux-$arch/cautem ./cmd/cautem; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/quarshell-runtime -o /out/helpers/linux-$arch/cautem-init ./cmd/cautem-init; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/quarshell-runtime -o /out/helpers/linux-$arch/cautem-sshd ./cmd/cautem-sshd; \
	GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -C /src/quarshell-runtime -o /out/helpers/linux-$arch/cautem-supervisor ./cmd/cautem-supervisor

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/quarshell-gateway /usr/local/bin/quarshell-gateway
COPY --from=build /out/helpers/ /usr/local/lib/cautem/
COPY --from=build /src/quarshell-providers/profiles/ /usr/local/providers/
COPY --from=build /src/quarshell-gateway/LICENSE /src/quarshell-gateway/NOTICE /usr/share/licenses/quarshell-gateway/
COPY --from=build /src/quarshell-cli/LICENSE /src/quarshell-cli/NOTICE /usr/share/licenses/quarshell-cli/
COPY --from=build /src/quarshell-runtime/LICENSE /src/quarshell-runtime/NOTICE /usr/share/licenses/quarshell-runtime/
LABEL org.opencontainers.image.title="quarshell-gateway" \
      org.opencontainers.image.description="cautem control-plane gateway" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/KLORQ/quarshell-gateway"
ENV XDG_STATE_HOME=/var/lib
VOLUME ["/var/lib/openshell"]
EXPOSE 7443 7444
HEALTHCHECK --interval=15s --timeout=3s --start-period=3s --retries=5 \
  CMD curl -fsS http://127.0.0.1:7443/v1/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/quarshell-gateway"]
CMD ["--listen", "0.0.0.0:7443", "--grpc-listen", "0.0.0.0:7444"]
