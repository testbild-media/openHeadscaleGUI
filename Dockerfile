# Optional container image. The recommended installation is install.sh
# (systemd). Run with host networking so the UDP ports for STUN/WireGuard
# and the TCP/UDP forward ports are reachable, see docker-compose.yml.
FROM golang:1.27-bookworm AS build
ARG VERSION=docker
ARG HEADSCALE_VERSION=0.29.7
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/testbild-media/openHeadscaleGUI/internal/app.Version=${VERSION}" \
      -o /out/ohg ./cmd/ohg
RUN set -eux; \
    arch="$(go env GOARCH)"; \
    f="headscale_${HEADSCALE_VERSION}_linux_${arch}"; \
    base="https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}"; \
    curl -fsSL -o "/out/headscale" "$base/$f"; \
    curl -fsSL -o /tmp/checksums.txt "$base/checksums.txt"; \
    want="$(awk -v f="$f" '$2==f {print $1}' /tmp/checksums.txt)"; \
    echo "$want  /out/headscale" | sha256sum -c -; \
    chmod 0755 /out/headscale

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ohg /usr/local/bin/ohg
COPY --from=build /out/headscale /usr/local/lib/ohg/headscale
ENV OHG_DATA_DIR=/var/lib/ohg \
    OHG_HEADSCALE_BIN=/usr/local/lib/ohg/headscale \
    TS_NO_LOGS_NO_SUPPORT=true
VOLUME ["/var/lib/ohg"]
EXPOSE 80/tcp 443/tcp 3478/udp
ENTRYPOINT ["/usr/local/bin/ohg"]
CMD ["serve"]
