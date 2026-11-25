# syntax=docker/dockerfile:1
# Multi-stage build for the easy-ha-proxy web admin panel. The templates,
# static JS/CSS and i18n catalogues live in go/panel/web. Build from the
# repository root (VERSION is read from there):
#   docker build -f go/panel/Dockerfile -t easy-ha-proxy-panel:go .

FROM --platform=$BUILDPLATFORM golang:1.27.4-alpine AS builder
ARG TARGETOS
ARG TARGETARCH

RUN apk add --no-cache tzdata ca-certificates file

WORKDIR /src/go/panel
COPY VERSION /src/VERSION
COPY go/panel/go.mod go/panel/go.sum ./
RUN go mod download
COPY go/panel/ ./

RUN set -euo pipefail; \
    GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-amd64}" CGO_ENABLED=0 \
    go build -trimpath -ldflags="-s -w -X easy-ha-proxy/panel/internal/config.Version=$(tr -d '\r' < /src/VERSION)" \
    -o /out/easy-ha-proxy-panel ./cmd/easy-ha-proxy-panel; \
    arch="${TARGETARCH:-amd64}"; \
    desc="$(file /out/easy-ha-proxy-panel)"; \
    echo "Built panel binary for ${arch}: ${desc}"; \
    if [ "${arch}" = "arm64" ]; then echo "${desc}" | grep -qi "aarch64\|arm64"; \
    elif [ "${arch}" = "amd64" ]; then echo "${desc}" | grep -qi "x86-64\|amd64"; fi

FROM scratch

COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /out/easy-ha-proxy-panel /usr/local/bin/easy-ha-proxy-panel
COPY go/panel/web/static /app/static
COPY go/panel/web/translations /app/translations
COPY go/panel/web/templates /app/templates

# Which build this is, for the panel's footer and its comparison with the
# host: CI passes the commit, its date and the Go panel's source tree (the
# same fingerprint the image is keyed by and the host reports as go_web_tree).
ARG EHP_BUILD_REVISION=""
ARG EHP_BUILD_DATE=""
ARG EHP_SOURCE_TREE=""
ENV EHP_BUILD_REVISION=${EHP_BUILD_REVISION} \
    EHP_BUILD_DATE=${EHP_BUILD_DATE} \
    EHP_SOURCE_TREE=${EHP_SOURCE_TREE}

ENV HAPROXY_ADMIN_STATIC_DIR=/app/static \
    HAPROXY_ADMIN_TEMPLATES_DIR=/app/templates \
    HAPROXY_ADMIN_TRANSLATIONS_DIR=/app/translations \
    HAPROXY_ADMIN_LISTEN_ADDR=0.0.0.0:5000

EXPOSE 5000
USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=4 \
    CMD ["/usr/local/bin/easy-ha-proxy-panel", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/easy-ha-proxy-panel"]
CMD ["serve"]
