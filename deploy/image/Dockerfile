# makit-shield: the request shield (makit-core shield serve) as a container, for Kubernetes and Docker.
# Build from the repository root:  docker build -f deploy/image/Dockerfile -t makit-shield .
# Static binary on distroless (no shell, no package manager), running as an unprivileged user.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src/core
COPY core/go.mod core/go.sum ./
RUN go mod download
COPY core/ ./
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/makit-core .
# Writable places the gate uses: state (bans, ranges, certificates) and logs (snapshots, reports).
RUN mkdir -p /out/var/lib/makit/shield /out/var/log/makit/shield /out/etc/makit

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
LABEL org.opencontainers.image.title="makit-shield" \
      org.opencontainers.image.description="makit request shield: decides on every request behind your load balancer or gateway" \
      org.opencontainers.image.source="https://github.com/material-atomic/makit" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="$VERSION"
COPY --from=build /out/makit-core /usr/local/bin/makit-core
COPY security/ /usr/share/makit/security/
COPY --from=build --chown=65532:65532 /out/var/lib/makit /var/lib/makit
COPY --from=build --chown=65532:65532 /out/var/log/makit /var/log/makit
COPY --from=build --chown=65532:65532 /out/etc/makit /etc/makit
# The bundled catalog, then your own files (a ConfigMap at /etc/makit/security) win.
ENV MAKIT_SECURITY=/usr/share/makit/security:/etc/makit/security \
    MAKIT_SHIELD_CONFIG=/etc/makit/shield.yaml
USER 65532:65532
EXPOSE 9180 9181
ENTRYPOINT ["/usr/local/bin/makit-core"]
CMD ["shield", "serve"]
