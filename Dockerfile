# syntax=docker/dockerfile:1

# Built on the build machine's own architecture and cross-compiled, so
# multi-arch images need no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27 AS build
ARG TARGETOS TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath \
    -ldflags "-s -w -X github.com/tyler-lloyd/zora/pkg/cniplugin.Version=$VERSION" \
    -o /out/ ./cmd/zora-agent ./cmd/zora-cni

# No shell, no package manager: just the two static binaries. The agent runs
# as root because it writes to root-owned directories on the node.
FROM gcr.io/distroless/static-debian12
COPY --from=build /out/zora-agent /out/zora-cni /usr/local/bin/
ENTRYPOINT ["/usr/local/bin/zora-agent"]
CMD ["run"]
