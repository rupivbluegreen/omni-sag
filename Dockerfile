# syntax=docker/dockerfile:1
#
# Multi-arch image for the omni-sag gateway. The build stage runs on the
# builder's native architecture and cross-compiles a fully static
# (CGO_ENABLED=0) binary for the requested target, so no QEMU emulation is
# needed. The runtime stage is distroless/static — it ships CA certificates
# (required for the LDAPS bind to Active Directory) and runs as a nonroot
# user, with nothing else in the image.

# ---- build stage --------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.25 AS build
WORKDIR /src

# Cache module downloads separately from the source.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# VERSION is stamped in by CI (the pushed tag). TARGETOS/TARGETARCH are
# provided automatically by buildx per requested --platform.
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/omni-sag ./cmd/omni-sag

# ---- runtime stage ------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/omni-sag /omni-sag

# The gateway's SSH listener (see config.yaml `listen: ":2222"`).
EXPOSE 2222

# Mount a config at this path (host key + evidence paths in it are resolved
# relative to the working directory, so mount them alongside or use absolute
# paths in the config).
ENTRYPOINT ["/omni-sag"]
CMD ["-config", "/etc/omni-sag/config.yaml"]
