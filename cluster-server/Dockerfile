# syntax = docker/dockerfile-upstream:1.24.0-labs
#
# Container image for the remote cluster-server PoC.
#
ARG BUILD_CONTAINER=ghcr.io/siderolabs/build-container:2.338.0-26.04

#FROM --platform=${BUILDPLATFORM} ghcr.io/siderolabs/talosctl:v1.14.0-alpha.1-90-g00d739d0a AS talosctl
FROM scratch as talosctl
COPY talosctl-linux-amd64 /talosctl

FROM ${BUILD_CONTAINER}
USER root
WORKDIR /tmp

COPY --from=talosctl /talosctl /usr/local/bin/talosctl

ENTRYPOINT ["/usr/local/bin/talosctl", "remote-provision-launch"]
