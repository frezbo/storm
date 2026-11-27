#!/usr/bin/env bash

set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cluster_server_dir="${script_dir}/cluster-server"

make talosctl-linux-amd64
cp _out/talosctl-linux-amd64 "${cluster_server_dir}/talosctl-linux-amd64"
docker buildx build --push --platform=linux/amd64 -t storm.goose-piano.ts.net:5000/talos-cluster-server:latest -f "${cluster_server_dir}/Dockerfile" "${cluster_server_dir}/"
# talos-cluster-server now runs as a Talos ContainerConfig
# (patches/container-talos-cluster-server.yaml), not a Deployment. A :latest
# re-push is not picked up automatically: pin the new digest in that patch (or
# remove and re-add the document) and sync the Omni template.

make talosctl
make integration-test

make kernel initramfs PLATFORM=linux/amd64
make installer-base PLATFORM=linux/amd64,linux/arm64 PUSH=true
make imager PUSH=true
make installer PLATFORM=linux/amd64,linux/arm64
