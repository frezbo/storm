# Remote cluster-server (PoC)

Runs `talosctl remote-provision-launch` as a Talos container (ContainerConfig) so a
developer can point `talosctl cluster create --remote-endpoint=...` at a
remote KVM-capable node instead of provisioning QEMU locally.

This is the PoC deployment path. The longer-term plan packages the server
as a Talos extension service — see `REMOTE-PROVISIONER-PLAN.md`.

## 1. Build the binary

```sh
make talosctl-linux-amd64
```

Produces `_out/talosctl-linux-amd64`, which the image packages.

## 2. Build and push the image

```sh
REGISTRY=ghcr.io/<you>
docker build -f hack/cluster-server/Dockerfile \
  -t $REGISTRY/talos-cluster-server:latest .
docker push $REGISTRY/talos-cluster-server:latest
```

The image is based on `ghcr.io/siderolabs/build-container` (already carries
qemu-system, swtpm, virtiofsd, mkisofs). Override the base with
`--build-arg BUILD_CONTAINER=...` if needed.

## 3. Deploy

The server runs as a Talos `ContainerConfig` (not a Kubernetes Deployment), defined in
`../patches/container-talos-cluster-server.yaml` and referenced from
`../cluster-template.yaml`. Edit `image:` there, then sync the Omni template.

For the initial Kubernetes migration, do not sync the new containers while the
old pods are running. Stop active builds and provisioned VMs first. Use a staged
Omni template with neither the old workload manifests nor the new container
patches, keeping all UserVolumeConfig patches. Sync that intermediate state and
verify the old workload pods and their child processes have exited before
syncing the final template. This prevents simultaneous writers to the same
registry, BuildKit and cluster-server state. Keep the old manifests for rollback;
stop the Talos containers before restoring them.

Preview each stage:

```sh
omnictl cluster template sync --dry-run --verbose -f <template>
```

Container startup and volume compatibility still need live testing; offline
validation does not prove either.

The container runs with `network.mode: host` and `security.profile: privileged`,
and the host `/dev` is bind-mounted into it. Host networking puts the QEMU
bridge/tap and the spawned loadbalancer/dhcpd in the host network namespace.
The `/dev` mount exposes `/dev/kvm`, `/dev/net/tun` and `/dev/vhost-net`
(the privileged profile allows device access but does not create device nodes).

Status/logs: `talosctl get containerstatus`, `talosctl logs --namespace taloscontainers talos-cluster-server`
(or `talosctl containers --namespace taloscontainers`).

## 4. Connect

The gRPC API listens directly on the host at **port 50100** (the NodePort
30100 is gone along with the Kubernetes Service):

```sh
talosctl cluster create dev --remote-endpoint=<nodeIP>:50100
talosctl cluster --remote-endpoint=<nodeIP>:50100 --name=dev show
talosctl cluster --remote-endpoint=<nodeIP>:50100 --name=dev destroy
```

`--remote-endpoint` is a persistent flag on `talosctl cluster`, so it
applies to `create`, `show`, and `destroy`.

## Notes / PoC limitations

- **Boot assets**: the server reads kernel/initramfs/ISO paths from the
  request. Until gRPC artifact upload lands, those files must already exist
  on the node at the requested paths (e.g. rsync them into the
  `talos-clusterserver` user volume, or bake them into the image).
- **VM reachability**: Storm routes `172.16.0.0/16` through Tailscale. Give
  each concurrent cluster its own `--cidr 172.16.N.0/24`; the generic
  provisioner default is `10.5.0.0/24`. Each cluster gets its own bridge, and
  its load balancer binds that cluster's gateway (`172.16.N.1`), so clusters
  on distinct subnets can share `--control-plane-port`. Never use 6443:
  Storm's own kube-apiserver listens on `*:6443`, so the load balancer fails
  with `bind: address already in use`. Use e.g. `--control-plane-port 6444`.
- **No auth**: the gRPC server is unauthenticated. Only expose port 50100
  on a trusted network.
- **State**: persisted to `/var/mnt/talos-clusterserver` (the
  `talos-clusterserver` user volume); survives container restarts. Talos runs
  exactly one instance of a ContainerConfig, so there is a single writer.
