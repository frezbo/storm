# Keyless Tailscale join for Storm (TPM attestation + Fly OIDC)

Goal: Storm joins the tailnet after a reinstall with no stored secret anywhere (repo, Omni template, Fly secrets). Trust is rooted in Storm's TPM and Secure Boot state, not in a key or a network path.

## Flow

```
Storm                                   Fly (app: storm-attest)                 Tailscale
attester ContainerConfig                verifier
  1 GET /nonce  ───────────────────────▶  nonce (single use, 60 s)
  2 EK pub, AK pub, AK creation data ──▶  EK pub == enrolled pin?
  3                                ◀───   MakeCredential(EK, AK name) challenge
  4 ActivateCredential, quote(PCR 7, nonce) ─▶  secret matches, quote signed by AK,
                                          nonce fresh, PCR 7 == policy
  5                                       Fly OIDC token (aud: tailscale)  ───────▶  token exchange
  6                                       ◀─── short-lived API token (trust credential)
  7                                       POST auth key: one-off, preauthorized,
                                          tag:storm, expiry 10 min           ───────▶
  8 auth key  ◀──────────────────────────
  9 write /var/lib/tailscale/authkey (0600)
tailscale extension: TS_AUTHKEY=file:/var/lib/tailscale/authkey, TS_AUTH_ONCE=true ─▶ join
```

Enrollment (once, by hand): record Storm's EK public key in the verifier's policy. The EK is derived from the endorsement seed with the standard template, so it is the same key on every boot and reinstall; no persistent handle is needed.

## Components

- **Attester** (Go, `go-attestation`): Talos `ContainerConfig`, `profile: privileged` (`devices` only supports `rawVolume`), hostPath mounts `/dev/tpmrm0` and `/var/lib/tailscale`. Runs as a watcher: every 30 s it asks tailscaled's LocalAPI (`/var/run/tailscale/tailscaled.sock`) for `BackendState` and attests only on `NeedsLogin`, skipping while the key it last wrote is younger than its 10-minute expiry. It writes the key file for the extension's next start and also starts the login itself through `POST /localapi/v0/start` with `AuthKey`, because with `TS_AUTH_ONCE` the extension reads the file only when it starts. (`tailscaled.state` exists before the first login, so it is no signal; Omni 1.13 rejects `ContainerConfig` `lifecycle`, so a one-shot would restart every 5 s.) Logs: `talosctl logs --namespace taloscontainers storm-attest`. Image must not come from `storm.goose-piano.ts.net:5000`: that name only resolves after Tailscale is up. Pull from GHCR, pinned by digest.
- **Verifier** (Go, Fly app `storm-attest`, machine `verifier`, no public IP): reached at `storm-attest.internal:8080` over io's WireGuard route to Fly's private network (`fdaa:2:154::/48`; io's DNS resolves `.internal`). Holds only the policy (EK pin, PCR 7 value); gets Tailscale access through Fly OIDC, so no Tailscale secret. The LAN leg is plain HTTP, so the attester sends a per-join X25519 key bound into the quote (`nonce = SHA-256(server nonce || key)`) and the verifier returns the auth key sealed to it (HKDF + AES-GCM): a relay can neither read the key nor substitute its own.
- **Tailscale trust credential**: custom issuer `https://oidc.fly.io/noel-georgi`, subject exactly `noel-georgi:storm-attest:verifier` (Fly `sub` is `org:app:machine-name`), scope `auth_keys`, tag `tag:storm`. Optional later: custom claim `image_digest` pinned to the deployed verifier image.
- **Talos**: `ExtensionServiceConfig` for tailscale sets `TS_AUTHKEY=file:/var/lib/tailscale/authkey` and `TS_AUTH_ONCE=true`. `patches/tailscale.yaml` then holds no secret and can be committed. The extension restarts until the file exists.

## Policy

- EK public key: pinned (trust on first use; AMD fTPM has no EK certificate in NV).
- PCR 7 (Secure Boot policy and keys): `6DDF368215AC1DA1F2A14EB6259AA689841D32B852DD9A3831A894BD15CB5326` as of 2026-11-27. Not pinned: PCR 4/11, which change with every Talos upgrade.
- Freshness: verifier-issued nonce in the quote; auth key is one-off with a 10-minute expiry, so a leaked key is useless after the join or the timeout.

## Verified

| Claim | Evidence |
|---|---|
| `tailscale up --auth-key` accepts `file:` | `cmd/tailscale/cli/up.go:102` |
| containerboot passes `TS_AUTHKEY` through unchanged | `cmd/containerboot/tailscaled.go:121` |
| A container can use the TPM while Talos uses it for LUKS | probe pod via `/dev/tpmrm0`: persistent handles listed, PCR 7 matches the host's `/sys/class/tpm/tpm0/pcr-sha256/7` |
| No EK certificate in NV | `tpm2_nvreadpublic`: `0x1c00002`, `0x1c0000a` absent |
| SELinux does not block `/dev/tpmrm0` | `/sys/fs/selinux/enforce` = `0` (permissive) |
| Fly issuer and claims | `https://oidc.fly.io/noel-georgi/.well-known/openid-configuration`: `sub`, `app_name`, `machine_id`, `image_digest`, ... |
| End-to-end keyless join | 2026-11-27: node deleted from the tailnet, attester minted and logged in through the LocalAPI; Storm re-joined as `tag:storm`, same name and `100.121.51.33`, registry, BuildKit and cluster server reachable |
| A deleted node reports `BackendState: Running` | LocalAPI status after deletion: `Running`, `AuthURL` set, `Self.Online` false; the attester treats a pending `AuthURL` as needing login |

## Open

- Creating the `storm-attest` Fly app needs a broader Aperture `flyio` grant; the current one covers three existing apps only.
- Tailscale trust-credential matching on `image_digest` (custom claims) is documented but not yet tried.
- PCR 7 changes after a firmware dbx/db update or a Secure Boot key change: the verifier rejects until the policy is updated. Recovery: put a one-off `TS_AUTHKEY` inline in the extension config for that boot.
- AMD's online fTPM EK certificate service could replace the EK pin with real certificate validation; not checked.

## Future: Omni as the OIDC issuer (idea, 2026-11-27)

If this PoC works, the same shape generalizes beyond Storm: Talos exposes an API to produce TPM quotes, Omni verifies them (it already knows each machine through SideroLink) and acts as the OIDC issuer, and Talos makes the resulting machine identity token available to workloads through an API or a local socket, like Fly's `/.fly/api`. Talos clusters managed by Omni could then authenticate to clouds and any other OIDC-federated service (Tailscale, AWS, GCP, Azure) without stored keys. Plan it properly only after the PoC proves the attestation path.

Ideas to borrow for that plan (not used by this PoC):
- Fly KMS (`/v1/apps/{app}/secretkeys/{name}`: sign/verify/encrypt/decrypt): signing keys that never leave isolated hardware and are usable only by Machines of the owning app (403 otherwise). For Omni: the issuer's signing key held the same way, and per-cluster keys whose use is gated by the caller's attested identity; in Talos, the analogue is a workload-facing signing API backed by TPM-held keys.
- Stateless challenges: an `hs256`/encrypt key turns the nonce and its expiry into an opaque token, so the verifier needs no shared state across replicas.
- systemd `report-sign-tpm2.c`: quote, NvPCR certifications and key certification inside one exclusive audit session prove a single consistent snapshot; an onboarding "voucher" certifies the attestation key once, so later boots need only a quote.
