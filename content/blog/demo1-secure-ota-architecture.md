---
title: "Demo 1: Secure OTA — Architecture Deep Dive"
date: 2026-03-29
summary: "A production-grade OTA update architecture for embedded Linux — PKI, mTLS enrollment, manifest-first verification, A/B rollback, and the Yocto layers that wire it all together."
description: "A production-grade OTA update architecture for embedded Linux — PKI, mTLS enrollment, manifest-first verification, A/B rollback, and the Yocto layers that wire it all together."
tags: ["ota", "embedded-linux", "yocto", "rauc", "security", "pki"]
ShowToc: true
TocOpen: true
---

The Kernel Forge OTA Reference is a production-grade OTA update implementation for embedded Linux. Not a "RAUC getting started" tutorial—a reference for how the pieces fit together when you're thinking about fleet deployment, not just a single board on your desk.

This post walks through the full architecture: why each piece exists, how they connect, and where I drew the line between "reference implementation" and "production deployment."

The complete implementation is Apache-2.0 licensed, SPDX-headered throughout. The [OTA Reference](https://github.com/kernelforge-io/kernelforge-ota-reference) repository is the build entry point (kas/Yocto). Key components have their own repositories: [ota-fetch](https://github.com/kernelforge-io/ota-fetch), [kernelforge-pki](https://github.com/kernelforge-io/kernelforge-pki), and [ota-workbench](https://github.com/kernelforge-io/ota-workbench).

## System overview

The OTA pipeline has a few core responsibilities, and each one is handled by a distinct part of the architecture:

- **Identity and trust** — a PKI hierarchy that establishes who's who and who's allowed to talk to whom
- **Device enrollment** — how a fresh device goes from bare board to authenticated fleet member
- **Update delivery** — how the device discovers, fetches, and verifies updates
- **Installation and safety** — how updates get applied with rollback protection
- **Persistent state** — what survives across updates and what doesn't

```
┌──────────────────────────────────────────────────────────────┐
│                     OTA UPDATE FLOW                          │
│                                                              │
│  Build Server                        Device                  │
│  ┌──────────────┐                   ┌─────────────────────┐  │
│  │ Build image  │                   │                     │  │
│  │ Sign bundle  │                   │  ota-fetch daemon   │  │
│  │ Sign manifest│──── mTLS ───────▶│    │                │  │
│  │ Serve update │    channel        │    ▼                │  │
│  └──────────────┘                   │  Verify manifest    │  │
│                                     │  (signature + cert) │  │
│                                     │    │                │  │
│                                     │    ▼                │  │
│                                     │  Download payload   │  │
│                                     │  (hash verified)    │  │
│                                     │    │                │  │
│                                     │    ▼                │  │
│                                     │  RAUC install       │  │
│                                     │  (independent sig   │  │
│                                     │   verification)     │  │
│                                     │    │                │  │
│                                     │    ▼                │  │
│                                     │  A/B slot switch    │  │
│                                     │  + rollback safety  │  │
│                                     └─────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

The key design principle: verification happens at multiple layers, and each layer is independent. A compromised manifest doesn't lead to a compromised install, because RAUC does its own signature check. A compromised transport doesn't lead to a compromised manifest, because the manifest signature is verified against the PKI chain before anything else happens.

{{< youtube VIDEO_ID_HERE >}}

## PKI design

This is the part most OTA demos skip, and it's the part that matters most.

A single self-signed certificate is not a PKI. It's a checkbox. A real trust hierarchy gives you the ability to scope trust, rotate credentials, and revoke without burning down the fleet.

### The hierarchy

```
Root CA
├── OTA Intermediate CA
│   ├── RAUC bundle signing certificates (v3_rauc_signer)
│   └── Manifest signing certificates (v3_manifest_signer)
├── TLS Intermediate CA
│   ├── Server certificates (v3_tls_server)
│   └── Device enrollment client certificates (v3_device_enroll_client)
└── (Device Identity — issued at enrollment via TLS intermediate)
```

**Why separate intermediates?** Because different certificates serve different purposes and have different risk profiles:

- **OTA Intermediate** — used in the build pipeline to sign RAUC bundles and manifests. If this intermediate is compromised, you revoke it and re-sign. Device identity is unaffected.
- **TLS Intermediate** — issues server certificates for the OTA and enrollment servers, and device client certificates during enrollment. Rotates on its own schedule, independent of signing authority.

A flat PKI (everything signed by the same CA) means any compromise is a total compromise. Separation of purpose is the whole point.

### Extension profiles

The PKI uses explicit OpenSSL extension profiles rather than ad-hoc certificate flags. Each leaf certificate type has a named profile that constrains its usage:

- `v3_rauc_signer` — can sign RAUC bundles, nothing else
- `v3_manifest_signer` — can sign manifests, nothing else
- `v3_tls_server` — server authentication only
- `v3_tls_client` — client authentication (for mTLS)
- `v3_device_enroll_client` — enrollment-time client auth, scoped to the enrollment flow

This matters because a certificate's capabilities are baked into its extensions. A RAUC signing cert can't be repurposed for TLS server authentication, even if someone extracts the key. Purpose is enforced at the cryptographic level, not just by convention.

### The tooling: kfpki

The PKI isn't a collection of shell scripts wrapping `openssl` commands. It's a structured Python CLI (`kfpki.py`) with a deterministic directory layout:

```
PKI_HOME/
  ca/
    root/
      private/        # Root CA key (offline in production)
      certs/          # Root CA cert
      crl/            # Root CRL
      openssl.cnf     # Root CA config with extension profiles
    intermediates/
      ota/
        private/      # OTA intermediate key
        certs/        # OTA intermediate cert
        crl/          # OTA CRL
        openssl.cnf   # OTA-specific extensions
      tls/
        private/      # TLS intermediate key
        certs/        # TLS intermediate cert
        crl/          # TLS CRL
        openssl.cnf   # TLS-specific extensions
  clients/
    <client>/
      keys/           # Timestamped keys with stable symlinks
      certs/          # Timestamped certs with stable symlinks
      csrs/
  csr_pending/        # CSRs awaiting signature
  csr_processed/      # Signed CSRs (audit trail)
```

Every artifact is timestamped (`<client>_YYYYMMDDTHHMMSSZ.crt`), with stable symlinks updated for integration consumers. This means Yocto `local.conf` can point to `clients/<project>/certs/<project>.crt` and the symlink always resolves to the latest issued cert—no manual path updates when you rotate.

The workflow is: generate a CSR, it lands in `csr_pending/`, then `run_signer.py` signs it with the specified issuer and extension profile. Revocation is handled by `run_revoker.py`, which updates the issuer's CRL. Each intermediate maintains its own CRL independently.

A key safety guardrail: leaf issuance from the root CA is rejected by default. There's a `--allow-root-leaf-signing` override, but it only works when the PKI is in demo mode (tracked by a `.kernelforge_pki_mode` marker file). In a production layout, you physically can't issue a leaf from root through the tooling.

The entire hierarchy can also be bootstrapped inside a container (`kernelforge/ca:latest`) for CI/CD pipeline integration, with the repo root mounted at `/pki`.

### What the reference implements vs. what production adds

The reference implementation generates the full CA hierarchy and stores keys on disk. The PKI mode marker distinguishes `demo` (default path, root leaf signing available) from `real` (explicit `--pki-home`, root leaf signing blocked). In a production deployment, the Root CA private key would live in an HSM or offline air-gapped storage, intermediate CA keys would be in a KMS or hardware-backed store, and CRL distribution (or OCSP) would be operational rather than file-based.

The *structure* is production-grade. The *key storage* is appropriate for a reference—and documented as such.

## Device enrollment

A device fresh off the manufacturing line doesn't have an identity yet. It has a **device token**—a one-time credential that's valid for exactly one thing: enrolling with the enrollment service to obtain a proper device certificate.

### The enrollment service: kf-pki-enrolld

Enrollment is handled by `kf-pki-enrolld`, a purpose-built C service that owns the HTTP API and token database, then delegates to the PKI's signer for certificate issuance.

The token lifecycle:

1. An operator mints a one-time token for a specific device ID with a TTL:
   ```
   kf-pki-enrolld --mint-token --device-id device-0001 --ttl-seconds 3600
   ```
   The plaintext token is displayed once. It's placed on the device during provisioning (in the reference, it's pre-placed at `/var/lib/ota-fetch/identity/enroll.token`).

2. On first boot, the device's `ota-fetch-enroll` service detects the token file and calls the enrollment endpoint:
   ```
   POST /v1/enroll
   Authorization: Bearer <token>
   {"csr_pem": "...", "device_id": "device-0001"}
   ```

3. The service validates the token (correct device ID, not expired, not already used), then signs the CSR through the PKI's TLS intermediate using the `v3_tls_client` extension profile.

4. The device receives its signed certificate, stores it alongside the private key in `/var/lib/ota-fetch/identity/`, and the token file is consumed.

### The enrollment flow

```
┌────────────┐         ┌───────────────────┐         ┌──────────────┐
│   Device   │         │  kf-pki-enrolld   │         │     TLS      │
│ (factory   │         │                   │         │ Intermediate │
│  fresh)    │         │                   │         │     CA       │
└─────┬──────┘         └────────┬──────────┘         └──────┬───────┘
      │                         │                           │
      │  1. Present bearer      │                           │
      │     token + CSR ──────▶│                           │
      │                         │                           │
      │                         │  2. Validate token,       │
      │                         │     sign CSR ───────────▶│
      │                         │                           │
      │                         │  3. Return signed         │
      │  4. Receive device      │◀──── device cert ────────│
      │◀─── cert + key pair ───│                           │
      │                         │                           │
      │  5. Store cert/key in   │                           │
      │     /var/lib/ota-fetch/ │                           │
      │     identity/           │                           │
      │     Token consumed.     │                           │
      │                         │                           │
```

After enrollment, the device has:

- A device-specific certificate signed by the TLS Intermediate CA
- A corresponding private key (generated on-device, never transmitted)
- The CA chains needed to validate the OTA server's identity

This is how the device authenticates for all subsequent mTLS connections.

### The systemd orchestration

Enrollment and update polling are separate systemd units with an explicit dependency:

```ini
# ota-fetch-enroll.service — runs once, only if a token exists
[Unit]
ConditionPathExists=/var/lib/ota-fetch/identity/enroll.token
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/ota-fetch enroll --config /etc/ota-fetch/ota-fetch.conf \
          --token-file /var/lib/ota-fetch/identity/enroll.token
```

```ini
# ota-fetch.service — the polling daemon, waits for enrollment
[Unit]
Wants=ota-fetch-enroll.service
After=ota-fetch-enroll.service
RequiresMountsFor=/var
```

The `ConditionPathExists` on the enrollment unit means it only fires on first boot (or after a factory reset that restores a token). The main `ota-fetch` service declares `After=ota-fetch-enroll.service`, so it won't start polling until enrollment completes. After the first successful enrollment, the token is gone, the enrollment service is a no-op, and `ota-fetch` starts immediately on every subsequent boot.

### Manufacturing simulation

In the reference implementation, enrollment is simulated—the device token is pre-placed in the image and the enrollment service runs locally. This is called out explicitly because the enrollment boundary is exactly where a real manufacturing integration would plug in. The reference shows the protocol and flow; production adds the provisioning infrastructure.

## mTLS: mutual authentication

Every connection between the device and the OTA server uses mutual TLS. The server presents its certificate (signed by the TLS Intermediate CA), and the device presents its certificate (also signed by the TLS Intermediate CA). Both sides validate the other's chain back to the Root CA.

This means:

- A rogue server can't push updates to a device (the device validates the server's cert)
- A rogue device can't pull updates from the server (the server validates the device's cert)
- The transport layer is encrypted and authenticated in both directions

No API keys. No shared secrets. Certificate-based mutual authentication.

The trust anchors for this are visible in the ota-fetch config:

```ini
[network]
server_url = https://kf-updates.lab:8443/r5bp/lab/edgeai
tls_ca_cert = /etc/ota-fetch/trust/tls-ca-chain.pem
tls_client_cert = /var/lib/ota-fetch/identity/client.crt
tls_client_key = /var/lib/ota-fetch/identity/client.key
```

Note the path split: `tls_ca_cert` is in `/etc/ota-fetch/trust/` (baked into the rootfs image, replaceable with every update), while `tls_client_cert` and `tls_client_key` are in `/var/lib/ota-fetch/identity/` (runtime provisioned during enrollment, persistent across updates). Static trust ships with the OS; dynamic identity is provisioned once and persists forever.

## Update verification chain

This is the part I spent the most time on, because it's where most OTA implementations are weakest. The typical pattern is: download the update, then verify it. That's backwards.

### The verification sequence

**Step 1: Manifest first.** The device downloads the manifest and its detached signature before touching the payload. The manifest is small—kilobytes, not megabytes.

**Step 2: Verify the manifest signature.** The signer certificate is validated against the manifest CA chain (`manifest-ca-chain.pem`), then the manifest signature is verified. The supported signer key types are Ed25519, ECDSA (SHA-256), and RSA (SHA-256). If the chain or signature is invalid, the process stops here. No payload download. Fail fast.

**Step 3: Check the payload hash.** The manifest contains a SHA-256 hash of the payload. After downloading the payload, the device computes the hash and compares. If it doesn't match, the payload is discarded.

**Step 4: RAUC independent verification.** The RAUC bundle has its own signature, verified by RAUC independently against its own configured keyring. This is a second, fully independent verification layer—RAUC doesn't trust ota-fetch's verification, and ota-fetch doesn't trust RAUC's. Both must pass.

```
  Manifest + Signature
        │
        ▼
  Verify signer cert chains
  to manifest CA
        │
        ├── FAIL → stop, log, done
        │
        ▼ PASS
  Verify manifest signature
        │
        ├── FAIL → stop, log, done
        │
        ▼ PASS
  Download payload
        │
        ▼
  Verify payload SHA-256
  against manifest
        │
        ├── FAIL → discard payload, log, done
        │
        ▼ PASS
  Hand to RAUC
        │
        ▼
  RAUC verifies bundle
  signature (independent keyring)
        │
        ├── FAIL → reject install, log, done
        │
        ▼ PASS
  Install to inactive slot
  Mark pending, reboot
```

**Why double verification?** Defense in depth. If ota-fetch has a bug that bypasses its verification, RAUC still catches it. If someone manages to tamper with the manifest after ota-fetch verifies it (unlikely but not impossible in a compromised system), RAUC's independent check on the actual bundle is the last gate. Neither layer alone is sufficient. Together, they cover each other's failure modes.

Note the independent trust anchors: ota-fetch validates manifests against `manifest-ca-chain.pem` (rooted in the OTA Intermediate CA), while RAUC validates bundles against `rauc-keyring.pem` (also rooted in the OTA Intermediate CA but verified independently). Two separate config files, two separate code paths, two separate verification decisions.

## RAUC integration and A/B safety

The device maintains two complete root filesystem slots and two corresponding boot partition slots. RAUC manages which slot is active, which is the install target, and what happens when a boot fails.

### Slot layout

The partition table carries four OTA-relevant partitions, referenced by GPT partition label rather than device path—so the config survives disk re-enumeration:

```ini
# system.conf
[system]
compatible=kf-rock-5b-plus
bootloader=uboot

[keyring]
path=/etc/rauc/rauc-keyring.pem

[slot.rootfs.0]
device=/dev/disk/by-partlabel/rootfsA
type=ext4
bootname=A

[slot.rootfs.1]
device=/dev/disk/by-partlabel/rootfsB
type=ext4
bootname=B

[slot.bootfs.0]
device=/dev/disk/by-partlabel/bootA
type=vfat
parent=rootfs.0

[slot.bootfs.1]
device=/dev/disk/by-partlabel/bootB
type=vfat
parent=rootfs.1
```

Each root filesystem slot has a paired boot partition (`bootfs`) declared as a `parent` relationship. When RAUC installs a bundle, it writes the rootfs image to the inactive rootfs slot and the kernel/dtb to the corresponding bootfs slot as a single atomic operation. The `parent` linkage is what makes this work—RAUC won't install a kernel to `bootB` while writing a rootfs to `rootfsA`.

The `compatible` field (`kf-rock-5b-plus`) is checked against the bundle's declared compatibility at install time. A bundle built for a different board variant is rejected before any write happens.

### The full disk layout

The WIC template defines the complete GPT partition map for the Rock 5B+:

```
# GPT Layout (rk3588-ab-dualrootfs.wks.in)
# +---+-----------+--------+--------+---------------------------------------+
# | # | label     | fstype | size   | purpose                               |
# +---+-----------+--------+--------+---------------------------------------+
# | 1 | spl       | none   |  -     | Rockchip first-stage loader           |
# | 2 | u-boot    | none   | 4 MB   | U-Boot ITB                            |
# | 3 | uboot-env | none   | 1 MB   | U-Boot environment (boot counters)    |
# | 4 | bootscript| vfat   | 128 MB | boot.scr (slot-selection script)      |
# | 5 | bootA     | vfat   | 128 MB | Slot A: FIT image + extlinux          |
# | 6 | bootB     | vfat   | 128 MB | Slot B: FIT image + extlinux          |
# | 7 | rootfsA   | ext4   | 2 GB   | Slot A: root filesystem               |
# | 8 | rootfsB   | ext4   | 2 GB   | Slot B: root filesystem               |
# | 9 | kf_var    | ext4   | 4 GB   | Persistent /var (survives all updates)|
# +---+-----------+--------+--------+---------------------------------------+
```

Nine partitions, every one with a purpose. The U-Boot environment partition (partition 3) is where the boot counters (`BOOT_A_LEFT`, `BOOT_B_LEFT`, `BOOT_ORDER`) live—separate from both the boot and root partitions so they survive slot switches. The persistent `/var` partition (partition 9) is where device identity and OTA state live. The boot partitions carry a FIT image (kernel + DTB) and an extlinux config, with each slot's extlinux pointing to its corresponding rootfs by PARTLABEL.

### Bundles and verification

The RAUC bundle uses the `verity` format—dm-verity protected, not just CMS-signed. This means the bundle payload is integrity-checked at the block level during extraction, not just signature-checked at the envelope level.

The bundle build recipe shows where the signing keys enter the pipeline:

```python
# Signing inputs from the build environment, not baked into the layer
RAUC_KEY_FILE ?= "${@os.environ.get('RAUC_KEY_FILE', '')}"
RAUC_CERT_FILE ?= "${@os.environ.get('RAUC_CERT_FILE', '')}"
RAUC_KEYRING_FILE ?= "${@os.environ.get('RAUC_KEYRING_FILE', '')}"
RAUC_INTERMEDIATE_FILE ?= "${@os.environ.get('RAUC_INTERMEDIATE_FILE', '')}"

# Include the OTA intermediate in the bundle signature
BUNDLE_ARGS += " --intermediate=${RAUC_INTERMEDIATE_FILE}"
```

Two things to note here. First, the signing keys come from the environment (passed through kas/container), never stored in the Yocto layer itself. The recipe hard-fails if any signing input is missing. Second, the OTA Intermediate certificate is included in the bundle via `--intermediate`, which means the device can validate the full chain from bundle signature → intermediate → root CA without needing the intermediate pre-installed on every device. The device keyring (`rauc-keyring.pem`) only needs the root CA.

The build also runs a post-build verification step: after generating the bundle, it calls `rauc info --keyring=...` against its own output. This catches signing misconfigurations at build time rather than deployment time—a bad bundle never leaves the pipeline.

### Boot counting and rollback

The A/B slot switch is managed by U-Boot with a boot counting mechanism. Here's the core logic from `boot.cmd`:

```bash
# Each slot starts with 3 boot attempts
if test -z "${BOOT_A_LEFT}";  then setenv BOOT_A_LEFT 3;  fi
if test -z "${BOOT_B_LEFT}";  then setenv BOOT_B_LEFT 3;  fi

for BOOT_SLOT in "${BOOT_ORDER}"; do
    # ... select first slot with remaining attempts
    # Decrement counter before boot
    setexpr BOOT_A_LEFT ${BOOT_A_LEFT} - 1
done

# Safety net: if BOTH slots exhausted, reset and reboot
if test -n "${bootpart}"; then
    saveenv
else
    setenv BOOT_A_LEFT 3
    setenv BOOT_B_LEFT 3
    saveenv
    reset
fi
```

`BOOT_ORDER` determines which slot is tried first (set by RAUC during install). Each slot gets 3 boot attempts. Every boot decrements the counter *before* loading the kernel, so if the system hangs or kernel panics, the counter is already lower on the next power cycle. Three attempts is generous enough to survive transient failures (flaky SD card read, power brownout during boot) but tight enough to fail over to the other slot quickly.

The fallback-of-last-resort is the `else` branch: if both slots are exhausted, counters reset to 3 and the board reboots. This prevents a permanent brick in the pathological case where both slots are damaged. Most OTA demos don't handle this case.

### Marking good

The boot counter is a dead man's switch—it only counts *down*. Something has to reset it to confirm the boot succeeded. That's the `rauc-mark-good` systemd service:

```ini
[Unit]
Description=RAUC Good-marking Service
After=boot-complete.target
Requires=boot-complete.target

[Service]
Type=oneshot
ExecStart=rauc status mark-good
```

The chain is: U-Boot decrements the boot counter → boots the selected slot → systemd starts services → the system reaches `boot-complete.target` (all critical services are up) → `rauc status mark-good` runs and resets the boot counter for this slot. If the system never reaches `boot-complete.target` within 3 boots, U-Boot automatically falls to the other slot.

This is intentionally stock RAUC—the mark-good mechanism is well-tested and there's no reason to reimplement it. The opinionated part is the *gate*: `boot-complete.target`. In the reference implementation this is the default systemd target, but in a production deployment you'd gate it on your application-level health check: inference engine loaded, sensor pipeline responding, whatever "healthy" means for your workload.

The guarantee: a bad update never bricks a device. The worst case is a rollback to the previous known-good slot.

## ota-fetch: the custom OTA daemon

ota-fetch is a lightweight C program with one job: poll for updates, verify them, and hand off to RAUC. It's deliberately minimal—libcurl for transport, OpenSSL for cryptography, cJSON for manifest parsing.

### Why a custom daemon?

The manifest-first, fail-fast verification chain described earlier requires control over the update flow that generic OTA clients don't give you. Most clients treat "download then verify" as a single step. ota-fetch treats them as separate stages with independent failure modes and independent trust decisions. Building that on top of an existing client would mean fighting the client's assumptions about update flow. Writing it from scratch in C keeps the control surface small and the dependencies minimal.

### How it works

ota-fetch runs as a foreground polling loop under systemd supervision. It's not a daemon in the traditional fork-and-background sense—systemd handles restart, logging, and lifecycle. The poll interval is configurable (default: 3600 seconds, set to 60 in the demo for quick iteration).

Each poll cycle:

1. Fetch `manifest.json`, `manifest.json.sig`, and `signer.crt` from the OTA server over mTLS.
2. Verify the signer certificate chains to the configured manifest CA.
3. Verify the manifest signature. If either check fails, stop. No payload download.
4. Compare the manifest's SHA-256 against the currently installed manifest. If unchanged, sleep until the next cycle (daemon mode) or exit (oneshot mode).
5. Select the release matching the configured `device_id`, falling back to `"default"` if no device-specific release exists.
6. Download the payload file to the inbox directory.
7. Verify the payload's SHA-256 against the manifest. If it doesn't match, discard and stop.
8. Call `rauc install <bundle_path>`. On success, move the manifest to the `current` directory and trigger a reboot.

### Configuration

The config makes the dual trust model visible at a glance:

```ini
[network]
server_url = https://kf-updates.lab:8443/r5bp/lab/edgeai
tls_ca_cert = /etc/ota-fetch/trust/tls-ca-chain.pem
tls_client_cert = /var/lib/ota-fetch/identity/client.crt
tls_client_key = /var/lib/ota-fetch/identity/client.key
enroll_url = http://kf-updates.lab:8081/v1/enroll

[system]
manifest_ca_cert = /etc/ota-fetch/trust/manifest-ca-chain.pem
device_id = device-0001
update_interval_sec = 60
inbox_manifest_dir = /var/lib/ota-fetch/inbox
current_manifest_dir = /var/lib/ota-fetch/current
```

`tls_ca_cert` and `tls_client_cert/key` handle transport authentication (mTLS). `manifest_ca_cert` handles content authentication (manifest signatures). These are independent trust chains—different CA intermediates, different purposes, different compromise radii.

### The manifest

The manifest format is intentionally simple:

```json
{
  "manifest_version": "9.9.9-test",
  "created": "2026-03-01T04:31:33Z",
  "releases": [{
    "device_id": "default",
    "release_name": "dev-test",
    "release_version": "0.0.3",
    "created": "2026-03-15T22:36:04Z",
    "files": [{
      "file_type": "rauc_bundle",
      "filename": "latest.raucb",
      "size": 731703007,
      "sha256": "44a6df53d639a5123900b64b51b9ce78...",
      "path": "default/latest.raucb"
    }]
  }]
}
```

A few design decisions worth noting. Update detection is based on the SHA-256 of the entire manifest file, not version comparison. This sidesteps all the edge cases around version string parsing and ordering—if the manifest changed, there's something new to evaluate. The `device_id` field allows the same OTA server to serve different releases to different hardware variants from a single manifest. The `file_type` field (`rauc_bundle` vs. `rauc_bundle_test`) controls whether RAUC is actually invoked—`rauc_bundle_test` marks the manifest current without installing, which is useful for CI and integration testing.

### What ota-fetch is not

It's not an update framework. It doesn't manage slots, decide rollback policy, or track fleet state. It doesn't implement retry backoff or staged rollouts. Those are RAUC's job and the fleet management layer's job, respectively. ota-fetch is a fetch-verify-handoff pipeline—deliberately scoped so that each piece of the system does one thing.

## The Kernel Forge Yocto layers

Everything described so far—the PKI trust anchors, the A/B boot plumbing, the OTA daemon, the RAUC configuration—gets assembled into a bootable image through a set of five Yocto layers. The layer structure is where the architecture becomes a buildable system.

### Layer responsibilities

```
meta-kernelforge-rock5bplus  — BSP: machine config, kernel, U-Boot, device tree
meta-kernelforge-system      — A/B plumbing: boot script, extlinux, RAUC slot config,
                                FIT image builder, fstab with persistent /var
meta-kernelforge-distro      — Distro policy: systemd, networkd, RAUC distro feature
meta-kernelforge-platform    — Packagegroups and ota-fetch recipe
meta-kernelforge-images      — Image recipes, includes, WIC partition template
```

The split is by concern, not by convenience. The system layer owns everything about A/B slot mechanics and boot artifacts—but knows nothing about which board it's running on. The BSP layer owns the Rock 5B+ specifics—but knows nothing about OTA. The platform layer owns ota-fetch—but has no opinion about partition layout. This means you can swap the BSP layer for a different board and the entire OTA stack comes along unchanged.

### How they compose

The image recipe `kf-r5bp.bb` pulls it together:

```
kf-r5bp.bb
  └── requires kf-image-base.bb
        ├── packagegroup-kernelforge-base (systemd, e2fsprogs, iproute2)
        └── packagegroup-kernelforge-ota-core (ota-fetch, kf-bootscr,
              kf-extlinux, kf-fitimage, kf-fwenv, libubootenv-bin)
  └── includes kf-image-rauc.inc
        └── packagegroup-kernelforge-rauc (rauc, rauc-conf, rauc-mark-good)
  └── includes kf-image-wireless.inc
        └── packagegroup-kernelforge-wireless (iwd, wireless-regdb)
  └── inherits kf-bootfs-vfat (stages boot trees for WIC)
```

The `kf-ab-slots` bbclass is the bridge between the image build and the partition layout. It runs after `do_rootfs` and before `do_image_wic`, staging two boot trees (A and B) from the image's `/boot` content. Slot B's `extlinux.conf` gets rewritten to point to `PARTLABEL=rootfsB`. The class exports the staged tree paths to WIC, which populates the bootA and bootB partitions from them.

This class is deliberately OTA-framework-agnostic. It stages boot trees and rewrites extlinux—that's it. No RAUC assumptions, no U-Boot env manipulation. It could be paired with SWUpdate or a custom updater without modification.

### Trust anchor delivery

The ota-fetch recipe handles the split between static trust and dynamic identity at the filesystem level:

- **Static trust** (ships in the image): `tls-ca-chain.pem` and `manifest-ca-chain.pem` are installed to `/etc/ota-fetch/trust/` at build time. These are the CA chains the device uses to validate servers and manifests.
- **Dynamic identity** (provisioned at runtime): `/var/lib/ota-fetch/identity/` is created with mode `0700` and starts empty. The enrollment service populates it on first boot.

The CA chain PEM files are sourced from the PKI during the build. In practice, you'd point your Yocto `local.conf` at the PKI's stable symlinks, and a certificate rotation in the PKI automatically flows into the next image build.

## Persistent state

Not everything should reset on update. Device identity, configuration, and operational state need to survive A/B slot switches.

The root filesystem is immutable and replaceable—that's the whole point of A/B. But `/var` is a persistent mount on its own 4 GB ext4 partition (`PARTLABEL=kf_var`), separate from both rootfs slots. It survives every slot switch, every update, every rollback.

The fstab entry makes the persistence explicit:

```
PARTLABEL=kf_var    /var    ext4    rw,noatime,nodev,nosuid,errors=remount-ro    0  2
```

Mounted by partition label, with `errors=remount-ro` as a safety net—if the persistent volume develops filesystem errors, it remounts read-only rather than corrupting state silently.

What lives in `/var`:

- **Device identity** (`/var/lib/ota-fetch/identity/`): the device certificate, private key, and enrollment token. The device never needs to re-enroll after an update.
- **Manifest state** (`/var/lib/ota-fetch/inbox` and `/var/lib/ota-fetch/current`): the inbox holds in-progress downloads (cleaned at the start of each poll cycle), and the current directory holds the manifest from the last successful install. This is how ota-fetch knows whether a manifest represents a new update or the same one it already applied.
- **Logs** (`/var/log/ota-fetch.log`): ota-fetch appends to its log file across reboots, giving you a continuous operational record that isn't wiped by an update.

The design is intentional: the root filesystem carries the OS and application code (replaceable), the persistent volume carries identity and state (durable). A clean separation means you can update the entire operating system without losing track of who the device is or what it's done.

### What doesn't persist (on purpose)

Everything in the root filesystem is ephemeral by design. If an update introduces a new default config, it takes effect immediately—there's no merge conflict with a stale config from the previous slot. If a binary is compromised, the next update replaces it completely. The root filesystem is treated as a known-good snapshot from the build server, not as a living system that accumulates state.

This also means the reference implementation doesn't carry forward application runtime state (model weights, inference caches, job queues) across updates. In a production deployment with containerized workloads—which is what Demo 2 covers—container volumes and orchestration state would get their own persistent storage, separate from both the OTA state and the root filesystem.

## What production deployment adds

This section is important because it draws a clear, honest line between "reference implementation" and "production system." Everything above works and demonstrates the architecture. Crossing into production adds real engineering challenges at every layer.

**Key management and storage.** The reference stores CA keys on disk; production means Root CA keys in an HSM or offline air-gapped storage, intermediate keys in a KMS (AWS KMS, Azure Key Vault, etc.), and device-side key storage in a TPM or secure element where available. The hard part isn't "use an HSM"—it's integrating the HSM into the signing pipeline without introducing a manual step that someone eventually skips.

**Certificate lifecycle.** The reference generates CRLs but doesn't distribute them. Production means a CRL distribution point or OCSP responder that devices actually check, automated certificate rotation before expiry, and monitoring that alerts when a certificate is approaching end-of-life. The hard part is making revocation fast enough to matter—a compromised device cert that takes 24 hours to propagate is 24 hours of exposure.

**Fleet management.** The reference updates one device. Production means a device registry with inventory and status tracking, staged rollouts (canary → percentage → full fleet), fleet-level rollback policies (not just device-level), and update status reporting. The hard part is the rollout orchestration—knowing when a canary has passed and it's safe to proceed, and having the confidence to abort automatically when it hasn't.

**Manufacturing integration.** The reference pre-places a token on the filesystem. Production means real provisioning line integration, hardware root of trust (secure boot chain from ROM), and per-device unique identity bound to hardware. The hard part is the handoff between manufacturing and IT—the token needs to be generated, placed, and tracked without introducing a gap where an untrusted device could enroll.

**Operational infrastructure.** Update artifact storage and CDN, logging and alerting pipeline, compliance documentation and audit trail. The hard part is the logging pipeline—not *having* logs, but making them queryable enough to answer "which devices are running which version right now?" in under 30 seconds.

Each of these is a real engineering effort. The reference implementation proves the architecture works; production deployment is where you build the operational wrapper around it.

## Closing

The OTA pipeline is the trust anchor for everything Kernel Forge builds on top of. It's not the flashy part of edge AI. It's the part that determines whether you can maintain, patch, and trust what's running on your hardware.

Next up: Demo 2 — containerized inference workloads with least privilege, built on top of this OTA foundation.

The full implementation is available at [github.com/kernelforge-io/kernelforge-ota-reference](https://github.com/kernelforge-io/kernelforge-ota-reference), Apache-2.0 licensed with SPDX headers throughout.

— Kernel Forge
