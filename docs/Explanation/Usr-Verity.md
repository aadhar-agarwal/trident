
# Usr-Verity

Usr data integrity verification, or usr-verity, is a specific utilization
of [dm-verity](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/verity.html),
an integral part of the kernel that ensures that I/O for anything on the
protected filesystem (in this case, usr: `/usr`) is verified against a known
good state. This is achieved by creating a hash tree of the usr filesystem
contents, which is then used to validate the integrity of the data being
accessed.

The Merkle hash tree is visualized in the
[kernel documentation](https://docs.kernel.org/admin-guide/device-mapper/verity.html)
like this, where the `usr-hash` is the root node of the hash tree:

``` text
                            [   usr    ]
                           /    . . .    \
                [entry_0]                 [entry_1]
               /  . . .  \                 . . .   \
    [entry_0_0]   . . .  [entry_0_127]    . . . .  [entry_1_127]
      / ... \             /   . . .  \             /           \
blk_0 ... blk_127  blk_16256   blk_16383      blk_32640 . . . blk_32767
```

Trident partners with Image Customizer to deploy images that have `usr`
configured with dm-verity and a partition storing the `usr-hash`.

## Use Image Customizer to Create a COSI File

To create a COSI file with usr-verity enabled, Image Customizer provides some
[guidance](https://microsoft.github.io/azure-linux-image-tools/imagecustomizer/concepts/verity.html).

At a high level, there are only a couple things that need to be configured:

1. In addition to the typical `usr-data` partition definition, a `usr-hash`
   partition is needed like this:

    ``` yaml
    storage:
      disks:
      - partitionTableType: gpt
        partitions:
        - label: usr-data
          id: usr-data
          size: 2G
        - label: usr-hash
          id: usr-hash
          size: 128M
    ```

2. The [verity](https://microsoft.github.io/azure-linux-image-tools/imagecustomizer/api/configuration/verity.html)
   section is required:

    ``` yaml
    verity:
    - id: usr
      name: usr
      dataDeviceId: usr-data
      hashDeviceId: usr-hash
      dataDeviceMountIdType: part-label
      hashDeviceMountIdType: part-label
    ```

3. Usr-verity filesystems should be created as read-only:

    ``` yaml
    - deviceId: usr
      type: ext4
      mountPoint:
        path: /usr
        options: defaults,ro
    ```

4. Usr-verity requires some changes to support UKI rather than grub:

    ``` yaml
    os:
      kernelCommandLine:
        extraCommandLine:
        - rd.hostonly=0

    uki:
      mode: create

    previewFeatures:
    - uki
    ```

With these sections defined for `usr`, Image Customizer will generate a COSI
file containing a `usr-hash` partition and an OS with Usr Verity enabled.

## Use Trident to Deploy the COSI File

Once you have a COSI file that enables `Usr Verity`, Trident can be used to
deploy it during install or update.

Create a Trident Host Configuration file that aligns to the Image Customizer
COSI. Specifically:

1. Include `usr-data` and `usr-hash` partitions/filesystems

    ```yaml
    storage:
      disks:
      - id: os
        device: /dev/sda
        partitionTableType: gpt
        partitions:
        - id: usr-data
          type: usr
          size: 4G
        - id: usr-hash
          type: usr-verity
          size: 1G
    ```

2. Create [verity](../Reference/Host-Configuration/API-Reference/VerityDevice.md)
   section:

    ```yaml
    storage:
      verity:
      - id: usr
        name: usr
        dataDeviceId: usr-data
        hashDeviceId: usr-hash
    ```

## ACL signed `/usr` A/B updates

ACL signed images advertise `acl.verity_usr_signature=PARTUUID=<uuid>` in
both pre-signed slot addons. The marker, not the mere presence of signature
partitions, requires signed servicing. Unmarked policy-only images and the
existing `veritySignaturePaths` DER-file contract keep their previous signature
behavior. Slot-addon roots are checked against the selected `/usr` payload for
policy-only images too, without requiring new signature partitions.

The raw GPT partitions are `HASH-SIG-A` (PARTUUID
`3514648f-e3da-44ae-89ba-8d0552418f88`) and `HASH-SIG-B` (PARTUUID
`d8941eb2-f713-4bb6-b4ae-bd8350ca27d4`). They use the architecture-specific
DPS `/usr` verity-signature type (x64 `e7bb33fb-06cf-4e81-8273-e543b413e2e2`;
arm64 `c23ce4ff-44bd-4b00-b2d4-b41b3419e02a`). COSI's existing GPT-to-image
association carries these unmounted partitions; no schema extension is needed.
Each initialized signature partition contains JSON with exactly `rootHash`
(64 lowercase ASCII hexadecimal characters) and `signature` (canonical Base64
detached DER CMS). CMS signs exactly those 64 ASCII characters, without a
newline. NUL padding extends the payload to a multiple of 4096 bytes, at most
1 MiB.

Factory signed images retain the existing **A-active/B-empty** layout. Only
`USR-A`/`HASH-A` are initialized and only `HASH-SIG-A` contains a signature;
`USR-B`, `HASH-B`, and `HASH-SIG-B` remain zero-filled reserved partitions.
Publication metadata records `"initialized_slots": ["a"]`. Both pre-signed
addon templates still carry the source-A root hash and their respective slot's
data, hash, and signature PARTUUIDs. A template's capability marker does not
mean its slot is initialized or bootable. Do not clone A's btrfs filesystem
into factory B: that duplicates `/usr/share/ic/etc/fstab` and causes the pinned
Image Customizer to discover two rootfs candidates before verity PARTUUID
selection.

COSI must include the reserved B partitions in its GPT/image association, with
full partition-sized zero-filled images, not omitted or zero-length payloads.
Trident checks both slots' identities and image sizes, but extracts and
cryptographically verifies only the tuple selected by COSI's actual `/usr`
data/tree association. For these factory artifacts that is A, including
`HASH-SIG-A`; it does not require valid data or a signature in inactive B.
The first A-to-B update writes that source-A tuple into destination
`USR-B`/`HASH-B`/`HASH-SIG-B`, then verifies it before switching boot assets.
B's signature partition must have the same capacity as the selected source
signature image. A's existing tuple remains untouched for rollback. Later
updates likewise select by source payload, not by the destination slot letter.

Before any inactive-slot write, Trident validates source GPT identity, capacity,
data/tree association, both slot capabilities, the actual destination GPT and
active mapping, and the selected source signature. It caches the selected tuple,
opens it using kernel signature verification, and reads the entire mapping.
The signature always comes from the **source data slot**, even when installing
that payload into the other destination slot. The destination's pre-signed addon
must already name that payload's root hash and the destination PARTUUIDs.
Inconsistent templates are rejected, never patched or re-signed on the guest.

Only the inactive data/tree/signature partitions are written, using the normal
raw writer and sync operation. Trident reads back the complete tuple and opens
the target mapping with the signature before entering the update chroot. It
verifies again before a separately invoked finalize switches boot metadata.
Preflight failures perform no tuple writes; interrupted staging may leave an
incomplete inactive slot but does not change active/rollback tuple bytes.
Rollback continues to select the preserved slot and its existing boot assets.

Staging persists `stagedSignedUsr` with the `AbUpdateStaged` HostStatus: target
slot/root, partition identities/sizes/hashes, boot-asset hashes, and the final
UKI name. Finalize always rechecks this tuple and kernel signature trust,
including retries between or after the addon-directory and UKI renames. It
accepts the exact staged or already-renamed assets, never a missing or modified
marker as permission to downgrade. Missing, changed, or ambiguous assets fail
before boot-variable updates. The persisted entry is explicitly selected even
when the staged UKI filename no longer exists. Older unsigned staged records
without this field remain compatible; marked assets without a durable signed
record require restaging. Completing the update or rollback clears the record.

This path supports A/B updates of existing compatible ACL UKI disks. It rejects
signed clean-install/stream-image operations before partitioning and does not
migrate or repartition old layouts; provision finalized signed ACL disk images
through the image deployment path. Preflight needs temporary space for the
compressed tuple and its expanded data/tree/signature, plus the ESP image.
Bounded ESP inspection (including legacy UKI capability detection) and signed
tuple caching use private temporary directories in the running host's
disk-backed `/var/tmp`, not `/tmp` or the not-yet-written target root.
Ensure this host filesystem has enough free space; changing `TMPDIR` is not
required to service an ESP larger than the host's `/tmp` tmpfs.

The running kernel must support signed dm-verity and trust the CMS signer.
Publication/rollout must ensure the target and rollback kernels also trust their
required signers, including rotation overlap. Source-kernel preflight cannot
prove a future kernel's keyring; Secure Boot and userspace CMS parsing are not
substitutes for kernel verification.

ACL signed-root boot additionally requires the ACL-owned cryptsetup 2.4.3
backport, with a bumped ACL package release. Azure Linux 3's stock cryptsetup
2.4.3 (with device-mapper 2.03.23) discards kernel key error codes. The backport
must preserve `ENOKEY`, `EKEYREVOKED`, `EKEYEXPIRED`, and `EKEYREJECTED` for
VERITY activation only. Root-capable initrd builds must require the capability
marker from patched `cryptsetup-libs` and include that patched runtime; the
upstream version string alone is insufficient. This prerequisite applies to
both target and rollback signed-root boot environments.

ACL's transient signed-activation service uses systemd `StatusErrno` with
`NotifyAccess=main` to distinguish those key failures from setup or I/O failures,
not a generic process exit code. Invalid JSON/CMS prevalidation can degrade
directly; unknown setup and I/O failures remain fatal. This boot-only fallback
does not relax Trident's update checks: every signed activation failure during
preflight, staging, or finalization rejects servicing without unsigned fallback.
Real Linux boot validation of the patched library and typed-error path remains a
rollout prerequisite; compilation and offline tests do not establish it.

After booting the expected target, Trident logs ACL's version-1 structured
`/run/acl/usr-verity.json` diagnostic (`slot`, `rootHash`, `requestedMode`,
`verification`, `reason`). A `verified` report is cross-checked against the live
signature-verified mapping; `degraded` is never reported as verified. Audit
fallback, tag-off and IMDS-unavailable boots retain existing availability-first
completion and health-check policies. **No new automatic rollback condition is
introduced for degraded verification.** This runtime report is never used to
accept an update preflight.
