//! Strict signed-/usr update preflight. Boot fallback is deliberately not an
//! authorization to install an invalid update.

use std::{
    array,
    collections::{BTreeMap, HashSet},
    fs::{self, File},
    io::{self, Read, Write},
    ops::ControlFlow,
    path::{Path, PathBuf},
};

use anyhow::{bail, ensure, Context, Error};
use log::{info, warn};
use serde::Deserialize;
use tempfile::{NamedTempFile, TempDir};
use uuid::Uuid;
use zstd::stream::read::Decoder;

use osutils::{
    block_devices, container,
    filesystems::MountFileSystemType,
    lsblk,
    mount::{self, MountGuard},
    sfdisk::{SfDisk, SfDiskLabel},
    uki,
    verity_signature::{self, MAX_SIGNATURE_PARTITION_SIZE, SIGNATURE_BLOCK_SIZE},
    veritysetup::{self, VerityDevice},
};
use sysdefs::{acl, partition_types::DiscoverablePartitionType};
use trident_api::{
    constants::{ROOT_MOUNT_POINT_PATH, USR_MOUNT_POINT_PATH, USR_VERITY_DEVICE_NAME},
    error::{ReportError, ServicingError, TridentResultExt},
    status::{AbVolumeSelection, ServicingType, StagedSignedUsr, StagedSignedUsrPartition},
    BlockDeviceId,
};

use crate::{
    engine::{
        boot::uki::{self as boot_uki, ACL_ADDON_TEMPLATES_DIR, TMP_UKI_NAME, UKI_DIRECTORY},
        EngineContext,
    },
    io_utils::hashing_reader::{self, HashingReader, HashingReader384},
    osimage::{OsImageFile, OsImagePartition},
    subsystems::esp,
};

use super::verity;

const SIGNATURE_MARKER: &str = "acl.verity_usr_signature";
const ROOT_HASH: &str = "usrhash";
const DATA_PARTITION: &str = "systemd.verity_usr_data";
const HASH_PARTITION: &str = "systemd.verity_usr_hash";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    A,
    B,
}

impl Slot {
    fn from_volume(volume: AbVolumeSelection) -> Self {
        match volume {
            AbVolumeSelection::VolumeA => Self::A,
            AbVolumeSelection::VolumeB => Self::B,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }

    fn addon(self) -> &'static str {
        match self {
            Self::A => "slot-a.addon.efi",
            Self::B => "slot-b.addon.efi",
        }
    }

    fn signature_uuid(self) -> Uuid {
        match self {
            Self::A => acl::ACL_HASH_SIG_A_PARTUUID,
            Self::B => acl::ACL_HASH_SIG_B_PARTUUID,
        }
    }
}

#[derive(Debug)]
struct Addon {
    root_hash: String,
    data: Uuid,
    hash: Uuid,
    signature: Option<Uuid>,
}

fn argument<'a>(cmdline: &'a str, key: &str) -> Result<Option<&'a str>, Error> {
    let mut result = None;
    for arg in cmdline.split_ascii_whitespace() {
        let (name, value) = arg.split_once('=').unwrap_or((arg, ""));
        if name == key {
            ensure!(
                result.is_none() && !value.is_empty(),
                "Duplicate or empty {key}"
            );
            result = Some(value);
        }
    }
    Ok(result)
}

fn partuuid(value: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(
        value
            .strip_prefix("PARTUUID=")
            .context("Expected PARTUUID reference")?,
    )
    .context("Invalid addon partition UUID")
}

impl Addon {
    fn parse(cmdline: &str) -> Result<Self, Error> {
        let root_hash = argument(cmdline, ROOT_HASH)?.context("Addon has no usrhash")?;
        ensure!(
            verity_signature::valid_root_hash(root_hash),
            "Invalid addon usrhash"
        );
        ensure!(
            !cmdline.contains("root-hash-signature"),
            "Static root-hash-signature is unsupported for ACL signed /usr"
        );
        Ok(Self {
            root_hash: root_hash.to_owned(),
            data: partuuid(
                argument(cmdline, DATA_PARTITION)?.context("Addon has no /usr data partition")?,
            )?,
            hash: partuuid(
                argument(cmdline, HASH_PARTITION)?.context("Addon has no /usr hash partition")?,
            )?,
            signature: argument(cmdline, SIGNATURE_MARKER)?
                .map(partuuid)
                .transpose()?,
        })
    }
}

pub(super) struct CachedImage {
    pub(super) id: BlockDeviceId,
    pub(super) image: OsImageFile,
    pub(super) compressed: NamedTempFile,
    raw_sha384: String,
}

pub(crate) struct SignedUsrUpdate {
    pub(super) images: Vec<CachedImage>,
    root_hash: String,
    signature: Vec<u8>,
    target_volume: AbVolumeSelection,
    part_uuids: [Uuid; 3],
    _cache_dir: TempDir,
}

fn preflight_cache_dir(host_root: &Path) -> Result<TempDir, Error> {
    // Preflight precedes target writes/mounts. Use the running host's disk-backed
    // /var/tmp, not newroot or a potentially small /tmp tmpfs (even for legacy).
    let directory = esp::ensure_esp_extraction_dir(host_root)
        .unstructured("Failed to prepare disk-backed image inspection")?;
    tempfile::tempdir_in(directory).context("Failed to create image preflight cache")
}

/// Cache and verify the exact compressed artifact before any destination
/// writes. Bound both compressed and expanded data by COSI metadata.
fn extract(
    ctx: &EngineContext,
    image: &OsImageFile,
    directory: &Path,
) -> Result<(NamedTempFile, NamedTempFile), Error> {
    let mut extracted = None;
    ctx.image
        .as_ref()
        .context("No OS image")?
        .read_images(|path, reader| {
            if path != image.path {
                return ControlFlow::Continue(());
            }
            let result =
                extract_image(ctx, image, reader, directory).map(|files| extracted = Some(files));
            ControlFlow::Break(result.structured(ServicingError::DeployImages))
        })
        .unstructured("Failed to extract signed /usr image artifact")?;
    extracted.with_context(|| format!("Image payload '{}' is missing", image.path.display()))
}

fn extract_image(
    ctx: &EngineContext,
    image: &OsImageFile,
    reader: impl Read,
    directory: &Path,
) -> Result<(NamedTempFile, NamedTempFile), Error> {
    let mut compressed = NamedTempFile::new_in(directory)?;
    let mut reader = HashingReader384::new(
        reader.take(
            image
                .compressed_size
                .checked_add(1)
                .context("Image size overflow")?,
        ),
    );
    let size = io::copy(&mut reader, &mut compressed)?;
    ensure!(
        size == image.compressed_size,
        "Compressed image length mismatch"
    );
    ensure!(image.sha384 == reader.hash(), "Image SHA384 mismatch");
    compressed.as_file().sync_all()?;
    let mut raw = NamedTempFile::new_in(directory)?;
    let mut decoder = Decoder::new(File::open(compressed.path())?)?;
    if let Some(max) = ctx.image_zstd_max_window_log() {
        decoder.window_log_max(max)?;
    }
    let size = io::copy(
        &mut decoder.take(
            image
                .uncompressed_size
                .checked_add(1)
                .context("Image size overflow")?,
        ),
        &mut raw,
    )?;
    ensure!(
        size == image.uncompressed_size,
        "Expanded image length mismatch"
    );
    raw.as_file().sync_all()?;
    Ok((compressed, raw))
}

/// Returns None only for legacy images without the capability marker. Presence
/// of empty HASH-SIG partitions alone must not opt a legacy image into signing.
pub(crate) fn prepare(ctx: &EngineContext) -> Result<Option<SignedUsrUpdate>, Error> {
    let Some(image) = ctx.image.as_ref() else {
        return Ok(None);
    };
    if !image.is_uki() {
        return Ok(None);
    }
    let host_root = container::get_host_relative_path(ROOT_MOUNT_POINT_PATH.into())
        .unstructured("Failed to locate host staging filesystem")?;
    let cache_dir = preflight_cache_dir(&host_root)?;
    let (_, esp) = extract(ctx, &image.esp_filesystem()?.image_file, cache_dir.path())?;
    let mount_dir = tempfile::tempdir_in(cache_dir.path())?;
    mount::mount(
        esp.path(),
        mount_dir.path(),
        MountFileSystemType::Vfat,
        &["ro".into(), "umask=0077".into()],
    )?;
    let guard = MountGuard {
        mount_dir: mount_dir.path(),
    };
    let templates = mount_dir.path().join(ACL_ADDON_TEMPLATES_DIR);
    let mut cmdlines = Vec::new();
    for slot in [Slot::A, Slot::B] {
        let path = templates.join(slot.addon());
        cmdlines.push(if path.exists() {
            uki::read_cmdline(path)?
        } else {
            String::new()
        });
    }
    // Also inspect the live boot assets: a marker without usable templates must
    // not silently become an unsigned update.
    let mut marked = cmdlines.iter().any(|s| s.contains(SIGNATURE_MARKER));
    let uki_dir = mount_dir.path().join(UKI_DIRECTORY);
    let mut other_cmdlines = Vec::new();
    for entry in fs::read_dir(uki_dir)? {
        let path = entry?.path();
        if path.is_file() {
            let cmdline = uki::read_cmdline(&path)?;
            marked |= cmdline.contains(SIGNATURE_MARKER);
            other_cmdlines.push(cmdline);
            let addons = uki::uki_addon_dir(&path);
            if addons.exists() {
                for addon in fs::read_dir(addons)? {
                    let addon = addon?.path();
                    if uki::is_uki_addon_file(&addon) {
                        let cmdline = uki::read_cmdline(&addon)?;
                        marked |= cmdline.contains(SIGNATURE_MARKER);
                        if addon
                            .file_name()
                            .is_some_and(|name| name != Slot::A.addon() && name != Slot::B.addon())
                        {
                            other_cmdlines.push(cmdline);
                        }
                    }
                }
            }
        }
    }
    if ctx.image_distro().is_acl() && templates.exists() {
        let target = Slot::from_volume(ctx.get_ab_update_volume().context("No update slot")?);
        let usr = image
            .filesystems()
            .find(|fs| fs.mount_point == Path::new(USR_MOUNT_POINT_PATH))
            .context("ACL slot addon requires a /usr image")?;
        let root = usr
            .verity
            .as_ref()
            .context("ACL slot addon requires /usr verity")?;
        // Also protect policy-only slot addons, without imposing the new
        // signature format or GPT-layout contract on legacy images.
        let target_root = argument(&cmdlines[usize::from(target == Slot::B)], ROOT_HASH)?
            .context("Target slot addon has no usrhash")?;
        ensure!(
            target_root.eq_ignore_ascii_case(&root.roothash),
            "Target slot addon root does not match the selected /usr payload"
        );
    }
    if !marked {
        return Ok(None);
    }
    ensure!(
        ctx.image_distro().is_acl(),
        "Signed /usr slot capability is supported only for ACL images"
    );
    for cmdline in other_cmdlines {
        for key in [SIGNATURE_MARKER, ROOT_HASH, DATA_PARTITION, HASH_PARTITION] {
            ensure!(
                argument(&cmdline, key)?.is_none(),
                "Signed /usr boot arguments must occur only in the selected slot addon"
            );
        }
        ensure!(
            !cmdline.contains("root-hash-signature"),
            "Static signature option outside the slot addon"
        );
    }
    ensure!(
        ctx.servicing_type == ServicingType::AbUpdate && !ctx.is_stream_image,
        "Signed /usr requires an A/B update of an existing compatible disk; clean install/stream-image is not supported"
    );
    let active = ctx
        .ab_active_volume
        .context("Signed /usr requires a known active slot")?;
    let destination = Slot::from_volume(ctx.get_ab_update_volume().context("No update slot")?);
    ensure!(
        destination != Slot::from_volume(active),
        "Cannot write the active signed /usr slot"
    );
    let addons = [Addon::parse(&cmdlines[0])?, Addon::parse(&cmdlines[1])?];
    for (slot, addon) in [Slot::A, Slot::B].into_iter().zip(&addons) {
        ensure!(
            addon.signature == Some(slot.signature_uuid()),
            "Missing or incorrect signed /usr capability for {slot:?}"
        );
        let data_uuid = match slot {
            Slot::A => acl::ACL_USR_A_PARTUUID,
            Slot::B => acl::ACL_USR_B_PARTUUID,
        };
        ensure!(
            addon.data == data_uuid,
            "Slot addon /usr UUID does not match ACL layout"
        );
    }
    drop(guard);

    let usr = image
        .filesystems()
        .find(|fs| fs.mount_point == Path::new(USR_MOUNT_POINT_PATH))
        .context("Signed image has no /usr filesystem")?;
    let hash = usr
        .verity
        .as_ref()
        .context("Signed /usr is not verity protected")?;
    // Regular A/B servicing does not derive its Host Configuration from COSI,
    // so unlike stream-image, it has not loaded the lazy GPT association yet.
    let mut image_with_gpt = image.clone();
    image_with_gpt
        .partitioning_info()?
        .context("Signed /usr requires COSI GPT metadata")?;
    let partitions: Vec<_> = image_with_gpt
        .partitions()
        .context("Signed /usr requires COSI GPT metadata")?
        .collect();
    validate_unique_partitions(&partitions)?;
    let source = select_source(&partitions, &usr.image_file, &hash.hash_image_file)?;
    let source_addon = &addons[usize::from(source == Slot::B)];
    let target_addon = &addons[usize::from(destination == Slot::B)];
    validate_roots(source_addon, target_addon, &hash.roothash)?;
    for (slot, addon) in [Slot::A, Slot::B].into_iter().zip(&addons) {
        for (label, kind, uuid) in slot_parts(slot, addon) {
            let part = partition_by_label(&partitions, &label)?;
            ensure!(
                part.info.part_type == kind && part.info.part_uuid == uuid,
                "Source GPT label/type/UUID mismatch for {label}"
            );
            ensure!(
                part.info.size == part.image_file.uncompressed_size,
                "Source GPT/payload capacity mismatch for {label}"
            );
        }
    }
    let signature_part = partition_by_label(&partitions, &format!("HASH-SIG-{}", source.suffix()))?;
    ensure!(
        signature_part.info.size > 0
            && signature_part.info.size <= MAX_SIGNATURE_PARTITION_SIZE
            && signature_part.info.size % SIGNATURE_BLOCK_SIZE == 0,
        "Invalid HASH-SIG capacity"
    );

    let usr_id = ctx
        .get_usr_block_device_id()
        .context("No /usr block device")?;
    let device = ctx
        .spec
        .storage
        .verity_device(&usr_id)
        .context("/usr is not a verity device")?;
    let signature_id = signature_destination(ctx, destination)?;
    let ids = [
        device.data_device_id.clone(),
        device.hash_device_id.clone(),
        signature_id,
    ];
    let selected_images = [
        &usr.image_file,
        &hash.hash_image_file,
        &signature_part.image_file,
    ];
    validate_destination(ctx, &ids, destination, &addons, &selected_images)?;

    let mut caches = Vec::new();
    let mut raws = Vec::new();
    for (id, image) in ids.into_iter().zip(selected_images) {
        let (compressed, raw) = extract(ctx, image, cache_dir.path())?;
        let (_, raw_sha384) = hashing_reader::compute_file_hash(raw.path())?;
        caches.push(CachedImage {
            id,
            image: image.clone(),
            compressed,
            raw_sha384,
        });
        raws.push(raw);
    }
    let signature = verity_signature::read_signature(File::open(raws[2].path())?, &hash.roothash)?;
    verify_temporary_mapping(raws[0].path(), raws[1].path(), &hash.roothash, &signature)
        .context("Source-kernel signed /usr preflight failed (signer must be in kernel trust)")?;
    info!("Signed /usr preflight verified source slot {source:?} for destination slot {destination:?}");
    Ok(Some(SignedUsrUpdate {
        images: caches,
        root_hash: hash.roothash.clone(),
        signature,
        target_volume: ctx.get_ab_update_volume().context("No update slot")?,
        part_uuids: [
            target_addon.data,
            target_addon.hash,
            destination.signature_uuid(),
        ],
        _cache_dir: cache_dir,
    }))
}

fn validate_roots(source: &Addon, target: &Addon, root_hash: &str) -> Result<(), Error> {
    ensure!(source.root_hash == root_hash && target.root_hash == root_hash,
        "Source /usr root and target-slot addon disagree; publish matching pre-signed slot templates");
    Ok(())
}

fn slot_parts(slot: Slot, addon: &Addon) -> [(String, DiscoverablePartitionType, Uuid); 3] {
    [
        (
            format!("USR-{}", slot.suffix()),
            DiscoverablePartitionType::Unknown(acl::ACL_USR_PARTITION_TYPE_UUID),
            addon.data,
        ),
        (
            format!("HASH-{}", slot.suffix()),
            DiscoverablePartitionType::UsrVerity.resolve(),
            addon.hash,
        ),
        (
            format!("HASH-SIG-{}", slot.suffix()),
            DiscoverablePartitionType::UsrVeritySig.resolve(),
            slot.signature_uuid(),
        ),
    ]
}

fn partition_by_label<'a>(
    parts: &'a [OsImagePartition],
    label: &str,
) -> Result<&'a OsImagePartition, Error> {
    parts
        .iter()
        .find(|p| p.info.name == label)
        .with_context(|| format!("Missing source GPT partition {label}"))
}

fn validate_unique_partitions(parts: &[OsImagePartition]) -> Result<(), Error> {
    let mut uuids = HashSet::new();
    let mut names = HashSet::new();
    let mut paths = HashSet::new();
    for part in parts {
        ensure!(
            uuids.insert(part.info.part_uuid)
                && names.insert(&part.info.name)
                && paths.insert(&part.image_file.path),
            "Ambiguous source GPT partition identity"
        );
    }
    Ok(())
}

fn same_image(a: &OsImageFile, b: &OsImageFile) -> bool {
    a.path == b.path
        && a.sha384 == b.sha384
        && a.compressed_size == b.compressed_size
        && a.uncompressed_size == b.uncompressed_size
}

fn select_source(
    parts: &[OsImagePartition],
    data: &OsImageFile,
    hash: &OsImageFile,
) -> Result<Slot, Error> {
    for slot in [Slot::A, Slot::B] {
        if same_image(
            &partition_by_label(parts, &format!("USR-{}", slot.suffix()))?.image_file,
            data,
        ) {
            ensure!(
                same_image(
                    &partition_by_label(parts, &format!("HASH-{}", slot.suffix()))?.image_file,
                    hash
                ),
                "Source /usr data and hash tree belong to different slots"
            );
            return Ok(slot);
        }
    }
    bail!("Cannot associate /usr data payload with a source GPT slot")
}

fn signature_destination(ctx: &EngineContext, slot: Slot) -> Result<BlockDeviceId, Error> {
    let partitions: Vec<_> = ctx
        .spec
        .storage
        .disks
        .iter()
        .flat_map(|d| &d.partitions)
        .filter(|p| p.uuid == Some(slot.signature_uuid()))
        .collect();
    ensure!(
        partitions.len() == 1,
        "Missing or ambiguous destination HASH-SIG UUID"
    );
    let id = &partitions[0].id;
    let pairs = &ctx
        .spec
        .storage
        .ab_update
        .as_ref()
        .context("No A/B configuration")?
        .volume_pairs;
    let pair = pairs
        .iter()
        .find(|p| &p.volume_a_id == id || &p.volume_b_id == id)
        .context("HASH-SIG is not an A/B volume pair")?;
    let selected = match slot {
        Slot::A => &pair.volume_a_id,
        Slot::B => &pair.volume_b_id,
    };
    ensure!(
        selected == id,
        "HASH-SIG A/B pairing disagrees with GPT identity"
    );
    Ok(id.clone())
}

fn validate_destination(
    ctx: &EngineContext,
    ids: &[BlockDeviceId; 3],
    slot: Slot,
    addons: &[Addon; 2],
    images: &[&OsImageFile; 3],
) -> Result<(), Error> {
    let pairs = &ctx
        .spec
        .storage
        .ab_update
        .as_ref()
        .context("No A/B configuration")?
        .volume_pairs;
    for id in &ids[..2] {
        ensure!(
            pairs.iter().any(|pair| &pair.id == id),
            "Signed /usr data and tree must both use A/B volume pairs"
        );
    }
    let paths = ids
        .iter()
        .map(|id| {
            ctx.get_block_device_path(id)
                .context("Missing destination device")?
                .canonicalize()
                .context("Cannot resolve destination device")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let disk_path = block_devices::get_disk_for_partition(&paths[0])?;
    let disk = SfDisk::get_info(&disk_path)?;
    ensure!(disk.label == SfDiskLabel::Gpt, "Signed /usr requires GPT");
    let mut identities = HashSet::new();
    for (part_slot, addon) in [Slot::A, Slot::B].into_iter().zip(addons) {
        for (label, kind, uuid) in slot_parts(part_slot, addon) {
            let candidates: Vec<_> = disk
                .partitions
                .iter()
                .filter(|p| p.name.as_deref() == Some(&label) || p.id.match_uuid(&uuid))
                .collect();
            ensure!(
                candidates.len() == 1,
                "Missing/ambiguous destination partition {label}; reimage required"
            );
            let p = candidates[0];
            ensure!(
                p.name.as_deref() == Some(&label)
                    && p.id.match_uuid(&uuid)
                    && p.partition_type == kind,
                "Destination GPT label/type/UUID mismatch for {label}; no migration is performed"
            );
            ensure!(
                identities.insert(p.node.canonicalize()?),
                "Aliased active/inactive partitions"
            );
        }
    }
    // HostStatus alone is not enough to authorize writes: prove its active
    // slot agrees with the live mapping, without using its trust diagnostic
    // to authorize the *target* signature.
    let active_slot = if slot == Slot::A { Slot::B } else { Slot::A };
    let active_addon = &addons[usize::from(active_slot == Slot::B)];
    let live = veritysetup::status(USR_VERITY_DEVICE_NAME)?
        .active()
        .context("Active /usr mapping is missing")?;
    for (path, uuid) in [
        (&live.data_device_path, active_addon.data),
        (&live.hash_device_path, active_addon.hash),
    ] {
        let partition = disk
            .partitions
            .iter()
            .find(|p| p.id.match_uuid(&uuid))
            .context("Missing active partition")?;
        ensure!(
            path.canonicalize()? == partition.node.canonicalize()?,
            "Live /usr disagrees with the configured active slot"
        );
    }
    for ((path, (label, _, uuid)), image) in paths
        .iter()
        .zip(slot_parts(slot, &addons[usize::from(slot == Slot::B)]))
        .zip(images)
    {
        let p = disk
            .partitions
            .iter()
            .find(|p| p.id.match_uuid(&uuid))
            .context("Missing destination partition")?;
        ensure!(
            p.node.canonicalize()? == *path,
            "Configured destination does not match inactive {label}"
        );
        ensure!(
            p.size >= image.uncompressed_size,
            "Inactive {label} is too small"
        );
        if label.starts_with("HASH-SIG-") {
            ensure!(
                p.size == image.uncompressed_size,
                "HASH-SIG capacity must match source (no stale trailing bytes)"
            );
        }
        let state = lsblk::get(path)?;
        ensure!(
            state.mountpoints.is_empty() && state.mountpoint.is_none() && !state.readonly,
            "Inactive {label} is mounted or read-only"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use trident_api::{
        config::{AbUpdate, AbVolumePair, Disk, Partition},
        primitives::hash::Sha384Hash,
    };

    use crate::osimage::{mock::MockOsImage, GptPartitionInfo, OsImage};

    fn file(path: &str) -> OsImageFile {
        OsImageFile {
            path: path.into(),
            sha384: Sha384Hash::from("0".repeat(96).as_str()),
            compressed_size: 42,
            uncompressed_size: 4096,
        }
    }

    fn partition(label: &str) -> OsImagePartition {
        OsImagePartition {
            image_file: file(label),
            info: GptPartitionInfo {
                name: label.to_owned(),
                part_uuid: Uuid::new_v4(),
                part_type: DiscoverablePartitionType::Usr.resolve(),
                size: 4096,
                first_lba: 10,
                last_lba: 17,
                flags: 0,
                partition_number: 1,
            },
        }
    }

    fn partitions() -> Vec<OsImagePartition> {
        [
            "USR-A",
            "HASH-A",
            "HASH-SIG-A",
            "USR-B",
            "HASH-B",
            "HASH-SIG-B",
        ]
        .into_iter()
        .map(partition)
        .collect()
    }

    fn cmdline(slot: Slot, hash: &str, signed: bool) -> String {
        let marker = if signed {
            format!(" {SIGNATURE_MARKER}=PARTUUID={}", slot.signature_uuid())
        } else {
            String::new()
        };
        format!("usrhash={hash} systemd.verity_usr_data=PARTUUID={} systemd.verity_usr_hash=PARTUUID={}{marker}",
                    Uuid::from_u128(1), Uuid::from_u128(2))
    }

    #[test]
    fn signed_and_legacy_addons_are_distinct() {
        let hash = "a".repeat(64);
        assert_eq!(
            Addon::parse(&cmdline(Slot::A, &hash, true))
                .unwrap()
                .signature,
            Some(Slot::A.signature_uuid())
        );
        assert!(Addon::parse(&cmdline(Slot::A, &hash, false))
            .unwrap()
            .signature
            .is_none());
        for bad in [
            format!("{} usrhash={hash}", cmdline(Slot::A, &hash, true)),
            format!("{} {SIGNATURE_MARKER}", cmdline(Slot::A, &hash, true)),
            format!(
                "{} systemd.verity_usr_options=root-hash-signature=/boot/old.der",
                cmdline(Slot::A, &hash, true)
            ),
            cmdline(Slot::A, "short", true),
        ] {
            Addon::parse(&bad).unwrap_err();
        }
    }

    #[test]
    fn source_slot_is_not_destination_slot() {
        let parts = partitions();
        for source in [Slot::A, Slot::B] {
            let data = file(&format!("USR-{}", source.suffix()));
            let hash = file(&format!("HASH-{}", source.suffix()));
            let actual = select_source(&parts, &data, &hash).unwrap();
            assert_eq!(actual, source);
            for destination in [Slot::A, Slot::B] {
                let signature =
                    partition_by_label(&parts, &format!("HASH-SIG-{}", actual.suffix())).unwrap();
                assert_eq!(
                    signature.image_file.path,
                    Path::new(&format!("HASH-SIG-{}", source.suffix()))
                );
                assert_eq!(
                    destination.signature_uuid(),
                    if destination == Slot::A {
                        acl::ACL_HASH_SIG_A_PARTUUID
                    } else {
                        acl::ACL_HASH_SIG_B_PARTUUID
                    }
                );
            }
        }
    }

    #[test]
    fn rejects_target_addon_with_different_root_even_when_source_is_valid() {
        let root = "a".repeat(64);
        let source = Addon::parse(&cmdline(Slot::A, &root, true)).unwrap();
        let matching_target = Addon::parse(&cmdline(Slot::B, &root, true)).unwrap();
        validate_roots(&source, &matching_target, &root).unwrap();
        let different_target = Addon::parse(&cmdline(Slot::B, &"b".repeat(64), true)).unwrap();
        validate_roots(&source, &different_target, &root).unwrap_err();
        validate_roots(&source, &matching_target, &"c".repeat(64)).unwrap_err();
    }

    #[test]
    fn rejects_cross_slot_tree_missing_and_ambiguous_identity() {
        let mut parts = partitions();
        select_source(&parts, &file("USR-A"), &file("HASH-B")).unwrap_err();
        let mut mismatched = file("HASH-A");
        mismatched.uncompressed_size += 1;
        select_source(&parts, &file("USR-A"), &mismatched).unwrap_err();
        parts.remove(2);
        partition_by_label(&parts, "HASH-SIG-A").unwrap_err();
        let duplicate_uuid = parts[0].info.part_uuid;
        parts[1].info.part_uuid = duplicate_uuid;
        validate_unique_partitions(&parts).unwrap_err();
    }

    fn context() -> EngineContext {
        let mut ctx = EngineContext {
            servicing_type: ServicingType::AbUpdate,
            ab_active_volume: Some(AbVolumeSelection::VolumeA),
            ..Default::default()
        };
        let mut a = Partition::new("sig-a", 4096u64);
        a.uuid = Some(Slot::A.signature_uuid());
        let mut b = Partition::new("sig-b", 4096u64);
        b.uuid = Some(Slot::B.signature_uuid());
        ctx.spec.storage.disks = vec![Disk {
            partitions: vec![a, b],
            ..Default::default()
        }];
        ctx.spec.storage.ab_update = Some(AbUpdate {
            volume_pairs: vec![AbVolumePair {
                id: "sig".to_owned(),
                volume_a_id: "sig-a".to_owned(),
                volume_b_id: "sig-b".to_owned(),
            }],
        });
        ctx
    }

    #[test]
    fn inactive_signature_selection_preserves_active_and_rollback() {
        let mut ctx = context();
        for (active, target, expected) in [
            (AbVolumeSelection::VolumeA, Slot::B, "sig-b"),
            (AbVolumeSelection::VolumeB, Slot::A, "sig-a"),
        ] {
            ctx.ab_active_volume = Some(active);
            assert_eq!(
                Slot::from_volume(ctx.get_ab_update_volume().unwrap()),
                target
            );
            assert_eq!(signature_destination(&ctx, target).unwrap(), expected);
        }
        let pair = &mut ctx.spec.storage.ab_update.as_mut().unwrap().volume_pairs[0];
        std::mem::swap(&mut pair.volume_a_id, &mut pair.volume_b_id);
        signature_destination(&ctx, Slot::A).unwrap_err();
    }

    #[test]
    fn unmarked_legacy_non_uki_image_does_not_require_signatures() {
        let ctx = EngineContext {
            image: Some(OsImage::mock(MockOsImage::new())),
            ..Default::default()
        };
        assert!(prepare(&ctx).unwrap().is_none());
    }

    #[test]
    fn runtime_status_is_diagnostic_not_a_fallback_success() {
        for (mode, verification) in [
            ("off", "not-requested"),
            ("unavailable", "not-requested"),
            ("audit", "degraded"),
            ("audit", "verified"),
        ] {
            let status = RuntimeStatus {
                version: 1,
                slot: "b".into(),
                root_hash: "a".repeat(64),
                requested_mode: mode.into(),
                verification: verification.into(),
                reason: "test".into(),
            };
            status.validate(Slot::B).unwrap();
            status.validate(Slot::A).unwrap_err();
            let invalid = RuntimeStatus {
                requested_mode: "off".into(),
                verification: "verified".into(),
                ..status
            };
            invalid.validate(Slot::B).unwrap_err();
        }
    }
}
const RUNTIME_STATUS_PATH: &str = "/run/acl/usr-verity.json";
const MAX_RUNTIME_STATUS_SIZE: u64 = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeStatus {
    version: u32,
    slot: String,
    root_hash: String,
    requested_mode: String,
    verification: String,
    reason: String,
}

impl RuntimeStatus {
    fn validate(&self, expected_slot: Slot) -> Result<(), Error> {
        ensure!(
            self.version == 1 && verity_signature::valid_root_hash(&self.root_hash),
            "Invalid signed /usr runtime status version or rootHash"
        );
        ensure!(
            self.slot == expected_slot.suffix().to_ascii_lowercase(),
            "Runtime status refers to a different slot"
        );
        ensure!(
            matches!(
                (self.requested_mode.as_str(), self.verification.as_str()),
                ("audit", "verified" | "degraded") | ("off" | "unavailable", "not-requested")
            ),
            "Inconsistent signed /usr runtime mode/verification"
        );
        Ok(())
    }
}

/// Diagnostic only, called after booting the expected target. This must never
/// feed update preflight or add an automatic-rollback condition.
pub(crate) fn report_runtime_status(ctx: &EngineContext) {
    let result = (|| -> Result<(), Error> {
        let path = container::get_host_relative_path(RUNTIME_STATUS_PATH.into())
            .unstructured("Failed to locate host /usr runtime status")?;
        let file = match File::open(path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RUNTIME_STATUS_SIZE + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= MAX_RUNTIME_STATUS_SIZE,
            "Oversized /usr runtime status"
        );
        let status: RuntimeStatus = serde_json::from_slice(&bytes)?;
        status.validate(Slot::from_volume(
            ctx.get_ab_update_volume().context("Unknown boot slot")?,
        ))?;
        let live = veritysetup::status(USR_VERITY_DEVICE_NAME)?
            .active()
            .context("/usr mapping is inactive")?;
        ensure!(
            live.root_hash == status.root_hash,
            "Runtime status rootHash differs from active /usr"
        );
        if status.verification == "verified" {
            ensure!(
                live.status == "verified (with signature)",
                "Runtime status claims verification without a signature-verified kernel mapping"
            );
            info!("ACL /usr signed verification: slot={} rootHash={} requestedMode={} verification={} reason={:?}",
                    status.slot, status.root_hash, status.requested_mode, status.verification, status.reason);
        } else {
            warn!("ACL /usr signed verification: slot={} rootHash={} requestedMode={} verification={} reason={:?}; existing completion/rollback policy unchanged",
                    status.slot, status.root_hash, status.requested_mode, status.verification, status.reason);
        }
        Ok(())
    })();
    if let Err(error) = result {
        warn!("Cannot validate ACL /usr runtime diagnostic (not verified): {error:#}; existing completion/rollback policy unchanged");
    }
}
fn signature_file(signature: &[u8]) -> Result<NamedTempFile, Error> {
    let mut file = NamedTempFile::new()?;
    file.write_all(signature)?;
    file.as_file().sync_all()?;
    Ok(file)
}

fn verify_temporary_mapping(
    data: &Path,
    hash: &Path,
    root_hash: &str,
    signature: &[u8],
) -> Result<(), Error> {
    let signature_file = signature_file(signature)?;
    let device = VerityDevice::new(
        format!("trident-signed-usr-{}", Uuid::new_v4()),
        data,
        hash,
        root_hash,
    );
    device.open_with_signature(signature_file.path())?;
    let verified = read_verified_device(&device);
    let closed = device.close();
    match (verified, closed) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(close_error)) => Err(error.context(format!(
            "Also failed to close preflight mapping: {close_error:#}"
        ))),
    }
}

fn asset_hash(path: &Path) -> Result<String, Error> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "Expected a regular boot asset"
    );
    Ok(hashing_reader::compute_file_hash(path)?.1)
}

fn addon_hashes(directory: &Path) -> Result<BTreeMap<String, String>, Error> {
    ensure!(
        fs::symlink_metadata(directory)?.file_type().is_dir(),
        "Expected an addon directory"
    );
    fs::read_dir(directory)?
        .map(|entry| {
            let entry = entry?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| Error::msg("Non-UTF8 addon name"))?;
            Ok((name, asset_hash(&entry.path())?))
        })
        .collect()
}

fn applicable_asset(staged: &Path, renamed: &Path) -> Result<PathBuf, Error> {
    let present = |path: &Path| match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    };
    match (present(staged)?, present(renamed)?) {
        (true, false) => Ok(staged.to_owned()),
        (false, true) => Ok(renamed.to_owned()),
        (true, true) => bail!("Both staged and renamed signed boot assets exist"),
        (false, false) => bail!(
            "Missing staged and renamed signed boot asset: {}",
            staged.display()
        ),
    }
}

fn validate_boot_assets(
    esp: &Path,
    expected: &StagedSignedUsr,
) -> Result<(PathBuf, PathBuf), Error> {
    ensure!(
        Path::new(&expected.uki_name)
            .file_name()
            .and_then(|name| name.to_str())
            == Some(&expected.uki_name)
            && expected.uki_name != TMP_UKI_NAME
            && expected.uki_name.ends_with(".efi"),
        "Invalid persisted signed UKI name"
    );
    let directory = esp.join(UKI_DIRECTORY);
    let staged = directory.join(TMP_UKI_NAME);
    let renamed = directory.join(&expected.uki_name);
    let image = applicable_asset(&staged, &renamed)?;
    let addons = applicable_asset(&uki::uki_addon_dir(&staged), &uki::uki_addon_dir(&renamed))?;
    ensure!(
        image == staged || addons == uki::uki_addon_dir(&renamed),
        "Signed UKI was renamed before its addons"
    );
    ensure!(
        asset_hash(&image)? == expected.uki_sha384,
        "Signed UKI changed after staging"
    );
    ensure!(
        addon_hashes(&addons)? == expected.addons,
        "Signed UKI addons changed after staging"
    );
    let target = Slot::from_volume(expected.target_volume);
    let addon = Addon::parse(&uki::read_cmdline(addons.join(target.addon()))?)?;
    ensure!(
        verity_signature::valid_root_hash(&expected.root_hash)
            && addon.root_hash == expected.root_hash
            && addon.data == expected.partitions[0].part_uuid
            && addon.hash == expected.partitions[1].part_uuid
            && addon.signature == Some(target.signature_uuid())
            && expected.partitions[2].part_uuid == target.signature_uuid(),
        "Signed slot addon no longer describes the persisted tuple/capability"
    );
    Ok((image, addons))
}

/// Both renames are individually durable, but not atomic together. Every entry
/// into this function, even with both assets renamed, revalidates before moving
/// files or allowing boot variables to be changed.
fn finish_signed_boot_assets(
    esp: &Path,
    expected: &StagedSignedUsr,
    verify_tuple: impl FnOnce() -> Result<(), Error>,
) -> Result<String, Error> {
    let (image, addons) = validate_boot_assets(esp, expected)?;
    verify_tuple()?;
    let directory = esp.join(UKI_DIRECTORY);
    let destination = directory.join(&expected.uki_name);
    let destination_addons = uki::uki_addon_dir(&destination);
    if addons != destination_addons {
        fs::rename(addons, &destination_addons)
            .context("Failed to rename verified signed addons")?;
        File::open(&directory)?.sync_all()?;
    }
    if image != destination {
        fs::rename(image, &destination).context("Failed to rename verified signed UKI")?;
        File::open(&directory)?.sync_all()?;
    }
    Ok(expected.uki_name.clone())
}

fn verify_raw_readback(path: &Path, size: u64, sha384: &str) -> Result<(), Error> {
    let mut reader = HashingReader384::new(File::open(path)?.take(size));
    let bytes = io::copy(&mut reader, &mut io::sink())?;
    ensure!(
        bytes == size && reader.hash() == sha384,
        "Staged signed /usr tuple readback failed: {}",
        path.display()
    );
    Ok(())
}

fn verify_persisted_tuple(ctx: &EngineContext, expected: &StagedSignedUsr) -> Result<(), Error> {
    ensure!(
        ctx.get_ab_update_volume() == Some(expected.target_volume),
        "Signed /usr destination slot changed after staging"
    );
    let usr_id = ctx
        .get_usr_block_device_id()
        .context("Missing /usr device")?;
    let device = ctx
        .spec
        .storage
        .verity_device(&usr_id)
        .context("Missing /usr verity device")?;
    let ids = [
        device.data_device_id.clone(),
        device.hash_device_id.clone(),
        signature_destination(ctx, Slot::from_volume(expected.target_volume))?,
    ];
    let mut paths = Vec::new();
    for (id, partition) in ids.iter().zip(&expected.partitions) {
        ensure!(
            id == &partition.id,
            "Signed /usr target device association changed"
        );
        let path = ctx
            .get_block_device_path(id)
            .context("Missing signed /usr target partition")?;
        let block = lsblk::get(&path)?;
        ensure!(
            block
                .part_uuid
                .is_some_and(|id| id.match_uuid(&partition.part_uuid))
                && block.size >= partition.size
                && (id != &ids[2] || block.size == partition.size),
            "Signed /usr target partition identity/capacity changed"
        );
        verify_raw_readback(&path, partition.size, &partition.sha384)?;
        paths.push(path);
    }
    let signature = verity_signature::read_signature(File::open(&paths[2])?, &expected.root_hash)?;
    verify_temporary_mapping(&paths[0], &paths[1], &expected.root_hash, &signature)
}

/// Old unsigned staged records have no signed state. A surviving marker without
/// a durable tuple is not enough to authorize a pre-feature signed update.
fn validate_legacy_staged_assets(ctx: &EngineContext, esp: &Path) -> Result<(), Error> {
    let directory = esp.join(UKI_DIRECTORY);
    let Some(target) = ctx.get_ab_update_volume() else {
        return Ok(());
    };
    if !directory.try_exists()? {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if !path.is_dir() {
            continue;
        }
        let addon = path.join(Slot::from_volume(target).addon());
        if addon.try_exists()? {
            ensure!(
                !uki::read_cmdline(addon)?.contains(SIGNATURE_MARKER),
                "Signed staged assets have no durable signed state; restage this update"
            );
        }
    }
    Ok(())
}

pub(crate) fn verify_staged_before_switch(
    ctx: &EngineContext,
    esp: &Path,
    expected: Option<&StagedSignedUsr>,
) -> Result<Option<String>, Error> {
    match expected {
        Some(expected) => {
            finish_signed_boot_assets(esp, expected, || verify_persisted_tuple(ctx, expected))
                .map(Some)
        }
        None => {
            validate_legacy_staged_assets(ctx, esp)?;
            Ok(None)
        }
    }
}

fn read_verified_device(device: &VerityDevice) -> Result<(), Error> {
    // Activation checks the signature; reading the complete mapping additionally
    // verifies the data/tree pair, before executing anything from target /usr.
    io::copy(&mut File::open(device.device_path())?, &mut io::sink())
        .context("Signed /usr data/tree verification failed")?;
    Ok(())
}

impl SignedUsrUpdate {
    pub(crate) fn staged_state(
        &self,
        ctx: &EngineContext,
        esp: &Path,
    ) -> Result<StagedSignedUsr, Error> {
        ensure!(self.images.len() == 3, "Invalid signed /usr tuple");
        let image = esp.join(UKI_DIRECTORY).join(TMP_UKI_NAME);
        let state = StagedSignedUsr {
            target_volume: self.target_volume,
            root_hash: self.root_hash.clone(),
            partitions: array::from_fn(|i| StagedSignedUsrPartition {
                id: self.images[i].id.clone(),
                part_uuid: self.part_uuids[i],
                size: self.images[i].image.uncompressed_size,
                sha384: self.images[i].raw_sha384.clone(),
            }),
            uki_name: boot_uki::planned_uki_name(ctx, esp)?,
            uki_sha384: asset_hash(&image)?,
            addons: addon_hashes(&uki::uki_addon_dir(&image))?,
        };
        validate_boot_assets(esp, &state)?;
        Ok(state)
    }

    pub(super) fn open_staged(&self, ctx: &EngineContext) -> Result<(), Error> {
        for cache in &self.images {
            let path = ctx
                .get_block_device_path(&cache.id)
                .context("Missing staged device")?;
            verify_raw_readback(&path, cache.image.uncompressed_size, &cache.raw_sha384)?;
        }
        let path = ctx
            .get_block_device_path(&self.images[2].id)
            .context("Missing signature device")?;
        let signature = verity_signature::read_signature(File::open(path)?, &self.root_hash)?;
        ensure!(
            signature == self.signature,
            "Staged signature changed after preflight"
        );
        let usr_id = ctx
            .get_usr_block_device_id()
            .context("Missing /usr device")?;
        let device = ctx
            .spec
            .storage
            .verity_device(&usr_id)
            .context("Missing /usr verity device")?;
        let (data, hash) = verity::get_verity_device_paths(ctx, device)?;
        let staged = VerityDevice::new(
            verity::get_updated_device_name(&device.name),
            data,
            hash,
            &self.root_hash,
        );
        staged.open_with_signature(signature_file(&signature)?.path())?;
        if let Err(e) = read_verified_device(&staged) {
            if let Err(close_error) = staged.close() {
                warn!("Failed to close rejected signed /usr mapping: {close_error:#}");
            }
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod resume_tests {
    use super::*;

    use trident_api::{
        constants::VAR_TMP_PATH,
        primitives::hash::Sha384Hash,
        status::{decode_host_status, HostStatus, ServicingState},
    };

    use crate::datastore::DataStore;

    fn pe(cmdline: &str) -> Vec<u8> {
        let mut bytes = vec![0; 128];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        bytes[64..68].copy_from_slice(b"PE\0\0");
        bytes[70..72].copy_from_slice(&1u16.to_le_bytes());
        bytes[88..96].copy_from_slice(b".cmdline");
        bytes[96..100].copy_from_slice(&(cmdline.len() as u32).to_le_bytes());
        bytes[104..108].copy_from_slice(&(cmdline.len() as u32).to_le_bytes());
        bytes[108..112].copy_from_slice(&128u32.to_le_bytes());
        bytes.extend_from_slice(cmdline.as_bytes());
        bytes
    }

    fn addon_cmdline(root: &str, signed: bool) -> String {
        let marker = if signed {
            format!(" {SIGNATURE_MARKER}=PARTUUID={}", Slot::B.signature_uuid())
        } else {
            String::new()
        };
        format!("usrhash={root} systemd.verity_usr_data=PARTUUID={} systemd.verity_usr_hash=PARTUUID={}{marker}",
            Uuid::from_u128(1), Uuid::from_u128(2))
    }

    fn fixture(esp: &Path) -> StagedSignedUsr {
        let ctx = EngineContext {
            ab_active_volume: Some(AbVolumeSelection::VolumeA),
            ..Default::default()
        };
        let image = esp.join(UKI_DIRECTORY).join(TMP_UKI_NAME);
        let addons = uki::uki_addon_dir(&image);
        fs::create_dir_all(&addons).unwrap();
        fs::write(&image, pe("console=ttyS0")).unwrap();
        let root = "a".repeat(64);
        fs::write(
            addons.join(Slot::B.addon()),
            pe(&addon_cmdline(&root, true)),
        )
        .unwrap();
        StagedSignedUsr {
            target_volume: AbVolumeSelection::VolumeB,
            root_hash: root,
            partitions: array::from_fn(|i| StagedSignedUsrPartition {
                id: format!("part-{i}"),
                part_uuid: if i == 2 {
                    Slot::B.signature_uuid()
                } else {
                    Uuid::from_u128(i as u128 + 1)
                },
                size: 16,
                sha384: "0".repeat(96),
            }),
            uki_name: boot_uki::planned_uki_name(&ctx, esp).unwrap(),
            uki_sha384: asset_hash(&image).unwrap(),
            addons: addon_hashes(&addons).unwrap(),
        }
    }

    fn interrupted_assets(esp: &Path, state: &StagedSignedUsr, renames: usize) {
        let directory = esp.join(UKI_DIRECTORY);
        let staged = directory.join(TMP_UKI_NAME);
        let renamed = directory.join(&state.uki_name);
        if renames >= 1 {
            fs::rename(uki::uki_addon_dir(&staged), uki::uki_addon_dir(&renamed)).unwrap();
        }
        if renames >= 2 {
            fs::rename(staged, renamed).unwrap();
        }
    }

    fn reload_staged_state(directory: &Path, expected: &StagedSignedUsr) -> StagedSignedUsr {
        let database = directory.join("state.db");
        let mut store = DataStore::open_or_create(&database).unwrap();
        store
            .with_host_status(|status| {
                status.servicing_state = ServicingState::AbUpdateStaged;
                status.staged_signed_usr = Some(expected.clone());
            })
            .unwrap();
        drop(store);
        let persisted = read_staged_state(directory);
        assert_eq!(&persisted, expected);
        persisted
    }

    fn read_staged_state(directory: &Path) -> StagedSignedUsr {
        let reopened = DataStore::open(&directory.join("state.db")).unwrap();
        assert_eq!(
            reopened.host_status().servicing_state,
            ServicingState::AbUpdateStaged
        );
        reopened.host_status().staged_signed_usr.clone().unwrap()
    }

    #[test]
    fn signed_finalize_revalidates_before_and_after_each_asset_rename() {
        // 0: before addon rename; 1: after addon/before UKI; 2: after UKI.
        for renames in 0..=2 {
            let directory = tempfile::tempdir().unwrap();
            let expected = fixture(directory.path());
            let expected = reload_staged_state(directory.path(), &expected);
            interrupted_assets(directory.path(), &expected, renames);
            let mut verifications = 0;
            for _ in 0..2 {
                let expected = read_staged_state(directory.path());
                let entry = finish_signed_boot_assets(directory.path(), &expected, || {
                    verifications += 1;
                    Ok(())
                })
                .unwrap();
                assert_eq!(entry, expected.uki_name);
                assert_eq!(
                    validate_boot_assets(directory.path(), &expected).unwrap().0,
                    directory
                        .path()
                        .join(UKI_DIRECTORY)
                        .join(&expected.uki_name)
                );
            }
            assert_eq!(
                verifications, 2,
                "A retry must not reuse a previous kernel verification"
            );
        }
    }

    #[test]
    fn signed_finalize_rejects_kernel_failure_at_every_resume_point() {
        for renames in 0..=2 {
            let directory = tempfile::tempdir().unwrap();
            let expected = fixture(directory.path());
            interrupted_assets(directory.path(), &expected, renames);
            let before = validate_boot_assets(directory.path(), &expected).unwrap();
            let error = finish_signed_boot_assets(directory.path(), &expected, || {
                bail!("kernel rejected signing key")
            })
            .unwrap_err();
            assert!(error.to_string().contains("kernel rejected"));
            assert_eq!(
                validate_boot_assets(directory.path(), &expected).unwrap(),
                before
            );
        }
    }

    #[test]
    fn signed_finalize_never_downgrades_missing_or_changed_assets() {
        for renames in 0..=2 {
            for mutation in 0..7 {
                let directory = tempfile::tempdir().unwrap();
                let expected = fixture(directory.path());
                interrupted_assets(directory.path(), &expected, renames);
                let (image, addons) = validate_boot_assets(directory.path(), &expected).unwrap();
                let addon = addons.join(Slot::B.addon());
                match mutation {
                    0 => fs::remove_file(&addon).unwrap(),
                    1 => fs::write(&addon, pe(&addon_cmdline(&expected.root_hash, false))).unwrap(),
                    2 => fs::write(&addon, pe(&addon_cmdline(&"b".repeat(64), true))).unwrap(),
                    3 => fs::write(&image, pe("changed kernel")).unwrap(),
                    4 => fs::remove_file(&image).unwrap(),
                    5 => fs::write(addons.join("unexpected.addon.efi"), pe("extra")).unwrap(),
                    6 => fs::remove_dir_all(&addons).unwrap(),
                    _ => unreachable!(),
                }
                finish_signed_boot_assets(directory.path(), &expected, || {
                    panic!("Changed assets must be rejected before kernel activation")
                })
                .unwrap_err();
                verify_staged_before_switch(
                    &EngineContext::default(),
                    directory.path(),
                    Some(&expected),
                )
                .unwrap_err();
            }
        }
    }

    #[test]
    fn signed_finalize_rejects_duplicate_and_out_of_order_assets() {
        let directory = tempfile::tempdir().unwrap();
        let expected = fixture(directory.path());
        let staged = directory.path().join(UKI_DIRECTORY).join(TMP_UKI_NAME);
        let renamed = staged.parent().unwrap().join(&expected.uki_name);
        fs::copy(&staged, &renamed).unwrap();
        validate_boot_assets(directory.path(), &expected).unwrap_err();
        fs::remove_file(staged).unwrap();
        validate_boot_assets(directory.path(), &expected).unwrap_err();
    }

    #[test]
    fn persisted_capability_cannot_be_removed_even_if_asset_hash_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let mut expected = fixture(directory.path());
        let addons = uki::uki_addon_dir(&directory.path().join(UKI_DIRECTORY).join(TMP_UKI_NAME));
        fs::write(
            addons.join(Slot::B.addon()),
            pe(&addon_cmdline(&expected.root_hash, false)),
        )
        .unwrap();
        expected.addons = addon_hashes(&addons).unwrap();
        validate_boot_assets(directory.path(), &expected).unwrap_err();
    }

    #[test]
    fn signed_finalize_checks_tuple_again_after_interruption() {
        for renames in 0..=2 {
            for changed in 0..3 {
                let directory = tempfile::tempdir().unwrap();
                let mut expected = fixture(directory.path());
                let paths: [PathBuf; 3] =
                    array::from_fn(|i| directory.path().join(format!("tuple-{i}")));
                for (path, partition) in paths.iter().zip(&mut expected.partitions) {
                    fs::write(path, [1; 16]).unwrap();
                    partition.sha384 = asset_hash(path).unwrap();
                }
                let expected = reload_staged_state(directory.path(), &expected);
                for (path, partition) in paths.iter().zip(&expected.partitions) {
                    verify_raw_readback(path, partition.size, &partition.sha384).unwrap();
                }
                interrupted_assets(directory.path(), &expected, renames);
                let before = validate_boot_assets(directory.path(), &expected).unwrap();
                for bytes in [&[2; 16][..], &[1; 8][..]] {
                    fs::write(&paths[changed], bytes).unwrap();
                    let expected = read_staged_state(directory.path());
                    finish_signed_boot_assets(directory.path(), &expected, || {
                        for (path, partition) in paths.iter().zip(&expected.partitions) {
                            verify_raw_readback(path, partition.size, &partition.sha384)?;
                        }
                        Ok(())
                    })
                    .unwrap_err();
                    assert_eq!(
                        validate_boot_assets(directory.path(), &expected).unwrap(),
                        before
                    );
                }
            }
        }
    }

    #[test]
    fn legacy_staged_state_is_compatible_but_incomplete_signed_state_is_not() {
        let legacy = HostStatus {
            servicing_state: ServicingState::AbUpdateStaged,
            ..Default::default()
        };
        let mut yaml = serde_yaml::to_value(legacy).unwrap();
        assert!(decode_host_status(yaml.clone())
            .unwrap()
            .staged_signed_usr
            .is_none());
        let directory = tempfile::tempdir().unwrap();
        let ctx = EngineContext {
            ab_active_volume: Some(AbVolumeSelection::VolumeA),
            ..Default::default()
        };
        assert!(verify_staged_before_switch(&ctx, directory.path(), None)
            .unwrap()
            .is_none());
        for renames in 0..=2 {
            let legacy_esp = tempfile::tempdir().unwrap();
            let legacy_assets = fixture(legacy_esp.path());
            let staged_addons =
                uki::uki_addon_dir(&legacy_esp.path().join(UKI_DIRECTORY).join(TMP_UKI_NAME));
            fs::write(
                staged_addons.join(Slot::B.addon()),
                pe(&addon_cmdline(&legacy_assets.root_hash, false)),
            )
            .unwrap();
            interrupted_assets(legacy_esp.path(), &legacy_assets, renames);
            assert!(verify_staged_before_switch(&ctx, legacy_esp.path(), None)
                .unwrap()
                .is_none());
        }
        let expected = fixture(directory.path());
        for renames in 0..=2 {
            if renames == 1 {
                interrupted_assets(directory.path(), &expected, 1);
            } else if renames == 2 {
                fs::rename(
                    directory.path().join(UKI_DIRECTORY).join(TMP_UKI_NAME),
                    directory
                        .path()
                        .join(UKI_DIRECTORY)
                        .join(&expected.uki_name),
                )
                .unwrap();
            }
            verify_staged_before_switch(&ctx, directory.path(), None).unwrap_err();
        }
        let mut incomplete = serde_yaml::to_value(expected).unwrap();
        incomplete.as_mapping_mut().unwrap().remove("partitions");
        yaml.as_mapping_mut()
            .unwrap()
            .insert("stagedSignedUsr".into(), incomplete);
        decode_host_status(yaml).unwrap_err();
    }

    #[test]
    fn legacy_esp_larger_than_tmp_budget_uses_host_disk_cache() {
        let host = tempfile::tempdir_in(VAR_TMP_PATH).unwrap();
        let cache = preflight_cache_dir(host.path()).unwrap();
        assert_eq!(cache.path().parent().unwrap(), host.path().join("var/tmp"));
        let raw_size = 128 * 1024 * 1024;
        let compressed = zstd::stream::encode_all(io::repeat(0).take(raw_size), 1).unwrap();
        let source = cache.path().join("source.zstd");
        fs::write(&source, &compressed).unwrap();
        let image = OsImageFile {
            path: "esp.raw.zstd".into(),
            compressed_size: compressed.len() as u64,
            uncompressed_size: raw_size,
            sha384: Sha384Hash::from(asset_hash(&source).unwrap()),
        };
        let (compressed_file, raw) = extract_image(
            &EngineContext::default(),
            &image,
            &compressed[..],
            cache.path(),
        )
        .unwrap();
        assert_eq!(raw.as_file().metadata().unwrap().len(), raw_size);
        assert_eq!(raw.path().parent().unwrap(), cache.path());
        assert_eq!(compressed_file.path().parent().unwrap(), cache.path());
        assert!(!host.path().join("mnt/newroot").exists());
    }

    #[test]
    fn disk_backed_extraction_still_rejects_bad_bounds_and_checksums() {
        let host = tempfile::tempdir().unwrap();
        let cache = preflight_cache_dir(host.path()).unwrap();
        let compressed = zstd::stream::encode_all(&b"ESP bytes"[..], 1).unwrap();
        let source = cache.path().join("source.zstd");
        fs::write(&source, &compressed).unwrap();
        let image = OsImageFile {
            path: "esp.raw.zstd".into(),
            compressed_size: compressed.len() as u64,
            uncompressed_size: 9,
            sha384: Sha384Hash::from(asset_hash(&source).unwrap()),
        };
        for mutation in 0..5 {
            let mut invalid = image.clone();
            match mutation {
                0 => invalid.compressed_size -= 1,
                1 => invalid.compressed_size += 1,
                2 => invalid.uncompressed_size -= 1,
                3 => invalid.uncompressed_size += 1,
                4 => invalid.sha384 = Sha384Hash::from("0".repeat(96)),
                _ => unreachable!(),
            }
            extract_image(
                &EngineContext::default(),
                &invalid,
                &compressed[..],
                cache.path(),
            )
            .unwrap_err();
        }
    }
}
