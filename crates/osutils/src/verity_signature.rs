//! Discoverable Partitions Specification root-hash signature payloads.

use std::io::Read;

use anyhow::{ensure, Context, Error};
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::cms::CmsContentInfo;
use serde::Deserialize;

pub const MAX_SIGNATURE_PARTITION_SIZE: u64 = 1024 * 1024;
pub const SIGNATURE_BLOCK_SIZE: u64 = 4096;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Payload {
    root_hash: String,
    signature: String,
}

/// Parsing is not a trust decision. The caller must activate dm-verity with
/// this DER signature and the independently selected root hash in the kernel.
pub fn read_signature(reader: impl Read, expected_root_hash: &str) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_SIGNATURE_PARTITION_SIZE + 1)
        .read_to_end(&mut bytes)
        .context("Failed to read verity signature partition")?;
    ensure!(
        !bytes.is_empty()
            && bytes.len() as u64 <= MAX_SIGNATURE_PARTITION_SIZE
            && bytes.len() as u64 % SIGNATURE_BLOCK_SIZE == 0,
        "Verity signature partition must be 4096-byte aligned and at most 1 MiB"
    );
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    ensure!(
        bytes[end..].iter().all(|b| *b == 0),
        "Nonzero bytes after verity signature JSON padding"
    );
    let payload: Payload =
        serde_json::from_slice(&bytes[..end]).context("Invalid verity signature JSON")?;
    ensure!(
        valid_root_hash(&payload.root_hash),
        "Invalid signature rootHash"
    );
    ensure!(
        payload.root_hash == expected_root_hash,
        "Signature rootHash does not match the selected /usr payload"
    );
    let signature = STANDARD
        .decode(&payload.signature)
        .context("Invalid signature Base64")?;
    ensure!(
        !signature.is_empty() && STANDARD.encode(&signature) == payload.signature,
        "Signature must be nonempty canonical Base64"
    );
    let cms = CmsContentInfo::from_der(&signature).context("Signature is not DER CMS")?;
    ensure!(
        cms.to_der()? == signature,
        "Signature must contain exactly one DER CMS object"
    );
    require_detached(&signature)?;
    Ok(signature)
}

// OpenSSL's safe CMS API does not expose its detached flag.
// Inspect only the DER envelope/encapContentInfo after OpenSSL parsed it.
fn der_value<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], Error> {
    ensure!(input.len() >= 2 && input[0] == tag, "Invalid CMS DER tag");
    let first = input[1];
    *input = &input[2..];
    let length = if first < 128 {
        usize::from(first)
    } else {
        let count = usize::from(first & 127);
        ensure!(
            count > 0 && count <= 4 && input.len() >= count,
            "Invalid CMS DER length"
        );
        let mut length = 0usize;
        for byte in &input[..count] {
            length = (length << 8) | usize::from(*byte);
        }
        *input = &input[count..];
        length
    };
    ensure!(input.len() >= length, "Truncated CMS DER");
    let value = &input[..length];
    *input = &input[length..];
    Ok(value)
}

fn require_detached(signature: &[u8]) -> Result<(), Error> {
    let mut outer = signature;
    let mut envelope = der_value(&mut outer, 0x30)?;
    const SIGNED_DATA_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02";
    ensure!(
        der_value(&mut envelope, 0x06)? == SIGNED_DATA_OID,
        "CMS must be SignedData"
    );
    let mut explicit = der_value(&mut envelope, 0xa0)?;
    let mut signed = der_value(&mut explicit, 0x30)?;
    der_value(&mut signed, 0x02)?;
    der_value(&mut signed, 0x31)?;
    let mut content = der_value(&mut signed, 0x30)?;
    const DATA_OID: &[u8] = b"\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
    ensure!(
        der_value(&mut content, 0x06)? == DATA_OID && content.is_empty(),
        "CMS must sign detached data, not contain an embedded payload"
    );
    Ok(())
}

pub fn valid_root_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::Write;

    use openssl::{
        asn1::Asn1Time,
        hash::MessageDigest,
        pkcs7::{Pkcs7, Pkcs7Flags},
        pkey::PKey,
        rsa::Rsa,
        stack::Stack,
        x509::{X509NameBuilder, X509},
    };
    use serde_json::json;
    use tempfile::NamedTempFile;
    use uuid::Uuid;

    use crate::{dependencies::Dependency, veritysetup::VerityDevice};

    fn padded(json: &str) -> Vec<u8> {
        let mut bytes = json.as_bytes().to_vec();
        bytes.resize(bytes.len().div_ceil(4096) * 4096, 0);
        bytes
    }

    fn payload(root: &str) -> Vec<u8> {
        payload_with_flags(root, Pkcs7Flags::BINARY | Pkcs7Flags::DETACHED)
    }

    fn payload_with_flags(root: &str, flags: Pkcs7Flags) -> Vec<u8> {
        let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "parser-test-untrusted")
            .unwrap();
        let name = name.build();
        let mut cert = X509::builder().unwrap();
        cert.set_version(2).unwrap();
        cert.set_subject_name(&name).unwrap();
        cert.set_issuer_name(&name).unwrap();
        cert.set_pubkey(&key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(&key, MessageDigest::sha256()).unwrap();
        let cms = Pkcs7::sign(
            &cert.build(),
            &key,
            &Stack::new().unwrap(),
            root.as_bytes(),
            flags,
        )
        .unwrap();
        padded(
            &json!({"rootHash": root, "signature": STANDARD.encode(cms.to_der().unwrap())})
                .to_string(),
        )
    }

    #[test]
    fn accepts_bounded_payload_but_does_not_establish_trust() {
        let root = "a".repeat(64);
        let mut bytes = payload(&root);
        let signature = read_signature(bytes.as_slice(), &root).unwrap();
        bytes.resize(MAX_SIGNATURE_PARTITION_SIZE as usize, 0);
        assert_eq!(read_signature(bytes.as_slice(), &root).unwrap(), signature);
    }

    #[test]
    fn rejects_wrong_hash_and_noncanonical_hashes() {
        let root = "a".repeat(64);
        read_signature(payload(&root).as_slice(), &"b".repeat(64)).unwrap_err();
        for hash in [
            "A".repeat(64),
            "a".repeat(63),
            format!("{root}\n"),
            "é".repeat(32),
        ] {
            assert!(!valid_root_hash(&hash));
        }
    }

    #[test]
    fn rejects_attached_cms_and_trailing_der() {
        let root = "a".repeat(64);
        read_signature(
            payload_with_flags(&root, Pkcs7Flags::BINARY).as_slice(),
            &root,
        )
        .unwrap_err();
        let original = payload(&root);
        let end = original.iter().position(|b| *b == 0).unwrap();
        let mut value: Payload = serde_json::from_slice(&original[..end]).unwrap();
        let mut signature = STANDARD.decode(&value.signature).unwrap();
        signature.push(0);
        value.signature = STANDARD.encode(signature);
        let bytes =
            padded(&json!({"rootHash": value.root_hash, "signature": value.signature}).to_string());
        read_signature(bytes.as_slice(), &root).unwrap_err();
    }

    #[test]
    fn rejects_missing_duplicate_unknown_and_malformed_fields() {
        let root = "a".repeat(64);
        for json in [
            "{}".to_owned(),
            format!(r#"{{"rootHash":"{root}","rootHash":"{root}","signature":"YQ=="}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"YQ==","signature":"YQ=="}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"YQ==","extra":1}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"YQ"}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"YR=="}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"Y Q=="}}"#),
            format!(r#"{{"rootHash":"{root}","signature":""}}"#),
            format!(r#"{{"rootHash":"{root}","signature":"YQ=="}}"#),
        ] {
            read_signature(padded(&json).as_slice(), &root).unwrap_err();
        }
    }

    #[test]
    fn rejects_truncated_oversized_and_embedded_junk() {
        let root = "a".repeat(64);
        let bytes = payload(&root);
        read_signature(&bytes[..bytes.len() - 1], &root).unwrap_err();
        read_signature(
            vec![0; MAX_SIGNATURE_PARTITION_SIZE as usize + 4096].as_slice(),
            &root,
        )
        .unwrap_err();
        read_signature(&[][..], &root).unwrap_err();
        let mut junk = bytes;
        let end = junk.iter().position(|b| *b == 0).unwrap();
        junk[end + 1] = b'x';
        read_signature(junk.as_slice(), &root).unwrap_err();
    }

    #[test]
    #[ignore = "requires Linux root, loop devices, dm-verity and kernel signature support"]
    fn kernel_rejects_untrusted_signature_without_unsigned_fallback() {
        let data = NamedTempFile::new().unwrap();
        let tree = NamedTempFile::new().unwrap();
        data.as_file().set_len(64 * 1024).unwrap();
        tree.as_file().set_len(64 * 1024).unwrap();
        let output = Dependency::Veritysetup
            .cmd()
            .arg("format")
            .arg(data.path())
            .arg(tree.path())
            .output_and_check()
            .unwrap();
        let root = output
            .lines()
            .find_map(|line| line.strip_prefix("Root hash:"))
            .unwrap()
            .trim();
        assert!(valid_root_hash(root));
        let device = VerityDevice::new(
            format!("trident-test-{}", Uuid::new_v4()),
            data.path(),
            tree.path(),
            root,
        );
        // Prove ordinary activation works before testing signature rejection.
        device.open().unwrap();
        device.close().unwrap();
        let signature = read_signature(payload(root).as_slice(), root).unwrap();
        let mut der = NamedTempFile::new().unwrap();
        der.write_all(&signature).unwrap();
        der.flush().unwrap();
        device.open_with_signature(der.path()).unwrap_err();
        assert!(!device.is_active().unwrap());
    }
}
