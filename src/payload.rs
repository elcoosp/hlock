use crate::error::Error;
use crate::lockfile::{Attestation, SlsaPredicate};

#[derive(Debug, Clone)]
pub struct HashPayload {
    pub algo_id: u8,
    pub digest: Vec<u8>,
    pub attestation: Attestation,
}

pub struct DepPayload {
    pub content_id: u64,
    pub dep_type: u8,
    pub target_os: Option<u8>,
    pub target_arch: Option<u8>,
    pub req_feat_indices: Vec<usize>,
}

pub struct PayloadData {
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<HashPayload>,
    pub features: Vec<String>,
    pub deps: Vec<DepPayload>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    buf.push(0x05);
    buf.extend(crate::varint::encode_varint(data.source_idx as u64));
    buf.extend(crate::varint::encode_varint(data.major));
    buf.extend(crate::varint::encode_varint(data.minor));
    buf.extend(crate::varint::encode_varint(data.patch));

    buf.extend(crate::varint::encode_varint(data.hashes.len() as u64));
    for hash in &data.hashes {
        buf.push(hash.algo_id);
        buf.push(hash.digest.len() as u8);
        buf.extend_from_slice(&hash.digest);

        match &hash.attestation {
            Attestation::None => buf.push(0x00),
            Attestation::ExternalBundleSha256(bundle_hash) => {
                buf.push(0x01);
                buf.extend_from_slice(bundle_hash);
            }
            Attestation::InlineSlsa(pred) => {
                buf.push(0x02);
                let builder_bytes = pred.builder.as_bytes();
                buf.extend(crate::varint::encode_varint(builder_bytes.len() as u64));
                buf.extend_from_slice(builder_bytes);
                let source_bytes = pred.source.as_bytes();
                buf.extend(crate::varint::encode_varint(source_bytes.len() as u64));
                buf.extend_from_slice(source_bytes);
            }
        }
    }

    buf.extend(crate::varint::encode_varint(data.features.len() as u64));
    for feat in &data.features {
        let bytes = feat.as_bytes();
        buf.extend(crate::varint::encode_varint(bytes.len() as u64));
        buf.extend_from_slice(bytes);
    }

    buf.extend(crate::varint::encode_varint(data.deps.len() as u64));
    for dep in &data.deps {
        buf.extend_from_slice(&dep.content_id.to_le_bytes());
        buf.push(dep.dep_type);
        if dep.dep_type == 0x04 {
            buf.push(dep.target_os.unwrap_or(0x00));
            buf.push(dep.target_arch.unwrap_or(0x00));
        }
        buf.extend(crate::varint::encode_varint(dep.req_feat_indices.len() as u64));
        for idx in &dep.req_feat_indices {
            buf.extend(crate::varint::encode_varint(*idx as u64));
        }
    }

    let crc = crate::crc32::calculate(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());
    buf
}

pub fn unpack_payload(bytes: &[u8], line_number: usize) -> Result<PayloadData, Error> {
    if bytes.len() < 8 { return Err(Error::InvalidBase64 { line_number }); }
    let mut cursor = 0;

    let version = bytes[cursor]; cursor += 1;
    if version != 0x04 && version != 0x05 { return Err(Error::UnknownPayloadVersion { line_number, version }); }
    let is_v5 = version == 0x05;

    let source_idx = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let major = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })?;
    let minor = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })?;
    let patch = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })?;

    let hash_count = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut hashes = Vec::new();
    for _ in 0..hash_count {
        if cursor + 2 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let algo_id = bytes[cursor]; cursor += 1;
        if algo_id > 0x03 { return Err(Error::UnknownHashAlgorithm { line_number, algo_id }); }
        let hash_len = bytes[cursor] as usize; cursor += 1;
        if cursor + hash_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let digest = bytes[cursor..cursor + hash_len].to_vec();
        cursor += hash_len;

        let attestation = if is_v5 {
            if cursor + 1 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
            let attest_type = bytes[cursor]; cursor += 1;
            match attest_type {
                0x00 => Attestation::None,
                0x01 => {
                    if cursor + 32 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
                    let mut bundle = [0u8; 32];
                    bundle.copy_from_slice(&bytes[cursor..cursor+32]);
                    cursor += 32;
                    Attestation::ExternalBundleSha256(bundle)
                }
                0x02 => {
                    let builder_len = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
                    if cursor + builder_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
                    let builder = String::from_utf8(bytes[cursor..cursor + builder_len].to_vec()).unwrap_or_default();
                    cursor += builder_len;

                    let source_len = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
                    if cursor + source_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
                    let source = String::from_utf8(bytes[cursor..cursor + source_len].to_vec()).unwrap_or_default();
                    cursor += source_len;

                    Attestation::InlineSlsa(SlsaPredicate { builder, source })
                }
                _ => return Err(Error::UnknownAttestationType { line_number, type_id: attest_type }),
            }
        } else {
            Attestation::None
        };

        hashes.push(HashPayload { algo_id, digest, attestation });
    }

    let feat_count = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut features = Vec::with_capacity(feat_count);
    for _ in 0..feat_count {
        let str_len = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
        if cursor + str_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        features.push(String::from_utf8(bytes[cursor..cursor + str_len].to_vec()).unwrap_or_default());
        cursor += str_len;
    }

    let dep_count = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut deps = Vec::new();
    for _ in 0..dep_count {
        if cursor + 9 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let content_id = u64::from_le_bytes(bytes[cursor..cursor+8].try_into().unwrap());
        cursor += 8;

        let dep_type = bytes[cursor]; cursor += 1;
        if dep_type > 0x04 { return Err(Error::UnknownDepType { line_number, type_id: dep_type }); }

        let mut target_os = None;
        let mut target_arch = None;
        if dep_type == 0x04 {
            if cursor + 2 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
            target_os = Some(bytes[cursor]); cursor += 1;
            target_arch = Some(bytes[cursor]); cursor += 1;
        }

        let req_count = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
        let mut req_indices = Vec::with_capacity(req_count);
        for _ in 0..req_count {
            req_indices.push(crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize);
        }
        deps.push(DepPayload { content_id, dep_type, target_os, target_arch, req_feat_indices: req_indices });
    }

    if cursor + 4 != bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
    let expected_crc = u32::from_le_bytes(bytes[cursor..cursor+4].try_into().unwrap());
    if expected_crc != crate::crc32::calculate(&bytes[..cursor]) { return Err(Error::IntegrityCheckFailed { line_number }); }

    Ok(PayloadData { source_idx, major, minor, patch, hashes, features, deps })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_v5_base_structure() {
        let data = PayloadData {
            source_idx: 1, major: 1, minor: 0, patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0xAA; 32],
                attestation: Attestation::None,
            }],
            features: vec![],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x05);
        assert_eq!(packed[5], 0x01); // HashCount
        assert_eq!(packed[6], 0x01); // AlgoId
        assert_eq!(packed[7], 32);   // HashLen
        assert_eq!(packed[40], 0x00); // AttestationType None
        assert_eq!(packed[41], 0x00); // FeatureCount
        assert_eq!(packed[42], 0x00); // DepCount
    }

    #[test]
    fn test_pack_v5_dep_content_id() {
        let data = PayloadData {
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], features: vec![],
            deps: vec![DepPayload {
                content_id: 12345678, dep_type: 0x00, target_os: None, target_arch: None, req_feat_indices: vec![],
            }],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[7], 0x01); // DepCount
        assert_eq!(&packed[8..16], &12345678u64.to_le_bytes()); // Content ID
        assert_eq!(packed[16], 0x00); // DepType
    }

    #[test]
    fn test_pack_v5_dep_target_and_feats() {
        let data = PayloadData {
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], features: vec!["derive".to_string()],
            deps: vec![DepPayload {
                content_id: 0, dep_type: 0x04,
                target_os: Some(0x01), target_arch: Some(0x02),
                req_feat_indices: vec![0],
            }],
        };
        let packed = pack_payload(&data);

        let mut cursor = 0;
        assert_eq!(packed[cursor], 0x05); cursor += 1; // Version
        assert_eq!(packed[cursor], 0x00); cursor += 1; // SourceIdx
        assert_eq!(packed[cursor], 0x01); cursor += 1; // Major
        assert_eq!(packed[cursor], 0x00); cursor += 1; // Minor
        assert_eq!(packed[cursor], 0x00); cursor += 1; // Patch
        assert_eq!(packed[cursor], 0x00); cursor += 1; // HashCount

        assert_eq!(packed[cursor], 0x01); cursor += 1; // FeatureCount
        assert_eq!(packed[cursor], 0x06); cursor += 1; // Feature String Len
        cursor += 6; // Skip "derive"

        assert_eq!(packed[cursor], 0x01); cursor += 1; // DepCount

        assert_eq!(&packed[cursor..cursor+8], &0u64.to_le_bytes()); cursor += 8; // Content ID
        assert_eq!(packed[cursor], 0x04); cursor += 1; // DepType OptionalTarget
        assert_eq!(packed[cursor], 0x01); cursor += 1; // Target OS
        assert_eq!(packed[cursor], 0x02); cursor += 1; // Target Arch
        assert_eq!(packed[cursor], 0x01); cursor += 1; // ReqFeatCount
        assert_eq!(packed[cursor], 0x00); // FeatIdx 0
    }

    #[test]
    fn test_pack_v7_hash_with_inline_slsa() {
        let data = PayloadData {
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0xAA; 32],
                attestation: Attestation::InlineSlsa(SlsaPredicate {
                    builder: "github.com/actions".to_string(),
                    source: "git+https://github.com/pkg".to_string(),
                }),
            }],
            features: vec![],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x05); // Version 0x05
        let hash_start = 6;
        let hash_len = packed[hash_start + 1] as usize;
        let attest_type_pos = hash_start + 2 + hash_len;
        assert_eq!(packed[attest_type_pos], 0x02); // Inline SLSA
    }

    #[test]
    fn test_unpack_roundtrip_v5() {
        let data = PayloadData {
            source_idx: 0, major: 2, minor: 0, patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01, digest: vec![0; 32], attestation: Attestation::None,
            }],
            features: vec!["sync".to_string()],
            deps: vec![DepPayload {
                content_id: 99, dep_type: 0x01, target_os: None, target_arch: None, req_feat_indices: vec![0],
            }],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();

        assert_eq!(unpacked.features[0], "sync");
        assert_eq!(unpacked.deps[0].content_id, 99);
        assert_eq!(unpacked.deps[0].req_feat_indices[0], 0);
        assert!(matches!(unpacked.hashes[0].attestation, Attestation::None));
    }

    #[test]
    fn test_unpack_v7_inline_slsa_roundtrip() {
        let data = PayloadData {
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01,
                digest: vec![0; 32],
                attestation: Attestation::InlineSlsa(SlsaPredicate {
                    builder: "builder".to_string(),
                    source: "source".to_string(),
                }),
            }],
            features: vec![],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();

        assert_eq!(unpacked.hashes.len(), 1);
        match &unpacked.hashes[0].attestation {
            Attestation::InlineSlsa(p) => {
                assert_eq!(p.builder, "builder");
                assert_eq!(p.source, "source");
            }
            _ => panic!("Expected InlineSlsa attestation"),
        }
    }

    #[test]
    fn test_unpack_v4_fallback_attestation_none() {
        let mut buf = Vec::new();
        buf.push(0x04); // v0.4
        buf.push(0x00); // src
        buf.push(0x01); // maj
        buf.push(0x00); // min
        buf.push(0x00); // pat
        buf.push(0x01); // hash count
        buf.push(0x01); // algo sha256
        buf.push(0x04); // hash len
        buf.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // digest
        buf.push(0x00); // feat count
        buf.push(0x00); // dep count
        let crc = crate::crc32::calculate(&buf);
        buf.extend_from_slice(&crc.to_le_bytes());

        let unpacked = unpack_payload(&buf, 0).unwrap();
        assert_eq!(unpacked.hashes[0].algo_id, 0x01);
        assert!(matches!(unpacked.hashes[0].attestation, Attestation::None));
    }

    #[test]
    fn test_unpack_invalid_version_v5() {
        let mut bad_payload = pack_payload(&PayloadData {
            source_idx: 0, major: 0, minor: 0, patch: 0, hashes: vec![HashPayload { algo_id: 0x01, digest: vec![], attestation: Attestation::None }], features: vec![], deps: vec![]
        });
        bad_payload[0] = 0x03;
        assert!(matches!(unpack_payload(&bad_payload, 1), Err(Error::UnknownPayloadVersion { .. })));
    }
}
