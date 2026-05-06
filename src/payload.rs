use crate::error::Error;
use crate::lockfile::{Attestation, SlsaPredicate, PeerResolution};

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
    pub logical_name: Option<String>,
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<HashPayload>,
    pub features: Vec<String>,
    pub resolved_peers: Vec<PeerResolution>,
    pub deps: Vec<DepPayload>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);

    buf.push(0x06);

    match &data.logical_name {
        Some(name) => {
            let bytes = name.as_bytes();
            buf.extend(crate::varint::encode_varint(bytes.len() as u64));
            buf.extend_from_slice(bytes);
        }
        None => buf.push(0x00),
    }

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

    buf.extend(crate::varint::encode_varint(data.resolved_peers.len() as u64));
    for peer in &data.resolved_peers {
        let name_bytes = peer.peer_name.as_bytes();
        buf.extend(crate::varint::encode_varint(name_bytes.len() as u64));
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&peer.satisfied_by_content_id.to_le_bytes());
        buf.push(if peer.is_hoisted_to_root { 0x01 } else { 0x00 });
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
    if version != 0x06 { return Err(Error::UnknownPayloadVersion { line_number, version }); }

    let logical_name_len = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let logical_name = if logical_name_len > 0 {
        if cursor + logical_name_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        Some(String::from_utf8(bytes[cursor..cursor + logical_name_len].to_vec()).unwrap_or_default())
    } else {
        None
    };
    cursor += logical_name_len;

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

        if cursor + 1 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let attest_type = bytes[cursor]; cursor += 1;
        let attestation = match attest_type {
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

    let peer_count = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut resolved_peers = Vec::new();
    for _ in 0..peer_count {
        let p_name_len = crate::varint::decode_varint(bytes, &mut cursor).map_err(|_| Error::InvalidBase64 { line_number })? as usize;
        if cursor + p_name_len > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let p_name = String::from_utf8(bytes[cursor..cursor + p_name_len].to_vec()).unwrap_or_default();
        cursor += p_name_len;

        if cursor + 9 > bytes.len() { return Err(Error::InvalidBase64 { line_number }); }
        let sat_cid = u64::from_le_bytes(bytes[cursor..cursor+8].try_into().unwrap());
        cursor += 8;
        let is_hoisted = bytes[cursor] == 0x01;
        cursor += 1;

        resolved_peers.push(PeerResolution { peer_name: p_name, satisfied_by_content_id: sat_cid, is_hoisted_to_root: is_hoisted });
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

    Ok(PayloadData { logical_name, source_idx, major, minor, patch, hashes, features, resolved_peers, deps })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_v8_logical_name_and_peers() {
        let data = PayloadData {
            logical_name: Some("react-v18".to_string()),
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![PeerResolution {
                peer_name: "react-dom".to_string(),
                satisfied_by_content_id: 12345,
                is_hoisted_to_root: true,
            }],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x06);
        assert_eq!(packed[1], 0x09);
        assert_eq!(&packed[2..11], "react-v18".as_bytes());
    }

    #[test]
    fn test_unpack_v8_roundtrip_alias_peers() {
        let data = PayloadData {
            logical_name: Some("alias".to_string()),
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![PeerResolution {
                peer_name: "peer".to_string(),
                satisfied_by_content_id: 99,
                is_hoisted_to_root: false,
            }],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();

        assert_eq!(unpacked.logical_name, Some("alias".to_string()));
        assert_eq!(unpacked.resolved_peers.len(), 1);
        assert_eq!(unpacked.resolved_peers[0].satisfied_by_content_id, 99);
        assert!(!unpacked.resolved_peers[0].is_hoisted_to_root);
    }

    #[test]
    fn test_pack_v5_base_structure() {
        let data = PayloadData {
            logical_name: None, source_idx: 1, major: 1, minor: 0, patch: 0,
            hashes: vec![HashPayload { algo_id: 0x01, digest: vec![0xAA; 32], attestation: Attestation::None }],
            features: vec![], resolved_peers: vec![], deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x06);
        assert_eq!(packed[1], 0x00);
        assert_eq!(packed[2], 0x01);
    }

    #[test]
    fn test_pack_v5_dep_content_id() {
        let data = PayloadData {
            logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], features: vec![], resolved_peers: vec![],
            deps: vec![DepPayload { content_id: 12345678, dep_type: 0x00, target_os: None, target_arch: None, req_feat_indices: vec![] }],
        };
        let packed = pack_payload(&data);

        // Header: 06 00 00 01 00 00 00 00 = 7 bytes
        // DepCount is at index 7
        assert_eq!(packed[7], 0x01);
        assert_eq!(&packed[8..16], &12345678u64.to_le_bytes());
        assert_eq!(packed[16], 0x00);
    }

    #[test]
    fn test_unpack_roundtrip_v5() {
        let data = PayloadData {
            logical_name: None, source_idx: 0, major: 2, minor: 0, patch: 0,
            hashes: vec![HashPayload { algo_id: 0x01, digest: vec![0; 32], attestation: Attestation::None }],
            features: vec!["sync".to_string()],
            resolved_peers: vec![],
            deps: vec![DepPayload { content_id: 99, dep_type: 0x01, target_os: None, target_arch: None, req_feat_indices: vec![0] }],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();
        assert_eq!(unpacked.features[0], "sync");
        assert_eq!(unpacked.deps[0].content_id, 99);
        assert!(matches!(unpacked.hashes[0].attestation, Attestation::None));
    }

    #[test]
    fn test_pack_v7_hash_with_inline_slsa() {
        let data = PayloadData {
            logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![HashPayload {
                algo_id: 0x01, digest: vec![0xAA; 32],
                attestation: Attestation::InlineSlsa(SlsaPredicate { builder: "github.com/actions".to_string(), source: "git+https://github.com/pkg".to_string() }),
            }],
            features: vec![], resolved_peers: vec![], deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x06);
        let hash_start = 7;
        let hash_len = packed[hash_start + 1] as usize;
        let attest_type_pos = hash_start + 2 + hash_len;
        assert_eq!(packed[attest_type_pos], 0x02);
    }

    #[test]
    fn test_unpack_invalid_version_v5() {
        let mut bad_payload = pack_payload(&PayloadData {
            logical_name: None, source_idx: 0, major: 0, minor: 0, patch: 0,
            hashes: vec![HashPayload { algo_id: 0x01, digest: vec![], attestation: Attestation::None }],
            features: vec![], resolved_peers: vec![], deps: vec![]
        });
        bad_payload[0] = 0x05;
        assert!(matches!(unpack_payload(&bad_payload, 1), Err(Error::UnknownPayloadVersion { .. })));
    }
}
