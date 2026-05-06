use crate::error::Error;

pub struct PayloadData {
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: Vec<u8>,
    pub deps: Vec<(u64, u8)>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + (data.deps.len() * 3));

    buf.push(0x02);
    buf.extend(crate::varint::encode_varint(data.source_idx as u64));
    buf.extend(crate::varint::encode_varint(data.major));
    buf.extend(crate::varint::encode_varint(data.minor));
    buf.extend(crate::varint::encode_varint(data.patch));

    buf.push(data.hash.len() as u8);
    buf.extend_from_slice(&data.hash);

    buf.extend(crate::varint::encode_varint(data.deps.len() as u64));
    for (line_idx, dep_type) in &data.deps {
        buf.extend(crate::varint::encode_varint(*line_idx));
        buf.push(*dep_type);
    }

    let crc = crate::crc32::calculate(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    buf
}

pub fn unpack_payload(bytes: &[u8], line_number: usize) -> Result<PayloadData, Error> {
    if bytes.len() < 5 {
        return Err(Error::InvalidBase64 { line_number });
    }

    let mut cursor = 0;

    let version = bytes[cursor];
    cursor += 1;
    if version != 0x02 {
        return Err(Error::UnknownPayloadVersion { line_number, version });
    }

    let source_idx = crate::varint::decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })? as usize;

    let major = crate::varint::decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;
    let minor = crate::varint::decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;
    let patch = crate::varint::decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;

    if cursor >= bytes.len() {
        return Err(Error::InvalidBase64 { line_number });
    }
    let hash_len = bytes[cursor] as usize;
    cursor += 1;

    if cursor + hash_len + 4 > bytes.len() {
        return Err(Error::InvalidBase64 { line_number });
    }
    let hash = bytes[cursor..cursor + hash_len].to_vec();
    cursor += hash_len;

    let dep_count = crate::varint::decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut deps = Vec::with_capacity(dep_count);
    for _ in 0..dep_count {
        let line_idx = crate::varint::decode_varint(bytes, &mut cursor)
            .map_err(|_| Error::InvalidBase64 { line_number })?;

        if cursor >= bytes.len() {
            return Err(Error::InvalidBase64 { line_number });
        }
        let dep_type = bytes[cursor];
        cursor += 1;

        if dep_type > 0x03 {
            return Err(Error::UnknownDepType { line_number, type_id: dep_type });
        }

        deps.push((line_idx, dep_type));
    }

    if cursor + 4 != bytes.len() {
        return Err(Error::InvalidBase64 { line_number });
    }

    let payload_data = &bytes[..cursor];
    let expected_crc = u32::from_le_bytes(bytes[cursor..cursor+4].try_into().unwrap());
    let actual_crc = crate::crc32::calculate(payload_data);

    if expected_crc != actual_crc {
        return Err(Error::IntegrityCheckFailed { line_number });
    }

    Ok(PayloadData { source_idx, major, minor, patch, hash, deps })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_v3_structure() {
        let data = PayloadData {
            source_idx: 1,
            major: 1,
            minor: 0,
            patch: 0,
            hash: vec![0xAA, 0xBB],
            deps: vec![(0, 0x00), (5, 0x01)],
        };
        let packed = pack_payload(&data);

        assert_eq!(packed[0], 0x02);
        assert_eq!(packed[1], 0x01);
        assert_eq!(packed[2], 0x01);
        assert_eq!(packed[3], 0x00);
        assert_eq!(packed[4], 0x00);
        assert_eq!(packed[5], 0x02);
        assert_eq!(packed[6..8], [0xAA, 0xBB]);
        assert_eq!(packed[8], 0x02);
        assert_eq!(packed[9], 0x00);
        assert_eq!(packed[10], 0x00);
        assert_eq!(packed[11], 0x05);
        assert_eq!(packed[12], 0x01);
        assert_eq!(packed.len(), 17);
    }

    #[test]
    fn test_unpack_roundtrip_v3() {
        let data = PayloadData {
            source_idx: 2,
            major: 18,
            minor: 2,
            patch: 0,
            hash: vec![0x01, 0x02, 0x03, 0x04],
            deps: vec![(10, 0x02), (20, 0x03)],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();

        assert_eq!(unpacked.source_idx, 2);
        assert_eq!(unpacked.major, 18);
        assert_eq!(unpacked.hash, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(unpacked.deps, vec![(10, 0x02), (20, 0x03)]);
    }

    #[test]
    fn test_unpack_invalid_version_v3() {
        let mut bad_payload = pack_payload(&PayloadData {
            source_idx: 0, major: 0, minor: 0, patch: 0, hash: vec![], deps: vec![]
        });
        bad_payload[0] = 0x01;
        assert!(matches!(unpack_payload(&bad_payload, 1), Err(Error::UnknownPayloadVersion { .. })));
    }

    #[test]
    fn test_unpack_invalid_dep_type() {
        let mut payload = pack_payload(&PayloadData {
            source_idx: 0, major: 0, minor: 0, patch: 0, hash: vec![], deps: vec![(0, 0x00)]
        });
        payload[8] = 0xFF;
        let crc = crate::crc32::calculate(&payload[..payload.len()-4]);
        let len = payload.len();
        payload[len-4..].copy_from_slice(&crc.to_le_bytes());

        assert!(matches!(unpack_payload(&payload, 1), Err(Error::UnknownDepType { .. })));
    }
}
