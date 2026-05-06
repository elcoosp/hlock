use crate::varint::{encode_varint, decode_varint};
use crate::error::Error;
use crate::crc32;

pub struct PayloadData {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: Vec<u8>,
    pub dep_indices: Vec<u64>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + (data.dep_indices.len() * 2));

    // 1. Version Header
    buf.push(0x01);

    // 2. Semver
    buf.extend(encode_varint(data.major));
    buf.extend(encode_varint(data.minor));
    buf.extend(encode_varint(data.patch));

    // 3. Dynamic Hash
    buf.push(data.hash.len() as u8);
    buf.extend_from_slice(&data.hash);

    // 4. Dependencies
    buf.extend(encode_varint(data.dep_indices.len() as u64));
    for dep in &data.dep_indices {
        buf.extend(encode_varint(*dep));
    }

    // 5. CRC32 Trailer
    let crc = crc32::calculate(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    buf
}

pub fn unpack_payload(bytes: &[u8], line_number: usize) -> Result<PayloadData, Error> {
    if bytes.len() < 5 {
        return Err(Error::InvalidBase64 { line_number });
    }

    let mut cursor = 0;

    // 1. Version
    let version = bytes[cursor];
    cursor += 1;
    if version != 0x01 {
        return Err(Error::UnknownPayloadVersion { line_number, version });
    }

    // 2. Semver
    let major = decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;
    let minor = decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;
    let patch = decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })?;

    // 3. Hash
    if cursor >= bytes.len() {
        return Err(Error::InvalidBase64 { line_number });
    }
    let hash_len = bytes[cursor] as usize;
    cursor += 1;

    if cursor + hash_len + 4 > bytes.len() { // +4 for CRC
        return Err(Error::InvalidBase64 { line_number });
    }
    let hash = bytes[cursor..cursor + hash_len].to_vec();
    cursor += hash_len;

    // 4. Dependencies
    let dep_count = decode_varint(bytes, &mut cursor)
        .map_err(|_| Error::InvalidBase64 { line_number })? as usize;
    let mut dep_indices = Vec::with_capacity(dep_count);
    for _ in 0..dep_count {
        dep_indices.push(decode_varint(bytes, &mut cursor)
            .map_err(|_| Error::InvalidBase64 { line_number })?);
    }

    // 5. CRC32 Validation
    if cursor + 4 != bytes.len() {
        return Err(Error::InvalidBase64 { line_number });
    }

    let payload_data = &bytes[..cursor];
    let expected_crc = u32::from_le_bytes(bytes[cursor..cursor+4].try_into().unwrap());
    let actual_crc = crc32::calculate(payload_data);

    if expected_crc != actual_crc {
        return Err(Error::IntegrityCheckFailed { line_number });
    }

    Ok(PayloadData { major, minor, patch, hash, dep_indices })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_v2_structure() {
        let data = PayloadData {
            major: 1,
            minor: 0,
            patch: 0,
            hash: vec![0xAA, 0xBB],
            dep_indices: vec![],
        };
        let packed = pack_payload(&data);

        // Byte 0: Version (0x01)
        assert_eq!(packed[0], 0x01);
        // Byte 1: Major varint (0x01)
        assert_eq!(packed[1], 0x01);
        // Byte 2: Minor varint (0x00)
        assert_eq!(packed[2], 0x00);
        // Byte 3: Patch varint (0x00)
        assert_eq!(packed[3], 0x00);
        // Byte 4: HashLen (0x02)
        assert_eq!(packed[4], 0x02);
        // Bytes 5-6: Hash
        assert_eq!(packed[5..7], [0xAA, 0xBB]);
        // Byte 7: DepCount varint (0x00)
        assert_eq!(packed[7], 0x00);
        // Bytes 8-11: CRC32
        assert_eq!(packed.len(), 12);
    }

    #[test]
    fn test_unpack_roundtrip() {
        let data = PayloadData {
            major: 18,
            minor: 2,
            patch: 0,
            hash: vec![0x01, 0x02, 0x03, 0x04],
            dep_indices: vec![5, 10],
        };
        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed, 0).unwrap();

        assert_eq!(unpacked.major, 18);
        assert_eq!(unpacked.hash, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(unpacked.dep_indices, vec![5, 10]);
    }

    #[test]
    fn test_unpack_invalid_version() {
        let mut bad_payload = pack_payload(&PayloadData {
            major: 0, minor: 0, patch: 0, hash: vec![], dep_indices: vec![]
        });
        bad_payload[0] = 0x99; // corrupt version
        assert!(matches!(unpack_payload(&bad_payload, 1), Err(Error::UnknownPayloadVersion { .. })));
    }

    #[test]
    fn test_unpack_crc_corruption() {
        let mut payload = pack_payload(&PayloadData {
            major: 0, minor: 0, patch: 0, hash: vec![], dep_indices: vec![]
        });
        payload[1] ^= 0x01; // flip bits in payload data
        assert!(matches!(unpack_payload(&payload, 1), Err(Error::IntegrityCheckFailed { .. })));
    }
}
