use crate::error::Error;

pub struct PayloadData {
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<(u8, Vec<u8>)>,
    pub deps: Vec<(u64, u8)>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + (data.hashes.len() * 35) + (data.deps.len() * 3));

    buf.push(0x03);
    buf.extend(crate::varint::encode_varint(data.source_idx as u64));
    buf.extend(crate::varint::encode_varint(data.major));
    buf.extend(crate::varint::encode_varint(data.minor));
    buf.extend(crate::varint::encode_varint(data.patch));

    buf.extend(crate::varint::encode_varint(data.hashes.len() as u64));
    for (algo_id, digest) in &data.hashes {
        buf.push(*algo_id);
        buf.push(digest.len() as u8);
        buf.extend_from_slice(digest);
    }

    buf.extend(crate::varint::encode_varint(data.deps.len() as u64));
    for (line_idx, dep_type) in &data.deps {
        buf.extend(crate::varint::encode_varint(*line_idx));
        buf.push(*dep_type);
    }

    let crc = crate::crc32::calculate(&buf);
    buf.extend_from_slice(&crc.to_le_bytes());

    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_v4_multi_hash() {
        let data = PayloadData {
            source_idx: 1,
            major: 1, minor: 0, patch: 0,
            hashes: vec![
                (0x01, vec![0xAA; 32]),
                (0x03, vec![0xBB; 32]),
            ],
            deps: vec![(0, 0x00)],
        };
        let packed = pack_payload(&data);

        assert_eq!(packed[0], 0x03);
        assert_eq!(packed[1], 0x01);
        assert_eq!(packed[5], 0x02);
        assert_eq!(packed[6], 0x01);
        assert_eq!(packed[7], 32);
        assert_eq!(packed[8..40], [0xAA; 32]);
        assert_eq!(packed[40], 0x03);
        assert_eq!(packed[41], 32);
        assert_eq!(packed[42..74], [0xBB; 32]);
        assert_eq!(packed[74], 0x01);
    }

    #[test]
    fn test_pack_v4_no_hash() {
        let data = PayloadData {
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            hashes: vec![],
            deps: vec![],
        };
        let packed = pack_payload(&data);
        assert_eq!(packed[0], 0x03);
        assert_eq!(packed[5], 0x00);
        assert_eq!(packed[6], 0x00);
    }
}
