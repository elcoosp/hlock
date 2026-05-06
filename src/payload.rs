use crate::varint::{encode_varint, decode_varint};

pub struct PayloadData {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: [u8; 16],
    pub dep_indices: Vec<u64>,
}

pub fn pack_payload(data: &PayloadData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + (data.dep_indices.len() * 2));

    buf.extend(encode_varint(data.major));
    buf.extend(encode_varint(data.minor));
    buf.extend(encode_varint(data.patch));
    buf.extend_from_slice(&data.hash);
    buf.extend(encode_varint(data.dep_indices.len() as u64));

    for dep in &data.dep_indices {
        buf.extend(encode_varint(*dep));
    }

    buf
}

pub fn unpack_payload(bytes: &[u8]) -> Result<PayloadData, &'static str> {
    let mut cursor = 0;

    let major = decode_varint(bytes, &mut cursor)?;
    let minor = decode_varint(bytes, &mut cursor)?;
    let patch = decode_varint(bytes, &mut cursor)?;

    if cursor + 16 > bytes.len() {
        return Err("Unexpected end of bytes reading hash");
    }
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&bytes[cursor..cursor + 16]);
    cursor += 16;

    let dep_count = decode_varint(bytes, &mut cursor)? as usize;
    let mut dep_indices = Vec::with_capacity(dep_count);
    for _ in 0..dep_count {
        dep_indices.push(decode_varint(bytes, &mut cursor)?);
    }

    Ok(PayloadData { major, minor, patch, hash, dep_indices })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_and_unpack() {
        let data = PayloadData {
            major: 18,
            minor: 2,
            patch: 0,
            hash: [0xAA, 0xBB, 0xCC, 0xDD, 0,0,0,0,0,0,0,0,0,0,0,0],
            dep_indices: vec![1, 5],
        };

        let packed = pack_payload(&data);
        let unpacked = unpack_payload(&packed).unwrap();

        assert_eq!(unpacked.major, 18);
        assert_eq!(unpacked.minor, 2);
        assert_eq!(unpacked.patch, 0);
        assert_eq!(unpacked.hash, data.hash);
        assert_eq!(unpacked.dep_indices, vec![1, 5]);
    }
}
