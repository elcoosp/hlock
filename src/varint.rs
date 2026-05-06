/// Encodes a u64 into an Unsigned LEB128 (Varint) byte vector.
pub fn encode_varint(value: u64) -> Vec<u8> {
    let mut buffer = Vec::new();
    let mut mut_value = value;
    loop {
        let byte = (mut_value & 0x7F) as u8;
        mut_value >>= 7;
        if mut_value != 0 {
            buffer.push(byte | 0x80);
        } else {
            buffer.push(byte);
            break;
        }
    }
    buffer
}

/// Decodes a Unsigned LEB128 (Varint) from a byte slice starting at the cursor.
/// Updates the cursor to point to the byte immediately following the varint.
pub fn decode_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, &'static str> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;

    loop {
        if *cursor >= bytes.len() {
            return Err("Unexpected end of bytes while decoding varint");
        }
        let byte = bytes[*cursor];
        *cursor += 1;

        result |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 64 {
            return Err("Varint too large for u64");
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_single_byte() {
        assert_eq!(encode_varint(127), vec![0x7F]);
    }

    #[test]
    fn test_encode_two_bytes() {
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
    }

    #[test]
    fn test_decode_single_byte() {
        assert_eq!(decode_varint(&[0x7F], &mut 0), Ok(127));
    }

    #[test]
    fn test_decode_two_bytes() {
        assert_eq!(decode_varint(&[0x80, 0x01], &mut 0), Ok(128));
    }

    #[test]
    fn test_decode_updates_cursor() {
        let mut cursor = 0;
        decode_varint(&[0x80, 0x01, 0xFF], &mut cursor).unwrap();
        assert_eq!(cursor, 2);
    }

    #[test]
    fn test_encode_zero() {
        assert_eq!(encode_varint(0), vec![0x00]);
    }

    #[test]
    fn test_decode_zero() {
        assert_eq!(decode_varint(&[0x00], &mut 0), Ok(0));
    }

    #[test]
    fn test_roundtrip_300() {
        assert_eq!(decode_varint(&encode_varint(300), &mut 0), Ok(300));
    }
}
