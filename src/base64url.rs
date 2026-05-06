const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

pub fn encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = chunk[0] as u32;
        let mut b1 = 0u32;
        let mut b2 = 0u32;

        if chunk.len() > 1 { b1 = chunk[1] as u32; }
        if chunk.len() > 2 { b2 = chunk[2] as u32; }

        let combined = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);

        if chunk.len() > 1 {
            result.push(ALPHABET[((combined >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(ALPHABET[(combined & 0x3F) as usize] as char);
        }
    }

    result
}

pub fn decode(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut lookup = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        lookup[c as usize] = i as u8;
    }

    let mut result = Vec::with_capacity(data.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &c in data {
        let val = lookup[c as usize];
        if val == 255 { return Err("Invalid Base64URL character"); }

        buffer = (buffer << 6) | val as u32;
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            result.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn test_encode_two_bytes() {
        assert_eq!(encode(&[0xFB, 0xCF]), "-88");
    }

    #[test]
    fn test_decode_roundtrip() {
        let original = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = encode(&original);
        let decoded = decode(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_encode_one_byte() {
        assert_eq!(encode(&[0x00]), "AA");
    }

    #[test]
    fn test_decode_invalid_char() {
        assert!(decode(&[0xFF]).is_err());
    }
}
