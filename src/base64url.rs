const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut result = String::with_capacity((data.len() * 4).div_ceil(3));
    let chunks = data.chunks(3);

    for chunk in chunks {
        let b0 = u32::from(chunk[0]);
        let mut b1 = 0u32;
        let mut b2 = 0u32;

        if chunk.len() > 1 {
            b1 = u32::from(chunk[1]);
        }
        if chunk.len() > 2 {
            b2 = u32::from(chunk[2]);
        }

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

/// Decodes a Base64URL-encoded byte slice back into its original bytes.
///
/// # Errors
/// Returns `"Invalid Base64URL character"` when `data` contains a byte that is
/// not part of the URL-safe Base64 alphabet (`A-Z`, `a-z`, `0-9`, `-`, `_`).
pub fn decode(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut lookup = [255u8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        // `i` runs over the 64-entry alphabet, so it always fits in a `u8`;
        // the unreachable fallback keeps the table's "invalid" marker.
        lookup[usize::from(c)] = u8::try_from(i).unwrap_or(u8::MAX);
    }

    let mut result = Vec::with_capacity(data.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;

    for &c in data {
        let val = lookup[usize::from(c)];
        if val == 255 {
            return Err("Invalid Base64URL character");
        }

        buffer = (buffer << 6) | u32::from(val);
        bits += 6;

        if bits >= 8 {
            bits -= 8;
            // `buffer` only ever accumulates `bits + 8` bits here (its high bits
            // are masked off after every push), so the byte extracted from the
            // top of `buffer` is always < 256 and fits in a `u8`.
            result.push(u8::try_from(buffer >> bits).unwrap_or_default());
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
