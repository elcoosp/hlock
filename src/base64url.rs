//! URL-safe Base64 without padding (v1.0).
//!
//! v1.0 changes versus 0.x:
//! - the 256-entry decode table is a **`const`**, not rebuilt on every call;
//! - decoding is **canonical**: trailing unused bits must be zero;
//! - `decode_into` writes into a caller-owned buffer to avoid allocation in
//!   hot loops (the deserializer reuses one buffer across all package lines).

/// Decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// A byte outside the URL-safe alphabet.
    InvalidCharacter { position: usize },
    /// Trailing bits after the last full group are non-zero.
    NonCanonicalTrailingBits,
}

impl std::fmt::Display for Base64Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCharacter { position } => {
                write!(f, "invalid base64url character at byte offset {position}")
            }
            Self::NonCanonicalTrailingBits => {
                write!(f, "non-canonical base64url trailing bits")
            }
        }
    }
}

impl std::error::Error for Base64Error {}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Const decode table: `255` marks invalid bytes.
const fn build_lookup() -> [u8; 256] {
    let mut lookup = [255u8; 256];
    let mut i = 0;
    while i < 64 {
        // Loop bound guarantees i < 64, so the casts are lossless.
        #[allow(clippy::cast_possible_truncation)]
        {
            lookup[ALPHABET[i] as usize] = i as u8;
        }
        i += 1;
    }
    lookup
}

const LOOKUP: [u8; 256] = build_lookup();

/// URL-safe Base64 encodes `data` (no padding).
#[must_use]
pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    let (chunks, remainder) = data.as_chunks::<3>();
    for chunk in chunks {
        let combined =
            (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
        for shift in [18, 12, 6, 0] {
            out.push(ALPHABET[((combined >> shift) & 0x3F) as usize] as char);
        }
    }
    let rem = remainder;
    match rem.len() {
        1 => {
            let combined = u32::from(rem[0]) << 16;
            out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
        }
        2 => {
            let combined = (u32::from(rem[0]) << 16) | (u32::from(rem[1]) << 8);
            out.push(ALPHABET[((combined >> 18) & 0x3F) as usize] as char);
            out.push(ALPHABET[((combined >> 12) & 0x3F) as usize] as char);
            out.push(ALPHABET[((combined >> 6) & 0x3F) as usize] as char);
        }
        _ => {}
    }
    out
}

/// URL-safe Base64 decodes `data` into a freshly allocated `Vec<u8>`.
///
/// # Errors
/// Returns [`Base64Error::InvalidCharacter`] for bytes outside the alphabet
/// and [`Base64Error::NonCanonicalTrailingBits`] when the final group carries
/// non-zero unused bits (never produced by [`encode`]).
pub fn decode(data: &[u8]) -> Result<Vec<u8>, Base64Error> {
    let mut out = Vec::with_capacity(data.len() * 3 / 4);
    decode_into(data, &mut out)?;
    Ok(out)
}

/// URL-safe Base64 decodes `data`, appending to `out` (reusable-buffer API).
///
/// `out` is cleared before decoding.
///
/// # Errors
/// Same as [`decode`].
pub fn decode_into(data: &[u8], out: &mut Vec<u8>) -> Result<(), Base64Error> {
    out.clear();
    out.reserve(data.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for (pos, &c) in data.iter().enumerate() {
        let val = LOOKUP[usize::from(c)];
        if val == 255 {
            return Err(Base64Error::InvalidCharacter { position: pos });
        }
        buffer = (buffer << 6) | u32::from(val);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            // Invariant: `bits + 8 <= 14`, so the extracted byte fits in u8.
            #[allow(clippy::cast_possible_truncation)]
            out.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    // Canonical tail: remaining bits must all be zero.
    if bits > 0 && buffer != 0 {
        return Err(Base64Error::NonCanonicalTrailingBits);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_empty() {
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn encode_two_bytes() {
        assert_eq!(encode(&[0xFB, 0xCF]), "-88");
    }

    #[test]
    fn encode_one_byte() {
        assert_eq!(encode(&[0x00]), "AA");
    }

    #[test]
    fn roundtrip_lengths_0_to_70() {
        for len in 0..=70usize {
            #[allow(clippy::cast_possible_truncation)] // value is pre-reduced mod 256
            let original: Vec<u8> = (0..len).map(|i| (i * 37 % 256) as u8).collect();
            let encoded = encode(&original);
            assert_eq!(encoded.len(), (len * 4).div_ceil(3));
            let decoded = decode(encoded.as_bytes()).unwrap();
            assert_eq!(decoded, original, "len {len}");
        }
    }

    #[test]
    fn decode_invalid_char_position() {
        let err = decode(b"AB~D").unwrap_err();
        assert_eq!(err, Base64Error::InvalidCharacter { position: 2 });
    }

    #[test]
    fn decode_rejects_non_canonical_trailing_bits() {
        // "AB" encodes one byte 0x00; "AC" would carry non-zero trailing bits.
        let err = decode(b"AC").unwrap_err();
        assert_eq!(err, Base64Error::NonCanonicalTrailingBits);
        // Canonical single-char groups are impossible (2 chars min), and a
        // 3-char group must have zero trailing bits.
        assert!(decode(b"AAA").is_ok());
    }

    #[test]
    fn decode_into_reuses_buffer() {
        let mut buf = Vec::new();
        decode_into(b"AAAA", &mut buf).unwrap();
        assert_eq!(buf, vec![0, 0, 0]);
        decode_into(b"BBBB", &mut buf).unwrap();
        assert_eq!(buf, vec![0x04, 0x10, 0x41]);
    }
}
