//! Strict hexadecimal encoding and decoding.
//!
//! The single decoder used across the crate. Unlike the 0.x implementations,
//! decoding is **strict**: odd-length input and non-hex digits are errors, and
//! keys or signatures are never silently truncated.

/// Lowercase hex-encodes `bytes` into a freshly allocated `String`.
#[must_use]
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0x0F)] as char);
    }
    out
}

/// Hex-decoding failure with a byte-offset for precise diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexError {
    /// Byte offset in the input where decoding failed.
    pub position: usize,
    /// Human-readable reason (odd length, non-hex digit).
    pub reason: &'static str,
}

impl std::fmt::Display for HexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} at byte offset {}", self.reason, self.position)
    }
}

impl std::error::Error for HexError {}

/// Strictly hex-decodes `s` into a freshly allocated `Vec<u8>`.
///
/// Accepts upper- and lowercase digits. Rejects odd-length input and any
/// non-hex byte, reporting the offending offset.
///
/// # Errors
/// Returns [`HexError`] for odd-length input or non-hex digits.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(HexError {
            position: bytes.len(),
            reason: "odd-length hex string",
        });
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = nibble(bytes[i], i)?;
        let lo = nibble(bytes[i + 1], i + 1)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8, pos: usize) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError {
            position: pos,
            reason: "non-hex digit",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_round_trip() {
        for len in 0..=66usize {
            let data: Vec<u8> = (0..len)
                .map(|i| u8::try_from(i * 7 % 256).unwrap_or(0))
                .collect();
            let hex = encode(&data);
            assert_eq!(hex.len(), len * 2);
            assert_eq!(decode(&hex).unwrap(), data);
        }
    }

    #[test]
    fn encode_is_lowercase() {
        assert_eq!(encode(&[0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef");
        assert_eq!(encode(&[]), "");
    }

    #[test]
    fn decode_accepts_uppercase() {
        assert_eq!(decode("DEADBEEF").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(decode("DeAdBeEf").unwrap(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn decode_rejects_odd_length() {
        let err = decode("abc").unwrap_err();
        assert_eq!(err.position, 3);
        assert_eq!(err.reason, "odd-length hex string");
    }

    #[test]
    fn decode_rejects_non_hex_with_position() {
        let err = decode("abxy").unwrap_err();
        assert_eq!(err.position, 2);
        assert_eq!(err.reason, "non-hex digit");
    }

    #[test]
    fn decode_empty() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }
}
