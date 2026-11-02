//! Unsigned LEB128 varint encoding and decoding (v1.0).
//!
//! Encoding writes directly into a caller-owned buffer (`push_varint`) — the
//! 0.x `encode_varint` allocated one `Vec` per field and dominated `pack_payload`
//! profiles. Decoding rejects **non-canonical (overlong) encodings**, which 0.x
//! silently accepted.

/// Appends the unsigned LEB128 encoding of `value` to `out` (zero-alloc).
pub fn push_varint(out: &mut Vec<u8>, value: u64) {
    let mut v = value;
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            out.push(byte | 0x80);
        } else {
            out.push(byte);
            return;
        }
    }
}

/// Number of bytes [`push_varint`] will write for `value`.
#[must_use]
pub const fn varint_len(value: u64) -> usize {
    // ceil(bits / 7), minimum 1; bits = 64 - leading_zeros.
    let bits = 64 - value.leading_zeros() as usize;
    let ceil = bits.div_ceil(7);
    if ceil < 1 { 1 } else { ceil }
}

/// Varint decoding failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarintError {
    /// Input ended before the continuation bits terminated.
    UnexpectedEnd,
    /// Encoding spans more bytes than a `u64` can occupy.
    TooLarge,
    /// Overlong encoding: the final byte could have been omitted.
    NonCanonical,
}

impl std::fmt::Display for VarintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedEnd => write!(f, "unexpected end of bytes while decoding varint"),
            Self::TooLarge => write!(f, "varint too large for u64"),
            Self::NonCanonical => write!(f, "non-canonical (overlong) varint encoding"),
        }
    }
}

impl std::error::Error for VarintError {}

/// Decodes an unsigned LEB128 varint from `bytes` starting at `*cursor`,
/// advancing the cursor past it.
///
/// Overlong encodings (e.g. `0x80 0x00` for `0`) are rejected: the last byte
/// of a canonical varint always has a non-zero payload.
///
/// # Errors
/// Returns [`VarintError::UnexpectedEnd`], [`VarintError::TooLarge`], or
/// [`VarintError::NonCanonical`].
pub fn decode_varint(bytes: &[u8], cursor: &mut usize) -> Result<u64, VarintError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *cursor >= bytes.len() {
            return Err(VarintError::UnexpectedEnd);
        }
        let byte = bytes[*cursor];
        *cursor += 1;

        let payload = u64::from(byte & 0x7F);
        // A canonical encoding never places a non-zero payload in the final
        // byte's discarded bits.
        if shift >= 64 || (shift == 63 && payload > 1) {
            return Err(VarintError::TooLarge);
        }
        result |= payload << shift;

        if byte & 0x80 == 0 {
            if payload == 0 && shift > 0 {
                return Err(VarintError::NonCanonical);
            }
            return Ok(result);
        }
        shift += 7;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_varint_single_byte() {
        let mut buf = Vec::new();
        push_varint(&mut buf, 127);
        assert_eq!(buf, vec![0x7F]);
    }

    #[test]
    fn push_varint_two_bytes() {
        let mut buf = Vec::new();
        push_varint(&mut buf, 128);
        assert_eq!(buf, vec![0x80, 0x01]);
    }

    #[test]
    fn push_varint_zero() {
        let mut buf = Vec::new();
        push_varint(&mut buf, 0);
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn push_varint_zero_alloc_matches_legacy_encoding() {
        let mut buf = Vec::new();
        push_varint(&mut buf, 300);
        assert_eq!(buf, vec![0xAC, 0x02]);
    }

    #[test]
    fn varint_len_matches_pushed_bytes() {
        for value in [0u64, 1, 127, 128, 300, u64::from(u32::MAX), u64::MAX] {
            let mut buf = Vec::new();
            push_varint(&mut buf, value);
            assert_eq!(buf.len(), varint_len(value), "{value}");
        }
    }

    #[test]
    fn round_trip_boundaries() {
        for value in [
            0u64,
            1,
            126,
            127,
            128,
            16_383,
            16_384,
            u64::from(u32::MAX),
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            push_varint(&mut buf, value);
            let mut cursor = 0;
            assert_eq!(decode_varint(&buf, &mut cursor).unwrap(), value);
            assert_eq!(cursor, buf.len());
        }
    }

    #[test]
    fn decode_rejects_overlong_encoding() {
        // 0 encoded as 0x80 0x00 is non-canonical.
        let mut cursor = 0;
        assert_eq!(
            decode_varint(&[0x80, 0x00], &mut cursor),
            Err(VarintError::NonCanonical)
        );
    }

    #[test]
    fn decode_rejects_truncated() {
        let mut cursor = 0;
        assert_eq!(
            decode_varint(&[0x80], &mut cursor),
            Err(VarintError::UnexpectedEnd)
        );
    }

    #[test]
    fn decode_rejects_too_large() {
        let bytes = [0xFF; 11];
        let mut cursor = 0;
        assert_eq!(
            decode_varint(&bytes, &mut cursor),
            Err(VarintError::TooLarge)
        );
    }

    #[test]
    fn decode_allows_max_u64() {
        // Canonical encoding of u64::MAX is 10 bytes.
        let mut buf = Vec::new();
        push_varint(&mut buf, u64::MAX);
        assert_eq!(buf.len(), 10);
        let mut cursor = 0;
        assert_eq!(decode_varint(&buf, &mut cursor).unwrap(), u64::MAX);
    }
}
