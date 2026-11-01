//! Digest calculation and validation

use crate::error::Error;
use std::fmt::Write as _;

/// Encodes `bytes` as lowercase hexadecimal.
#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn find_digest_or_signature_boundary(content: &str) -> usize {
    let mut offset = 0;
    for line in content.lines() {
        if line.starts_with("@digest ") || line.starts_with("@signature ") {
            return offset;
        }
        offset += line.len();
        if offset < content.len() {
            offset += 1;
        }
    }
    content.len()
}

#[must_use]
pub fn whole_lockfile_digest(content: &str) -> [u8; 32] {
    let boundary = find_digest_or_signature_boundary(content);
    let hash = blake3::hash(&content.as_bytes()[..boundary]);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

///
/// # Errors
///
/// Returns `Err` if `DuplicateDigestDirective` occurs; or if the whole-lockfile digest does not match.
pub fn validate_digest(content: &str) -> Result<(), Error> {
    let mut digest_lines = Vec::new();
    for line in content.lines() {
        if line.starts_with("@digest ") {
            digest_lines.push(line);
        }
    }
    if digest_lines.is_empty() {
        return Ok(());
    }
    if digest_lines.len() > 1 {
        return Err(Error::DuplicateDigestDirective);
    }

    let hex_str = digest_lines[0]
        .strip_prefix("@digest ")
        .ok_or(Error::DuplicateDigestDirective)?
        .trim();
    let expected = hex_to_bytes(hex_str).ok_or_else(|| Error::DigestMismatch {
        expected: String::new(),
        actual: String::new(),
    })?;
    if expected.len() != 32 {
        return Err(Error::DigestMismatch {
            expected: hex_str.to_string(),
            actual: String::new(),
        });
    }
    let boundary = find_digest_or_signature_boundary(content);
    let computed = blake3::hash(&content.as_bytes()[..boundary]);
    if computed.as_bytes() != expected.as_slice() {
        return Err(Error::DigestMismatch {
            expected: hex_str.to_string(),
            actual: bytes_to_hex(computed.as_bytes()),
        });
    }
    Ok(())
}

/// Computes the whole-lockfile digest and returns it as lowercase hex.
///
/// # Errors
///
/// Never returns `Err` in practice; the digest is computed over the raw content.
#[must_use]
pub fn digest_hex(content: &str) -> String {
    bytes_to_hex(&whole_lockfile_digest(content))
}
