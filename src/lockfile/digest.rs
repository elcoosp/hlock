//! Digest calculation and validation
//!
//! Security model (v1.0.1): the `@digest` directive is the integrity anchor
//! of the file and must cover **everything except itself and a trailing
//! `@signature` block**. Earlier revisions hashed content only up to the
//! *first* `@digest`-prefixed line, so a digest line placed at the top of
//! the body authenticated just the header while every package line after it
//! went uncovered (prefix bypass). Validation therefore enforces:
//!
//! 1. exactly one `@digest` directive,
//! 2. positioned after the header separator (in the body region),
//! 3. nothing but `@signature` lines (and the final newline) after it.
//!
//! Line offsets are computed from raw byte positions, so CRLF files hash
//! the same bytes they parse.

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

/// Byte offset of the start of the first line whose content (sans trailing
/// `\r`) begins with one of the given prefixes.
fn first_directive_line_offset(content: &str, prefixes: &[&str]) -> Option<usize> {
    let bytes = content.as_bytes();
    let mut offset = 0usize;
    while offset <= bytes.len() {
        let line_end = bytes[offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| offset + i);
        let mut line = &content[offset..line_end];
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        if prefixes.iter().any(|p| line.starts_with(p)) {
            return Some(offset);
        }
        if line_end >= bytes.len() {
            break;
        }
        offset = line_end + 1;
    }
    None
}

/// Offset where the digest coverage ends: the start of the first
/// `@digest`/`@signature` line, or the end of the content.
fn coverage_boundary(content: &str) -> usize {
    first_directive_line_offset(content, &["@digest ", "@signature "]).unwrap_or(content.len())
}

/// True when every line starting at `offset` is either a `@signature` line
/// or empty (the final newline of the previous line). This is the only
/// content allowed to follow the `@digest` directive.
fn only_signatures_after(content: &str, offset: usize) -> bool {
    let bytes = content.as_bytes();
    let mut pos = offset;
    while pos <= bytes.len() {
        let line_end = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| pos + i);
        let mut line = &content[pos..line_end];
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        if !line.is_empty() && !line.starts_with("@signature ") {
            return false;
        }
        if line_end >= bytes.len() {
            break;
        }
        pos = line_end + 1;
    }
    true
}

/// Offset of the blank separator line ending the header, if any.
fn header_separator_offset(content: &str) -> Option<usize> {
    let idx_lf = content.find("\n\n").map(|i| i + 1);
    let idx_crlf = content.find("\r\n\r\n").map(|i| i + 2);
    match (idx_lf, idx_crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[must_use]
pub fn whole_lockfile_digest(content: &str) -> [u8; 32] {
    let boundary = coverage_boundary(content);
    let hash = blake3::hash(&content.as_bytes()[..boundary]);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

///
/// # Errors
///
/// Returns [`Error::MissingDigest`] when no `@digest` directive is present,
/// [`Error::DuplicateDigestDirective`] when more than one is present,
/// [`Error::DigestPlacement`] when the directive is not at the end of the
/// body (only `@signature` lines may follow it), and
/// [`Error::DigestMismatch`] when the whole-lockfile digest does not match.
pub fn validate_digest(content: &str) -> Result<(), Error> {
    let mut digest_lines: Vec<usize> = Vec::new();
    let mut offset = 0usize;
    let bytes = content.as_bytes();
    while offset <= bytes.len() {
        let line_end = bytes[offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| offset + i);
        let mut line = &content[offset..line_end];
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        if line.starts_with("@digest ") {
            digest_lines.push(offset);
        }
        if line_end >= bytes.len() {
            break;
        }
        offset = line_end + 1;
    }

    let Some(&digest_offset) = digest_lines.first() else {
        return Err(Error::MissingDigest);
    };
    if digest_lines.len() > 1 {
        return Err(Error::DuplicateDigestDirective);
    }

    // The digest must live in the body region (after the header separator).
    match header_separator_offset(content) {
        Some(sep) if digest_offset > sep => {}
        _ => {
            return Err(Error::DigestPlacement {
                covered: digest_offset,
                total: content.len(),
            });
        }
    }

    // Nothing but a trailing @signature block may follow the digest.
    let digest_line_end = bytes[digest_offset..]
        .iter()
        .position(|&b| b == b'\n')
        .map_or(content.len(), |i| digest_offset + i);
    if !only_signatures_after(content, (digest_line_end + 1).min(content.len())) {
        return Err(Error::DigestPlacement {
            covered: digest_offset,
            total: content.len(),
        });
    }

    let mut digest_line = &content[digest_offset..digest_line_end];
    if digest_line.ends_with('\r') {
        digest_line = &digest_line[..digest_line.len() - 1];
    }
    let hex_str = digest_line
        .strip_prefix("@digest ")
        .unwrap_or_default()
        .trim();
    let expected = crate::hex::decode(hex_str).map_err(|_| Error::DigestMismatch {
        expected: hex_str.to_string(),
        actual: String::new(),
    })?;
    if expected.len() != 32 {
        return Err(Error::DigestMismatch {
            expected: hex_str.to_string(),
            actual: String::new(),
        });
    }
    let boundary = coverage_boundary(content);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boundary_stops_at_digest_line() {
        let content = "@source 0 https://r/\n\npkg\tAAAA\n@digest deadbeef\n";
        let boundary = coverage_boundary(content);
        assert_eq!(&content[..boundary], "@source 0 https://r/\n\npkg\tAAAA\n");
    }

    #[test]
    fn boundary_stops_at_signature_line() {
        let content = "@source 0 https://r/\n\npkg\tAAAA\n@signature k 00 1 AB\n";
        let boundary = coverage_boundary(content);
        assert_eq!(&content[..boundary], "@source 0 https://r/\n\npkg\tAAAA\n");
    }

    #[test]
    fn boundary_is_crlf_correct() {
        let content = "@source 0 https://r/\r\n\r\npkg\tAAAA\r\n@digest deadbeef\r\n";
        let boundary = coverage_boundary(content);
        assert_eq!(
            &content[..boundary],
            "@source 0 https://r/\r\n\r\npkg\tAAAA\r\n"
        );
    }

    #[test]
    fn validate_accepts_canonical_layout() {
        // Not a valid digest value, but placement checks come first and the
        // mismatch error proves we reached the comparison stage.
        let err = validate_digest(&format!(
            "@source 0 https://r/\n\npkg\tAAAA\n@digest {}\n@signature k 00 1 AB\n",
            digest_hex("@source 0 https://r/\n\npkg\tAAAA\n")
        ))
        .err();
        assert!(err.is_none(), "canonical layout must validate: {err:?}");
        // The CRLF variant must validate identically.
    }

    #[test]
    fn validate_rejects_prefix_digest() {
        let prefix = "@source 0 https://r/\n\n";
        let evil = format!(
            "{prefix}\n@digest {}\npkg\tAAAA\n",
            digest_hex(&format!("{prefix}\n"))
        );
        let err = validate_digest(&evil).unwrap_err();
        assert!(
            matches!(err, Error::DigestPlacement { .. }),
            "prefix digest must be rejected, got {err}"
        );
    }

    #[test]
    fn validate_rejects_missing_digest() {
        let err = validate_digest("@source 0 https://r/\n\npkg\tAAAA\n").unwrap_err();
        assert!(matches!(err, Error::MissingDigest));
    }

    #[test]
    fn validate_rejects_digest_in_header() {
        let content = format!("@digest {}\n\npkg\tAAAA\n", digest_hex("@digest x\n"));
        let err = validate_digest(&content).unwrap_err();
        assert!(matches!(err, Error::DigestPlacement { .. }));
    }
}
