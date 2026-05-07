use crate::base64url;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Base64URL decode failed: {0}")]
    InvalidBase64(&'static str),

    #[error("Ed25519 verification failed")]
    VerificationFailed,

    #[error("Malformed signature directive: {reason}")]
    MalformedDirective { reason: String },
}

pub fn sign_lockfile(
    serialized_lockfile: &str,
    key_id: &str,
    private_key: &[u8; 64],
) -> Result<String, SignatureError> {
    if key_id.contains(' ') {
        return Err(SignatureError::MalformedDirective {
            reason: "key_id must not contain spaces".to_string(),
        });
    }
    if key_id.is_empty() {
        return Err(SignatureError::MalformedDirective {
            reason: "key_id must not be empty".to_string(),
        });
    }
    if !serialized_lockfile.ends_with('\n') {
        return Err(SignatureError::MalformedDirective {
            reason: "serialized lockfile must end with a newline".to_string(),
        });
    }

    let seed: [u8; 32] = private_key[..32].try_into().map_err(|_| {
        SignatureError::MalformedDirective {
            reason: "private_key first 32 bytes must be valid seed".to_string(),
        }
    })?;

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(serialized_lockfile.as_bytes());
    let encoded = base64url::encode(signature.to_bytes().as_ref());

    Ok(format!("{}@signature {} {}\n", serialized_lockfile, key_id, encoded))
}

pub fn verify_signature(
    lockfile_content: &str,
    public_key: &[u8; 32],
) -> Result<(), SignatureError> {
    let sig_start = match lockfile_content.rfind("@signature ") {
        Some(pos) => {
            if pos > 0 && lockfile_content.as_bytes()[pos - 1] != b'\n' {
                return Ok(());
            }
            pos
        }
        None => return Ok(()),
    };

    let sig_line_full = &lockfile_content[sig_start..];
    let sig_line_end = sig_line_full.find('\n').unwrap_or(sig_line_full.len());
    let sig_line = &sig_line_full[..sig_line_end];

    let after_sig = sig_line_full.get(sig_line_end..).unwrap_or("");
    let after_sig = after_sig.strip_prefix('\n').unwrap_or(after_sig);
    if !after_sig.is_empty() {
        return Err(SignatureError::MalformedDirective {
            reason: "@signature must be the last line in the file".to_string(),
        });
    }

    let rest = &sig_line["@signature ".len()..];
    let mut parts = rest.splitn(2, ' ');
    let _key_id = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective {
            reason: "Missing key_id after @signature".to_string(),
        }
    })?;
    let encoded_sig = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective {
            reason: "Missing signature after key_id".to_string(),
        }
    })?;

    if encoded_sig.is_empty() {
        return Err(SignatureError::MalformedDirective {
            reason: "Signature is empty".to_string(),
        });
    }

    let sig_bytes = base64url::decode(encoded_sig.as_bytes()).map_err(SignatureError::InvalidBase64)?;
    if sig_bytes.len() != 64 {
        return Err(SignatureError::MalformedDirective {
            reason: format!("Signature must be 64 bytes, got {}", sig_bytes.len()),
        });
    }
    let sig_array: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        SignatureError::MalformedDirective {
            reason: "Signature must be 64 bytes".to_string(),
        }
    })?;

    let message = &lockfile_content.as_bytes()[..sig_start];

    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(|e| {
        SignatureError::MalformedDirective {
            reason: format!("Invalid Ed25519 public key: {}", e),
        }
    })?;

    let signature = ed25519::Signature::from_bytes(&sig_array);

    use ed25519_dalek::Verifier;
    verifying_key.verify(message, &signature).map_err(|_| SignatureError::VerificationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];

    fn public_key() -> [u8; 32] {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&SEED);
        *signing_key.verifying_key().as_bytes()
    }

    fn expanded_private_key() -> [u8; 64] {
        let mut key = [0u8; 64];
        let pk = public_key();
        key[..32].copy_from_slice(&SEED);
        key[32..].copy_from_slice(&pk);
        key
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        let signed = sign_lockfile(lockfile, "ci@example.com", &private_key).unwrap();

        assert!(signed.starts_with(lockfile));
        assert!(signed.contains("@signature ci@example.com "));
        assert!(signed.ends_with('\n'));

        let sig_pos = signed.find("@signature ").unwrap();
        let message_bytes = &signed.as_bytes()[..sig_pos];
        eprintln!("Message bytes len: {}", message_bytes.len());
        eprintln!("Message bytes: {:?}", message_bytes);

        let signing_key = ed25519_dalek::SigningKey::from_bytes(&SEED);
        use ed25519_dalek::Signer;
        let expected_sig = signing_key.sign(message_bytes);
        eprintln!("Expected sig bytes: {:?}", expected_sig.to_bytes().as_ref());

        let result = verify_signature(&signed, &public_key());
        if let Err(e) = &result {
            eprintln!("Verification error: {:?}", e);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_no_signature() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        assert!(verify_signature(lockfile, &public_key()).is_ok());
    }

    #[test]
    fn test_verify_tampered_message() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        let signed = sign_lockfile(lockfile, "ci@example.com", &private_key).unwrap();

        let tampered = signed.replace("reg.com", "reg.org");

        assert!(matches!(
            verify_signature(&tampered, &public_key()),
            Err(SignatureError::VerificationFailed)
        ));
    }

    #[test]
    fn test_sign_rejects_spaces_in_key_id() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        assert!(sign_lockfile(lockfile, "ci at example", &private_key).is_err());
    }

    #[test]
    fn test_sign_rejects_empty_key_id() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        assert!(sign_lockfile(lockfile, "", &private_key).is_err());
    }

    #[test]
    fn test_sign_rejects_no_trailing_newline() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA";
        let private_key = expanded_private_key();
        assert!(sign_lockfile(lockfile, "ci@example.com", &private_key).is_err());
    }

    #[test]
    fn test_verify_ignores_embedded_signature() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        let signed = sign_lockfile(lockfile, "ci@example.com", &private_key).unwrap();
        let with_embedded = signed.replace("@signature ", "x@signature ");
        assert!(verify_signature(&with_embedded, &public_key()).is_ok());
    }

    #[test]
    fn test_verify_rejects_content_after_signature() {
        let lockfile = "@source 0 https://reg.com/\n\npkg\tAAAA\n";
        let private_key = expanded_private_key();
        let signed = sign_lockfile(lockfile, "ci@example.com", &private_key).unwrap();
        let with_extra = format!("{}extra\n", signed);
        assert!(matches!(
            verify_signature(&with_extra, &public_key()),
            Err(SignatureError::MalformedDirective { .. })
        ));
    }

    #[test]
    fn test_verify_rejects_empty_signature() {
        let content = "@source 0 https://reg.com/\n\npkg\tAAAA\n@signature ci@example.com \n";
        assert!(matches!(
            verify_signature(content, &public_key()),
            Err(SignatureError::MalformedDirective { .. })
        ));
    }

    #[test]
    fn test_verify_rejects_invalid_base64() {
        let content = "@source 0 https://reg.com/\n\npkg\tAAAA\n@signature ci@example.com !!!invalid!!!\n";
        assert!(matches!(
            verify_signature(content, &public_key()),
            Err(SignatureError::InvalidBase64(_))
        ));
    }
}
