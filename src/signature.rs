use crate::base64url;
use fips204::traits::{SerDes as FipsSerDes, Signer as FipsSigner, Verifier as FipsVerifier};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519 = 0x00,
    MlDsa65 = 0x02,
}

#[derive(Debug, Clone)]
pub struct SignatureDirective {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub expires_epoch: u64,
    pub signature_bytes: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("Base64URL decode failed: {0}")]
    InvalidBase64(&'static str),
    #[error("Ed25519 verification failed")]
    VerificationFailed,
    #[error("ML-DSA-65 verification failed")]
    MlDsaVerificationFailed,
    #[error("Malformed signature directive: {reason}")]
    MalformedDirective { reason: String },
    #[error("Key '{key_id}' is not in the trusted key set")]
    UntrustedKey { key_id: String },
    #[error("Signature from '{key_id}' expired at epoch {expires_epoch}")]
    SignatureExpired { key_id: String, expires_epoch: u64 },
    #[error("Unsupported signature algorithm ID {algo_id}")]
    UnsupportedSignatureAlgorithm { algo_id: u8 },
}

pub fn parse_signature_directive(line: &str) -> Result<SignatureDirective, SignatureError> {
    let rest = line.strip_prefix("@signature ").ok_or_else(|| {
        SignatureError::MalformedDirective { reason: "missing @signature prefix".to_string() }
    })?;
    let mut parts = rest.splitn(4, ' ');
    let key_id = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective { reason: "missing key_id".to_string() }
    })?.to_string();
    let algo_hex = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective { reason: "missing algo_id".to_string() }
    })?;
    let expires_str = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective { reason: "missing expires_epoch".to_string() }
    })?;
    let sig_b64 = parts.next().ok_or_else(|| {
        SignatureError::MalformedDirective { reason: "missing signature".to_string() }
    })?;
    if key_id.contains(' ') || key_id.is_empty() {
        return Err(SignatureError::MalformedDirective { reason: "invalid key_id".to_string() });
    }
    let algo_id = u8::from_str_radix(algo_hex, 16).map_err(|_| {
        SignatureError::MalformedDirective { reason: "algo_id must be two hex digits".to_string() }
    })?;
    let algorithm = match algo_id {
        0x00 => SignatureAlgorithm::Ed25519,
        0x02 => SignatureAlgorithm::MlDsa65,
        _ => return Err(SignatureError::UnsupportedSignatureAlgorithm { algo_id }),
    };
    let expires_epoch: u64 = expires_str.parse().map_err(|_| {
        SignatureError::MalformedDirective { reason: "expires_epoch must be decimal".to_string() }
    })?;
    let signature_bytes = base64url::decode(sig_b64.as_bytes()).map_err(SignatureError::InvalidBase64)?;
    let expected_len = match algorithm {
        SignatureAlgorithm::Ed25519 => 64,
        SignatureAlgorithm::MlDsa65 => fips204::ml_dsa_65::SIG_LEN,
    };
    if expected_len > 0 && signature_bytes.len() != expected_len {
        return Err(SignatureError::MalformedDirective {
            reason: format!("expected {} signature bytes, got {}", expected_len, signature_bytes.len()),
        });
    }
    Ok(SignatureDirective { key_id, algorithm, expires_epoch, signature_bytes })
}

pub fn sign_lockfile(
    serialized_lockfile: &str,
    key_id: &str,
    algorithm: SignatureAlgorithm,
    private_key: &[u8],
    expires_epoch: u64,
) -> Result<String, SignatureError> {
    if key_id.contains(' ') {
        return Err(SignatureError::MalformedDirective { reason: "key_id must not contain spaces".to_string() });
    }
    if key_id.is_empty() {
        return Err(SignatureError::MalformedDirective { reason: "key_id must not be empty".to_string() });
    }
    if !serialized_lockfile.ends_with('\n') {
        return Err(SignatureError::MalformedDirective { reason: "serialized lockfile must end with a newline".to_string() });
    }
    let (algo_id, encoded_sig) = match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if private_key.len() != 32 {
                return Err(SignatureError::MalformedDirective { reason: "Ed25519 private key must be 32 bytes".to_string() });
            }
            let seed: [u8; 32] = private_key.try_into().map_err(|_| {
                SignatureError::MalformedDirective { reason: "invalid Ed25519 seed".to_string() }
            })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            use ed25519_dalek::Signer;
            let sig = signing_key.sign(serialized_lockfile.as_bytes());
            (0x00u8, base64url::encode(sig.to_bytes().as_ref()))
        }
        SignatureAlgorithm::MlDsa65 => {
            if private_key.len() != fips204::ml_dsa_65::SK_LEN {
                return Err(SignatureError::MalformedDirective {
                    reason: format!("ML-DSA-65 private key must be {} bytes", fips204::ml_dsa_65::SK_LEN),
                });
            }
            let key_bytes: <fips204::ml_dsa_65::PrivateKey as FipsSerDes>::ByteArray = private_key.try_into().map_err(|_| {
                SignatureError::MalformedDirective {
                    reason: "invalid ML-DSA-65 private key".to_string(),
                }
            })?;
            let sk: fips204::ml_dsa_65::PrivateKey = FipsSerDes::try_from_bytes(key_bytes)
                .map_err(|e| SignatureError::MalformedDirective {
                    reason: format!("invalid ML-DSA-65 private key: {}", e),
                })?;
            let sig: <fips204::ml_dsa_65::PrivateKey as FipsSigner>::Signature = FipsSigner::try_sign(&sk, serialized_lockfile.as_bytes(), &[])
                .map_err(|e| SignatureError::MalformedDirective {
                    reason: format!("ML-DSA-65 signing failed: {}", e),
                })?;
            (0x02u8, base64url::encode(&sig[..]))
        }
    };
    Ok(format!("{}@signature {} {:02x} {} {}\n", serialized_lockfile, key_id, algo_id, expires_epoch, encoded_sig))
}

pub fn verify_signature(
    lockfile_content: &str,
    trusted_keys: &HashMap<String, (Vec<u8>, SignatureAlgorithm)>,
) -> Result<(), SignatureError> {
    let mut sig_start: Option<usize> = None;
    let mut sig_directives: Vec<SignatureDirective> = Vec::new();
    for line in lockfile_content.lines() {
        if line.starts_with("@signature ") {
            if sig_start.is_none() {
                sig_start = lockfile_content.find("@signature ");
            }
            sig_directives.push(parse_signature_directive(line)?);
        }
    }
    if sig_directives.is_empty() { return Ok(()); }
    let sig_start = sig_start.unwrap();
    if sig_start > 0 && lockfile_content.as_bytes()[sig_start - 1] != b'\n' { return Ok(()); }
    let message = &lockfile_content.as_bytes()[..sig_start];
    let after_sigs = &lockfile_content[sig_start..];
    let last_sig_end = after_sigs.rfind('\n').map(|i| sig_start + i + 1).unwrap_or(lockfile_content.len());
    if last_sig_end < lockfile_content.len() {
        return Err(SignatureError::MalformedDirective { reason: "@signature must be the last lines in the file".to_string() });
    }
    for directive in &sig_directives {
        let (expected_pub_key, expected_algo) = trusted_keys.get(&directive.key_id).ok_or_else(|| {
            SignatureError::UntrustedKey { key_id: directive.key_id.clone() }
        })?;
        if directive.algorithm != *expected_algo {
            return Err(SignatureError::MalformedDirective {
                reason: format!("key '{}' uses algo {:?} but trusted key expects {:?}", directive.key_id, directive.algorithm, expected_algo),
            });
        }
        if directive.expires_epoch != 0 {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            if now > directive.expires_epoch {
                return Err(SignatureError::SignatureExpired {
                    key_id: directive.key_id.clone(),
                    expires_epoch: directive.expires_epoch,
                });
            }
        }
        match directive.algorithm {
            SignatureAlgorithm::Ed25519 => {
                if expected_pub_key.len() != 32 {
                    return Err(SignatureError::MalformedDirective { reason: "Ed25519 public key must be 32 bytes".to_string() });
                }
                let pk_bytes: [u8; 32] = expected_pub_key.as_slice().try_into().map_err(|_| {
                    SignatureError::MalformedDirective { reason: "invalid Ed25519 public key".to_string() }
                })?;
                let sig_bytes: [u8; 64] = directive.signature_bytes.as_slice().try_into().map_err(|_| {
                    SignatureError::MalformedDirective { reason: "invalid Ed25519 signature".to_string() }
                })?;
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
                    SignatureError::MalformedDirective { reason: format!("invalid Ed25519 public key: {}", e) }
                })?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                use ed25519_dalek::Verifier;
                verifying_key.verify(message, &signature).map_err(|_| SignatureError::VerificationFailed)?;
            }
            SignatureAlgorithm::MlDsa65 => {
                if expected_pub_key.len() != fips204::ml_dsa_65::PK_LEN {
                    return Err(SignatureError::MalformedDirective {
                        reason: format!("ML-DSA-65 public key must be {} bytes", fips204::ml_dsa_65::PK_LEN),
                    });
                }
                let pk_bytes: <fips204::ml_dsa_65::PublicKey as FipsSerDes>::ByteArray = expected_pub_key.as_slice().try_into().map_err(|_| {
                    SignatureError::MalformedDirective {
                        reason: "invalid ML-DSA-65 public key".to_string(),
                    }
                })?;
                let vk: fips204::ml_dsa_65::PublicKey = FipsSerDes::try_from_bytes(pk_bytes)
                    .map_err(|e| SignatureError::MalformedDirective {
                        reason: format!("invalid ML-DSA-65 public key: {}", e),
                    })?;
                let sig_bytes: <fips204::ml_dsa_65::PublicKey as FipsVerifier>::Signature = directive.signature_bytes.as_slice().try_into().map_err(|_| {
                    SignatureError::MalformedDirective {
                        reason: "invalid ML-DSA-65 signature".to_string(),
                    }
                })?;
                if !FipsVerifier::verify(&vk, message, &sig_bytes, &[]) {
                    return Err(SignatureError::MlDsaVerificationFailed);
                }
            }
        }
    }
    Ok(())
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

    fn make_trusted() -> HashMap<String, (Vec<u8>, SignatureAlgorithm)> {
        let mut m = HashMap::new();
        m.insert("ci@example.com".to_string(), (public_key().to_vec(), SignatureAlgorithm::Ed25519));
        m
    }

    #[test]
    fn test_parse_signature_directive_v12() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@co.com", SignatureAlgorithm::Ed25519, &SEED, 1735689600).unwrap();
        let sig_line = signed.lines().find(|l| l.starts_with("@signature ")).unwrap();
        let directive = parse_signature_directive(sig_line).unwrap();
        assert_eq!(directive.key_id, "ci@co.com");
        assert_eq!(directive.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(directive.expires_epoch, 1735689600);
        assert_eq!(directive.signature_bytes.len(), 64);
    }

    #[test]
    fn test_sign_v12_ed25519_format() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@co.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        assert!(signed.contains("@signature ci@co.com 00 0 "));
        assert!(signed.ends_with('\n'));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        assert!(signed.starts_with(lockfile));
        assert!(signed.contains("@signature ci@example.com 00 0 "));
        assert!(signed.ends_with('\n'));
        assert!(verify_signature(&signed, &make_trusted()).is_ok());
    }

    #[test]
    fn test_verify_tampered_message() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let tampered = signed.replace("r.com", "r.org");
        match verify_signature(&tampered, &make_trusted()) {
            Err(SignatureError::VerificationFailed) => {}
            other => panic!("expected VerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_no_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        assert!(verify_signature(lockfile, &trusted).is_ok());
    }

    #[test]
    fn test_sign_rejects_spaces_in_key_id() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        assert!(sign_lockfile(lockfile, "ci at example", SignatureAlgorithm::Ed25519, &SEED, 0).is_err());
    }

    #[test]
    fn test_sign_rejects_empty_key_id() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        assert!(sign_lockfile(lockfile, "", SignatureAlgorithm::Ed25519, &SEED, 0).is_err());
    }

    #[test]
    fn test_sign_rejects_no_trailing_newline() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA";
        assert!(sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).is_err());
    }

    #[test]
    fn test_verify_ignores_embedded_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let with_embedded = signed.replace("@signature ", "x@signature ");
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        assert!(verify_signature(&with_embedded, &trusted).is_ok());
    }

    #[test]
    fn test_untrusted_key_rejected_with_signed_lockfile() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        match verify_signature(&signed, &trusted) {
            Err(SignatureError::UntrustedKey { key_id }) if key_id == "ci@example.com" => {}
            other => panic!("expected UntrustedKey, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_content_after_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let with_extra = format!("{}extra", signed);
        match verify_signature(&with_extra, &make_trusted()) {
            Err(SignatureError::MalformedDirective { .. }) => {}
            other => panic!("expected MalformedDirective, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_empty_signature() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@signature ci@example.com 00 0 \n";
        match verify_signature(content, &make_trusted()) {
            Err(SignatureError::MalformedDirective { .. }) => {}
            other => panic!("expected MalformedDirective, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_invalid_base64() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@signature ci@example.com 00 0 !!!invalid!!!\n";
        match verify_signature(content, &make_trusted()) {
            Err(SignatureError::InvalidBase64(_)) => {}
            other => panic!("expected InvalidBase64, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_rejects_untrusted_key() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        match verify_signature(&signed, &trusted) {
            Err(SignatureError::UntrustedKey { .. }) => {}
            other => panic!("expected UntrustedKey, got {:?}", other),
        }
    }

    #[test]
    fn test_ml_dsa65_sign_produces_directive() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (_pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let result = sign_lockfile(lockfile, "pq@co.com", SignatureAlgorithm::MlDsa65, &sk_bytes, 0);
        assert!(result.is_ok(), "sign_lockfile MlDsa65 failed: {:?}", result);
        let signed = result.unwrap();
        assert!(signed.contains("@signature pq@co.com 02 0 "));
    }

    #[test]
    fn test_ml_dsa65_sign_and_verify_roundtrip() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);

        let signed = sign_lockfile(lockfile, "pq@test.com", SignatureAlgorithm::MlDsa65, &sk_bytes, 0).unwrap();

        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert("pq@test.com".to_string(), (vk_bytes.to_vec(), SignatureAlgorithm::MlDsa65));

        let result = verify_signature(&signed, &trusted);
        assert!(result.is_ok(), "ML-DSA-65 verify failed: {:?}", result);
    }

    #[test]
    fn test_ml_dsa65_verify_tampered() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);

        let signed = sign_lockfile(lockfile, "pq@test.com", SignatureAlgorithm::MlDsa65, &sk_bytes, 0).unwrap();

        let tampered = signed.replace("r.com", "r.org");
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert("pq@test.com".to_string(), (vk_bytes.to_vec(), SignatureAlgorithm::MlDsa65));

        match verify_signature(&tampered, &trusted) {
            Err(SignatureError::MlDsaVerificationFailed) => {}
            other => panic!("expected MlDsaVerificationFailed, got {:?}", other),
        }
    }

    #[test]
    fn test_ml_dsa65_sign_rejects_wrong_key_length() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let result = sign_lockfile(lockfile, "pq@co.com", SignatureAlgorithm::MlDsa65, &[42u8; 100], 0);
        assert!(matches!(result, Err(SignatureError::MalformedDirective { .. })));
    }

    #[test]
    fn test_parse_signature_directive_accepts_ml_dsa65_algo_id() {
        let sig_bytes = vec![0u8; fips204::ml_dsa_65::SIG_LEN];
        let sig_b64 = base64url::encode(&sig_bytes);
        let line = format!("@signature pq@co.com 02 0 {}", sig_b64);
        let directive = parse_signature_directive(&line).unwrap();
        assert_eq!(directive.algorithm, SignatureAlgorithm::MlDsa65);
        assert_eq!(directive.key_id, "pq@co.com");
    }

    #[test]
    fn test_verify_with_owned_vec_keys() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(lockfile, "ci@example.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();

        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert("ci@example.com".to_string(), (public_key().to_vec(), SignatureAlgorithm::Ed25519));

        assert!(verify_signature(&signed, &trusted).is_ok());
    }

    #[test]
    fn test_ed448_algo_rejected() {
        let sig_bytes = vec![0u8; 64];
        let sig_b64 = base64url::encode(&sig_bytes);
        let line = format!("@signature test@key 01 0 {}", sig_b64);
        let result = parse_signature_directive(&line);
        assert!(matches!(result, Err(SignatureError::UnsupportedSignatureAlgorithm { algo_id: 1 })),
            "expected UnsupportedSignatureAlgorithm for algo_id 01, got {:?}", result);
    }
}
