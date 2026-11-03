use crate::base64url;
use ed25519_dalek::{Signer as EdSigner, Verifier as EdVerifier};
use fips204::traits::{SerDes as FipsSerDes, Signer as FipsSigner, Verifier as FipsVerifier};
use std::collections::HashMap;
use std::hash::BuildHasher;

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
    InvalidBase64(String),
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

///
/// # Errors
///
/// Returns `Err` if `MalformedDirective` occurs; `UnsupportedSignatureAlgorithm` occurs; or if a payload is not valid base64url.
pub fn parse_signature_directive(line: &str) -> Result<SignatureDirective, SignatureError> {
    let rest =
        line.strip_prefix("@signature ")
            .ok_or_else(|| SignatureError::MalformedDirective {
                reason: "missing @signature prefix".to_string(),
            })?;
    let mut parts = rest.splitn(4, ' ');
    let key_id = parts
        .next()
        .ok_or_else(|| SignatureError::MalformedDirective {
            reason: "missing key_id".to_string(),
        })?
        .to_string();
    let algo_hex = parts
        .next()
        .ok_or_else(|| SignatureError::MalformedDirective {
            reason: "missing algo_id".to_string(),
        })?;
    let expires_str = parts
        .next()
        .ok_or_else(|| SignatureError::MalformedDirective {
            reason: "missing expires_epoch".to_string(),
        })?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| SignatureError::MalformedDirective {
            reason: "missing signature".to_string(),
        })?;
    if key_id.contains(' ') || key_id.is_empty() {
        return Err(SignatureError::MalformedDirective {
            reason: "invalid key_id".to_string(),
        });
    }
    let algo_id = if algo_hex.len() == 2 && algo_hex.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        u8::from_str_radix(algo_hex, 16).map_err(|_| SignatureError::MalformedDirective {
            reason: "algo_id must be two hex digits".to_string(),
        })?
    } else {
        return Err(SignatureError::MalformedDirective {
            reason: "algo_id must be two hex digits".to_string(),
        });
    };
    let algorithm = match algo_id {
        0x00 => SignatureAlgorithm::Ed25519,
        0x02 => SignatureAlgorithm::MlDsa65,
        _ => return Err(SignatureError::UnsupportedSignatureAlgorithm { algo_id }),
    };
    let expires_epoch: u64 =
        expires_str
            .parse()
            .map_err(|_| SignatureError::MalformedDirective {
                reason: "expires_epoch must be decimal".to_string(),
            })?;
    let signature_bytes = base64url::decode(sig_b64.as_bytes())
        .map_err(|err| SignatureError::InvalidBase64(err.to_string()))?;
    let expected_len = match algorithm {
        SignatureAlgorithm::Ed25519 => 64,
        SignatureAlgorithm::MlDsa65 => fips204::ml_dsa_65::SIG_LEN,
    };
    if expected_len > 0 && signature_bytes.len() != expected_len {
        return Err(SignatureError::MalformedDirective {
            reason: format!(
                "expected {} signature bytes, got {}",
                expected_len,
                signature_bytes.len()
            ),
        });
    }
    Ok(SignatureDirective {
        key_id,
        algorithm,
        expires_epoch,
        signature_bytes,
    })
}

///
/// # Errors
///
/// Returns `Err` if `MalformedDirective` occurs.
pub fn sign_lockfile(
    serialized_lockfile: &str,
    key_id: &str,
    algorithm: SignatureAlgorithm,
    private_key: &[u8],
    expires_epoch: u64,
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
    let (algo_id, encoded_sig) = match algorithm {
        SignatureAlgorithm::Ed25519 => {
            if private_key.len() != 32 {
                return Err(SignatureError::MalformedDirective {
                    reason: "Ed25519 private key must be 32 bytes".to_string(),
                });
            }
            let seed: [u8; 32] =
                private_key
                    .try_into()
                    .map_err(|_| SignatureError::MalformedDirective {
                        reason: "invalid Ed25519 seed".to_string(),
                    })?;
            let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
            let sig = signing_key.sign(serialized_lockfile.as_bytes());
            (0x00u8, base64url::encode(sig.to_bytes().as_ref()))
        }
        SignatureAlgorithm::MlDsa65 => {
            if private_key.len() != fips204::ml_dsa_65::SK_LEN {
                return Err(SignatureError::MalformedDirective {
                    reason: format!(
                        "ML-DSA-65 private key must be {} bytes",
                        fips204::ml_dsa_65::SK_LEN
                    ),
                });
            }
            let key_bytes: <fips204::ml_dsa_65::PrivateKey as FipsSerDes>::ByteArray = private_key
                .try_into()
                .map_err(|_| SignatureError::MalformedDirective {
                    reason: "invalid ML-DSA-65 private key".to_string(),
                })?;
            let sk: fips204::ml_dsa_65::PrivateKey = FipsSerDes::try_from_bytes(key_bytes)
                .map_err(|e| SignatureError::MalformedDirective {
                    reason: format!("invalid ML-DSA-65 private key: {e}"),
                })?;
            let sig: <fips204::ml_dsa_65::PrivateKey as FipsSigner>::Signature =
                FipsSigner::try_sign(&sk, serialized_lockfile.as_bytes(), &[]).map_err(|e| {
                    SignatureError::MalformedDirective {
                        reason: format!("ML-DSA-65 signing failed: {e}"),
                    }
                })?;
            (0x02u8, base64url::encode(&sig[..]))
        }
    };
    Ok(format!(
        "{serialized_lockfile}@signature {key_id} {algo_id:02x} {expires_epoch} {encoded_sig}\n"
    ))
}

/// Verifies every `@signature` directive in `lockfile_content` against `trusted_keys`.
///
/// A lockfile without any `@signature` line is considered unsigned and passes
/// at this layer; the CLI gates (`verify`/`check`/`ci`) decide whether an
/// unsigned file is acceptable for the requested trust policy.
///
/// `now_epoch` governs signature expiry (spec §2.4): callers pass the CLI
/// `--time` override or the wall clock.
///
/// # Errors
///
/// Returns `Err` if a directive is malformed ([`SignatureError::MalformedDirective`]),
/// the key id is not present in `trusted_keys` ([`SignatureError::UntrustedKey`]),
/// the signature has expired ([`SignatureError::SignatureExpired`]),
/// or the cryptographic verification fails ([`SignatureError::VerificationFailed`] or
/// [`SignatureError::MlDsaVerificationFailed`]).
pub fn verify_signature<S: BuildHasher + Default>(
    lockfile_content: &str,
    trusted_keys: &HashMap<String, (Vec<u8>, SignatureAlgorithm), S>,
    now_epoch: u64,
) -> Result<(), SignatureError> {
    let Some((sig_start, sig_directives)) = collect_signature_region(lockfile_content)? else {
        return Ok(());
    };
    let message = &lockfile_content.as_bytes()[..sig_start];
    for directive in &sig_directives {
        let (expected_pub_key, expected_algo) = trusted_key_for(directive, trusted_keys)?;
        if directive.algorithm != expected_algo {
            return Err(SignatureError::MalformedDirective {
                reason: format!(
                    "key '{}' uses algo {:?} but trusted key expects {:?}",
                    directive.key_id, directive.algorithm, expected_algo
                ),
            });
        }
        check_signature_expiry(directive, now_epoch)?;
        match directive.algorithm {
            SignatureAlgorithm::Ed25519 => verify_ed25519(message, directive, &expected_pub_key)?,
            SignatureAlgorithm::MlDsa65 => verify_mldsa65(message, directive, &expected_pub_key)?,
        }
    }
    Ok(())
}

/// True when the content carries at least one `@signature` directive line.
#[must_use]
pub fn has_signature_block(lockfile_content: &str) -> bool {
    lockfile_content
        .lines()
        .any(|line| line.starts_with("@signature "))
}

/// Scans the `@signature` block, returning its start offset and parsed directives.
///
/// Returns `Ok(None)` when the lockfile is unsigned or the block is not a
/// standalone trailing section (both treated as "nothing to verify").
fn collect_signature_region(
    lockfile_content: &str,
) -> Result<Option<(usize, Vec<SignatureDirective>)>, SignatureError> {
    let bytes = lockfile_content.as_bytes();
    let mut sig_start: Option<usize> = None;
    let mut sig_directives: Vec<SignatureDirective> = Vec::new();
    let mut offset = 0usize;
    while offset <= bytes.len() {
        let line_end = bytes[offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map_or(bytes.len(), |i| offset + i);
        let mut line = &lockfile_content[offset..line_end];
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        if line.starts_with("@signature ") {
            if sig_start.is_none() {
                sig_start = Some(offset);
            }
            sig_directives.push(parse_signature_directive(line)?);
        }
        if line_end >= bytes.len() {
            break;
        }
        offset = line_end + 1;
    }
    if sig_directives.is_empty() {
        return Ok(None);
    }
    let Some(sig_start) = sig_start else {
        // Unreachable when a directive was parsed, but treat defensively as unsigned.
        return Ok(None);
    };
    if sig_start > 0 && bytes[sig_start - 1] != b'\n' {
        return Ok(None);
    }
    let last_line_end = bytes[sig_start..]
        .iter()
        .rposition(|&b| b == b'\n')
        .map_or(sig_start, |i| sig_start + i);
    // Everything after the last signature line must be empty (i.e. the file
    // ends with the block and its final newline).
    if lockfile_content[last_line_end..]
        .lines()
        .any(|l| !l.trim().is_empty())
    {
        return Err(SignatureError::MalformedDirective {
            reason: "@signature must be the last lines in the file".to_string(),
        });
    }
    Ok(Some((sig_start, sig_directives)))
}

/// Resolves the trusted public key and algorithm for a signature directive.
fn trusted_key_for<S: BuildHasher + Default>(
    directive: &SignatureDirective,
    trusted_keys: &HashMap<String, (Vec<u8>, SignatureAlgorithm), S>,
) -> Result<(Vec<u8>, SignatureAlgorithm), SignatureError> {
    trusted_keys.get(&directive.key_id).map_or_else(
        || {
            Err(SignatureError::UntrustedKey {
                key_id: directive.key_id.clone(),
            })
        },
        |(key, algo)| Ok((key.clone(), *algo)),
    )
}

/// Rejects the directive when its expiry epoch is in the past at `now_epoch`.
/// `expires_epoch == 0` means the signature never expires.
fn check_signature_expiry(
    directive: &SignatureDirective,
    now_epoch: u64,
) -> Result<(), SignatureError> {
    if directive.expires_epoch == 0 {
        return Ok(());
    }
    if now_epoch > directive.expires_epoch {
        return Err(SignatureError::SignatureExpired {
            key_id: directive.key_id.clone(),
            expires_epoch: directive.expires_epoch,
        });
    }
    Ok(())
}

/// Verifies an Ed25519 signature over `message` with the trusted public key.
fn verify_ed25519(
    message: &[u8],
    directive: &SignatureDirective,
    expected_pub_key: &[u8],
) -> Result<(), SignatureError> {
    if expected_pub_key.len() != 32 {
        return Err(SignatureError::MalformedDirective {
            reason: "Ed25519 public key must be 32 bytes".to_string(),
        });
    }
    let pk_bytes: [u8; 32] =
        expected_pub_key
            .try_into()
            .map_err(|_| SignatureError::MalformedDirective {
                reason: "invalid Ed25519 public key".to_string(),
            })?;
    let sig_bytes: [u8; 64] = directive
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::MalformedDirective {
            reason: "invalid Ed25519 signature".to_string(),
        })?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|e| {
        SignatureError::MalformedDirective {
            reason: format!("invalid Ed25519 public key: {e}"),
        }
    })?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key
        .verify(message, &signature)
        .map_err(|_| SignatureError::VerificationFailed)
}

/// Verifies an ML-DSA-65 signature over `message` with the trusted public key.
fn verify_mldsa65(
    message: &[u8],
    directive: &SignatureDirective,
    expected_pub_key: &[u8],
) -> Result<(), SignatureError> {
    if expected_pub_key.len() != fips204::ml_dsa_65::PK_LEN {
        return Err(SignatureError::MalformedDirective {
            reason: format!(
                "ML-DSA-65 public key must be {} bytes",
                fips204::ml_dsa_65::PK_LEN
            ),
        });
    }
    let pk_bytes: <fips204::ml_dsa_65::PublicKey as FipsSerDes>::ByteArray = expected_pub_key
        .try_into()
        .map_err(|_| SignatureError::MalformedDirective {
            reason: "invalid ML-DSA-65 public key".to_string(),
        })?;
    let vk: fips204::ml_dsa_65::PublicKey =
        FipsSerDes::try_from_bytes(pk_bytes).map_err(|e| SignatureError::MalformedDirective {
            reason: format!("invalid ML-DSA-65 public key: {e}"),
        })?;
    let sig_bytes: <fips204::ml_dsa_65::PublicKey as FipsVerifier>::Signature = directive
        .signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SignatureError::MalformedDirective {
            reason: "invalid ML-DSA-65 signature".to_string(),
        })?;
    if !FipsVerifier::verify(&vk, message, &sig_bytes, &[]) {
        return Err(SignatureError::MlDsaVerificationFailed);
    }
    Ok(())
}

/// Domain-separation tag for the canonical root-rotation payload.
const ROTATION_DOMAIN: &[u8] = b"hlock/rotation/v1";

/// Builds the canonical rotation payload signed by the *old* root key:
///
/// `"hlock/rotation/v1" || len32le(new_key_id) || new_key_id || algo_id ||
/// len32le(new_pubkey) || new_pubkey || new_expires.u64le || len8(role) ||
/// role || len32le(old_key_id) || old_key_id || threshold`
///
/// Every variable-length field is length-prefixed, so the encoding is
/// injective and no field boundary can be forged.
#[must_use]
#[allow(clippy::cast_possible_truncation)] // length prefixes of bounded fields
pub fn rotation_payload(
    new_key_id: &str,
    algorithm: SignatureAlgorithm,
    new_public_key: &[u8],
    new_expires_epoch: u64,
    new_role: crate::policy::TrustRole,
    old_key_id: &str,
    threshold: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        ROTATION_DOMAIN.len()
            + 4
            + new_key_id.len()
            + 1
            + 4
            + new_public_key.len()
            + 8
            + 1
            + 4
            + old_key_id.len()
            + 1,
    );
    out.extend_from_slice(ROTATION_DOMAIN);
    out.extend_from_slice(&(new_key_id.len() as u32).to_le_bytes());
    out.extend_from_slice(new_key_id.as_bytes());
    out.push(match algorithm {
        SignatureAlgorithm::Ed25519 => 0x00,
        SignatureAlgorithm::MlDsa65 => 0x02,
    });
    out.extend_from_slice(&(new_public_key.len() as u32).to_le_bytes());
    out.extend_from_slice(new_public_key);
    out.extend_from_slice(&new_expires_epoch.to_le_bytes());
    out.push(new_role.as_str().len() as u8);
    out.extend_from_slice(new_role.as_str().as_bytes());
    out.extend_from_slice(&(old_key_id.len() as u32).to_le_bytes());
    out.extend_from_slice(old_key_id.as_bytes());
    out.push(threshold);
    out
}

/// Signs the canonical rotation payload with the old root's private key.
///
/// # Errors
/// Returns [`SignatureError::MalformedDirective`] when the key length does
/// not match the algorithm.
#[allow(clippy::too_many_arguments)] // explicit crypto parameter list
pub fn sign_rotation(
    new_key_id: &str,
    algorithm: SignatureAlgorithm,
    new_public_key: &[u8],
    new_expires_epoch: u64,
    new_role: crate::policy::TrustRole,
    old_key_id: &str,
    threshold: u8,
    old_algorithm: SignatureAlgorithm,
    old_private_key: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    let payload = rotation_payload(
        new_key_id,
        algorithm,
        new_public_key,
        new_expires_epoch,
        new_role,
        old_key_id,
        threshold,
    );
    match old_algorithm {
        SignatureAlgorithm::Ed25519 => {
            let seed: [u8; 32] =
                old_private_key
                    .try_into()
                    .map_err(|_| SignatureError::MalformedDirective {
                        reason: "Ed25519 private key must be 32 bytes".to_string(),
                    })?;
            let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
            Ok(sk.sign(&payload).to_bytes().to_vec())
        }
        SignatureAlgorithm::MlDsa65 => {
            let key_bytes: <fips204::ml_dsa_65::PrivateKey as FipsSerDes>::ByteArray =
                old_private_key
                    .try_into()
                    .map_err(|_| SignatureError::MalformedDirective {
                        reason: format!(
                            "ML-DSA-65 private key must be {} bytes",
                            fips204::ml_dsa_65::SK_LEN
                        ),
                    })?;
            let sk: fips204::ml_dsa_65::PrivateKey = FipsSerDes::try_from_bytes(key_bytes)
                .map_err(|e| SignatureError::MalformedDirective {
                    reason: format!("invalid ML-DSA-65 private key: {e}"),
                })?;
            let sig: <fips204::ml_dsa_65::PrivateKey as FipsSigner>::Signature =
                FipsSigner::try_sign(&sk, &payload, &[]).map_err(|e| {
                    SignatureError::MalformedDirective {
                        reason: format!("ML-DSA-65 signing failed: {e}"),
                    }
                })?;
            Ok(sig.to_vec())
        }
    }
}

/// Verifies a `@root-rotation` record against the *old* root's public key.
///
/// This is the check `verify` / `check` / `ci` enforce: a rotation record
/// whose signature was not produced by the old root key is rejected
/// (mapped to `E0306 RotationSignatureInvalid` by the lockfile layer).
///
/// # Errors
/// Returns [`SignatureError::VerificationFailed`] /
/// [`SignatureError::MlDsaVerificationFailed`] when the signature is invalid
/// and [`SignatureError::MalformedDirective`] when the key material is
/// malformed.
pub fn verify_rotation_signature(
    rotation: &crate::lockfile::TrustRootRotation,
    old_public_key: &[u8],
    old_algorithm: SignatureAlgorithm,
) -> Result<(), SignatureError> {
    let payload = rotation_payload(
        &rotation.new_key_id,
        rotation.new_algorithm,
        &rotation.new_public_key,
        rotation.new_expires_epoch,
        rotation.new_role,
        &rotation.old_key_id,
        rotation.threshold,
    );
    match old_algorithm {
        SignatureAlgorithm::Ed25519 => {
            if old_public_key.len() != ed25519_dalek::PUBLIC_KEY_LENGTH {
                return Err(SignatureError::MalformedDirective {
                    reason: "Ed25519 public key must be 32 bytes".to_string(),
                });
            }
            let pk_bytes: [u8; ed25519_dalek::PUBLIC_KEY_LENGTH] = old_public_key
                .try_into()
                .map_err(|_| SignatureError::MalformedDirective {
                    reason: "invalid Ed25519 public key".to_string(),
                })?;
            let pk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|_| SignatureError::VerificationFailed)?;
            let Ok(sig) = ed25519_dalek::Signature::from_slice(&rotation.rotation_signature) else {
                return Err(SignatureError::VerificationFailed);
            };
            pk.verify(&payload, &sig)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        SignatureAlgorithm::MlDsa65 => {
            let key_bytes: <fips204::ml_dsa_65::PublicKey as FipsSerDes>::ByteArray =
                old_public_key
                    .try_into()
                    .map_err(|_| SignatureError::MalformedDirective {
                        reason: format!(
                            "ML-DSA-65 public key must be {} bytes",
                            fips204::ml_dsa_65::PK_LEN
                        ),
                    })?;
            let vk: fips204::ml_dsa_65::PublicKey =
                FipsSerDes::try_from_bytes(key_bytes).map_err(|e| {
                    SignatureError::MalformedDirective {
                        reason: format!("invalid ML-DSA-65 public key: {e}"),
                    }
                })?;
            let sig_bytes: <fips204::ml_dsa_65::PublicKey as FipsVerifier>::Signature = rotation
                .rotation_signature
                .as_slice()
                .try_into()
                .map_err(|_| SignatureError::MalformedDirective {
                    reason: "invalid ML-DSA-65 signature".to_string(),
                })?;
            if !FipsVerifier::verify(&vk, &payload, &sig_bytes, &[]) {
                return Err(SignatureError::MlDsaVerificationFailed);
            }
            Ok(())
        }
    }
}

/// Builds the new [`crate::policy::TrustRoot`] a rotation record introduces.
#[must_use]
pub fn rotation_new_root(
    rotation: &crate::lockfile::TrustRootRotation,
) -> crate::policy::TrustRoot {
    crate::policy::TrustRoot {
        key_id: rotation.new_key_id.clone(),
        algorithm: rotation.new_algorithm,
        public_key: rotation.new_public_key.clone(),
        expires_epoch: rotation.new_expires_epoch,
        role: rotation.new_role,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    fn public_key() -> [u8; 32] {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&SEED);
        *signing_key.verifying_key().as_bytes()
    }

    fn make_trusted() -> HashMap<String, (Vec<u8>, SignatureAlgorithm)> {
        let mut m = HashMap::new();
        m.insert(
            "ci@example.com".to_string(),
            (public_key().to_vec(), SignatureAlgorithm::Ed25519),
        );
        m
    }
    #[test]
    fn test_parse_signature_directive_v12() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@co.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            1_735_689_600,
        )
        .unwrap();
        let sig_line = signed
            .lines()
            .find(|l| l.starts_with("@signature "))
            .unwrap();
        let directive = parse_signature_directive(sig_line).unwrap();
        assert_eq!(directive.key_id, "ci@co.com");
        assert_eq!(directive.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(directive.expires_epoch, 1_735_689_600);
        assert_eq!(directive.signature_bytes.len(), 64);
    }

    #[test]
    fn test_sign_v12_ed25519_format() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed =
            sign_lockfile(lockfile, "ci@co.com", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        assert!(signed.contains("@signature ci@co.com 00 0 "));
        assert!(signed.ends_with('\n'));
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        assert!(signed.starts_with(lockfile));
        assert!(signed.contains("@signature ci@example.com 00 0 "));
        assert!(signed.ends_with('\n'));
        assert!(verify_signature(&signed, &make_trusted(), 0).is_ok());
    }

    #[test]
    fn test_verify_tampered_message() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        let tampered = signed.replace("r.com", "r.org");
        match verify_signature(&tampered, &make_trusted(), 0) {
            Err(SignatureError::VerificationFailed) => {}
            other => panic!("expected VerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_no_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        assert!(verify_signature(lockfile, &trusted, 0).is_ok());
    }

    #[test]
    fn test_sign_rejects_spaces_in_key_id() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        assert!(
            sign_lockfile(
                lockfile,
                "ci at example",
                SignatureAlgorithm::Ed25519,
                &SEED,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn test_sign_rejects_empty_key_id() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        assert!(sign_lockfile(lockfile, "", SignatureAlgorithm::Ed25519, &SEED, 0).is_err());
    }

    #[test]
    fn test_sign_rejects_no_trailing_newline() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA";
        assert!(
            sign_lockfile(
                lockfile,
                "ci@example.com",
                SignatureAlgorithm::Ed25519,
                &SEED,
                0
            )
            .is_err()
        );
    }

    #[test]
    fn test_verify_ignores_embedded_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        let with_embedded = signed.replace("@signature ", "x@signature ");
        let trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        assert!(verify_signature(&with_embedded, &trusted, 0).is_ok());
    }

    #[test]
    fn test_untrusted_key_rejected_with_signed_lockfile() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        let trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        match verify_signature(&signed, &trusted, 0) {
            Err(SignatureError::UntrustedKey { key_id }) if key_id == "ci@example.com" => {}
            other => panic!("expected UntrustedKey, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_content_after_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        let with_extra = format!("{signed}extra");
        match verify_signature(&with_extra, &make_trusted(), 0) {
            Err(SignatureError::MalformedDirective { .. }) => {}
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_empty_signature() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@signature ci@example.com 00 0 \n";
        match verify_signature(content, &make_trusted(), 0) {
            Err(SignatureError::MalformedDirective { .. }) => {}
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_invalid_base64() {
        let content =
            "@source 0 https://r.com/\n\npkg\tAAAA\n@signature ci@example.com 00 0 !!!invalid!!!\n";
        match verify_signature(content, &make_trusted(), 0) {
            Err(SignatureError::InvalidBase64(_)) => {}
            other => panic!("expected InvalidBase64, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_untrusted_key() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();
        let trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        match verify_signature(&signed, &trusted, 0) {
            Err(SignatureError::UntrustedKey { .. }) => {}
            other => panic!("expected UntrustedKey, got {other:?}"),
        }
    }

    #[test]
    fn test_ml_dsa65_sign_produces_directive() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (_pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let result = sign_lockfile(
            lockfile,
            "pq@co.com",
            SignatureAlgorithm::MlDsa65,
            &sk_bytes,
            0,
        );
        assert!(result.is_ok(), "sign_lockfile MlDsa65 failed: {result:?}");
        let signed = result.unwrap();
        assert!(signed.contains("@signature pq@co.com 02 0 "));
    }

    #[test]
    fn test_ml_dsa65_sign_and_verify_roundtrip() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);

        let signed = sign_lockfile(
            lockfile,
            "pq@test.com",
            SignatureAlgorithm::MlDsa65,
            &sk_bytes,
            0,
        )
        .unwrap();

        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert(
            "pq@test.com".to_string(),
            (vk_bytes.to_vec(), SignatureAlgorithm::MlDsa65),
        );

        let result = verify_signature(&signed, &trusted, 0);
        assert!(result.is_ok(), "ML-DSA-65 verify failed: {result:?}");
    }

    #[test]
    fn test_ml_dsa65_verify_tampered() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);

        let signed = sign_lockfile(
            lockfile,
            "pq@test.com",
            SignatureAlgorithm::MlDsa65,
            &sk_bytes,
            0,
        )
        .unwrap();

        let tampered = signed.replace("r.com", "r.org");
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert(
            "pq@test.com".to_string(),
            (vk_bytes.to_vec(), SignatureAlgorithm::MlDsa65),
        );

        match verify_signature(&tampered, &trusted, 0) {
            Err(SignatureError::MlDsaVerificationFailed) => {}
            other => panic!("expected MlDsaVerificationFailed, got {other:?}"),
        }
    }

    #[test]
    fn test_ml_dsa65_sign_rejects_wrong_key_length() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let result = sign_lockfile(
            lockfile,
            "pq@co.com",
            SignatureAlgorithm::MlDsa65,
            &[42u8; 100],
            0,
        );
        assert!(matches!(
            result,
            Err(SignatureError::MalformedDirective { .. })
        ));
    }

    #[test]
    fn test_parse_signature_directive_accepts_ml_dsa65_algo_id() {
        let sig_bytes = vec![0u8; fips204::ml_dsa_65::SIG_LEN];
        let sig_b64 = base64url::encode(&sig_bytes);
        let line = format!("@signature pq@co.com 02 0 {sig_b64}");
        let directive = parse_signature_directive(&line).unwrap();
        assert_eq!(directive.algorithm, SignatureAlgorithm::MlDsa65);
        assert_eq!(directive.key_id, "pq@co.com");
    }

    #[test]
    fn test_verify_with_owned_vec_keys() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            0,
        )
        .unwrap();

        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert(
            "ci@example.com".to_string(),
            (public_key().to_vec(), SignatureAlgorithm::Ed25519),
        );

        assert!(verify_signature(&signed, &trusted, 0).is_ok());
    }

    #[test]
    fn test_ed448_algo_rejected() {
        let sig_bytes = vec![0u8; 64];
        let sig_b64 = base64url::encode(&sig_bytes);
        let line = format!("@signature test@key 01 0 {sig_b64}");
        let result = parse_signature_directive(&line);
        assert!(
            matches!(
                result,
                Err(SignatureError::UnsupportedSignatureAlgorithm { algo_id: 1 })
            ),
            "expected UnsupportedSignatureAlgorithm for algo_id 01, got {result:?}"
        );
    }

    #[test]
    fn test_parse_signature_directive_error_branches() {
        // Missing the @signature prefix entirely.
        match parse_signature_directive("@sig ci@x 00 0 AAAA") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("prefix"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Empty key id (double space after the prefix).
        match parse_signature_directive("@signature  00 0 AAAA") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("key_id"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Missing algo id.
        match parse_signature_directive("@signature ci@x") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("algo_id"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Missing expires.
        match parse_signature_directive("@signature ci@x 00") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("expires"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Missing signature.
        match parse_signature_directive("@signature ci@x 00 0") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("signature"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Non-hex algo id.
        match parse_signature_directive("@signature ci@x zz 0 AAAA") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("hex"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Non-decimal expires.
        match parse_signature_directive("@signature ci@x 00 later AAAA") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("decimal"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Signature payload of the wrong length.
        match parse_signature_directive("@signature ci@x 00 0 AAAA") {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("expected 64"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
        // Display strings for the standalone error variants.
        assert_eq!(
            SignatureError::InvalidBase64(String::from("bad")).to_string(),
            "Base64URL decode failed: bad"
        );
        assert_eq!(
            SignatureError::VerificationFailed.to_string(),
            "Ed25519 verification failed"
        );
        assert_eq!(
            SignatureError::MlDsaVerificationFailed.to_string(),
            "ML-DSA-65 verification failed"
        );
        let expired = SignatureError::SignatureExpired {
            key_id: "k".to_string(),
            expires_epoch: 7,
        };
        assert_eq!(expired.to_string(), "Signature from 'k' expired at epoch 7");
        let unsupported = SignatureError::UnsupportedSignatureAlgorithm { algo_id: 9 };
        assert_eq!(
            unsupported.to_string(),
            "Unsupported signature algorithm ID 9"
        );
    }

    #[test]
    fn test_sign_ed25519_rejects_wrong_key_length() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let result = sign_lockfile(lockfile, "ci@x", SignatureAlgorithm::Ed25519, &[0u8; 31], 0);
        match result {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("32 bytes"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_expired_signature() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed = sign_lockfile(
            lockfile,
            "ci@example.com",
            SignatureAlgorithm::Ed25519,
            &SEED,
            1_000,
        )
        .unwrap();
        match verify_signature(&signed, &make_trusted(), 2_000) {
            Err(SignatureError::SignatureExpired {
                key_id,
                expires_epoch,
            }) => {
                assert_eq!(key_id, "ci@example.com");
                assert_eq!(expires_epoch, 1_000);
            }
            other => panic!("expected SignatureExpired, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_algorithm_mismatch_with_trusted_key() {
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed =
            sign_lockfile(lockfile, "pq@x", SignatureAlgorithm::MlDsa65, &sk_bytes, 0).unwrap();
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        // The trusted key claims Ed25519 while the directive says ML-DSA-65.
        trusted.insert(
            "pq@x".to_string(),
            (vk_bytes.to_vec(), SignatureAlgorithm::Ed25519),
        );
        match verify_signature(&signed, &trusted, 0) {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("uses algo"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_wrong_ed25519_public_key_length() {
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed =
            sign_lockfile(lockfile, "ci@x", SignatureAlgorithm::Ed25519, &SEED, 0).unwrap();
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert(
            "ci@x".to_string(),
            (vec![1, 2, 3], SignatureAlgorithm::Ed25519),
        );
        match verify_signature(&signed, &trusted, 0) {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("32 bytes"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_rejects_wrong_ml_dsa65_public_key_length() {
        let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
        let sk_bytes = FipsSerDes::into_bytes(sk);
        let vk_bytes = FipsSerDes::into_bytes(pk);
        let lockfile = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let signed =
            sign_lockfile(lockfile, "pq@x", SignatureAlgorithm::MlDsa65, &sk_bytes, 0).unwrap();
        let mut trusted: HashMap<String, (Vec<u8>, SignatureAlgorithm)> = HashMap::new();
        trusted.insert(
            "pq@x".to_string(),
            (vk_bytes[..16].to_vec(), SignatureAlgorithm::MlDsa65),
        );
        match verify_signature(&signed, &trusted, 0) {
            Err(SignatureError::MalformedDirective { reason }) => {
                assert!(reason.contains("ML-DSA-65 public key"), "{reason}");
            }
            other => panic!("expected MalformedDirective, got {other:?}"),
        }
    }
}
