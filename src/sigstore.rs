//! Sigstore / cosign signature verification (G09)
//!
//! v1.0.1: the cosign invocation no longer trusts any identity. Keyless
//! verification is only meaningful when the expected certificate identity is
//! pinned; hlock derives it from the lockfile's declared SLSA builder (the
//! `@provenance` / inline-attestation builder URL) and anchors the regexp to
//! exactly that prefix. An operator may widen it via
//! `HLOCK_SIGSTORE_IDENTITY_REGEXP`, but `.*`-style match-anything
//! verification is never applied silently.
use std::path::Path;
use std::process::Command;

/// Escapes regex metacharacters so a builder URL can be anchored literally.
fn escape_regex(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if "\\.^$|?*+()[]{}".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Resolves the certificate identity regexp: an explicit operator override
/// wins, otherwise the SLSA builder URL is anchored literally. With neither,
/// keyless verification is refused.
fn resolve_identity_regexp(
    identity_prefix: Option<&str>,
    custom: Option<&str>,
) -> Result<String, String> {
    if let Some(custom) = custom.map(str::trim).filter(|c| !c.is_empty()) {
        return Ok(custom.to_string());
    }
    match identity_prefix {
        Some(prefix) => Ok(format!("^{}", escape_regex(prefix))),
        None => Err(
            "refusing keyless verification without a pinned identity: no SLSA builder \
             provenance found and HLOCK_SIGSTORE_IDENTITY_REGEXP is unset"
                .to_string(),
        ),
    }
}

///
/// # Errors
///
/// Returns `Err` when cosign is missing, fails, or when no bundle is found.
/// `identity_prefix` (the SLSA builder URL) anchors the accepted certificate
/// identity; without it the caller must supply `HLOCK_SIGSTORE_IDENTITY_REGEXP`.
pub fn verify_sigstore(
    lockfile_path: &Path,
    bundle_path: Option<&Path>,
    identity_prefix: Option<&str>,
) -> Result<(), String> {
    let bundle = if let Some(p) = bundle_path {
        p.to_path_buf()
    } else {
        let mut default = lockfile_path.to_path_buf();
        default.set_extension("sigstore");
        if !default.exists() {
            return Err(format!(
                "No Sigstore bundle found (expected at {}). Provide --bundle or ensure a .sigstore file exists.",
                default.display()
            ));
        }
        default
    };

    let custom = std::env::var("HLOCK_SIGSTORE_IDENTITY_REGEXP").ok();
    let identity_regexp = resolve_identity_regexp(identity_prefix, custom.as_deref())?;

    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle")
        .arg(&bundle)
        .arg("--certificate-oidc-issuer")
        .arg("https://token.actions.githubusercontent.com")
        .arg("--certificate-identity-regexp")
        .arg(&identity_regexp)
        .arg(lockfile_path)
        .output()
        .map_err(|e| format!("Failed to execute cosign. Is it installed? {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cosign verification failed: {stderr}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_verify_sigstore_missing_bundle() {
        let tmp = std::env::temp_dir().join("hlock_sigstore_test_lockfile");
        fs::write(&tmp, b"dummy lockfile content").unwrap();
        let result = verify_sigstore(&tmp, None, None);
        assert!(result.is_err());
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_verify_sigstore_missing_cosign() {
        let tmp = std::env::temp_dir().join("hlock_sigstore_test_lockfile2");
        let _ = fs::write(&tmp, b"dummy");
        let mut sig = tmp.clone();
        sig.set_extension("sigstore");
        let _ = fs::write(&sig, b"dummy bundle");
        let result = verify_sigstore(&tmp, None, Some("https://github.com/actions"));
        if let Err(e) = &result {
            assert!(e.contains("cosign") || e.contains("Failed to execute"));
        }
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&sig);
    }

    #[test]
    fn resolve_identity_prefers_builder_over_nothing() {
        let resolved = resolve_identity_regexp(Some("https://github.com/actions"), None).unwrap();
        assert_eq!(resolved, r"^https://github\.com/actions");
    }

    #[test]
    fn resolve_identity_refuses_unpinned() {
        let err = resolve_identity_regexp(None, None).unwrap_err();
        assert!(err.contains("refusing keyless verification"));
    }

    #[test]
    fn resolve_identity_custom_wins() {
        let resolved =
            resolve_identity_regexp(Some("https://builder/"), Some("^https://other/")).unwrap();
        assert_eq!(resolved, "^https://other/");
    }

    #[test]
    fn escape_regex_anchors_metacharacters() {
        assert_eq!(
            escape_regex("https://github.com/a*b"),
            "https://github\\.com/a\\*b"
        );
    }
}
