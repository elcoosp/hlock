//! Sigstore / cosign signature verification (G09)
use std::path::Path;
use std::process::Command;

pub fn verify_sigstore(lockfile_path: &Path, bundle_path: Option<&Path>) -> Result<(), String> {
    let bundle = match bundle_path {
        Some(p) => p.to_path_buf(),
        None => {
            let mut default = lockfile_path.to_path_buf();
            default.set_extension("sigstore");
            if !default.exists() {
                return Err(format!(
                    "No Sigstore bundle found (expected at {}). Provide --bundle or ensure a .sigstore file exists.",
                    default.display()
                ));
            }
            default
        }
    };

    let output = Command::new("cosign")
        .arg("verify-blob")
        .arg("--bundle").arg(&bundle)
        .arg("--certificate-oidc-issuer").arg("https://token.actions.githubusercontent.com")
        .arg("--certificate-identity-regexp").arg(".*")
        .arg(lockfile_path)
        .output()
        .map_err(|e| format!("Failed to execute cosign. Is it installed? {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("cosign verification failed: {}", stderr));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn test_verify_sigstore_missing_bundle() {
        let tmp = std::env::temp_dir().join("hlock_sigstore_test_lockfile");
        fs::write(&tmp, b"dummy lockfile content").unwrap();
        let result = verify_sigstore(&tmp, None);
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
        let result = verify_sigstore(&tmp, None);
        if let Err(e) = &result {
            assert!(e.contains("cosign") || e.contains("Failed to execute"));
        }
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&sig);
    }
}
