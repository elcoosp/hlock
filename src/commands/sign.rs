//! `sign` command implementation.

use super::{Ctx, Path, deserialize, read_input, serialize, sign_lockfile, signature};

/// Runs the `sign` command.
pub(crate) fn run(
    file: &Path,
    key_id: &str,
    algorithm: &str,
    private_key: &str,
    expires: u64,
    in_place: bool,
    ctx: Ctx,
) {
    let Ctx { quiet, verbose, .. } = ctx;

    if in_place && file == std::path::Path::new("-") {
        eprintln!("Error: --in-place cannot be used with stdin input");
        std::process::exit(2);
    }
    if verbose {
        eprintln!("[verbose] Reading {}...", file.display());
    }
    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };
    let lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };
    let serialized = match serialize(&lockfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Serialize error: {}", e.error_code(), e);
            std::process::exit(1);
        }
    };

    let algo = match algorithm {
        "mldsa65" => signature::SignatureAlgorithm::MlDsa65,
        _ => signature::SignatureAlgorithm::Ed25519,
    };

    let key_hex = if let Some(path) = private_key.strip_prefix('@') {
        match std::fs::read_to_string(path) {
            Ok(h) => h.trim().to_string(),
            Err(e) => {
                eprintln!("Error reading key file: {e}");
                std::process::exit(2);
            }
        }
    } else {
        private_key.to_string()
    };

    // Strict hex: a typo must fail loudly instead of silently signing with
    // truncated key material (spec §2.1).
    let key_bytes = match hlock::hex::decode(key_hex.trim()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error: private key is not valid hex: {e}");
            std::process::exit(2);
        }
    };

    match sign_lockfile(&serialized, key_id, algo, &key_bytes, expires) {
        Ok(signed) => {
            if in_place {
                if let Err(e) = super::atomic_write(file, &signed) {
                    eprintln!("Error writing {}: {}", file.display(), e);
                    std::process::exit(1);
                }
            } else if !quiet {
                print!("{signed}");
            }
        }
        Err(e) => {
            eprintln!("Signing error: {e}");
            std::process::exit(1);
        }
    }
}
