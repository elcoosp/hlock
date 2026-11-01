//! `keygen` command implementation — generates signing keypairs.

use super::{Ctx, Path};
use hlock::signature::SignatureAlgorithm;

/// Runs the `keygen` command.
pub(crate) fn run(algorithm: &str, key_id: &str, expires: u64, out: Option<&Path>, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;

    let (algo, private_hex, public_hex) = match algorithm {
        "ed25519" => {
            let (sk, pk) = generate_ed25519();
            (SignatureAlgorithm::Ed25519, sk, pk)
        }
        "ml-dsa-65" | "mldsa65" => {
            let (sk, pk) = generate_ml_dsa_65();
            (SignatureAlgorithm::MlDsa65, sk, pk)
        }
        other => {
            eprintln!("Error: unknown algorithm '{other}'. Supported: ed25519, ml-dsa-65");
            std::process::exit(2);
        }
    };

    // Write the private key to a file when requested; it must never sit in a shell history.
    if let Some(path) = out {
        if let Err(e) = std::fs::write(path, format!("{private_hex}\n")) {
            eprintln!("Error writing private key: {e}");
            std::process::exit(2);
        }
        #[cfg(unix)]
        restrict_permissions(path);
    }

    if quiet {
        return;
    }

    let algo_name = match algo {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::MlDsa65 => "mldsa65",
    };

    println!("Generated a new {algo_name} keypair.");
    println!();
    if let Some(path) = out {
        println!(
            "Private key written to {} (keep it secret!)",
            path.display()
        );
    } else {
        println!("Private key (hex, KEEP SECRET):");
        println!("  {private_hex}");
    }
    println!();
    println!("Public key (hex):");
    println!("  {public_hex}");
    println!();
    println!("Paste-ready @trust-root directive:");
    println!(
        "  @trust-root {key_id} {:02x} {public_hex} {expires} root",
        algo as u8
    );
    println!();
    println!("Signing usage:");
    println!(
        "  hlock sign lockfile.hlock --key-id {key_id} --algorithm {algo_name} --private-key @private.key --expires {expires} --in-place"
    );
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Fills `dest` with cryptographically secure random bytes from the OS.
fn fill_random(dest: &mut [u8]) {
    getrandom::fill(dest).unwrap_or_else(|e| {
        eprintln!("Error: cannot read OS random bytes: {e}");
        std::process::exit(2);
    });
}

/// Generates an Ed25519 keypair from OS entropy; returns (private, public) key hex.
fn generate_ed25519() -> (String, String) {
    let mut seed = [0u8; 32];
    fill_random(&mut seed);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    (
        hex(signing.as_bytes()),
        hex(signing.verifying_key().as_bytes()),
    )
}

/// Generates an ML-DSA-65 (FIPS 204) keypair; returns (private, public) key hex.
fn generate_ml_dsa_65() -> (String, String) {
    use fips204::traits::SerDes as _;
    let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap_or_else(|e| {
        eprintln!("Error generating ML-DSA-65 keypair: {e:?}");
        std::process::exit(2);
    });
    (hex(&sk.into_bytes()), hex(&pk.into_bytes()))
}

/// Lowercase hex encoding.
fn hex(bytes: &[u8]) -> String {
    hlock::lockfile::digest::bytes_to_hex(bytes)
}
