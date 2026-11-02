//! `init` command implementation — bootstrap a signed lockfile in one step.
//!
//! `hlock init package-lock.json --from npm --with-trust-root` imports the
//! ecosystem lockfile, computes the BLAKE3 `@digest` and (optionally)
//! generates a root trust key, producing a lockfile that is verifiable from
//! the first commit.

use super::{Ctx, Path, import_npm, import_yarn, serialize};

/// Arguments for the `init` command.
pub(crate) struct InitArgs<'a> {
    pub(crate) source: &'a Path,
    pub(crate) from: &'a str,
    pub(crate) output: Option<&'a Path>,
    pub(crate) registry: &'a str,
    pub(crate) with_trust_root: bool,
    pub(crate) key_id: &'a str,
    pub(crate) algorithm: &'a str,
    pub(crate) expires: u64,
}

/// Runs the `init` command.
#[allow(clippy::too_many_lines)] // linear orchestration, split adds indirection
pub(crate) fn run(args: &InitArgs<'_>, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;

    let source_content = match std::fs::read_to_string(args.source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", args.source.display(), e);
            std::process::exit(2);
        }
    };

    let (mut lockfile, result) = match args.from {
        "yarn" | "pnpm" => match import_yarn(&source_content, args.registry) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[{}] Import failed: {}", e.error_code(), e);
                std::process::exit(2);
            }
        },
        "npm" => match import_npm(&source_content, args.registry) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[{}] Import failed: {}", e.error_code(), e);
                std::process::exit(2);
            }
        },
        other => {
            eprintln!("Error: unknown format '{other}'. Supported: yarn, npm, pnpm");
            std::process::exit(2);
        }
    };

    // Optional trust root: generate the keypair, attach the root directive.
    let mut private_key_hex: Option<String> = None;
    if args.with_trust_root {
        let algo = match args.algorithm {
            "ed25519" => hlock::signature::SignatureAlgorithm::Ed25519,
            "ml-dsa-65" | "mldsa65" => hlock::signature::SignatureAlgorithm::MlDsa65,
            other => {
                eprintln!("Error: unknown algorithm '{other}'. Supported: ed25519, ml-dsa-65");
                std::process::exit(2);
            }
        };
        let (private_hex, public_hex) = match algo {
            hlock::signature::SignatureAlgorithm::Ed25519 => super::keygen::generate_ed25519(),
            hlock::signature::SignatureAlgorithm::MlDsa65 => super::keygen::generate_ml_dsa_65(),
        };
        let pubkey = match hlock::hex::decode(public_hex.trim()) {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("Error decoding generated public key: {e}");
                std::process::exit(2);
            }
        };
        lockfile.trust_roots.push(hlock::policy::TrustRoot {
            key_id: args.key_id.to_string(),
            algorithm: algo,
            public_key: pubkey,
            expires_epoch: args.expires,
            role: hlock::policy::TrustRole::Root,
        });
        private_key_hex = Some(private_hex);
    }

    let out_path = args.output.map_or_else(
        || PathBuf::from("hlock.lock"),
        std::borrow::ToOwned::to_owned,
    );
    let serialized = match serialize(&lockfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Serialize error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };
    if let Err(e) = std::fs::write(&out_path, &serialized) {
        eprintln!("Error writing {}: {e}", out_path.display());
        std::process::exit(2);
    }

    if let Some(private_hex) = private_key_hex {
        let sk_path = out_path.with_extension("key");
        if let Err(e) = std::fs::write(&sk_path, format!("{private_hex}\n")) {
            eprintln!("Error writing private key: {e}");
            std::process::exit(2);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = std::fs::set_permissions(&sk_path, std::fs::Permissions::from_mode(0o600));
        }
        if !quiet {
            println!(
                "Root key generated. Private key: {} (keep it secret!)",
                sk_path.display()
            );
            println!(
                "Sign the lockfile: hlock sign {} --key-id {} --algorithm {} --private-key @{} --in-place",
                out_path.display(),
                args.key_id,
                args.algorithm,
                sk_path.display()
            );
        }
    }

    if !quiet {
        println!(
            "Initialized {} ({} packages, digest sealed) from {} ({})",
            out_path.display(),
            result.imported,
            args.source.display(),
            result.source_format
        );
        println!("Next steps:");
        println!(
            "  hlock verify {}   # confirm the digest",
            out_path.display()
        );
        println!(
            "  hlock ci {}       # run the full supply-chain gate",
            out_path.display()
        );
    }
}

use std::path::PathBuf;
