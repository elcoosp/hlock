//! `trust` command implementation — inspect and rotate trust roots.
//!
//! - `hlock trust list <file>` renders every trust root and rotation record.
//! - `hlock trust rotate <file> --old-private-key <hex|@path>` generates a new
//!   root key, signs the canonical rotation payload with the *old* key and
//!   appends a `@trust-root-rotation` record. `verify` / `check` / `ci` reject
//!   the lockfile unless that signature validates (E0306).

use std::path::PathBuf;

use super::{
    Ctx, Lockfile, Path, deserialize, output, read_input, serialize, signature::SignatureAlgorithm,
};

/// Reads and parses the lockfile, exiting with status 2 on failure.
fn load(file: &Path) -> (String, Lockfile) {
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
    (content, lockfile)
}

/// Lists all trust roots and rotation records.
fn run_list(file: &Path, format: &str, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    let (_, lockfile) = load(file);

    if output::parse_format(format) == output::OutputFormat::Json {
        if !quiet {
            let data = serde_json::json!({
                "trust_roots": lockfile.trust_roots.iter().map(|r| serde_json::json!({
                    "key_id": r.key_id,
                    "algorithm": algo_name(r.algorithm),
                    "public_key": hex(&r.public_key),
                    "expires_epoch": r.expires_epoch,
                    "role": r.role.as_str(),
                })).collect::<Vec<_>>(),
                "rotations": lockfile.root_rotations.iter().map(|rot| serde_json::json!({
                    "old_key_id": rot.old_key_id,
                    "new_key_id": rot.new_key_id,
                    "threshold": rot.threshold,
                    "new_algorithm": algo_name(rot.new_algorithm),
                    "new_expires_epoch": rot.new_expires_epoch,
                    "new_role": rot.new_role.as_str(),
                    "signed_by": rot.rotation_signature_key_id,
                })).collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&super::envelope("trust list", true, &data)).unwrap()
            );
        }
        return;
    }

    if quiet {
        return;
    }
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let green = output::styler(color_enabled, output::Style::Green);

    println!("{}", bold("Trust roots"));
    if lockfile.trust_roots.is_empty() {
        println!("  (none — run 'hlock init --with-trust-root' to create one)");
    }
    for root in &lockfile.trust_roots {
        println!(
            "  {} {} ({}, {}) expires {}",
            green("•"),
            bold(&root.key_id),
            root.role.as_str(),
            algo_name(root.algorithm),
            if root.expires_epoch == 0 {
                "never".to_string()
            } else {
                root.expires_epoch.to_string()
            }
        );
        println!("    pubkey {}", cyan(&hex(&root.public_key)));
    }

    println!();
    println!("{}", bold("Rotation records"));
    if lockfile.root_rotations.is_empty() {
        println!("  (none)");
    }
    for rot in &lockfile.root_rotations {
        println!(
            "  {} {} → {} ({}), signed by {}",
            green("•"),
            bold(&rot.old_key_id),
            bold(&rot.new_key_id),
            rot.new_role.as_str(),
            cyan(&rot.rotation_signature_key_id),
        );
    }
}

/// Parses the `--algorithm` flag.
fn parse_algorithm(algorithm: &str) -> SignatureAlgorithm {
    match algorithm {
        "ed25519" => SignatureAlgorithm::Ed25519,
        "ml-dsa-65" | "mldsa65" => SignatureAlgorithm::MlDsa65,
        other => {
            eprintln!("Error: unknown algorithm '{other}'. Supported: ed25519, ml-dsa-65");
            std::process::exit(2);
        }
    }
}

fn algo_name(algo: SignatureAlgorithm) -> &'static str {
    match algo {
        SignatureAlgorithm::Ed25519 => "ed25519",
        SignatureAlgorithm::MlDsa65 => "mldsa65",
    }
}

fn hex(bytes: &[u8]) -> String {
    hlock::lockfile::digest::bytes_to_hex(bytes)
}

/// Decodes a hex key argument; `@path` reads the key from a file.
fn decode_key_arg(spec: &str, expected_len: usize, what: &str) -> Vec<u8> {
    let hex_str = if let Some(path) = spec.strip_prefix('@') {
        match std::fs::read_to_string(path) {
            Ok(content) => content.trim().to_string(),
            Err(e) => {
                eprintln!("Error reading {what} from {path}: {e}");
                std::process::exit(2);
            }
        }
    } else {
        spec.to_string()
    };
    match hlock::hex::decode(hex_str.trim()) {
        Ok(bytes) => {
            if bytes.len() != expected_len {
                eprintln!(
                    "Error: {what} must be {expected_len} bytes, got {}",
                    bytes.len()
                );
                std::process::exit(2);
            }
            bytes
        }
        Err(e) => {
            eprintln!("Error: invalid hex in {what}: {e}");
            std::process::exit(2);
        }
    }
}

/// Bundled inputs for [`run_rotate`]. Grouping the rotation parameters keeps
/// the entry point within the argument limit; the body is split into helpers
/// below so no single function grows past the line budget.
struct RotateParams<'a> {
    file: &'a Path,
    new_key_id: &'a str,
    new_algorithm: &'a str,
    new_public_key_hex: Option<&'a str>,
    new_expires: u64,
    role: &'a str,
    threshold: u8,
    old_private_key: &'a str,
    output_path: Option<&'a Path>,
}

/// Parses the requested role, exiting with a usage error on an unknown value.
fn parse_role(role: &str) -> hlock::policy::TrustRole {
    match role {
        "root" => hlock::policy::TrustRole::Root,
        "targets" => hlock::policy::TrustRole::Targets,
        "snapshot" => hlock::policy::TrustRole::Snapshot,
        "delegation" => hlock::policy::TrustRole::Delegation,
        other => {
            eprintln!(
                "Error: unknown role '{other}'. Supported: root, targets, snapshot, delegation"
            );
            std::process::exit(2);
        }
    }
}

/// Resolves the current root trust record to rotate from, exiting when absent.
fn require_old_root(lockfile: &hlock::Lockfile) -> hlock::policy::TrustRoot {
    let old_root = lockfile
        .trust_roots
        .iter()
        .find(|r| r.role == hlock::policy::TrustRole::Root)
        .cloned();
    let Some(old_root) = old_root else {
        eprintln!(
            "Error: lockfile has no root trust key to rotate from; use 'hlock init --with-trust-root' first"
        );
        std::process::exit(1);
    };
    old_root
}

/// Resolves the new public key: either decodes the supplied hex or generates a
/// fresh keypair, returning the public bytes and any generated private key.
fn resolve_new_key(
    new_algorithm: &str,
    new_public_key_hex: Option<&str>,
) -> (Vec<u8>, Option<String>) {
    let new_algo = parse_algorithm(new_algorithm);
    if let Some(pk_hex) = new_public_key_hex {
        let pk_len = match new_algo {
            SignatureAlgorithm::Ed25519 => 32,
            SignatureAlgorithm::MlDsa65 => fips204::ml_dsa_65::PK_LEN,
        };
        return (decode_key_arg(pk_hex, pk_len, "new public key"), None);
    }
    let (sk, pk) = match new_algo {
        SignatureAlgorithm::Ed25519 => super::keygen::generate_ed25519(),
        SignatureAlgorithm::MlDsa65 => super::keygen::generate_ml_dsa_65(),
    };
    let pk_len = match new_algo {
        SignatureAlgorithm::Ed25519 => 32,
        SignatureAlgorithm::MlDsa65 => fips204::ml_dsa_65::PK_LEN,
    };
    (decode_key_arg(&pk, pk_len, "new public key"), Some(sk))
}

/// Appends the rotation record to `lockfile`, signing it with the old key and
/// self-checking that the freshly produced record validates.
fn push_rotation_record(
    lockfile: &mut hlock::Lockfile,
    params: &RotateParams<'_>,
    new_algo: SignatureAlgorithm,
    new_role: hlock::policy::TrustRole,
    old_root: &hlock::policy::TrustRoot,
    old_private: &[u8],
    new_public: Vec<u8>,
) {
    let rotation_signature = match hlock::signature::sign_rotation(
        &hlock::signature::RotationSpec {
            new_key_id: params.new_key_id,
            algorithm: new_algo,
            new_public_key: &new_public,
            new_expires_epoch: params.new_expires,
            new_role,
            old_key_id: &old_root.key_id,
            threshold: params.threshold,
        },
        old_root.algorithm,
        old_private,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Error: rotation signing failed: {e}");
            std::process::exit(2);
        }
    };

    lockfile
        .root_rotations
        .push(hlock::lockfile::TrustRootRotation {
            old_key_id: old_root.key_id.clone(),
            new_key_id: params.new_key_id.to_string(),
            threshold: params.threshold,
            new_algorithm: new_algo,
            new_public_key: new_public,
            new_expires_epoch: params.new_expires,
            new_role,
            rotation_signature_key_id: old_root.key_id.clone(),
            rotation_signature,
        });

    // Self-check: the record we just produced must validate.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    if let Err(e) = lockfile.validate_root_rotation(now) {
        eprintln!("Error: generated rotation record failed validation: {e}");
        std::process::exit(1);
    }
}

/// Serializes and atomically writes the updated lockfile, returning the path
/// that was written.
fn write_updated_lockfile(lockfile: &hlock::Lockfile, params: &RotateParams<'_>) -> PathBuf {
    let serialized = match serialize(lockfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Serialize error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };
    let target = params
        .output_path
        .map_or_else(|| params.file.to_path_buf(), Path::to_path_buf);
    if let Err(e) = super::atomic_write(&target, &serialized) {
        eprintln!("Error writing {}: {e}", target.display());
        std::process::exit(2);
    }
    target
}

/// Rotates the root key: generates the new key, signs with the old key,
/// appends the rotation record and rewrites the lockfile.
fn run_rotate(params: &RotateParams<'_>, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;
    run_rotate_inner(params, quiet);
}

fn run_rotate_inner(params: &RotateParams<'_>, quiet: bool) {
    let (content, mut lockfile) = load(params.file);
    let had_signature = hlock::signature::has_signature_block(&content);

    let new_algo = parse_algorithm(params.new_algorithm);
    let new_role = parse_role(params.role);
    let old_root = require_old_root(&lockfile);

    let old_sk_len = match old_root.algorithm {
        SignatureAlgorithm::Ed25519 => 32,
        SignatureAlgorithm::MlDsa65 => fips204::ml_dsa_65::SK_LEN,
    };
    let old_private = decode_key_arg(params.old_private_key, old_sk_len, "old private key");

    let (new_public, new_private_hex) =
        resolve_new_key(params.new_algorithm, params.new_public_key_hex);

    push_rotation_record(
        &mut lockfile,
        params,
        new_algo,
        new_role,
        &old_root,
        &old_private,
        new_public,
    );

    let target = write_updated_lockfile(&lockfile, params);

    if let Some(sk_hex) = new_private_hex {
        let sk_path = target.with_extension("new-key");
        if let Err(e) = super::atomic_write(&sk_path, &format!("{sk_hex}\n")) {
            eprintln!("Error writing new private key: {e}");
            std::process::exit(2);
        }
        if !quiet {
            println!(
                "New private key written to {} (keep it secret!)",
                sk_path.display()
            );
            println!("Distribute the matching public key to verifiers, then:");
            println!(
                "  hlock sign {} --key-id {} --algorithm {} --private-key @{} --in-place",
                target.display(),
                params.new_key_id,
                algo_name(new_algo),
                sk_path.display()
            );
        }
    }

    if !quiet {
        println!(
            "Rotation record appended: {} → {} (signed by {}, verified)",
            old_root.key_id, params.new_key_id, old_root.key_id
        );
        if had_signature {
            // The rewrite cannot keep the old @signature block: the digest
            // it signed no longer matches. Say so instead of silently
            // stripping the operator's signature.
            eprintln!(
                "! the previous @signature block was removed (the file changed); re-sign with the new key:"
            );
            eprintln!(
                "  hlock sign {} --key-id {} --in-place …",
                target.display(),
                params.new_key_id
            );
        }
    }
}

/// Runs the `trust` command.
pub(crate) fn run(args: &TrustArgs, ctx: Ctx) {
    match args {
        TrustArgs::List { file, format } => run_list(file, format, ctx),
        TrustArgs::Rotate {
            file,
            new_key_id,
            new_algorithm,
            new_public_key,
            new_expires,
            role,
            threshold,
            old_private_key,
            output,
        } => run_rotate(
            &RotateParams {
                file,
                new_key_id,
                new_algorithm,
                new_public_key_hex: new_public_key.as_deref(),
                new_expires: *new_expires,
                role,
                threshold: *threshold,
                old_private_key,
                output_path: output.as_deref(),
            },
            ctx,
        ),
    }
}

/// Arguments for the `trust` command (owning, for easy dispatch).
pub(crate) enum TrustArgs {
    /// Lists trust roots and rotation records.
    List { file: PathBuf, format: String },
    /// Generates and attaches a signed root-key rotation record.
    Rotate {
        file: PathBuf,
        new_key_id: String,
        new_algorithm: String,
        new_public_key: Option<String>,
        new_expires: u64,
        role: String,
        threshold: u8,
        old_private_key: String,
        output: Option<PathBuf>,
    },
}
