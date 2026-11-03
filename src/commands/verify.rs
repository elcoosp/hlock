//! `verify` command implementation.
//!
//! Gate semantics (v1.0.1):
//! - the `@digest` directive is **mandatory** and must cover the whole file
//!   (missing or misplaced digests are hard failures, spec §2.5);
//! - when trusted keys are pinned, the lockfile **must** carry a valid
//!   signature block — an unsigned file fails (E0307);
//! - when the lockfile carries signatures but no keys are pinned, the gate
//!   fails too (E0308): verification must never silently degrade to a
//!   digest-only check;
//! - `--time` governs signature expiry **and** trust-root expiry (§2.4).

use super::{
    Ctx, HashMap, Lockfile, Path, deserialize, now_epoch, output, parse_provenance_builder,
    read_input, signature, validate_digest, verify_signature,
};

/// Runs the `verify` command.
pub(crate) fn run(file: &Path, trusted_key: &[String], time: u64, sigstore: bool, ctx: Ctx) {
    let Ctx { verbose, .. } = ctx;

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

    check_digest(&content, ctx);

    let now = if time > 0 { time } else { now_epoch() };

    let lockfile: Lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("✗ [{}] parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    if verbose {
        eprintln!(
            "[verbose] Parsed lockfile: {} packages",
            lockfile.packages.len()
        );
    }

    let signed = signature::has_signature_block(&content);
    let trusted = collect_trusted_keys(trusted_key);
    if trusted.is_empty() && signed {
        super::fail_gate(&hlock::Error::SignatureWithoutTrustedKeys, ctx);
    }
    if !trusted.is_empty() {
        if !signed {
            super::fail_gate(&hlock::Error::UnsignedLockfile, ctx);
        }
        check_signature(&content, &trusted, now, ctx);
    }

    if !lockfile.trust_roots.is_empty() {
        check_trust_chain(&lockfile, now, ctx);
    }

    if sigstore {
        run_sigstore(&lockfile, file, ctx);
    }
}

/// Implements `verify --sigstore`: bundle verification is only meaningful
/// when the lockfile declares an SLSA builder via `@provenance`; the cosign
/// certificate identity must match that builder (never `.*`).
fn run_sigstore(lockfile: &Lockfile, file: &Path, ctx: Ctx) {
    if file == std::path::Path::new("-") {
        eprintln!("Error: --sigstore cannot verify stdin input");
        std::process::exit(2);
    }
    let Some(builder) = parse_provenance_builder(lockfile) else {
        eprintln!(
            "✗ --sigstore requires an @provenance directive with an SLSA builder, but none is present"
        );
        std::process::exit(1);
    };
    if file.exists() {
        if let Err(e) = hlock::verify_sigstore(file, None, Some(&builder)) {
            eprintln!("✗ sigstore: {e}");
            std::process::exit(1);
        }
        super::pass_gate("sigstore bundle valid", ctx);
    }
}

/// Fails the command when the blake3 digest does not match the body.
fn check_digest(content: &str, ctx: Ctx) {
    let t = std::time::Instant::now();
    if let Err(e) = validate_digest(content) {
        fail_with("✗", e, ctx);
    }
    if ctx.verbose {
        eprintln!("[verbose] Validating digest... {:?}", t.elapsed());
    }
    pass_with("digest valid", ctx);
}

/// Builds the trusted-key map from `key_id:keytype:hex` specs.
fn collect_trusted_keys(
    trusted_key: &[String],
) -> HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> {
    super::collect_trusted_keys_or_exit(trusted_key)
}

/// Fails the command when the `@signature` block does not verify.
fn check_signature(
    content: &str,
    trusted: &HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)>,
    now: u64,
    ctx: Ctx,
) {
    let t = std::time::Instant::now();
    if let Err(e) = verify_signature(content, trusted, now) {
        fail_with("✗", e, ctx);
    }
    if ctx.verbose {
        eprintln!("[verbose] Verifying signature... {:?}", t.elapsed());
    }
    pass_with("signature valid", ctx);
}

/// Fails the command when a trust root is expired or untrusted at `now`.
fn check_trust_chain(lockfile: &hlock::Lockfile, now: u64, ctx: Ctx) {
    if let Err(e) = lockfile.validate_trust_chain(now) {
        fail_with("✗", e, ctx);
    }
    pass_with("trust chain valid", ctx);
}

/// Prints a green check-marked success line unless quiet.
fn pass_with(label: &str, ctx: Ctx) {
    if !ctx.quiet {
        println!(
            "{} {label}",
            output::C {
                text: "✓",
                on: ctx.color_enabled
            }
            .gb()
        );
    }
}

/// Prints a red cross-marked failure and exits with status 1.
fn fail_with(label: &str, err: impl std::fmt::Display, ctx: Ctx) -> ! {
    eprintln!(
        "{} {err}",
        output::C {
            text: label,
            on: ctx.color_enabled
        }
        .rb()
    );
    std::process::exit(1);
}
