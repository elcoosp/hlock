//! `verify` command implementation.

use super::{
    Ctx, HashMap, Path, deserialize, output, parse_trusted_key, read_input, signature,
    validate_digest, verify_signature,
};

/// Runs the `verify` command.
pub(crate) fn run(file: &Path, trusted_key: &[String], time: u64, _sigstore: bool, ctx: Ctx) {
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

    let trusted = collect_trusted_keys(trusted_key);
    if !trusted.is_empty() {
        check_signature(&content, &trusted, ctx);
    }

    let lockfile = match deserialize(&content) {
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

    let now = effective_time(time);
    if !lockfile.trust_roots.is_empty() {
        check_trust_chain(&lockfile, now, ctx);
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
    let mut trusted: HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> = HashMap::new();
    for spec in trusted_key {
        if let Some((key_id, (pubkey, algo))) = parse_trusted_key(spec) {
            trusted.insert(key_id, (pubkey, algo));
        }
    }
    trusted
}

/// Fails the command when the `@signature` block does not verify.
fn check_signature(
    content: &str,
    trusted: &HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)>,
    ctx: Ctx,
) {
    let t = std::time::Instant::now();
    if let Err(e) = verify_signature(content, trusted) {
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

/// The verification time: the CLI override when set, otherwise the wall clock.
fn effective_time(time: u64) -> u64 {
    if time > 0 {
        time
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }
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
