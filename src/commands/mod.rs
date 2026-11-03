//! Command implementations for the hlock CLI.
//!
//! Each submodule owns one command's behavior; `main.rs` only parses
//! arguments and dispatches.

pub(crate) mod audit;
pub(crate) mod check;
pub(crate) mod ci;
pub(crate) mod completions;
pub(crate) mod config_cmd;
pub(crate) mod dependents;
pub(crate) mod deps;
pub(crate) mod diff;
pub(crate) mod digest;
pub(crate) mod explain;
pub(crate) mod fix;
pub(crate) mod graph;
pub(crate) mod import;
pub(crate) mod init;
pub(crate) mod keygen;
pub(crate) mod licenses;
pub(crate) mod lint_cmd;
pub(crate) mod merge_cmd;
pub(crate) mod outdated;
pub(crate) mod policy_test;
pub(crate) mod sbom_cmd;
pub(crate) mod sign;
pub(crate) mod stats;
pub(crate) mod tree;
pub(crate) mod trust;
pub(crate) mod verify;
pub(crate) mod why;

pub(crate) use super::{
    Cli, ExplanationKind, FixType, HlockConfig, ImportFormat, Lockfile, OutdatedSourceType,
    UpdateType, apply_fixes, build_fix_plan, check_outdated, deserialize, diff_lockfiles,
    explain_advisory, explain_rule, generate_sbom, import_npm, import_yarn, lint, lockfile, merge,
    merge_lockfiles, policy, sbom, serialize, serialize_diff, sign_lockfile, signature,
    validate_digest, verify_signature,
};
pub(crate) use crate::output;
pub(crate) use std::collections::{HashMap, HashSet};
pub(crate) use std::path::Path;

/// Shared execution context for command handlers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Ctx {
    pub(crate) quiet: bool,
    pub(crate) verbose: bool,
    pub(crate) color_enabled: bool,
}

/// Formats the uppercase advisory severity label, optionally colorized.
pub(crate) fn severity_label(severity: policy::AdvisorySeverity, color_enabled: bool) -> String {
    let label = severity.as_str().to_uppercase();
    match severity {
        policy::AdvisorySeverity::Critical | policy::AdvisorySeverity::High => output::C {
            text: &label,
            on: color_enabled,
        }
        .rb(),
        policy::AdvisorySeverity::Medium => output::C {
            text: &label,
            on: color_enabled,
        }
        .yb(),
        policy::AdvisorySeverity::Low => {
            output::styler(color_enabled, output::Style::Yellow)(&label)
        }
        policy::AdvisorySeverity::Info => {
            output::styler(color_enabled, output::Style::Blue)(&label)
        }
    }
}

fn read_input(path: &std::path::Path) -> Result<String, hlock::Error> {
    if path == std::path::Path::new("-") {
        std::io::read_to_string(std::io::stdin()).map_err(hlock::Error::Io)
    } else {
        std::fs::read_to_string(path).map_err(hlock::Error::Io)
    }
}

/// Current wall-clock epoch seconds (0 when the clock is before the epoch).
pub(crate) fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Prints a red failure line for a gate error and exits with status 1
/// (verification failure per the CLI contract).
pub(crate) fn fail_gate(err: &hlock::Error, ctx: Ctx) -> ! {
    eprintln!(
        "{} [{}] {err}",
        output::C {
            text: "✗",
            on: ctx.color_enabled
        }
        .rb(),
        err.error_code()
    );
    if let Some(hint) = err.hint() {
        eprintln!("  hint: {hint}");
    }
    std::process::exit(1);
}

/// Prints a green success line for a gate check unless quiet.
pub(crate) fn pass_gate(label: &str, ctx: Ctx) {
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

/// Wraps `data` in the stable JSON envelope every command emits in JSON
/// mode (spec §9): `{"schema":"hlock/v1","command":…,"ok":…,"data":…}`.
pub(crate) fn envelope(command: &str, ok: bool, data: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "schema": "hlock/v1",
        "command": command,
        "ok": ok,
        "data": data,
        "error": serde_json::Value::Null,
    })
}

/// Extracts the first SLSA builder id declared by an inline attestation,
/// used by `verify --sigstore` to pin the cosign certificate identity.
pub(crate) fn parse_provenance_builder(lockfile: &Lockfile) -> Option<String> {
    lockfile
        .packages
        .iter()
        .flat_map(|p| p.hashes.iter())
        .find_map(|h| match &h.attestation {
            hlock::Attestation::InlineSlsa(pred) => {
                let builder = pred.builder.trim();
                (!builder.is_empty()).then(|| builder.to_string())
            }
            _ => None,
        })
}

/// Writes `data` to `path` atomically: the payload lands in a temporary file
/// in the same directory which is then renamed over the target. A crash or
/// full disk mid-write can no longer truncate the caller's lockfile.
pub(crate) fn atomic_write(path: &std::path::Path, data: &str) -> std::io::Result<()> {
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(
            || std::path::PathBuf::from("."),
            std::path::Path::to_path_buf,
        );
    let mut tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .map_or_else(|| "hlock".to_string(), |n| n.to_string_lossy().to_string()),
        std::process::id()
    ));
    // Keep the private-key 0600 mode when the caller needs it.
    let write_result = (|| {
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data.as_bytes())
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, data)
        }
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    let _ = &mut tmp;
    Ok(())
}

/// Loads a baseline file (audit/ci): either a JSON array of advisory ids or
/// `{"schema": ..., "advisory_ids": [...]}`.
///
/// Exits with status 2 on unreadable or malformed baselines (config error).
pub(crate) fn load_baseline_file(path: &std::path::Path) -> std::collections::BTreeSet<String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading baseline {}: {e}", path.display());
            std::process::exit(2);
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[E0901] Baseline {} is not valid JSON: {e}", path.display());
            std::process::exit(2);
        }
    };
    let empty = Vec::new();
    let list = value
        .as_array()
        .or_else(|| value.get("advisory_ids").and_then(|v| v.as_array()))
        .unwrap_or(&empty);
    list.iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Parses one `KEY_ID:ALGO:HEX` trusted-key spec, strictly.
///
/// Malformed specs are a hard error (the whole point of pinning a key is
/// that a typo must never degrade into "skip verification"), and the hex
/// payload must decode cleanly with the exact public-key length for the
/// declared algorithm.
fn parse_trusted_key(
    spec: &str,
) -> Result<(String, (Vec<u8>, signature::SignatureAlgorithm)), String> {
    let (key_id, rest) = spec
        .split_once(':')
        .ok_or_else(|| format!("missing ':' separator (expected KEY_ID:ALGO:HEX, got {spec:?})"))?;
    let (algo_str, hex_key) = rest.split_once(':').ok_or_else(|| {
        format!("missing second ':' separator (expected KEY_ID:ALGO:HEX, got {spec:?})")
    })?;
    if key_id.is_empty() {
        return Err(format!("empty key id in trusted key spec {spec:?}"));
    }
    let (algo, expected_len) = match algo_str {
        "ed25519" => (signature::SignatureAlgorithm::Ed25519, 32usize),
        "mldsa65" => (
            signature::SignatureAlgorithm::MlDsa65,
            fips204::ml_dsa_65::PK_LEN,
        ),
        other => {
            return Err(format!(
                "unknown algorithm {other:?} in trusted key spec {spec:?} (supported: ed25519, mldsa65)"
            ));
        }
    };
    let pubkey = hlock::hex::decode(hex_key)
        .map_err(|e| format!("invalid public key hex in {spec:?}: {e}"))?;
    if pubkey.len() != expected_len {
        return Err(format!(
            "public key for {algo_str:?} must be {expected_len} bytes, got {} in {spec:?}",
            pubkey.len()
        ));
    }
    Ok((key_id.to_string(), (pubkey, algo)))
}

/// Builds the trusted-key map, exiting with status 2 on any malformed spec.
fn collect_trusted_keys_or_exit(
    specs: &[String],
) -> HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> {
    let mut trusted = HashMap::new();
    for spec in specs {
        match parse_trusted_key(spec) {
            Ok((key_id, entry)) => {
                trusted.insert(key_id, entry);
            }
            Err(reason) => {
                eprintln!("Error: {reason}");
                std::process::exit(2);
            }
        }
    }
    trusted
}

fn build_rule_set(rule_args: &[String]) -> Vec<Box<dyn hlock::lint::LintRule>> {
    use hlock::lint::{
        DenyCopyleft, DenyPostinstall, LintRule, MaxDepth, NoExpiredKeys, NoGitUrls,
        NoKnownVulnerabilities, NoPeerAsRuntime, NoSha1, RequireAttestation, RequireIntegrity,
        RequireLicense, RequireTrustRoot,
    };

    let all_rules: Vec<(&str, Box<dyn LintRule>)> = vec![
        ("no-git-urls", Box::new(NoGitUrls) as Box<dyn LintRule>),
        ("require-integrity", Box::new(RequireIntegrity)),
        ("no-sha1", Box::new(NoSha1)),
        ("no-peer-as-runtime", Box::new(NoPeerAsRuntime)),
        ("max-depth", Box::new(MaxDepth { max: 5 })),
        ("require-attestation", Box::new(RequireAttestation)),
        ("no-known-vulnerabilities", Box::new(NoKnownVulnerabilities)),
        ("require-license", Box::new(RequireLicense)),
        ("deny-copyleft", Box::new(DenyCopyleft)),
        ("require-trust-root", Box::new(RequireTrustRoot)),
        ("no-expired-keys", Box::new(NoExpiredKeys)),
        ("deny-postinstall", Box::new(DenyPostinstall)),
    ];

    let mut includes: HashSet<String> = HashSet::new();
    let mut excludes: HashSet<String> = HashSet::new();

    for arg in rule_args {
        if let Some(name) = arg.strip_prefix('-') {
            excludes.insert(name.to_string());
        } else {
            includes.insert(arg.clone());
        }
    }

    if includes.is_empty() && excludes.is_empty() {
        return all_rules.into_iter().map(|(_, r)| r).collect();
    }

    let valid_names: HashSet<&str> = all_rules.iter().map(|(n, _)| *n).collect();
    for name in includes.iter().chain(excludes.iter()) {
        if !valid_names.contains(name.as_str()) {
            eprintln!(
                "Error: unknown rule '{}'. Available rules: {}",
                name,
                valid_names
                    .iter()
                    .copied()
                    .collect::<Vec<&str>>()
                    .join(", ")
            );
            std::process::exit(2);
        }
    }

    all_rules
        .into_iter()
        .filter(|(name, _)| {
            if includes.is_empty() {
                true
            } else {
                includes.contains(*name)
            }
        })
        .filter(|(name, _)| !excludes.contains(*name))
        .map(|(_, r)| r)
        .collect()
}

fn parse_platform(spec: &str) -> Option<(lockfile::TargetOS, lockfile::TargetArch)> {
    let parts: Vec<&str> = spec.splitn(2, '-').collect();
    if parts.len() != 2 {
        return None;
    }
    let os = match parts[0] {
        "linux" => lockfile::TargetOS::Linux,
        "macos" => lockfile::TargetOS::MacOS,
        "windows" => lockfile::TargetOS::Windows,
        "freebsd" => lockfile::TargetOS::FreeBSD,
        "android" => lockfile::TargetOS::Android,
        "ios" => lockfile::TargetOS::IOS,
        "any" => lockfile::TargetOS::Any,
        _ => return None,
    };
    let arch = match parts[1] {
        "x86_64" => lockfile::TargetArch::X86_64,
        "aarch64" => lockfile::TargetArch::Aarch64,
        "wasm32" => lockfile::TargetArch::Wasm32,
        "arm" => lockfile::TargetArch::Arm,
        "s390x" => lockfile::TargetArch::S390x,
        "ppc64le" => lockfile::TargetArch::Ppc64le,
        "any" => lockfile::TargetArch::Any,
        _ => return None,
    };
    Some((os, arch))
}
