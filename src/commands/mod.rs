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

fn parse_trusted_key(spec: &str) -> Option<(String, (Vec<u8>, signature::SignatureAlgorithm))> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let key_id = parts[0].to_string();
    let algo = match parts[1] {
        "ed25519" => signature::SignatureAlgorithm::Ed25519,
        "mldsa65" => signature::SignatureAlgorithm::MlDsa65,
        _ => return None,
    };
    let hex_key = parts[2];
    let pubkey: Vec<u8> = (0..hex_key.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_key[i..i + 2], 16).ok())
        .collect();
    Some((key_id, (pubkey, algo)))
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
