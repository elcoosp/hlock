pub mod verify;
pub mod lint;
pub mod diff;
pub mod audit;
pub mod sbom;
pub mod sign;
pub mod graph;
pub mod merge;
pub mod completions;
pub mod info;
pub mod dedup;
pub mod why;
pub mod deps;
pub mod dependents;
pub mod check;
pub mod tree;
pub mod licenses;

use clap::CommandFactory;
use hlock::signature::SignatureAlgorithm;
use hlock::lint::LintRule;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

pub struct OutputConfig {
    pub quiet: bool,
    pub verbose: bool,
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputConfig {
    pub fn parse_format(format: &str) -> OutputFormat {
        match format {
            "json" => OutputFormat::Json,
            _ => OutputFormat::Text,
        }
    }
}

pub fn read_input(path: &Path) -> Result<String, hlock::Error> {
    if path == Path::new("-") {
        std::io::read_to_string(std::io::stdin())
            .map_err(hlock::Error::Io)
    } else {
        std::fs::read_to_string(path)
            .map_err(hlock::Error::Io)
    }
}

pub fn parse_trusted_key(spec: &str) -> Option<(String, (Vec<u8>, SignatureAlgorithm))> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 { return None; }
    let key_id = parts[0].to_string();
    let algo = match parts[1] {
        "ed25519" => SignatureAlgorithm::Ed25519,
        "mldsa65" => SignatureAlgorithm::MlDsa65,
        _ => return None,
    };
    let hex_key = parts[2];
    let pubkey: Vec<u8> = (0..hex_key.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_key[i..i+2], 16).ok())
        .collect();
    Some((key_id, (pubkey, algo)))
}

pub fn parse_platform(spec: &str) -> Option<(hlock::TargetOS, hlock::TargetArch)> {
    let parts: Vec<&str> = spec.splitn(2, '-').collect();
    if parts.len() != 2 { return None; }
    let os = match parts[0] {
        "linux" => hlock::TargetOS::Linux,
        "macos" => hlock::TargetOS::MacOS,
        "windows" => hlock::TargetOS::Windows,
        "freebsd" => hlock::TargetOS::FreeBSD,
        "android" => hlock::TargetOS::Android,
        "ios" => hlock::TargetOS::IOS,
        "any" => hlock::TargetOS::Any,
        _ => return None,
    };
    let arch = match parts[1] {
        "x86_64" => hlock::TargetArch::X86_64,
        "aarch64" => hlock::TargetArch::Aarch64,
        "wasm32" => hlock::TargetArch::Wasm32,
        "arm" => hlock::Arch,
        "s390x" => hlock::TargetArch::S390x,
        "ppc64le" => hlock::TargetArch::Ppc64le,
        "any" => hlock::TargetArch::Any,
        _ => return None,
    };
    Some((os, arch))
}

pub fn build_rule_set(rule_args: &[String]) -> Vec<Box<dyn LintRule>> {
    use hlock::lint::*;

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
            eprintln!("Error: unknown rule '{}'. Available rules: {}", name, valid_names.iter().cloned().collect::<Vec<&str>>().join(", "));
            std::process::exit(2);
        }
    }

    all_rules.into_iter()
        .filter(|(name, _)| {
            if !includes.is_empty() {
                includes.contains(*name)
            } else {
                true
            }
        })
        .filter(|(name, _)| !excludes.contains(*name))
        .map(|(_, r)| r)
        .collect()
}

pub fn verbose_log(verbose: bool, msg: &str) {
    if verbose {
        eprintln!("[verbose] {}", msg);
    }
}
