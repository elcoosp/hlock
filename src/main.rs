mod output;

use clap::{CommandFactory, Parser, Subcommand};
use hlock::*;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hlock", version, about = "Supply-chain lockfile integrity tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true, help = "Suppress non-error output")]
    quiet: bool,

    #[arg(short, long, global = true, help = "Show extra diagnostic information")]
    verbose: bool,

    #[arg(long, global = true, help = "Disable colored output")]
    no_color: bool,

    #[arg(long, default_value = "auto", global = true, help = "When to colorize: auto, always, never")]
    color: String,
}

#[derive(Subcommand)]
enum Commands {
    Verify {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0)]
        time: u64,
    },
    Lint {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        rule: Vec<String>,
        #[arg(long, default_value = "error")]
        severity: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Diff {
        #[arg(value_name = "OLD_FILE")]
        old_file: PathBuf,
        #[arg(value_name = "NEW_FILE")]
        new_file: PathBuf,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Audit {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Sbom {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        namespace: String,
        #[arg(long, default_value = "spdx-json")]
        format: String,
    },
    Sign {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        key_id: String,
        #[arg(long, default_value = "ed25519")]
        algorithm: String,
        #[arg(long)]
        private_key: String,
        #[arg(long, default_value_t = 0)]
        expires: u64,
        #[arg(long)]
        in_place: bool,
    },
    Graph {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        root: Vec<String>,
        #[arg(long)]
        platform: Option<String>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Merge {
        #[arg(long)]
        base: PathBuf,
        #[arg(long)]
        ours: PathBuf,
        #[arg(long)]
        theirs: PathBuf,
        #[arg(long, default_value = "fail")]
        strategy: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Completions {
        #[arg(value_name = "SHELL")]
        shell: String,
    },
}

fn parse_trusted_key(spec: &str) -> Option<(String, (Vec<u8>, signature::SignatureAlgorithm))> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 { return None; }
    let key_id = parts[0].to_string();
    let algo = match parts[1] {
        "ed25519" => signature::SignatureAlgorithm::Ed25519,
        "mldsa65" => signature::SignatureAlgorithm::MlDsa65,
        _ => return None,
    };
    let hex_key = parts[2];
    let pubkey: Vec<u8> = (0..hex_key.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex_key[i..i+2], 16).ok())
        .collect();
    Some((key_id, (pubkey, algo)))
}

fn parse_platform(spec: &str) -> Option<(lockfile::TargetOS, lockfile::TargetArch)> {
    let parts: Vec<&str> = spec.splitn(2, '-').collect();
    if parts.len() != 2 { return None; }
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

use std::collections::HashSet;

fn build_rule_set(rule_args: &[String]) -> Vec<Box<dyn hlock::lint::LintRule>> {
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

fn read_input(path: &std::path::Path) -> Result<String, hlock::Error> {
    if path == std::path::Path::new("-") {
        std::io::read_to_string(std::io::stdin())
            .map_err(hlock::Error::Io)
    } else {
        std::fs::read_to_string(path)
            .map_err(hlock::Error::Io)
    }
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose && cli.quiet {
        eprintln!("Error: --quiet and --verbose are mutually exclusive");
        std::process::exit(2);
    }

    let quiet = cli.quiet;
    let verbose = cli.verbose;
    let _color_config = output::ColorConfig::from_cli_args(
        &cli.color,
        cli.no_color,
        output::OutputFormat::Text,
    );

    match cli.command {
        Commands::Verify { file, trusted_key, time } => {
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };

            if let Err(e) = validate_digest(&content) {
                eprintln!("✗ {}", e);
                std::process::exit(1);
            }
            println!("✓ digest valid");

            let mut trusted: HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> = HashMap::new();
            for spec in &trusted_key {
                if let Some((key_id, (pubkey, algo))) = parse_trusted_key(spec) {
                    trusted.insert(key_id, (pubkey, algo));
                }
            }

            if !trusted.is_empty() {
                if let Err(e) = verify_signature(&content, &trusted) {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
                println!("✓ signature valid");
            }

            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("✗ parse error: {}", e); std::process::exit(2); }
            };

            let now = if time > 0 { time } else { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) };
            if !lockfile.trust_roots.is_empty() {
                if let Err(e) = lockfile.validate_trust_chain(now) {
                    eprintln!("✗ {}", e);
                    std::process::exit(1);
                }
                println!("✓ trust chain valid");
            }
        }

        Commands::Lint { file, rule, severity, format } => {
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let rules = build_rule_set(&rule);
            let report = hlock::lint::lint(&lockfile, &rules);

            let min_sev = match severity.as_str() {
                "error" => lint::LintSeverity::Error,
                "warning" => lint::LintSeverity::Warning,
                "info" => lint::LintSeverity::Info,
                _ => lint::LintSeverity::Error,
            };

            if format == "json" {
                let findings: Vec<serde_json::Value> = report.findings.iter()
                    .filter(|f| match min_sev {
                        lint::LintSeverity::Error => f.severity == lint::LintSeverity::Error,
                        lint::LintSeverity::Warning => matches!(f.severity, lint::LintSeverity::Error | lint::LintSeverity::Warning),
                        lint::LintSeverity::Info => true,
                    })
                    .map(|f| serde_json::json!({
                        "rule": f.rule,
                        "severity": match f.severity {
                            lint::LintSeverity::Error => "error",
                            lint::LintSeverity::Warning => "warning",
                            lint::LintSeverity::Info => "info",
                        },
                        "package": f.package,
                        "message": f.message,
                    }))
                    .collect();
                let error_count = findings.iter().filter(|f| f["severity"] == "error").count();
                let warning_count = findings.iter().filter(|f| f["severity"] == "warning").count();
                let info_count = findings.iter().filter(|f| f["severity"] == "info").count();
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "findings": findings,
                    "error_count": error_count,
                    "warning_count": warning_count,
                    "info_count": info_count,
                })).unwrap());
            } else {
                for f in &report.findings {
                    let sev_str = match f.severity {
                        lint::LintSeverity::Error => "ERROR",
                        lint::LintSeverity::Warning => "WARN",
                        lint::LintSeverity::Info => "INFO",
                    };
                    let pkg = f.package.as_deref().unwrap_or("-");
                    let skip = match min_sev {
                        lint::LintSeverity::Error => f.severity != lint::LintSeverity::Error,
                        lint::LintSeverity::Warning => !matches!(f.severity, lint::LintSeverity::Error | lint::LintSeverity::Warning),
                        lint::LintSeverity::Info => false,
                    };
                    if skip { continue; }
                    println!("{:8}{:24}{:12}{}", sev_str, f.rule, pkg, f.message);
                }
            }

            if report.has_errors() { std::process::exit(1); }
        }

        Commands::Diff { old_file, new_file, format } => {
            if verbose { eprintln!("[verbose] Reading {} and {}...", old_file.display(), new_file.display()); }
            let old_content = match read_input(&old_file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", old_file.display(), e); std::process::exit(2); }
            };
            let new_content = match read_input(&new_file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", new_file.display(), e); std::process::exit(2); }
            };
            let old_lf = match deserialize(&old_content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error in old file: {}", e); std::process::exit(2); }
            };
            let new_lf = match deserialize(&new_content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error in new file: {}", e); std::process::exit(2); }
            };

            let diff = diff_lockfiles(&old_lf, &new_lf);
            let fmt = match format.as_str() {
                "json" => lockfile::DiffFormat::Json,
                _ => lockfile::DiffFormat::Text,
            };
            print!("{}", serialize_diff(&diff, fmt));
        }

        Commands::Audit { file, format } => {
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };
            let report = lockfile.audit();

            if format == "json" {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "critical": report.critical.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                    "high": report.high.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                    "medium": report.medium.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                    "low": report.low.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                    "info": report.info.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                })).unwrap());
            } else {
                for adv in report.all_advisories() {
                    println!("{:10}{:16}{}   {}   {}", adv.severity.as_str().to_uppercase(), adv.package, adv.advisory_id, adv.affected_versions, adv.url);
                }
                println!("---");
                println!("Total: {} critical/high, {} medium, {} low, {} info", report.critical.len() + report.high.len(), report.medium.len(), report.low.len(), report.info.len());
            }

            if report.has_critical_or_high() { std::process::exit(1); }
        }

        Commands::Sbom { file, namespace, format } => {
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };
            let fmt = match format.as_str() {
                "cyclonedx-json" => sbom::SbomFormat::CycloneDxJson,
                _ => sbom::SbomFormat::SpdxJson,
            };
            match generate_sbom(&lockfile, fmt, &namespace) {
                Ok(s) => print!("{}", s),
                Err(e) => { eprintln!("SBOM generation error: {}", e); std::process::exit(1); }
            }
        }

        Commands::Sign { file, key_id, algorithm, private_key, expires, in_place } => {
            if in_place && file == std::path::Path::new("-") {
                eprintln!("Error: --in-place cannot be used with stdin input");
                std::process::exit(2);
            }
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let mut lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };
            let serialized = match serialize(&mut lockfile) {
                Ok(s) => s,
                Err(e) => { eprintln!("Serialize error: {}", e); std::process::exit(1); }
            };

            let algo = match algorithm.as_str() {
                "mldsa65" => signature::SignatureAlgorithm::MlDsa65,
                _ => signature::SignatureAlgorithm::Ed25519,
            };

            let key_hex = if let Some(path) = private_key.strip_prefix('@') {
                match std::fs::read_to_string(path) {
                    Ok(h) => h.trim().to_string(),
                    Err(e) => { eprintln!("Error reading key file: {}", e); std::process::exit(2); }
                }
            } else {
                private_key.clone()
            };

            let key_bytes: Vec<u8> = (0..key_hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&key_hex[i..i+2], 16).ok())
                .collect();

            match sign_lockfile(&serialized, &key_id, algo, &key_bytes, expires) {
                Ok(signed) => {
                    if in_place {
                        if let Err(e) = std::fs::write(&file, &signed) {
                            eprintln!("Error writing {}: {}", file.display(), e); std::process::exit(1);
                        }
                    } else {
                        print!("{}", signed);
                    }
                }
                Err(e) => { eprintln!("Signing error: {}", e); std::process::exit(1); }
            }
        }

        Commands::Graph { file, root, platform, output } => {
            if verbose { eprintln!("[verbose] Reading {}...", file.display()); }
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let root_cids: Vec<u64> = root.iter()
                .filter_map(|name| {
                    lockfile.packages.iter()
                        .find(|p| p.name == *name)
                        .map(|p| fnv::calculate(&format!("{}@{}.{}.{}", p.name, p.major, p.minor, p.patch)))
                })
                .collect();

            if root_cids.len() != root.len() {
                eprintln!("Some root packages not found in lockfile");
                std::process::exit(1);
            }

            let result = if let Some(ref plat) = platform {
                if let Some((os, arch)) = parse_platform(plat) {
                    extract_subgraph_platform(&lockfile, &root_cids, os, arch)
                } else {
                    eprintln!("Invalid platform format. Use <os>-<arch> (e.g. linux-x86_64)");
                    std::process::exit(1);
                }
            } else {
                extract_subgraph(&lockfile, &root_cids)
            };

            match result {
                Ok(mut sub) => {
                    let serialized = serialize(&mut sub).unwrap();
                    if let Some(out) = output {
                        if let Err(e) = std::fs::write(&out, &serialized) {
                            eprintln!("Error writing {}: {}", out.display(), e); std::process::exit(1);
                        }
                    } else {
                        print!("{}", serialized);
                    }
                }
                Err(e) => { eprintln!("Extraction error: {}", e); std::process::exit(1); }
            }
        }

        Commands::Merge { base, ours, theirs, strategy, output } => {
            let read_file = |path: &PathBuf| -> Result<Lockfile, String> {
                let content = read_input(path).map_err(|e| format!("Error reading {}: {}", path.display(), e))?;
                deserialize(&content).map_err(|e| format!("Parse error in {}: {}", path.display(), e))
            };

            let base_lf = match read_file(&base) { Ok(lf) => lf, Err(e) => { eprintln!("{}", e); std::process::exit(2); } };
            let ours_lf = match read_file(&ours) { Ok(lf) => lf, Err(e) => { eprintln!("{}", e); std::process::exit(2); } };
            let theirs_lf = match read_file(&theirs) { Ok(lf) => lf, Err(e) => { eprintln!("{}", e); std::process::exit(2); } };

            let strat = match strategy.as_str() {
                "ours" => merge::ConflictStrategy::Ours,
                "theirs" => merge::ConflictStrategy::Theirs,
                _ => merge::ConflictStrategy::Fail,
            };

            match merge_lockfiles(&base_lf, &ours_lf, &theirs_lf, strat) {
                Ok(result) => {
                    for conflict in &result.conflicts {
                        eprintln!("CONFLICT: {} (base: {:?}, ours: {}.{}, theirs: {}.{})",
                            conflict.package_name,
                            conflict.base.as_ref().map(|b| b.name.clone()),
                            conflict.ours.major, conflict.ours.minor,
                            conflict.theirs.major, conflict.theirs.minor);
                    }
                    let mut merged = result.lockfile;
                    let serialized = serialize(&mut merged).unwrap();
                    if let Some(out) = output {
                        if let Err(e) = std::fs::write(&out, &serialized) {
                            eprintln!("Error writing {}: {}", out.display(), e); std::process::exit(1);
                        }
                    } else {
                        print!("{}", serialized);
                    }
                    if !result.conflicts.is_empty() && strat == merge::ConflictStrategy::Fail {
                        std::process::exit(2);
                    } else if !result.conflicts.is_empty() {
                        std::process::exit(1);
                    }
                }
                Err(e) => { eprintln!("Merge error: {}", e); std::process::exit(2); }
            }
        }

        Commands::Completions { shell } => {
            use clap_complete::{generate, Shell};
            let shell_type = match shell.as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "elvish" => Shell::Elvish,
                "powershell" => Shell::PowerShell,
                _ => {
                    eprintln!("Error: unknown shell '{}'. Supported: bash, zsh, fish, elvish, powershell", shell);
                    std::process::exit(2);
                }
            };
            let mut cmd = Cli::command();
            let name = "hlock";
            generate(shell_type, &mut cmd, name, &mut std::io::stdout());
        }
    }
}
