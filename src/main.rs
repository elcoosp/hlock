mod output;

use clap::{CommandFactory, Parser, Subcommand};
use hlock::*;
use owo_colors::OwoColorize;
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
        #[arg(long, required = true)]
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
    Info {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Dedup {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Why {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        package: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Deps {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        package: String,
        #[arg(long)]
        transitive: bool,
        #[arg(long, default_value = "all")]
        dep_type: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Dependents {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        package: String,
        #[arg(long)]
        transitive: bool,
        #[arg(long, default_value = "all")]
        dep_type: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Check {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0)]
        time: u64,
        #[arg(long, default_value = "error")]
        severity: String,
        #[arg(long)]
        rule: Vec<String>,
        #[arg(long)]
        vex: bool,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Tree {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, required = true)]
        root: Vec<String>,
        #[arg(long)]
        depth: Option<u32>,
        #[arg(long, default_value = "all")]
        dep_type: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Licenses {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        missing: bool,
        #[arg(long)]
        allow: Option<String>,
        #[arg(long)]
        deny: Option<String>,
        #[arg(long)]
        strict: bool,
        #[arg(long, default_value = "text")]
        format: String,
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

    let quiet = cli.quiet;
    let verbose = cli.verbose && !quiet;
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
                eprintln!("{} {}", "✗".red().bold(), e);
                std::process::exit(1);
            }
            println!("{} digest valid", "✓".green().bold());

            let mut trusted: HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> = HashMap::new();
            for spec in &trusted_key {
                if let Some((key_id, (pubkey, algo))) = parse_trusted_key(spec) {
                    trusted.insert(key_id, (pubkey, algo));
                }
            }

            if !trusted.is_empty() {
                if let Err(e) = verify_signature(&content, &trusted) {
                    eprintln!("{} {}", "✗".red().bold(), e);
                    std::process::exit(1);
                }
                println!("{} signature valid", "✓".green().bold());
            }

            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("✗ parse error: {}", e); std::process::exit(2); }
            };

            let now = if time > 0 { time } else { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) };
            if !lockfile.trust_roots.is_empty() {
                if let Err(e) = lockfile.validate_trust_chain(now) {
                    eprintln!("{} {}", "✗".red().bold(), e);
                    std::process::exit(1);
                }
                println!("{} trust chain valid", "✓".green().bold());
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
                        lint::LintSeverity::Error => "ERROR".red().bold().to_string(),
                        lint::LintSeverity::Warning => "WARN".yellow().bold().to_string(),
                        lint::LintSeverity::Info => "INFO".blue().to_string(),
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
                    let sev_str = match adv.severity {
                        policy::AdvisorySeverity::Critical | policy::AdvisorySeverity::High => adv.severity.as_str().to_uppercase().red().bold().to_string(),
                        policy::AdvisorySeverity::Medium => adv.severity.as_str().to_uppercase().yellow().bold().to_string(),
                        policy::AdvisorySeverity::Low => adv.severity.as_str().to_uppercase().yellow().to_string(),
                        policy::AdvisorySeverity::Info => adv.severity.as_str().to_uppercase().blue().to_string(),
                    };
                    println!("{:10}{:16}{}   {}   {}", sev_str, adv.package, adv.advisory_id, adv.affected_versions, adv.url);
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

        Commands::Info { file, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };

            let digest_valid = validate_digest(&content).is_ok();

            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let mut registry_count = 0usize;
            let mut git_count = 0usize;
            let mut workspace_count = 0usize;
            let mut local_count = 0usize;
            let mut cas_count = 0usize;
            let mut ipfs_count = 0usize;

            for pkg in &lockfile.packages {
                if let Some(source) = lockfile.sources.get(pkg.source_idx) {
                    match source {
                        hlock::Source::Registry(_) => registry_count += 1,
                        hlock::Source::Git(_) => git_count += 1,
                        hlock::Source::Workspace => workspace_count += 1,
                        hlock::Source::Local(_) => local_count += 1,
                        hlock::Source::CasHttp(_) => cas_count += 1,
                        hlock::Source::Ipfs(_) => ipfs_count += 1,
                    }
                }
            }

            let fmt = output::parse_format(&format);

            if fmt == output::OutputFormat::Json {
                let mut sources_json = Vec::new();
                for (idx, source) in lockfile.sources.iter().enumerate() {
                    let mut obj = serde_json::json!({"index": idx});
                    match source {
                        hlock::Source::Registry(u) => { obj["url"] = serde_json::Value::String(u.clone()); obj["type"] = serde_json::Value::String("registry".to_string()); }
                        hlock::Source::Git(u) => { obj["url"] = serde_json::Value::String(u.clone()); obj["type"] = serde_json::Value::String("git".to_string()); }
                        hlock::Source::Local(u) => { obj["url"] = serde_json::Value::String(u.clone()); obj["type"] = serde_json::Value::String("local".to_string()); }
                        hlock::Source::Workspace => { obj["type"] = serde_json::Value::String("workspace".to_string()); }
                        hlock::Source::CasHttp(u) => { obj["url"] = serde_json::Value::String(u.clone()); obj["type"] = serde_json::Value::String("cas-http".to_string()); }
                        hlock::Source::Ipfs(u) => { obj["url"] = serde_json::Value::String(u.clone()); obj["type"] = serde_json::Value::String("ipfs".to_string()); }
                    }
                    sources_json.push(obj);
                }

                let policies_json: Vec<serde_json::Value> = lockfile.policies.iter().map(|p| serde_json::json!({"type": p.policy_type.as_str(), "pattern": p.package_pattern, "value": p.value})).collect();
                let trust_roots_json: Vec<serde_json::Value> = lockfile.trust_roots.iter().map(|tr| serde_json::json!({"key_id": tr.key_id, "algorithm": match tr.algorithm { hlock::signature::SignatureAlgorithm::Ed25519 => "ed25519", hlock::signature::SignatureAlgorithm::MlDsa65 => "mldsa65" }, "role": tr.role.as_str(), "expires_epoch": tr.expires_epoch})).collect();
                let overrides_json: Vec<serde_json::Value> = lockfile.overrides.iter().map(|o| serde_json::json!({"name": o.name, "from": o.from_version, "to": o.to_version})).collect();
                let features_json: Vec<serde_json::Value> = lockfile.features.iter().map(|(n, f)| serde_json::json!({"name": n, "flags": f})).collect();

                let adv_report = lockfile.audit();
                let advisory_summary = serde_json::json!({"critical": adv_report.critical.len(), "high": adv_report.high.len(), "medium": adv_report.medium.len(), "low": adv_report.low.len(), "info": adv_report.info.len()});

                let vex_json: Vec<serde_json::Value> = lockfile.vex_entries.iter().map(|v| serde_json::json!({"package": v.package, "advisory_id": v.advisory_id, "status": v.status.as_str()})).collect();

                let json = serde_json::json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "package_count": lockfile.packages.len(),
                    "packages_by_source": {"registry": registry_count, "git": git_count, "workspace": workspace_count, "local": local_count, "cas_http": cas_count, "ipfs": ipfs_count},
                    "sources": sources_json,
                    "mirrors": lockfile.mirrors.iter().map(|m| serde_json::json!({"scope": m.scope, "url": m.url})).collect::<Vec<_>>(),
                    "policy_count": lockfile.policies.len(),
                    "policies": policies_json,
                    "trust_roots": trust_roots_json,
                    "overrides": overrides_json,
                    "features": features_json,
                    "advisory_summary": advisory_summary,
                    "vex_entries": vex_json,
                    "license_summary": {"declared": lockfile.licenses.len(), "total": lockfile.packages.len()},
                    "workspace_root": lockfile.workspace_root,
                    "workspace_pkgs": lockfile.workspace_pkgs.iter().map(|wp| serde_json::json!({"name": wp.name, "manifest_path": wp.manifest_path})).collect::<Vec<_>>(),
                    "hoist_boundaries": lockfile.hoist_boundaries.iter().map(|hb| serde_json::json!({"consumer": hb.cosine, "allowed_deps": hb.allowed_deps})).collect::<Vec<_>>(),
                    "digest_valid": digest_valid,
                });

                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    println!("hlock v{} lockfile", env!("CARGO_PKG_VERSION"));
                    println!("────────────────────────");

                    let mut parts = Vec::new();
                    if registry_count > 0 { parts.push(format!("{} registry", registry_count)); }
                    if git_count > 0 { parts.push(format!("{} git", git_count)); }
                    if workspace_count > 0 { parts.push(format!("{} workspace", workspace_count)); }
                    if local_count > 0 { parts.push(format!("{} local", local_count)); }
                    if cas_count > 0 { parts.push(format!("{} cas-http", cas_count)); }
                    if ipfs_count > 0 { parts.push(format!("{} ipfs", ipfs_count)); }
                    let pkg_detail = if parts.is_empty() { String::new() } else { format!(" ({})", parts.join(", ")) };
                    println!("Packages:       {}{}", lockfile.packages.len(), pkg_detail);

                    println!("Sources:        {}", lockfile.sources.len());
                    for (idx, source) in lockfile.sources.iter().enumerate() {
                        let (url, type_str) = match source {
                            hlock::Source::Registry(u) => (u.as_str(), "registry"),
                            hlock::Source::Git(u) => (u.as_str(), "git"),
                            hlock::Source::Local(u) => (u.as_str(), "local"),
                            hlock::Source::Workspace => ("", "workspace"),
                            hlock::Source::CasHttp(u) => (u.as_str(), "cas-http"),
                            hlock::Source::Ipfs(u) => (u.as_str(), "ipfs"),
                        };
                        if url.is_empty() { println!("  [{}] {}", idx, type_str); } else { println!("  [{}] {} ({})", idx, url, type_str); }
                    }

                    if !lockfile.mirrors.is_empty() {
                        println!("Mirrors:        {}", lockfile.mirrors.len());
                        for m in &lockfile.mirrors { println!("  {} -> {}", m.scope, m.url); }
                    }

                    if !lockfile.policies.is_empty() {
                        println!("Policies:       {}", lockfile.policies.len());
                        for p in &lockfile.policies { println!("  {} {} {}", p.policy_type.as_str(), p.package_pattern, p.value); }
                    }

                    if !lockfile.trust_roots.is_empty() {
                        println!("Trust Roots:    {}", lockfile.trust_roots.len());
                        for tr in &lockfile.trust_roots {
                            let algo_str = match tr.algorithm { hlock::signature::SignatureAlgorithm::Ed25519 => "ed25519", hlock::signature::SignatureAlgorithm::MlDsa65 => "mldsa65" };
                            let expires_str = if tr.expires_epoch == 0 { "never expires".to_string() } else { format!("expires epoch {}", tr.expires_epoch) };
                            println!("  {} ({}, {}, {})", tr.key_id, algo_str, tr.role.as_str(), expires_str);
                        }
                    }

                    if !lockfile.overrides.is_empty() {
                        println!("Overrides:      {}", lockfile.overrides.len());
                        for o in &lockfile.overrides { println!("  {} {} -> {}", o.name, o.from_version, o.to_version); }
                    }

                    if !lockfile.features.is_empty() {
                        println!("Features:       {}", lockfile.features.len());
                        for (name, flags) in &lockfile.features { println!("  {} -> {}", name, flags.join(", ")); }
                    }

                    let adv_report = lockfile.audit();
                    if adv_report.total_count() > 0 {
                        println!("Advisories:     {} ({} critical, {} high, {} medium, {} low, {} info)", adv_report.total_count(), adv_report.critical.len(), adv_report.high.len(), adv_report.medium.len(), adv_report.low.len(), adv_report.info.len());
                        println!("  Run `hlock audit` for details.");
                    }

                    if !lockfile.vex_entries.is_empty() {
                        println!("VEX Entries:    {}", lockfile.vex_entries.len());
                        for v in &lockfile.vex_entries { println!("  {} / {} -> {}", v.package, v.advisory_id, v.status.as_str()); }
                    }

                    let declared = lockfile.licenses.len();
                    let total = lockfile.packages.len();
                    println!("Licenses:       {}/{} declared", declared, total);
                    if declared < total { println!("  Run `hlock licenses` for details."); }

                    if let Some(ref root) = lockfile.workspace_root {
                        println!("Workspace:      {}", root);
                        for wp in &lockfile.workspace_pkgs { println!("  └── {} ({})", wp.name, wp.manifest_path); }
                    }

                    if !lockfile.hoist_boundaries.is_empty() {
                        println!("Hoist Boundaries:");
                        for hb in &lockfile.hoist_boundaries { println!("  {} -> [{}]", hb.cosine, hb.allowed_deps.join(", ")); }
                    }

                    if digest_valid { println!("✓ Digest valid (blake3)"); } else { println!("✗ Digest invalid"); }
                }
            }
        }

        Commands::Dedup { file, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let opportunities = lockfile.dedup_opportunities();
            let fmt = output::parse_format(&format);

            if fmt == output::OutputFormat::Json {
                let json = serde_json::json!({
                    "opportunities": opportunities.iter().map(|o| serde_json::json!({"package": o.package_name, "versions": o.versions, "potential_saving_bytes": o.potential_saving_bytes})).collect::<Vec<_>>(),
                });
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    if opportunities.is_empty() {
                        println!("No deduplication opportunities found.");
                    } else {
                        println!("Deduplication Opportunities:");
                        println!();
                        println!("{:12}{:24}{:16}", "Package", "Versions", "Est. Saving");
                        println!("{:12}{:24}{:16}", "---------", "------------------------", "--------------");
                        for o in &opportunities {
                            println!("{:12}{:24}~{} bytes", o.package_name, o.versions.join(", "), o.potential_saving_bytes);
                        }
                    }
                }
            }
        }

        Commands::Tree { file, root, depth, dep_type, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let fmt = output::parse_format(&format);
            let max_depth = depth;
            let filter_dep_type = dep_type.clone();

            let root_names = root;

            struct TreeNode {
                name: String,
                version: String,
                dep_type: Option<String>,
                dependencies: Vec<TreeNode>,
            }

            impl TreeNode {
                fn to_json(&self) -> serde_json::Value {
                    let deps: Vec<serde_json::Value> = self.dependencies.iter().map(|d| d.to_json()).collect();
                    let mut obj = serde_json::json!({
                        "name": self.name,
                        "version": self.version,
                    });
                    if let Some(ref dt) = self.dep_type {
                        obj["dep_type"] = serde_json::Value::String(dt.clone());
                    }
                    obj["dependencies"] = serde_json::Value::Array(deps);
                    obj
                }
            }

            fn build_tree(
                lockfile: &hlock::Lockfile,
                name: &str,
                current_depth: u32,
                max_depth: Option<u32>,
                dep_type_filter: &str,
                visited: &mut HashSet<String>,
            ) -> TreeNode {
                let pkg = lockfile.packages.iter().find(|p| p.name == name);
                let version = pkg.map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch)).unwrap_or_default();
                let mut node = TreeNode {
                    name: name.to_string(),
                    version,
                    dep_type: None,
                    dependencies: Vec::new(),
                };

                if max_depth.map_or(false, |max| current_depth >= max) {
                    return node;
                }

                if visited.contains(name) {
                    return node;
                }
                visited.insert(name.to_string());

                if let Some(pkg) = pkg {
                    for dep in &pkg.dependencies {
                        let follows = match dep_type_filter {
                            "runtime" => matches!(dep.dep_type, hlock::DepType::Runtime),
                            "dev" => matches!(dep.dep_type, hlock::DepType::Dev),
                            "peer" => matches!(dep.dep_type, hlock::DepType::Peer),
                            _ => true,
                        };
                        if !follows { continue; }

                        if visited.contains(&dep.name) {
                            let dep_pkg = lockfile.packages.iter().find(|p| p.name == dep.name);
                            let dep_ver = dep_pkg.map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch)).unwrap_or_default();
                            let dt = match dep.dep_type {
                                hlock::DepType::Runtime => "runtime",
                                hlock::DepType::Dev => "dev",
                                hlock::DepType::Peer => "peer",
                                hlock::DepType::Optional => "optional",
                                hlock::DepType::OptionalTarget(_, _) => "optional-target",
                            };
                            node.dependencies.push(TreeNode {
                                name: format!("{} ↻", dep.name),
                                version: dep_ver,
                                dep_type: Some(dt.to_string()),
                                dependencies: Vec::new(),
                            });
                            continue;
                        }

                        let dt = match dep.dep_type {
                            hlock::DepType::Runtime => "runtime",
                            hlock::DepType::Dev => "dev",
                            hlock::DepType::Peer => "peer",
                            hlock::DepType::Optional => "optional",
                            hlock::DepType::OptionalTarget(_, _) => "optional-target",
                        };
                        let mut child = build_tree(lockfile, &dep.name, current_depth + 1, max_depth, dep_type_filter, visited);
                        child.dep_type = Some(dt.to_string());
                        node.dependencies.push(child);
                    }
                }

                visited.remove(name);
                node
            }

            fn render_tree_text(
                node: &TreeNode,
                prefix: &str,
                is_last: bool,
                show_dep_type: bool,
            ) {
                let connector = if is_last { "└" } else { "├" };
                let is_cycle = node.name.contains(" ↻");
                let display_name = if is_cycle {
                    node.name.clone()
                } else {
                    format!("{}@{}", node.name, node.version)
                };
                let type_suffix = if show_dep_type {
                    if let Some(ref dt) = node.dep_type {
                        format!(" ({})", dt)
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                println!("{}{}── {}{}", prefix, connector, display_name, type_suffix);

                let child_prefix = format!("{}{}", prefix, if is_last { "    " } else { "│   " });
                let dep_count = node.dependencies.len();
                for (i, child) in node.dependencies.iter().enumerate() {
                    let is_last_child = i == dep_count - 1;
                    render_tree_text(child, &child_prefix, is_last_child, show_dep_type);
                }
            }

            if fmt == output::OutputFormat::Json {
                let mut trees = Vec::new();
                for root_name in &root_names {
                    let mut visited = HashSet::new();
                    let tree = build_tree(&lockfile, root_name, 0, max_depth, &filter_dep_type, &mut visited);
                    trees.push(tree);
                }

                let root_pkg = lockfile.packages.iter().find(|p| root_names.first().map(|rn| p.name == *rn).unwrap_or(false));
                let root_version = root_pkg.map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch)).unwrap_or_default();

                let json = if root_names.len() == 1 {
                    serde_json::json!({
                        "root": root_names[0],
                        "root_version": root_version,
                        "tree": trees[0].to_json(),
                    })
                } else {
                    serde_json::json!({
                        "roots": root_names,
                        "trees": trees.iter().map(|t| t.to_json()).collect::<Vec<_>>(),
                    })
                };
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    for (i, root_name) in root_names.iter().enumerate() {
                        if root_names.len() > 1 && i > 0 {
                            println!();
                        }
                        let mut visited = HashSet::new();
                        let tree = build_tree(&lockfile, root_name, 0, max_depth, &filter_dep_type, &mut visited);
                        let show_dep_type = filter_dep_type == "all";
                        println!("{}@{}", tree.name, tree.version);
                        let dep_count = tree.dependencies.len();
                        for (j, child) in tree.dependencies.iter().enumerate() {
                            let is_last = j == dep_count - 1;
                            render_tree_text(child, "", is_last, show_dep_type);
                        }
                    }
                }
            }
        }

        Commands::Licenses { file, missing, allow, deny, strict, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let fmt = output::parse_format(&format);

            let licensed_map: std::collections::HashMap<&str, &str> = lockfile.licenses.iter()
                .map(|l| (l.package.as_str(), l.expression.as_str()))
                .collect();

            let allowed_licenses: Vec<String> = allow.as_ref().map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
            let denied_licenses: Vec<String> = deny.as_ref().map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();

            struct LicenseEntry {
                name: String,
                license: Option<String>,
                source: String,
                source_type: String,
                is_workspace: bool,
            }

            let mut entries: Vec<LicenseEntry> = Vec::new();
            for pkg in &lockfile.packages {
                let lic = licensed_map.get(pkg.name.as_str()).cloned();
                let (source, source_type) = match lockfile.sources.get(pkg.source_idx) {
                    Some(hlock::Source::Registry(u)) => (u.clone(), "registry".to_string()),
                    Some(hlock::Source::Git(u)) => (u.clone(), "git".to_string()),
                    Some(hlock::Source::Workspace) => (String::new(), "workspace".to_string()),
                    Some(hlock::Source::Local(u)) => (u.clone(), "local".to_string()),
                    Some(hlock::Source::CasHttp(u)) => (u.clone(), "cas-http".to_string()),
                    Some(hlock::Source::Ipfs(u)) => (u.clone(), "ipfs".to_string()),
                    None => (String::new(), "unknown".to_string()),
                };
                let is_workspace = source_type == "workspace";
                entries.push(LicenseEntry { name: pkg.name.clone(), license: lic.map(String::from), source, source_type, is_workspace });
            }

            let filtered_entries: Vec<&LicenseEntry> = if missing {
                entries.iter().filter(|e| e.license.is_none() && !e.is_workspace).collect()
            } else {
                entries.iter().collect()
            };

            let declared_count = entries.iter().filter(|e| e.license.is_some()).count();
            let undeclared_count = entries.iter().filter(|e| e.license.is_none() && !e.is_workspace).count();
            let workspace_count = entries.iter().filter(|e| e.is_workspace).count();
            let copyleft_keywords = ["GPL", "AGPL", "LGPL", "CPAL", "EUPL", "Ms-PL"];
            let copyleft_count = entries.iter().filter(|e| {
                e.license.as_ref().map_or(false, |l| copyleft_keywords.iter().any(|k| l.contains(k)))
            }).count();
            let permissive_count = declared_count - copyleft_count;

            let mut violations: Vec<serde_json::Value> = Vec::new();

            for entry in &entries {
                if entry.is_workspace { continue; }
                if let Some(ref lic) = entry.license {
                    for denied in &denied_licenses {
                        if lic.contains(denied) {
                            violations.push(serde_json::json!({
                                "package": entry.name,
                                "reason": "denied",
                                "license": lic,
                            }));
                        }
                    }
                    if !allowed_licenses.is_empty() {
                        let is_allowed = allowed_licenses.iter().any(|a| lic.contains(a) || a == lic);
                        if !is_allowed {
                            violations.push(serde_json::json!({
                                "package": entry.name,
                                "reason": "not-allowed",
                                "license": lic,
                            }));
                        }
                    }
                } else if strict {
                    violations.push(serde_json::json!({
                        "package": entry.name,
                        "reason": "undeclared",
                    }));
                } else if !allowed_licenses.is_empty() {
                    violations.push(serde_json::json!({
                        "package": entry.name,
                        "reason": "undeclared",
                    }));
                }
            }

            let has_violations = !violations.is_empty();

            if fmt == output::OutputFormat::Json {
                let pkgs_json: Vec<serde_json::Value> = filtered_entries.iter().map(|e| {
                    serde_json::json!({
                        "name": e.name,
                        "license": e.license,
                        "source": e.source,
                        "source_type": e.source_type,
                    })
                }).collect();
                let json = serde_json::json!({
                    "packages": pkgs_json,
                    "summary": {
                        "declared": declared_count,
                        "total": entries.len(),
                        "undeclared": undeclared_count,
                        "workspace": workspace_count,
                        "copyleft": copyleft_count,
                        "permissive": permissive_count,
                    },
                    "violations": violations,
                    "total_packages": entries.len(),
                });
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    if filtered_entries.is_empty() {
                        if missing {
                            println!("All packages have license declarations.");
                        } else {
                            println!("No license declarations found.");
                        }
                    } else {
                        println!("{:24}{:16}{:16}{}", "Package", "License", "Source", if missing { "Status" } else { "" });
                        println!("{:24}{:16}{:16}{}", "────────────────────────", "────────────────", "────────────────", if missing { "──────" } else { "" });
                        for entry in filtered_entries {
                            let lic_str = match &entry.license {
                                Some(l) => l.clone(),
                                None => "⚠ UNDECLARED".to_string(),
                            };
                            let src_short = if entry.source.is_empty() { entry.source_type.clone() } else {
                                let url = &entry.source;
                                if url.starts_with("https://") {
                                    url[8..].split('/').next().unwrap_or(&url[8..]).to_string()
                                } else {
                                    url.clone()
                                }
                            };
                            if missing {
                                println!("{:24}{:16}{:16}MISSING", entry.name, lic_str, src_short);
                            } else {
                                println!("{:24}{:16}{}", entry.name, lic_str, src_short);
                            }
                        }
                        println!();
                        println!("Summary: {}/{} declared, {} copyleft, {} permissive, {} undeclared, {} workspace", declared_count, entries.len(), copyleft_count, permissive_count, undeclared_count, workspace_count);
                    }
                }
            }

            if has_violations {
                std::process::exit(1);
            }
        }

        Commands::Check { file, trusted_key, time, severity, rule, vex, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };

            let digest_valid = validate_digest(&content).is_ok();

            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => {
                    let fmt = output::parse_format(&format);
                    if fmt == output::OutputFormat::Json {
                        if !quiet {
                            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                                "digest_valid": digest_valid,
                                "signature": { "present": false, "valid": false },
                                "trust_chain_valid": false,
                                "lint": { "error_count": 0, "warning_count": 0, "info_count": 0, "findings": [] },
                                "audit": { "critical": [], "high": [], "medium": [], "low": [], "info": [], "vex_suppressed": [] },
                                "passed": false,
                            })).unwrap());
                        }
                    } else {
                        if !quiet {
                            println!("{} parse error: {}", "✗".red().bold(), e);
                        }
                    }
                    std::process::exit(2);
                }
            };

            let now = if time > 0 { time } else { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) };

            let trust_chain_valid = if !lockfile.trust_roots.is_empty() {
                lockfile.validate_trust_chain(now).is_ok()
            } else {
                true
            };

            let mut trusted: HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> = HashMap::new();
            for spec in &trusted_key {
                if let Some((key_id, (pubkey, algo))) = parse_trusted_key(spec) {
                    trusted.insert(key_id, (pubkey, algo));
                }
            }

            let (sig_present, sig_valid, sig_key_id, sig_algo) = if !trusted.is_empty() {
                match verify_signature(&content, &trusted) {
                    Ok(()) => {
                        let first_key = trusted.keys().next().cloned().unwrap_or_default();
                        let first_algo = trusted.values().next().map(|(_, a)| *a).unwrap_or(signature::SignatureAlgorithm::Ed25519);
                        (true, true, first_key, first_algo)
                    }
                    Err(_) => {
                        let first_key = trusted.keys().next().cloned().unwrap_or_default();
                        let first_algo = trusted.values().next().map(|(_, a)| *a).unwrap_or(signature::SignatureAlgorithm::Ed25519);
                        (true, false, first_key, first_algo)
                    }
                }
            } else {
                (false, true, String::new(), signature::SignatureAlgorithm::Ed25519)
            };

            let rules = build_rule_set(&rule);
            let lint_report = hlock::lint::lint(&lockfile, &rules);

            let min_sev = match severity.as_str() {
                "warning" => lint::LintSeverity::Warning,
                "info" => lint::LintSeverity::Info,
                _ => lint::LintSeverity::Error,
            };

            let lint_errors: Vec<&lint::LintFinding> = lint_report.findings.iter()
                .filter(|f| match min_sev {
                    lint::LintSeverity::Error => f.severity == lint::LintSeverity::Error,
                    lint::LintSeverity::Warning => matches!(f.severity, lint::LintSeverity::Error | lint::LintSeverity::Warning),
                    lint::LintSeverity::Info => true,
                })
                .collect();

            let audit_report = if vex {
                lockfile.audit()
            } else {
                lockfile.effective_advisories()
            };

            let audit_has_critical_or_high = audit_report.has_critical_or_high();

            let hard_failure = !digest_valid || (sig_present && !sig_valid) || !trust_chain_valid;
            let soft_failure = !lint_errors.is_empty() || audit_has_critical_or_high;

            let fmt = output::parse_format(&format);

            if fmt == output::OutputFormat::Json {
                let sig_algo_str = match sig_algo {
                    signature::SignatureAlgorithm::Ed25519 => "ed25519",
                    signature::SignatureAlgorithm::MlDsa65 => "mldsa65",
                };
                let lint_findings: Vec<serde_json::Value> = lint_report.findings.iter()
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
                let vex_suppressed: Vec<serde_json::Value> = if !vex {
                    let full_audit = lockfile.audit();
                    let effective_ids: std::collections::HashSet<String> = audit_report.all_advisories().map(|a| a.advisory_id.clone()).collect();
                    full_audit.all_advisories()
                        .filter(|a| !effective_ids.contains(&a.advisory_id))
                        .map(|a| serde_json::json!({
                            "package": a.package,
                            "id": a.advisory_id,
                            "status": lockfile.vex_for(&a.package, &a.advisory_id).map(|v| v.status.as_str()).unwrap_or("unknown"),
                        }))
                        .collect()
                } else {
                    vec![]
                };
                if !quiet {
                    println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                        "digest_valid": digest_valid,
                        "signature": {
                            "present": sig_present,
                            "valid": sig_valid,
                            "key_id": sig_key_id,
                            "algorithm": sig_algo_str,
                        },
                        "trust_chain_valid": trust_chain_valid,
                        "lint": {
                            "error_count": lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Error).count(),
                            "warning_count": lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Warning).count(),
                            "info_count": lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Info).count(),
                            "findings": lint_findings,
                        },
                        "audit": {
                            "critical": audit_report.critical.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                            "high": audit_report.high.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                            "medium": audit_report.medium.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                            "low": audit_report.low.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                            "info": audit_report.info.iter().map(|a| serde_json::json!({"package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(), "url": a.url, "affected": a.affected_versions})).collect::<Vec<_>>(),
                            "vex_suppressed": vex_suppressed,
                        },
                        "passed": !hard_failure && !soft_failure,
                    })).unwrap());
                }
            } else {
                if !quiet {
                    if digest_valid { println!("{} Digest valid", "✓".green().bold()); }
                    else { println!("{} Digest invalid", "✗".red().bold()); }

                    if sig_present {
                        if sig_valid {
                            let algo_str = match sig_algo { signature::SignatureAlgorithm::Ed25519 => "ed25519", signature::SignatureAlgorithm::MlDsa65 => "mldsa65" };
                            println!("{} Signature valid ({}, {})", "✓".green().bold(), sig_key_id, algo_str);
                        } else {
                            println!("{} Signature invalid", "✗".red().bold());
                        }
                    } else {
                        println!("  No signature found (use --trusted-key to verify signatures)");
                    }

                    if trust_chain_valid { println!("{} Trust chain valid", "✓".green().bold()); }
                    else { println!("{} Trust chain invalid", "✗".red().bold()); }

                    let err_count = lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Error).count();
                    let warn_count = lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Warning).count();
                    let info_count = lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Info).count();
                    if err_count == 0 && warn_count == 0 && info_count == 0 {
                        println!("{} Lint: 0 errors, 0 warnings, 0 info", "✓".green().bold());
                    } else {
                        println!("Lint: {} error(s), {} warning(s), {} info(s)", err_count, warn_count, info_count);
                        for f in &lint_errors {
                            let sev_str = match f.severity {
                                lint::LintSeverity::Error => "ERROR".red().bold().to_string(),
                                lint::LintSeverity::Warning => "WARN".yellow().bold().to_string(),
                                lint::LintSeverity::Info => "INFO".blue().to_string(),
                            };
                            let pkg = f.package.as_deref().unwrap_or("-");
                            println!("  {} {:20} {:12} {}", sev_str, f.rule, pkg, f.message);
                        }
                    }

                    if !audit_has_critical_or_high && audit_report.total_count() == 0 {
                        println!("{} Audit: 0 vulnerabilities", "✓".green().bold());
                    } else if !audit_has_critical_or_high {
                        println!("{} Audit: {} (no critical/high)", "✓".green().bold(), audit_report.total_count());
                    } else {
                        let crit_count = audit_report.critical.len();
                        let high_count = audit_report.high.len();
                        let med_count = audit_report.medium.len();
                        let low_count = audit_report.low.len();
                        let info_count = audit_report.info.len();
                        print!("Audit: {} critical, {} high, {} medium, {} low, {} info", crit_count, high_count, med_count, low_count, info_count);
                        if !vex {
                            let full_audit = lockfile.audit();
                            let effective_ids: std::collections::HashSet<String> = audit_report.all_advisories().map(|a| a.advisory_id.clone()).collect();
                            let suppressed: Vec<_> = full_audit.all_advisories().filter(|a| !effective_ids.contains(&a.advisory_id)).collect();
                            if !suppressed.is_empty() {
                                print!(" ({} VEX-suppressed)", suppressed.len());
                            }
                        }
                        println!();
                        for adv in audit_report.all_advisories() {
                            let sev_str = match adv.severity {
                                policy::AdvisorySeverity::Critical | policy::AdvisorySeverity::High => adv.severity.as_str().to_uppercase().red().bold().to_string(),
                                policy::AdvisorySeverity::Medium => adv.severity.as_str().to_uppercase().yellow().bold().to_string(),
                                policy::AdvisorySeverity::Low => adv.severity.as_str().to_uppercase().yellow().to_string(),
                                policy::AdvisorySeverity::Info => adv.severity.as_str().to_uppercase().blue().to_string(),
                            };
                            println!("  {} {:12} {:16} {}", sev_str, adv.package, adv.advisory_id, adv.affected_versions);
                        }
                        if !vex {
                            let full_audit = lockfile.audit();
                            let effective_ids: std::collections::HashSet<String> = audit_report.all_advisories().map(|a| a.advisory_id.clone()).collect();
                            let suppressed: Vec<_> = full_audit.all_advisories().filter(|a| !effective_ids.contains(&a.advisory_id)).collect();
                            if !suppressed.is_empty() {
                                println!("({} advisory suppressed by VEX{})", suppressed.len(), suppressed.iter().map(|a| format!(": {}/{} → {}", a.package, a.advisory_id, lockfile.vex_for(&a.package, &a.advisory_id).map(|v| v.status.as_str()).unwrap_or("unknown"))).collect::<Vec<_>>().join(", "));
                            }
                        }
                    }

                    if hard_failure || soft_failure {
                        println!();
                        let mut fail_parts = Vec::new();
                        if !digest_valid { fail_parts.push("digest invalid".to_string()); }
                        if sig_present && !sig_valid { fail_parts.push("signature invalid".to_string()); }
                        if !trust_chain_valid { fail_parts.push("trust chain invalid".to_string()); }
                        if !lint_errors.is_empty() { fail_parts.push(format!("{} lint errors", lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Error).count())); }
                        if audit_has_critical_or_high { fail_parts.push(format!("{} critical/high advisory", audit_report.critical.len() + audit_report.high.len())); }
                        println!("{} {}", "✗".red().bold(), fail_parts.join(", "));
                    }
                }
            }

            if hard_failure {
                std::process::exit(2);
            } else if soft_failure {
                std::process::exit(1);
            }
        }

        Commands::Dependents { file, package, transitive, dep_type, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let pkg = match lockfile.packages.iter().find(|p| p.name == package) {
                Some(p) => p,
                None => { eprintln!("Error: package '{}' not found in lockfile", package); std::process::exit(1); }
            };

            let version = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
            let fmt = output::parse_format(&format);

            let direct: Vec<(String, String, String)> = lockfile.packages.iter()
                .filter(|p| p.dependencies.iter().any(|d| {
                    d.name == package &&
                    (dep_type == "all" || match dep_type.as_str() {
                        "runtime" => matches!(d.dep_type, hlock::DepType::Runtime),
                        "dev" => matches!(d.dep_type, hlock::DepType::Dev),
                        _ => true,
                    })
                }))
                .map(|p| {
                    let dep = p.dependencies.iter().find(|d| d.name == package).unwrap();
                    let dt = match dep.dep_type {
                        hlock::DepType::Runtime => "runtime",
                        hlock::DepType::Dev => "dev",
                        hlock::DepType::Peer => "peer",
                        hlock::DepType::Optional => "optional",
                        hlock::DepType::OptionalTarget(_, _) => "optional-target",
                    };
                    (p.name.clone(), format!("{}.{}.{}", p.major, p.minor, p.patch), dt.to_string())
                })
                .collect();

            let transitive_names: Vec<String> = if transitive {
                match dep_type.as_str() {
                    "runtime" => hlock::runtime_dependents_of(&lockfile, &package),
                    "dev" => hlock::dev_dependents_of(&lockfile, &package),
                    _ => hlock::dependents_of(&lockfile, &package),
                }
            } else {
                Vec::new()
            };

            let transitive_list: Vec<(String, String)> = transitive_names.iter()
                .filter(|name| !direct.iter().any(|(n, _, _)| n == *name))
                .filter_map(|name| {
                    lockfile.packages.iter().find(|p| p.name == *name).map(|p| {
                        (name.clone(), format!("{}.{}.{}", p.major, p.minor, p.patch))
                    })
                })
                .collect();

            if fmt == output::OutputFormat::Json {
                let json = serde_json::json!({
                    "package": package,
                    "version": version,
                    "direct": direct.iter().map(|(n, v, dt)| serde_json::json!({"name": n, "version": v, "dep_type": dt})).collect::<Vec<_>>(),
                    "transitive": transitive_list.iter().map(|(n, v)| serde_json::json!({"name": n, "version": v})).collect::<Vec<_>>(),
                });
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    println!("Direct dependents of {}:", package);
                    if direct.is_empty() {
                        println!("  (none)");
                    } else {
                        for (name, ver, dt) in &direct {
                            println!("  {}@{} ({})", name, ver, dt);
                        }
                    }
                    if transitive && !transitive_list.is_empty() {
                        println!();
                        println!("Transitive dependents:");
                        for (name, ver) in &transitive_list {
                            println!("  {}@{}", name, ver);
                        }
                    }
                }
            }
        }

        Commands::Deps { file, package, transitive, dep_type, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let pkg = match lockfile.packages.iter().find(|p| p.name == package) {
                Some(p) => p,
                None => { eprintln!("Error: package '{}' not found in lockfile", package); std::process::exit(1); }
            };

            let version = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
            let fmt = output::parse_format(&format);

            let direct: Vec<(String, String, String)> = pkg.dependencies.iter()
                .filter(|d| dep_type == "all" || match dep_type.as_str() {
                    "runtime" => matches!(d.dep_type, hlock::DepType::Runtime),
                    "dev" => matches!(d.dep_type, hlock::DepType::Dev),
                    "peer" => matches!(d.dep_type, hlock::DepType::Peer),
                    _ => true,
                })
                .filter_map(|d| {
                    lockfile.packages.iter().find(|p| p.name == d.name).map(|p| {
                        let v = format!("{}.{}.{}", p.major, p.minor, p.patch);
                        let dt = match d.dep_type {
                            hlock::DepType::Runtime => "runtime",
                            hlock::DepType::Dev => "dev",
                            hlock::DepType::Peer => "peer",
                            hlock::DepType::Optional => "optional",
                            hlock::DepType::OptionalTarget(_, _) => "optional-target",
                        };
                        (d.name.clone(), v, dt.to_string())
                    })
                })
                .collect();

            let transitive_names: HashSet<String> = if transitive {
                match dep_type.as_str() {
                    "runtime" => hlock::runtime_deps(&lockfile, &package),
                    "dev" => hlock::dev_deps(&lockfile, &package),
                    _ => hlock::transitive_deps(&lockfile, &package),
                }
            } else {
                HashSet::new()
            };

            let transitive_list: Vec<(String, String)> = transitive_names.iter()
                .filter(|name| !direct.iter().any(|(n, _, _)| n == *name))
                .filter_map(|name| {
                    lockfile.packages.iter().find(|p| p.name == *name).map(|p| {
                        (name.clone(), format!("{}.{}.{}", p.major, p.minor, p.patch))
                    })
                })
                .collect();

            if fmt == output::OutputFormat::Json {
                let json = serde_json::json!({
                    "package": package,
                    "version": version,
                    "direct": direct.iter().map(|(n, v, dt)| serde_json::json!({"name": n, "version": v, "dep_type": dt})).collect::<Vec<_>>(),
                    "transitive": transitive_list.iter().map(|(n, v)| serde_json::json!({"name": n, "version": v})).collect::<Vec<_>>(),
                });
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    println!("Direct dependencies of {}:", package);
                    if direct.is_empty() {
                        println!("  (none)");
                    } else {
                        for (name, ver, dt) in &direct {
                            println!("  {}@{} ({})", name, ver, dt);
                        }
                    }
                    if transitive && !transitive_list.is_empty() {
                        println!();
                        println!("Transitive dependencies:");
                        for (name, ver) in &transitive_list {
                            println!("  {}@{}", name, ver);
                        }
                    }
                }
            }
        }

        Commands::Why { file, package, format } => {
            let content = match read_input(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("Error reading {}: {}", file.display(), e); std::process::exit(2); }
            };
            let lockfile = match deserialize(&content) {
                Ok(lf) => lf,
                Err(e) => { eprintln!("Parse error: {}", e); std::process::exit(2); }
            };

            let pkg = match lockfile.packages.iter().find(|p| p.name == package) {
                Some(p) => p,
                None => { eprintln!("Error: package '{}' not found in lockfile", package); std::process::exit(1); }
            };

            let version = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
            let source_info = lockfile.sources.get(pkg.source_idx);
            let source_str = match source_info {
                Some(hlock::Source::Registry(u)) => u.clone(),
                Some(hlock::Source::Git(u)) => u.clone(),
                Some(hlock::Source::Workspace) => "workspace".to_string(),
                Some(hlock::Source::Local(u)) => u.clone(),
                Some(hlock::Source::CasHttp(u)) => u.clone(),
                Some(hlock::Source::Ipfs(u)) => u.clone(),
                None => "unknown".to_string(),
            };
            let source_type_str = match source_info {
                Some(hlock::Source::Registry(_)) => "registry",
                Some(hlock::Source::Git(_)) => "git",
                Some(hlock::Source::Workspace) => "workspace",
                Some(hlock::Source::Local(_)) => "local",
                Some(hlock::Source::CasHttp(_)) => "cas-http",
                Some(hlock::Source::Ipfs(_)) => "ipfs",
                None => "unknown",
            };

            let license = lockfile.license_for(&package).map(String::from);
            let integrity = pkg.hashes.first().map(|h| {
                let algo = match h.algo {
                    hlock::HashAlgorithm::Sha1 => "sha1",
                    hlock::HashAlgorithm::Sha256 => "sha256",
                    hlock::HashAlgorithm::Sha512 => "sha512",
                    hlock::HashAlgorithm::Blake3 => "blake3",
                };
                let hex: String = h.digest.iter().map(|b| format!("{:02x}", b)).collect();
                format!("{}-{}", algo, hex)
            });

            let advisories: Vec<&hlock::policy::Advisory> = lockfile.advisories.iter()
                .filter(|a| a.package == package)
                .collect();

            let prov_chain = lockfile.dependency_chain(&package);
            let has_provenance = !prov_chain.is_empty();

            let chains = if has_provenance {
                let primary: Vec<String> = prov_chain.iter().map(|p| p.package_name.clone()).collect();
                let mut all_chains = vec![primary];
                let graph_chains = hlock::graph::all_paths_to_roots(&lockfile, &package, 5);
                for gc in &graph_chains {
                    let primary_set: HashSet<String> = all_chains[0].iter().cloned().collect();
                    let gc_set: HashSet<String> = gc.iter().cloned().collect();
                    if gc_set != primary_set {
                        all_chains.push(gc.clone());
                    }
                    if all_chains.len() >= 5 { break; }
                }
                all_chains
            } else {
                hlock::graph::all_paths_to_roots(&lockfile, &package, 5)
            };

            let fmt = output::parse_format(&format);

            if fmt == output::OutputFormat::Json {
                let chains_json: Vec<Vec<serde_json::Value>> = chains.iter().map(|chain| {
                    chain.iter().map(|name| {
                        let constraint = lockfile.provenance_for(name).map(|p| p.constraint.clone());
                        let dep_type_str = lockfile.provenance_for(name).map(|p| match p.dep_type {
                            hlock::DepType::Runtime => "runtime",
                            hlock::DepType::Dev => "dev",
                            hlock::DepType::Peer => "peer",
                            _ => "other",
                        });
                        serde_json::json!({
                            "name": name,
                            "version": lockfile.packages.iter().find(|p| p.name == *name).map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch)).unwrap_or_default(),
                        "constraint": constraint,
                        "dep_type": dep_type_str,
                        })
                    }).collect()
                }).collect();

                let json = serde_json::json!({
                    "package": package,
                    "version": version,
                    "chains": chains_json,
                    "source": source_str,
                    "source_type": source_type_str,
                    "license": license,
                    "integrity": integrity,
                    "advisories": advisories.iter().map(|a| serde_json::json!({
                        "id": a.advisory_id,
                        "severity": a.severity.as_str(),
                    })).collect::<Vec<_>>(),
                    "has_provenance": has_provenance,
                });
                if !quiet { println!("{}", serde_json::to_string_pretty(&json).unwrap()); }
            } else {
                if !quiet {
                    println!("{}@{}", package, version);

                    for (i, chain) in chains.iter().enumerate() {
                        if chains.len() > 1 {
                            println!();
                            println!("Chain {}:", i + 1);
                        }
                        for (j, name) in chain.iter().enumerate() {
                            let pkg_ver = lockfile.packages.iter().find(|p| p.name == *name)
                                .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
                                .unwrap_or_default();
                            let constraint = lockfile.provenance_for(name).map(|p| p.constraint.as_str()).unwrap_or("");
                            let dep_type_str = lockfile.provenance_for(name).map(|p| match p.dep_type {
                                hlock::DepType::Runtime => "runtime",
                                hlock::DepType::Dev => "dev",
                                _ => "other"
                            }).unwrap_or("");
                            if j == 0 {
                                println!("  {}@{}", name, pkg_ver);
                            } else {
                                let prefix = if j == chain.len() - 1 { "└──" } else { "├──" };
                                if constraint.is_empty() {
                                    println!("  {} {}@{}", prefix, name, pkg_ver);
                                } else {
                                    println!("  {} {}@{} ({}, {})", prefix, name, pkg_ver, constraint, dep_type_str);
                                }
                            }
                        }
                    }

                    println!();
                    println!("Source: {}", source_str);
                    println!("License: {}", license.unwrap_or_else(|| "—".to_string()));
                    println!("Integrity: {}", integrity.unwrap_or_else(|| "—".to_string()));
                    if advisories.is_empty() {
                        println!("Advisories: none");
                    } else {
                        println!("Advisories:");
                        for a in &advisories {
                            println!("  {} {} ({})", a.severity.as_str().to_uppercase(), a.advisory_id, a.affected_versions);
                        }
                    }

                    if !has_provenance {
                        println!();
                        println!("Note: no @provenance data; constraints not available");
                    }
                }
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
