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
                        for wp in &lockfile.workspace_pkgs { println!("  +-- {} ({})", wp.name, wp.manifest_path); }
                    }

                    if !lockfile.hoist_boundaries.is_empty() {
                        println!("Hoist Boundaries:");
                        for hb in &lockfile.hoist_boundaries { println!("  {} -> [{}]", hb.cosine, hb.allowed_deps.join(", ")); }
                    }

                    if digest_valid { println!("Digest:         valid (blake3)"); } else { println!("Digest:         invalid"); }
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
