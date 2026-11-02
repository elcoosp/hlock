mod output;

use clap::{Parser, Subcommand};
pub(crate) use hlock::{
    ExplanationKind, FixType, HlockConfig, ImportFormat, Lockfile, OutdatedSourceType, UpdateType,
    apply_fixes, build_fix_plan, check_outdated, deserialize, diff_lockfiles, explain_advisory,
    explain_rule, generate_sbom, import_npm, import_yarn, lint, lockfile, merge, merge_lockfiles,
    policy, sbom, serialize, serialize_diff, sign_lockfile, signature, validate_digest,
    verify_signature,
};

use std::path::PathBuf;

#[derive(Parser)]
#[allow(clippy::struct_excessive_bools)] // clap global flags, not state logic
#[command(
    name = "hlock",
    version,
    about = "The supply-chain gate for npm — verify, lint, audit and sign lockfiles",
    after_help = "Exit codes: 0 = success, 1 = findings/verification failure, 2 = usage or input error"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    #[arg(short, long, global = true, help = "Suppress non-error output")]
    quiet: bool,

    #[arg(short, long, global = true, help = "Show extra diagnostic information")]
    verbose: bool,

    #[arg(long, global = true, help = "Disable colored output")]
    no_color: bool,

    #[arg(
        long,
        default_value = "auto",
        global = true,
        help = "When to colorize: auto, always, never"
    )]
    color: String,

    #[arg(
        short = 'J',
        long,
        global = true,
        help = "Shorthand for --format json on every command"
    )]
    json: bool,

    #[arg(long, global = true, help = "Path to config file (.hlockrc syntax)")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// One-shot supply-chain gate: verify + lint + audit (for CI pipelines)
    Ci {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, help = "Skip the verify gate (digest, signature, trust chain)")]
        no_verify: bool,
        #[arg(long, help = "Skip the lint gate")]
        no_lint: bool,
        #[arg(long, help = "Skip the audit gate")]
        no_audit: bool,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0, help = "Clock override as unix epoch")]
        time: u64,
        #[arg(
            long,
            default_value = "error",
            help = "Lint severity floor: error, warning, info"
        )]
        severity: String,
        #[arg(long, help = "Run only these lint rules")]
        rule: Vec<String>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Baseline of known advisories; fail only on new ones"
        )]
        baseline: Option<PathBuf>,
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Verify digest, signatures and the trust chain
    Verify {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        trusted_key: Vec<String>,
        #[arg(
            long,
            default_value_t = 0,
            help = "Clock override as unix epoch (governs signature AND trust-root expiry)"
        )]
        time: u64,
        #[arg(
            long,
            help = "Verify Sigstore/cosign signatures (requires SLSA builder provenance)"
        )]
        sigstore: bool,
    },
    Lint {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(
            long,
            help = "Run only these rules (default: every rule in the registry)"
        )]
        rule: Vec<String>,
        #[arg(
            long,
            default_value = "error",
            help = "Severity floor: error, warning, info"
        )]
        severity: String,
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Explain a lint rule or advisory in detail (`--list` shows the registry)
    Explain {
        #[arg(
            value_name = "RULE_OR_ID",
            help = "Rule name or advisory id (omit with --list)"
        )]
        rule_or_id: Option<String>,
        #[arg(long, help = "List every rule in the registry, optionally filtered")]
        list: bool,
        #[arg(long, help = "Lockfile path (required for advisory explanations)")]
        file: Option<PathBuf>,
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
        #[arg(long, help = "Query OSV for live vulnerability data")]
        online: bool,
        #[arg(long, help = "Merge online results with embedded advisories")]
        merge: bool,
        #[arg(
            long,
            value_name = "FILE",
            help = "Fail only on advisories not present in this baseline"
        )]
        baseline: Option<PathBuf>,
        #[arg(
            long,
            value_name = "FILE",
            help = "Write current advisories as a new baseline and exit 0"
        )]
        write_baseline: Option<PathBuf>,
        #[arg(long, default_value = "text")]
        format: String,
        #[arg(long, default_value_t = 30, help = "HTTP request timeout in seconds")]
        timeout: u64,
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
        #[arg(
            long,
            help = "Export the full graph as Graphviz DOT instead of extracting a subgraph"
        )]
        dot: bool,
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
    /// Check for newer versions of packages
    Outdated {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, help = "Show major version updates")]
        major: bool,
        #[arg(long, default_value = "all", help = "Filter: runtime, dev, peer, all")]
        dep_type: String,
        #[arg(long, default_value = "text")]
        format: String,
        #[arg(long, default_value_t = 30, help = "HTTP request timeout in seconds")]
        timeout: u64,
    },
    /// Auto-remediate vulnerabilities or outdated packages
    Fix {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, help = "Fix audit findings (vulnerabilities)")]
        audit: bool,
        #[arg(long, help = "Fix outdated packages")]
        outdated: bool,
        #[arg(long, help = "Fix both audit and outdated")]
        all: bool,
        #[arg(long, value_name = "PACKAGE", help = "Fix only this package")]
        package: Option<String>,
        #[arg(
            long,
            value_name = "VERSION",
            requires = "package",
            help = "Target version for --package"
        )]
        to: Option<String>,
        #[arg(long, help = "Show what would change without modifying")]
        dry_run: bool,
        #[arg(long, help = "Prompt for each fix")]
        interactive: bool,
        #[arg(long, default_value = "text")]
        format: String,
        #[arg(long, default_value_t = 30, help = "HTTP request timeout in seconds")]
        timeout: u64,
    },
    /// Bootstrap a lockfile from package-lock.json / yarn.lock (+ optional root key)
    Init {
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
        #[arg(long, required = true, help = "Input format: yarn, npm, pnpm")]
        from: String,
        #[arg(long, help = "Output path [default: hlock.lock]")]
        output: Option<PathBuf>,
        #[arg(long, default_value = "https://registry.npmjs.org/")]
        registry: String,
        #[arg(long, help = "Generate a root trust key and attach it to the lockfile")]
        with_trust_root: bool,
        #[arg(
            long,
            default_value = "root@localhost",
            help = "Key id for --with-trust-root"
        )]
        key_id: String,
        #[arg(
            long,
            default_value = "ed25519",
            help = "Key algorithm: ed25519, ml-dsa-65"
        )]
        algorithm: String,
        #[arg(
            long,
            default_value_t = 0,
            help = "Trust root expiry as unix epoch (0 = never)"
        )]
        expires: u64,
    },
    /// Convert from yarn.lock or package-lock.json
    Import {
        #[arg(value_name = "SOURCE")]
        source: PathBuf,
        #[arg(long, required = true, help = "Input format: yarn, npm, pnpm")]
        from: String,
        #[arg(long, help = "Output path [default: stdout]")]
        output: Option<PathBuf>,
        #[arg(long, default_value = "https://registry.npmjs.org/")]
        registry: String,
    },
    Keygen {
        #[arg(long, default_value = "ed25519", help = "ed25519 or ml-dsa-65")]
        algorithm: String,
        #[arg(long, default_value = "ci@example.com")]
        key_id: String,
        #[arg(long, default_value_t = 0, help = "Expiry as unix epoch (0 = never)")]
        expires: u64,
        #[arg(long, help = "Write the private key to this file instead of stdout")]
        output: Option<PathBuf>,
    },
    /// Inspect and rotate trust roots
    #[command(subcommand)]
    Trust(TrustCommand),
    /// Print the resolved configuration
    Config {
        #[arg(long, default_value = "text")]
        format: String,
    },
    Stats {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, help = "Show deduplication opportunities instead of metrics")]
        dedup: bool,
        #[arg(long, default_value = "text")]
        format: String,
    },
    Digest {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(
            long,
            help = "Verify the @digest line instead of printing the computed digest"
        )]
        check: bool,
    },
    PolicyTest {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long)]
        package: String,
        #[arg(long)]
        hook: Option<String>,
        #[arg(long)]
        script: Option<String>,
        #[arg(long, default_value = "text")]
        format: String,
    },
}

/// Subcommands of `hlock trust`.
#[derive(Subcommand)]
pub(crate) enum TrustCommand {
    /// List trust roots and rotation records
    List {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, default_value = "text")]
        format: String,
    },
    /// Generate a signed root-key rotation record
    Rotate {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, help = "Key id of the new root key")]
        new_key_id: String,
        #[arg(
            long,
            default_value = "ed25519",
            help = "New key algorithm: ed25519, ml-dsa-65"
        )]
        new_algorithm: String,
        #[arg(
            long,
            value_name = "HEX",
            help = "Use this public key instead of generating a new keypair"
        )]
        new_public_key: Option<String>,
        #[arg(
            long,
            default_value_t = 0,
            help = "New key expiry as unix epoch (0 = never)"
        )]
        new_expires: u64,
        #[arg(
            long,
            default_value = "root",
            help = "Role of the new key: root, targets, snapshot, delegation"
        )]
        role: String,
        #[arg(
            long,
            default_value_t = 1,
            help = "Signature threshold for the new key"
        )]
        threshold: u8,
        #[arg(
            long,
            value_name = "HEX|@FILE",
            help = "Old root private key (hex, or @path to a key file)"
        )]
        old_private_key: String,
        #[arg(long, help = "Write the updated lockfile here [default: in place]")]
        output: Option<PathBuf>,
    },
}

mod commands;

/// Exit code for a hard configuration error.
const CONFIG_ERROR: i32 = 2;

/// Loads the configuration with hard errors, reporting where it came from.
///
/// Precedence: `--config <file>` > `.hlockrc` (walked up) > XDG config >
/// defaults. An invalid TOML is `E0901`; an explicit `--config` path that
/// cannot be read is `E0902`.
fn load_config_or_exit(cli_config: Option<&std::path::Path>) -> (HlockConfig, &'static str) {
    if let Some(path) = cli_config {
        match std::fs::read_to_string(path) {
            Ok(content) => match toml::from_str::<HlockConfig>(&content) {
                Ok(cfg) => return (cfg, "--config"),
                Err(e) => {
                    eprintln!(
                        "[E0901] Config error: invalid TOML in {}: {e}",
                        path.display()
                    );
                    std::process::exit(CONFIG_ERROR);
                }
            },
            Err(e) => {
                eprintln!("[E0902] Config error: cannot read {}: {e}", path.display());
                std::process::exit(CONFIG_ERROR);
            }
        }
    }

    // .hlockrc in the working directory (no upward walk in v1: explicit wins).
    if let Ok(content) = std::fs::read_to_string(".hlockrc") {
        match toml::from_str::<HlockConfig>(&content) {
            Ok(cfg) => return (cfg, ".hlockrc"),
            Err(e) => {
                eprintln!("[E0901] Config error: invalid TOML in .hlockrc: {e}");
                std::process::exit(CONFIG_ERROR);
            }
        }
    }

    (HlockConfig::default(), "defaults")
}

fn main() {
    let cli = Cli::parse();

    let (config, config_source) = load_config_or_exit(cli.config.as_deref());

    // CLI flags win over the config file; the file wins over defaults.
    let quiet = cli.quiet || config.output.quiet;
    let verbose = (cli.verbose || config.output.verbose) && !quiet;
    let color_flag = if cli.no_color {
        "never"
    } else if cli.color != "auto" {
        cli.color.as_str()
    } else {
        config.output.color.as_str()
    };
    let color_config =
        output::ColorConfig::from_cli_args(color_flag, cli.no_color, output::OutputFormat::Text);
    let color_enabled = color_config.should_color();

    let ctx = commands::Ctx {
        quiet,
        verbose,
        color_enabled,
    };

    dispatch(cli.command, cli.json, &config, config_source, ctx);
}

/// Overrides `format` when the global `--json` shorthand is present.
fn fmt(format: &str, json: bool) -> &str {
    if json { "json" } else { format }
}

/// Routes a parsed command to its implementation.
fn dispatch(
    command: Commands,
    json: bool,
    config: &HlockConfig,
    config_source: &'static str,
    ctx: commands::Ctx,
) {
    match command {
        // Maintenance, graph, signing and tooling commands are handled first;
        // everything else falls through to the inspection dispatcher. The
        // wildcard patterns bind nothing, so `command` is not moved.
        Commands::Graph { .. }
        | Commands::Tree { .. }
        | Commands::Merge { .. }
        | Commands::Import { .. }
        | Commands::Init { .. }
        | Commands::Fix { .. }
        | Commands::Sign { .. }
        | Commands::Keygen { .. }
        | Commands::Trust(_)
        | Commands::Completions { .. } => dispatch_mutation(command, json, config, ctx),
        _ => dispatch_inspection(command, json, config, config_source, ctx),
    }
}

/// Runs the graph-structure and maintenance commands.
#[allow(clippy::too_many_lines)] // one arm per subcommand is intentional
fn dispatch_mutation(command: Commands, json: bool, config: &HlockConfig, ctx: commands::Ctx) {
    match command {
        Commands::Graph {
            file,
            root,
            platform,
            output,
            dot,
        } => commands::graph::run(
            &file,
            &root,
            platform.as_deref(),
            output.as_deref(),
            dot,
            ctx,
        ),
        Commands::Tree {
            file,
            root,
            depth,
            dep_type,
            format,
        } => commands::tree::run(&file, &root, depth, &dep_type, fmt(&format, json), ctx),
        Commands::Merge {
            base,
            ours,
            theirs,
            strategy,
            output,
        } => commands::merge_cmd::run(&base, &ours, &theirs, &strategy, output.as_deref(), ctx),
        Commands::Import {
            source,
            from,
            output,
            registry,
        } => {
            // [import] default_registry feeds the CLI default; explicit wins.
            let effective_registry = if registry == "https://registry.npmjs.org/" {
                config.import.default_registry.clone()
            } else {
                registry
            };
            commands::import::run(&source, &from, output.as_deref(), &effective_registry, ctx);
        }
        Commands::Init {
            source,
            from,
            output,
            registry,
            with_trust_root,
            key_id,
            algorithm,
            expires,
        } => {
            let effective_registry = if registry == "https://registry.npmjs.org/" {
                config.import.default_registry.clone()
            } else {
                registry
            };
            commands::init::run(
                &commands::init::InitArgs {
                    source: &source,
                    from: &from,
                    output: output.as_deref(),
                    registry: &effective_registry,
                    with_trust_root,
                    key_id: &key_id,
                    algorithm: &algorithm,
                    expires,
                },
                ctx,
            );
        }
        Commands::Fix {
            file,
            audit,
            outdated,
            all,
            package,
            to,
            dry_run,
            interactive,
            format,
            timeout,
        } => {
            // `--all` implies the audit path (pre-v0.19 behavior kept verbatim).
            let mode = if outdated && !audit && !all {
                commands::fix::FixMode::Outdated
            } else {
                commands::fix::FixMode::Audit
            };
            let _ = all;
            commands::fix::run(
                &commands::fix::FixArgs {
                    file: &file,
                    mode,
                    package: package.as_deref(),
                    to: to.as_deref(),
                    dry_run,
                    interactive,
                    format: fmt(&format, json),
                    timeout,
                },
                ctx,
            );
        }
        Commands::Sign {
            file,
            key_id,
            algorithm,
            private_key,
            expires,
            in_place,
        } => commands::sign::run(
            &file,
            &key_id,
            &algorithm,
            &private_key,
            expires,
            in_place,
            ctx,
        ),
        Commands::Keygen {
            algorithm,
            key_id,
            expires,
            output,
        } => commands::keygen::run(&algorithm, &key_id, expires, output.as_deref(), ctx),
        Commands::Trust(trust_cmd) => {
            let args = match trust_cmd {
                TrustCommand::List { file, format } => commands::trust::TrustArgs::List {
                    file,
                    format: fmt(&format, json).to_string(),
                },
                TrustCommand::Rotate {
                    file,
                    new_key_id,
                    new_algorithm,
                    new_public_key,
                    new_expires,
                    role,
                    threshold,
                    old_private_key,
                    output,
                } => commands::trust::TrustArgs::Rotate {
                    file,
                    new_key_id,
                    new_algorithm,
                    new_public_key,
                    new_expires,
                    role,
                    threshold,
                    old_private_key,
                    output,
                },
            };
            commands::trust::run(&args, ctx);
        }
        Commands::Completions { shell } => commands::completions::run(&shell, ctx),
        // `dispatch` only routes the commands above here.
        _ => unreachable!("non-maintenance command reached dispatch_mutation"),
    }
}

/// Runs the inspection commands (read-only lockfile analysis).
fn dispatch_inspection(
    command: Commands,
    json: bool,
    config: &HlockConfig,
    config_source: &'static str,
    ctx: commands::Ctx,
) {
    match command {
        Commands::Ci {
            file,
            no_verify,
            no_lint,
            no_audit,
            trusted_key,
            time,
            severity,
            rule,
            baseline,
            format,
        } => commands::ci::run(
            &commands::ci::CiArgs {
                file: &file,
                no_verify,
                no_lint,
                no_audit,
                trusted_key: &trusted_key,
                time,
                severity: &severity,
                rule: &rule,
                baseline: baseline.as_deref(),
                format: fmt(&format, json),
            },
            ctx,
        ),
        Commands::Verify {
            file,
            trusted_key,
            time,
            sigstore,
        } => commands::verify::run(&file, &trusted_key, time, sigstore, ctx),
        Commands::Lint {
            file,
            rule,
            severity,
            format,
        } => {
            // Config feeds the rule selection when the CLI passes none.
            let effective_rules: Vec<String> = if rule.is_empty() {
                config
                    .lint
                    .exclude_rules
                    .iter()
                    .map(|r| format!("!{r}"))
                    .collect()
            } else {
                rule
            };
            let effective_rules = if effective_rules.is_empty() && !config.lint.rules.is_empty() {
                config.lint.rules.clone()
            } else {
                effective_rules
            };
            commands::lint_cmd::run(&file, &effective_rules, &severity, fmt(&format, json), ctx);
        }
        Commands::Diff {
            old_file,
            new_file,
            format,
        } => commands::diff::run(&old_file, &new_file, fmt(&format, json), ctx),
        Commands::Audit {
            file,
            online,
            merge,
            baseline,
            write_baseline,
            format,
            timeout,
        } => commands::audit::run(
            &commands::audit::AuditArgs {
                file: &file,
                online: online || config.audit.online,
                merge,
                format: fmt(&format, json),
                timeout: config.outdated.timeout.max(timeout).min(if timeout == 30 {
                    config.outdated.timeout
                } else {
                    timeout
                }),
                baseline: baseline.as_deref(),
                write_baseline: write_baseline.as_deref(),
            },
            ctx,
        ),
        Commands::Sbom {
            file,
            namespace,
            format,
        } => commands::sbom_cmd::run(&file, &namespace, fmt(&format, json), ctx),
        other => dispatch_reports(other, json, config, config_source, ctx),
    }
}

/// Runs the report-style commands (summaries, listings and explanations).
#[allow(clippy::too_many_lines)] // one arm per subcommand is intentional
fn dispatch_reports(
    command: Commands,
    json: bool,
    config: &HlockConfig,
    config_source: &'static str,
    ctx: commands::Ctx,
) {
    match command {
        Commands::Why {
            file,
            package,
            format,
        } => commands::why::run(&file, &package, fmt(&format, json), ctx),
        Commands::Deps {
            file,
            package,
            transitive,
            dep_type,
            format,
        } => commands::deps::run(
            &file,
            &package,
            transitive,
            &dep_type,
            fmt(&format, json),
            ctx,
        ),
        Commands::Dependents {
            file,
            package,
            transitive,
            dep_type,
            format,
        } => commands::dependents::run(
            &file,
            &package,
            transitive,
            &dep_type,
            fmt(&format, json),
            ctx,
        ),
        Commands::Check {
            file,
            trusted_key,
            time,
            severity,
            rule,
            vex,
            format,
        } => {
            // [verify] trusted_keys from config when the CLI passes none.
            let effective_keys: Vec<String> = if trusted_key.is_empty() {
                config.verify.trusted_keys.clone()
            } else {
                trusted_key
            };
            commands::check::run(
                &commands::check::CheckArgs {
                    file: &file,
                    trusted_key: &effective_keys,
                    time,
                    severity: &severity,
                    rule: &rule,
                    vex,
                    format: fmt(&format, json),
                },
                ctx,
            );
        }
        Commands::Licenses {
            file,
            missing,
            allow,
            deny,
            strict,
            format,
        } => {
            // [licenses] config feeds allow/deny/strict; CLI flags win.
            let effective_allow = allow.or_else(|| {
                (!config.licenses.allow.is_empty()).then(|| config.licenses.allow.join(","))
            });
            let effective_deny = deny.or_else(|| {
                (!config.licenses.deny.is_empty()).then(|| config.licenses.deny.join(","))
            });
            commands::licenses::run(
                &file,
                missing,
                effective_allow.as_deref(),
                effective_deny.as_deref(),
                strict || config.licenses.strict,
                fmt(&format, json),
                ctx,
            );
        }
        Commands::Outdated {
            file,
            major,
            dep_type,
            format,
            timeout,
        } => commands::outdated::run(
            &file,
            major || config.outdated.check_major,
            &dep_type,
            fmt(&format, json),
            if timeout == 30 {
                config.outdated.timeout
            } else {
                timeout
            },
            ctx,
        ),
        Commands::Explain {
            rule_or_id,
            list,
            file,
            format,
        } => commands::explain::run(
            rule_or_id.as_deref(),
            list,
            file.as_deref(),
            fmt(&format, json),
            ctx,
        ),
        Commands::Stats {
            file,
            dedup,
            format,
        } => commands::stats::run(&file, dedup, fmt(&format, json), ctx),
        Commands::Digest { file, check } => commands::digest::run(&file, check, ctx),
        Commands::PolicyTest {
            file,
            package,
            hook,
            script,
            format,
        } => commands::policy_test::run(
            &file,
            &package,
            hook.as_deref(),
            script.as_deref(),
            fmt(&format, json),
            ctx,
        ),
        Commands::Config { format } => {
            commands::config_cmd::run(config, config_source, fmt(&format, json), ctx);
        }
        // `dispatch_inspection` only routes the report commands above here.
        _ => unreachable!("non-report command reached dispatch_reports"),
    }
}
