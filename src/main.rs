mod output;

use clap::{Parser, Subcommand};
pub(crate) use hlock::{
    ExplanationKind, FixType, HlockConfig, ImportFormat, Lockfile, OutdatedSourceType, UpdateType,
    apply_fixes, build_fix_plan, check_outdated, deserialize, diff_lockfiles, explain_advisory,
    explain_rule, extract_subgraph, extract_subgraph_platform, fnv, generate_sbom, import_npm,
    import_yarn, lint, lockfile, merge, merge_lockfiles, policy, sbom, serialize, serialize_diff,
    sign_lockfile, signature, validate_digest, verify_signature,
};

use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "hlock",
    version,
    about = "Supply-chain lockfile integrity tool"
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

    #[arg(long, global = true, help = "Path to config file")]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    Verify {
        #[arg(value_name = "FILE")]
        file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0)]
        time: u64,
        #[arg(long, help = "Verify Sigstore/cosign signatures (experimental)")]
        sigstore: bool,
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
        #[arg(long, help = "Query OSV for live vulnerability data")]
        online: bool,
        #[arg(long, help = "Merge online results with embedded advisories")]
        merge: bool,
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
        #[arg(long, help = "Show what would change without modifying")]
        dry_run: bool,
        #[arg(long, help = "Prompt for each fix")]
        interactive: bool,
        #[arg(long, default_value = "text")]
        format: String,
        #[arg(long, default_value_t = 30, help = "HTTP request timeout in seconds")]
        timeout: u64,
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
    /// Explain a lint rule or advisory in detail
    Explain {
        #[arg(value_name = "RULE_OR_ID")]
        rule_or_id: String,
        #[arg(long, help = "Lockfile path (required for advisory explanations)")]
        file: Option<PathBuf>,
        #[arg(long, default_value = "text")]
        format: String,
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
    Stats {
        #[arg(value_name = "FILE")]
        file: PathBuf,
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

mod commands;

fn main() {
    let cli = Cli::parse();

    let quiet = cli.quiet;
    let verbose = cli.verbose && !quiet;
    let color_config =
        output::ColorConfig::from_cli_args(&cli.color, cli.no_color, output::OutputFormat::Text);
    let color_enabled = color_config.should_color();

    // Load config file (unused for now, but available)
    let _config = HlockConfig::load(cli.config.as_deref());

    let ctx = commands::Ctx {
        quiet,
        verbose,
        color_enabled,
    };

    dispatch(cli.command, ctx);
}

/// Routes a parsed command to its implementation.
fn dispatch(command: Commands, ctx: commands::Ctx) {
    match command {
        // Maintenance, graph, signing and tooling commands are handled first;
        // everything else falls through to the inspection dispatcher. The
        // wildcard patterns bind nothing, so `command` is not moved.
        Commands::Graph { .. }
        | Commands::Tree { .. }
        | Commands::Merge { .. }
        | Commands::Import { .. }
        | Commands::Fix { .. }
        | Commands::Sign { .. }
        | Commands::Keygen { .. }
        | Commands::Completions { .. } => dispatch_mutation(command, ctx),
        _ => dispatch_inspection(command, ctx),
    }
}

/// Runs the graph-structure and maintenance commands.
fn dispatch_mutation(command: Commands, ctx: commands::Ctx) {
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
        } => commands::tree::run(&file, &root, depth, &dep_type, &format, ctx),
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
        } => commands::import::run(&source, &from, output.as_deref(), &registry, ctx),
        Commands::Fix {
            file,
            audit,
            outdated,
            all,
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
                    dry_run,
                    interactive,
                    format: &format,
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
        Commands::Completions { shell } => commands::completions::run(&shell, ctx),
        // `dispatch` only routes the eight commands above here.
        _ => unreachable!("non-maintenance command reached dispatch_mutation"),
    }
}

/// Runs the inspection commands (read-only lockfile analysis).
fn dispatch_inspection(command: Commands, ctx: commands::Ctx) {
    match command {
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
        } => commands::lint_cmd::run(&file, &rule, &severity, &format, ctx),
        Commands::Diff {
            old_file,
            new_file,
            format,
        } => commands::diff::run(&old_file, &new_file, &format, ctx),
        Commands::Audit {
            file,
            online,
            merge,
            format,
            timeout,
        } => commands::audit::run(&file, online, merge, &format, timeout, ctx),
        Commands::Sbom {
            file,
            namespace,
            format,
        } => commands::sbom_cmd::run(&file, &namespace, &format, ctx),
        other => dispatch_reports(other, ctx),
    }
}

/// Runs the report-style commands (summaries, listings and explanations).
fn dispatch_reports(command: Commands, ctx: commands::Ctx) {
    match command {
        Commands::Info { file, format } => commands::info::run(&file, &format, ctx),
        Commands::Dedup { file, format } => commands::dedup::run(&file, &format, ctx),
        Commands::Why {
            file,
            package,
            format,
        } => commands::why::run(&file, &package, &format, ctx),
        Commands::Deps {
            file,
            package,
            transitive,
            dep_type,
            format,
        } => commands::deps::run(&file, &package, transitive, &dep_type, &format, ctx),
        Commands::Dependents {
            file,
            package,
            transitive,
            dep_type,
            format,
        } => commands::dependents::run(&file, &package, transitive, &dep_type, &format, ctx),
        Commands::Check {
            file,
            trusted_key,
            time,
            severity,
            rule,
            vex,
            format,
        } => commands::check::run(
            &commands::check::CheckArgs {
                file: &file,
                trusted_key: &trusted_key,
                time,
                severity: &severity,
                rule: &rule,
                vex,
                format: &format,
            },
            ctx,
        ),
        Commands::Licenses {
            file,
            missing,
            allow,
            deny,
            strict,
            format,
        } => commands::licenses::run(
            &file,
            missing,
            allow.as_deref(),
            deny.as_deref(),
            strict,
            &format,
            ctx,
        ),
        Commands::Outdated {
            file,
            major,
            dep_type,
            format,
            timeout,
        } => commands::outdated::run(&file, major, &dep_type, &format, timeout, ctx),
        Commands::Explain {
            rule_or_id,
            file,
            format,
        } => commands::explain::run(&rule_or_id, file.as_deref(), &format, ctx),
        Commands::Stats { file, format } => commands::stats::run(&file, &format, ctx),
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
            &format,
            ctx,
        ),
        // `dispatch_inspection` only routes the report commands above here.
        _ => unreachable!("non-report command reached dispatch_reports"),
    }
}
