//! `fix` command implementation.

use super::{
    Ctx, FixType, Path, apply_fixes, build_fix_plan, deserialize, output, serialize,
    validate_digest,
};
use std::io::Write as _;

/// Which sources the fix plan draws from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FixMode {
    /// Refresh audit data only.
    Audit,
    /// Check for outdated packages only.
    Outdated,
}

/// Arguments for the `fix` command.
pub(crate) struct FixArgs<'a> {
    pub(crate) file: &'a Path,
    pub(crate) mode: FixMode,
    pub(crate) dry_run: bool,
    pub(crate) interactive: bool,
    pub(crate) format: &'a str,
    pub(crate) timeout: u64,
}

/// Runs the `fix` command.
pub(crate) fn run(args: &FixArgs<'_>, ctx: Ctx) {
    let FixArgs {
        file,
        mode,
        dry_run,
        interactive,
        format,
        timeout,
    } = args;
    let dry_run = *dry_run;
    let interactive = *interactive;
    let timeout = *timeout;
    let Ctx { quiet, verbose, .. } = ctx;

    if *file == std::path::Path::new("-") {
        eprintln!("Error: fix requires a real file path (not stdin)");
        std::process::exit(2);
    }

    let fix_type = match mode {
        FixMode::Audit => FixType::Audit,
        FixMode::Outdated => FixType::Outdated,
    };

    let content = match std::fs::read_to_string(*file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", (*file).display(), e);
            std::process::exit(2);
        }
    };
    let mut lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    if verbose {
        eprintln!("[verbose] Building fix plan...");
    }

    let plan = match build_fix_plan(&lockfile, fix_type, timeout) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error building fix plan: {e}");
            std::process::exit(2);
        }
    };

    if plan.fixes.is_empty() {
        if !quiet {
            println!("No fixes needed.");
        }
        std::process::exit(1);
    }

    let fmt = output::parse_format(format);

    if dry_run {
        render_dry_run(&plan, fmt, ctx);
        std::process::exit(0);
    }

    if interactive {
        confirm_and_apply(&mut lockfile, &plan, ctx);
    } else {
        apply_all(&mut lockfile, &plan, quiet);
    }

    let serialized = match serialize(&mut lockfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Serialize error: {}", e.error_code(), e);
            std::process::exit(1);
        }
    };

    if validate_digest(&serialized).is_ok() && !quiet {
        eprintln!(
            "{} Digest updated.",
            output::C {
                text: "✓",
                on: ctx.color_enabled
            }
            .gb()
        );
    }

    if let Err(e) = std::fs::write(file, &serialized) {
        eprintln!("Error writing {}: {}", (*file).display(), e);
        std::process::exit(1);
    }

    if !quiet {
        println!("Fix applied to {}", (*file).display());
    }
}

/// Prints the dry-run plan in the requested format, or nothing when quiet.
fn render_dry_run(plan: &hlock::FixPlan, fmt: output::OutputFormat, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    if fmt == output::OutputFormat::Json {
        let json = serde_json::json!({
            "would_fix": plan.fixes.iter().map(|f| serde_json::json!({
                "package": f.package, "current": f.current, "fixed": f.fixed,
                "advisory_id": f.advisory_id, "type": match f.fix_type { FixType::Audit => "audit", FixType::Outdated => "outdated" }
            })).collect::<Vec<_>>(),
            "total_vulnerabilities": plan.total_vulnerabilities,
        });
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        return;
    }
    if quiet {
        return;
    }
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let green = output::styler(color_enabled, output::Style::Green);
    println!("Would fix {} vulnerabilities:", plan.fixes.len());
    println!();
    println!(
        "{:12}{:12}{:12}{}",
        bold("Package"),
        bold("Current"),
        bold("Fixed"),
        bold("Advisory")
    );
    println!(
        "{:12}{:12}{:12}────────────",
        "────────────", "────────────", "────────────"
    );
    for fix in &plan.fixes {
        println!(
            "{:12}{:12}{:12}{}",
            bold(&fix.package),
            cyan(&fix.current),
            green(&fix.fixed),
            fix.advisory_id
        );
    }
    println!();
    println!("Run without --dry-run to apply.");
}

/// Prompts per-fix in interactive mode, applies the selected fixes.
fn confirm_and_apply(lockfile: &mut hlock::Lockfile, plan: &hlock::FixPlan, ctx: Ctx) -> usize {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let green = output::styler(color_enabled, output::Style::Green);

    let mut selected = vec![false; plan.fixes.len()];
    let stdin = std::io::stdin();
    for (i, fix) in plan.fixes.iter().enumerate() {
        print!(
            "Fix {} {} → {}? [y/n/a/q] ",
            bold(&fix.package),
            cyan(&fix.current),
            green(&fix.fixed)
        );
        std::io::stdout().flush().ok();
        let mut input = String::new();
        if stdin.read_line(&mut input).is_ok() {
            let answer = input.trim().to_lowercase();
            match answer.as_str() {
                "y" | "yes" => {
                    selected[i] = true;
                }
                "a" | "all" => {
                    selected.fill(true);
                    break;
                }
                "q" | "quit" => {
                    break;
                }
                _ => {
                    if !quiet {
                        eprintln!("  Skipped {} (major update)", fix.package);
                    }
                }
            }
        }
    }

    let applied = apply_fixes(lockfile, plan, &selected);
    if !quiet {
        eprintln!("Applied {applied} fix(es). Re-serialize and re-validate...");
    }
    applied
}

/// Applies every planned fix without prompting.
fn apply_all(lockfile: &mut hlock::Lockfile, plan: &hlock::FixPlan, quiet: bool) -> usize {
    let selected: Vec<bool> = plan.fixes.iter().map(|_| true).collect();
    let applied = apply_fixes(lockfile, plan, &selected);
    if !quiet {
        eprintln!("Applied {applied} fix(es).");
    }
    applied
}
