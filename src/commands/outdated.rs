//! `outdated` command implementation.
//!
//! v1.0.1: checks fan out over a bounded thread pool (spec §7, 8 workers)
//! with results kept in lockfile order, and unreachable packages surface in
//! an explicit `unknown` bucket instead of silently reading as "up to date".

use super::{
    Ctx, OutdatedSourceType, Path, UpdateType, check_outdated, deserialize, output, read_input,
};

/// Concurrent registry queries (spec §7: bounded fan-out).
const OUTDATED_WORKERS: usize = 8;

/// Runs the `outdated` command.
pub(crate) fn run(file: &Path, major: bool, _dep_type: &str, format: &str, timeout: u64, ctx: Ctx) {
    let Ctx {
        quiet,
        verbose,
        color_enabled,
    } = ctx;

    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };
    let lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    if verbose {
        eprintln!(
            "[verbose] Checking {} packages for updates...",
            lockfile.packages.len()
        );
    }

    let (outdated_list, skipped_list, unknown_list) =
        collect_updates(&lockfile, timeout, major, verbose);
    let fmt = output::parse_format(format);

    if fmt == output::OutputFormat::Json {
        render_json(
            &lockfile,
            &outdated_list,
            &skipped_list,
            &unknown_list,
            quiet,
        );
    } else {
        render_text(&outdated_list, &unknown_list, quiet, color_enabled);
    }

    // Findings → 1. Unreachable packages also fail the run (fail-closed):
    // an outdated check that could not reach the registry must never be
    // mistaken for a clean bill of health.
    if !outdated_list.is_empty() || !unknown_list.is_empty() {
        std::process::exit(1);
    }
}

/// Checks every registry package for a newer version.
///
/// Returns the outdated entries, the skipped entries with their reasons, and
/// the packages that could not be checked (network failure) with the reason.
fn collect_updates(
    lockfile: &hlock::Lockfile,
    timeout: u64,
    major: bool,
    verbose: bool,
) -> (
    Vec<serde_json::Value>,
    Vec<serde_json::Value>,
    Vec<serde_json::Value>,
) {
    let mut outdated_list = Vec::new();
    let mut skipped_list = Vec::new();
    let mut unknown_list = Vec::new();

    // Indices that need a live registry query; the rest are classified now.
    let mut to_query: Vec<(usize, String, String)> = Vec::new();
    for (idx, pkg) in lockfile.packages.iter().enumerate() {
        let current = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
        let source = lockfile.sources.get(pkg.source_idx);
        let source_type = OutdatedSourceType::from_source(source);

        if let Some(label) = source_type.skip_label() {
            skipped_list.push(serde_json::json!({ "package": pkg.name, "reason": label }));
            continue;
        }
        to_query.push((idx, pkg.name.clone(), current));
    }

    // Bounded fan-out: chunk the work across `OUTDATED_WORKERS` scoped
    // threads; results carry their original index so the output order stays
    // deterministic regardless of completion order.
    let mut results: Vec<(usize, Result<hlock::OutdatedInfo, String>)> = Vec::new();
    let chunk_size = to_query.len().div_ceil(OUTDATED_WORKERS).max(1);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for chunk in to_query.chunks(chunk_size) {
            handles.push(scope.spawn(move || {
                chunk
                    .iter()
                    .map(|(idx, name, current)| {
                        (
                            *idx,
                            check_outdated(name, current, OutdatedSourceType::Registry, timeout),
                        )
                    })
                    .collect::<Vec<_>>()
            }));
        }
        for handle in handles {
            if let Ok(part) = handle.join() {
                results.extend(part);
            }
        }
    });
    results.sort_by_key(|(idx, _)| *idx);

    for (_, result) in results {
        match result {
            Ok(info) => {
                if let Some(latest) = &info.latest {
                    let update_type = info.update_type;
                    if !major && matches!(update_type, UpdateType::Major) {
                        skipped_list.push(serde_json::json!({ "package": info.package, "reason": "major (use --major to show)" }));
                        continue;
                    }
                    outdated_list.push(serde_json::json!({
                        "package": info.package,
                        "current": info.current,
                        "latest": latest,
                        "update_type": update_type.to_string(),
                        "source_type": "registry",
                    }));
                }
            }
            Err(reason) => {
                if verbose {
                    eprintln!("[verbose] {reason}");
                }
                let package = reason.split(':').next().unwrap_or("").to_string();
                unknown_list.push(serde_json::json!({
                    "package": package,
                    "reason": reason,
                }));
            }
        }
    }
    (outdated_list, skipped_list, unknown_list)
}

/// Counts entries whose `update_type` equals `kind`.
fn count_by_type(list: &[serde_json::Value], kind: &str) -> usize {
    list.iter().filter(|o| o["update_type"] == kind).count()
}

/// Renders the outdated report as pretty-printed JSON.
fn render_json(
    lockfile: &hlock::Lockfile,
    outdated_list: &[serde_json::Value],
    skipped_list: &[serde_json::Value],
    unknown_list: &[serde_json::Value],
    quiet: bool,
) {
    let data = serde_json::json!({
        "outdated": outdated_list,
        "skipped": skipped_list,
        "unknown": unknown_list,
        "summary": {
            "total": lockfile.packages.len(),
            "outdated": outdated_list.len(),
            "major": count_by_type(outdated_list, "major"),
            "minor": count_by_type(outdated_list, "minor"),
            "patch": count_by_type(outdated_list, "patch"),
            "skipped": skipped_list.len(),
            "unknown": unknown_list.len(),
        }
    });
    let json = super::envelope("outdated", unknown_list.is_empty(), &data);
    if !quiet {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

/// Renders the outdated table and summary line as human-readable text.
fn render_text(
    outdated_list: &[serde_json::Value],
    unknown_list: &[serde_json::Value],
    quiet: bool,
    color_enabled: bool,
) {
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let colored_type = |s: &str| -> String {
        match s {
            "major" => output::styler(color_enabled, output::Style::Red)(s),
            "minor" => output::styler(color_enabled, output::Style::Yellow)(s),
            "patch" => output::styler(color_enabled, output::Style::Green)(s),
            _ => s.to_string(),
        }
    };
    if outdated_list.is_empty() && !quiet {
        println!("No outdated packages found.");
    }
    if !outdated_list.is_empty() && !quiet {
        println!(
            "{:16}{:12}{:12}{}",
            bold("Package"),
            bold("Current"),
            bold("Latest"),
            bold("Type")
        );
        println!(
            "{:16}{:12}{:12}─────",
            "────────────────", "────────────", "────────────"
        );
        for entry in outdated_list {
            let name = entry["package"].as_str().unwrap_or("");
            let current = entry["current"].as_str().unwrap_or("");
            let latest = entry["latest"].as_str().unwrap_or("");
            let update_type = entry["update_type"].as_str().unwrap_or("");
            println!(
                "{:16}{:12}{:12}{}",
                bold(name),
                cyan(current),
                cyan(latest),
                colored_type(update_type)
            );
        }
        println!();
        println!(
            "{} outdated ({} major, {} minor, {} patch)",
            bold(&outdated_list.len().to_string()),
            count_by_type(outdated_list, "major"),
            count_by_type(outdated_list, "minor"),
            count_by_type(outdated_list, "patch")
        );
    }
    if !unknown_list.is_empty() {
        eprintln!(
            "{} {} package(s) could not be checked (registry unreachable):",
            output::C {
                text: "!",
                on: color_enabled
            }
            .yb(),
            unknown_list.len()
        );
        for entry in unknown_list {
            let package = entry["package"].as_str().unwrap_or("");
            let reason = entry["reason"].as_str().unwrap_or("");
            eprintln!("  {package}: {reason}");
        }
        eprintln!("The check is inconclusive — treat these packages as unknown, not up to date.");
    }
}
