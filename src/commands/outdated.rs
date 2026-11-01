//! `outdated` command implementation.

use super::{
    Ctx, OutdatedSourceType, Path, UpdateType, check_outdated, deserialize, output, read_input,
};

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

    let (outdated_list, skipped_list) = collect_updates(&lockfile, timeout, major, verbose);
    let fmt = output::parse_format(format);

    if fmt == output::OutputFormat::Json {
        render_json(&lockfile, &outdated_list, &skipped_list, quiet);
    } else {
        render_text(&outdated_list, quiet, color_enabled);
    }

    if !outdated_list.is_empty() {
        std::process::exit(1);
    }
}

/// Checks every registry package for a newer version.
///
/// Returns the outdated entries (as JSON values) and the skipped entries with
/// their reasons.
fn collect_updates(
    lockfile: &hlock::Lockfile,
    timeout: u64,
    major: bool,
    verbose: bool,
) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let mut outdated_list = Vec::new();
    let mut skipped_list = Vec::new();

    for pkg in &lockfile.packages {
        let current = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
        let source = lockfile.sources.get(pkg.source_idx);
        let source_type = OutdatedSourceType::from_source(source);

        if let Some(label) = source_type.skip_label() {
            skipped_list.push(serde_json::json!({ "package": pkg.name, "reason": label }));
            continue;
        }

        match check_outdated(&pkg.name, &current, source_type, timeout) {
            Ok(info) => {
                if let Some(latest) = &info.latest {
                    let update_type = info.update_type;
                    if !major && matches!(update_type, UpdateType::Major) {
                        skipped_list.push(serde_json::json!({ "package": pkg.name, "reason": "major (use --major to show)" }));
                        continue;
                    }
                    outdated_list.push(serde_json::json!({
                        "package": pkg.name,
                        "current": current,
                        "latest": latest,
                        "update_type": update_type.to_string(),
                        "source_type": "registry",
                    }));
                }
            }
            Err(e) => {
                if verbose {
                    eprintln!("[verbose] Failed to check {}: {}", pkg.name, e);
                }
            }
        }
    }
    (outdated_list, skipped_list)
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
    quiet: bool,
) {
    let json = serde_json::json!({
        "outdated": outdated_list,
        "skipped": skipped_list,
        "summary": {
            "total": lockfile.packages.len(),
            "outdated": outdated_list.len(),
            "major": count_by_type(outdated_list, "major"),
            "minor": count_by_type(outdated_list, "minor"),
            "patch": count_by_type(outdated_list, "patch"),
            "skipped": skipped_list.len(),
        }
    });
    if !quiet {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

/// Renders the outdated table and summary line as human-readable text.
fn render_text(outdated_list: &[serde_json::Value], quiet: bool, color_enabled: bool) {
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
    if outdated_list.is_empty() {
        if !quiet {
            println!("No outdated packages found.");
        }
        return;
    }
    if quiet {
        return;
    }
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
