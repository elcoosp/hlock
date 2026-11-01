//! `licenses` command implementation.

use super::{Ctx, Lockfile, Path, deserialize, output, read_input};

/// One row of the licenses report.
struct LicenseEntry {
    name: String,
    license: Option<String>,
    source: String,
    source_type: String,
    is_workspace: bool,
}

/// Aggregate license statistics for the report summary.
struct LicenseSummary {
    declared: usize,
    undeclared: usize,
    workspace: usize,
    copyleft: usize,
    permissive: usize,
}

/// Reads and parses the lockfile at `file`, exiting with status 2 on failure.
fn load_lockfile(file: &Path) -> Lockfile {
    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };
    match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    }
}

/// Splits a comma-separated license list into trimmed entries.
fn parse_license_list(spec: Option<&str>) -> Vec<String> {
    spec.map(|s| s.split(',').map(|x| x.trim().to_string()).collect())
        .unwrap_or_default()
}

/// Builds one report row per package with its declared license and source.
fn collect_entries(lockfile: &Lockfile) -> Vec<LicenseEntry> {
    let licensed_map: std::collections::HashMap<&str, &str> = lockfile
        .licenses
        .iter()
        .map(|l| (l.package.as_str(), l.expression.as_str()))
        .collect();

    let mut entries: Vec<LicenseEntry> = Vec::new();
    for pkg in &lockfile.packages {
        let lic = licensed_map.get(pkg.name.as_str()).copied();
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
        entries.push(LicenseEntry {
            name: pkg.name.clone(),
            license: lic.map(String::from),
            source,
            source_type,
            is_workspace,
        });
    }
    entries
}

/// Computes the declared/undeclared/workspace/copyleft license statistics.
fn summarize(entries: &[LicenseEntry]) -> LicenseSummary {
    let declared = entries.iter().filter(|e| e.license.is_some()).count();
    let undeclared = entries
        .iter()
        .filter(|e| e.license.is_none() && !e.is_workspace)
        .count();
    let workspace = entries.iter().filter(|e| e.is_workspace).count();
    let copyleft_keywords = ["GPL", "AGPL", "LGPL", "CPAL", "EUPL", "CC-BY-SA"];
    let copyleft = entries
        .iter()
        .filter(|e| {
            e.license
                .as_ref()
                .is_some_and(|l| copyleft_keywords.iter().any(|k| l.contains(k)))
        })
        .count();
    LicenseSummary {
        declared,
        undeclared,
        workspace,
        copyleft,
        permissive: declared - copyleft,
    }
}

/// Collects license policy violations (denied, not-allowed and undeclared).
fn find_violations(
    entries: &[LicenseEntry],
    allowed: &[String],
    denied: &[String],
    strict: bool,
) -> Vec<serde_json::Value> {
    let mut violations: Vec<serde_json::Value> = Vec::new();

    for entry in entries {
        if entry.is_workspace {
            continue;
        }
        if let Some(ref lic) = entry.license {
            for denied_license in denied {
                if lic.contains(denied_license) {
                    violations.push(serde_json::json!({
                        "package": entry.name,
                        "reason": "denied",
                        "license": lic,
                    }));
                }
            }
            if !allowed.is_empty() {
                let is_allowed = allowed.iter().any(|a| lic.contains(a) || a == lic);
                if !is_allowed {
                    violations.push(serde_json::json!({
                        "package": entry.name,
                        "reason": "not-allowed",
                        "license": lic,
                    }));
                }
            }
        } else if strict || !allowed.is_empty() {
            violations.push(serde_json::json!({
                "package": entry.name,
                "reason": "undeclared",
            }));
        }
    }

    violations
}

/// Renders the licenses report as pretty-printed JSON.
fn render_json(
    entries: &[LicenseEntry],
    filtered: &[&LicenseEntry],
    violations: &[serde_json::Value],
    summary: &LicenseSummary,
    quiet: bool,
) {
    let pkgs_json: Vec<serde_json::Value> = filtered
        .iter()
        .map(|e| {
            serde_json::json!({
                "name": e.name,
                "license": e.license,
                "source": e.source,
                "source_type": e.source_type,
            })
        })
        .collect();
    let json = serde_json::json!({
        "packages": pkgs_json,
        "summary": {
            "declared": summary.declared,
            "total": entries.len(),
            "undeclared": summary.undeclared,
            "workspace": summary.workspace,
            "copyleft": summary.copyleft,
            "permissive": summary.permissive,
        },
        "violations": violations,
        "total_packages": entries.len(),
    });
    if !quiet {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

/// Shortens a source URL to its host for the table column.
fn short_source(entry: &LicenseEntry) -> String {
    if entry.source.is_empty() {
        return entry.source_type.clone();
    }
    let url = &entry.source;
    if let Some(stripped) = url.strip_prefix("https://") {
        stripped.split('/').next().unwrap_or(stripped).to_string()
    } else {
        url.clone()
    }
}

/// Prints the license table and its summary line, or an empty-report notice.
fn render_text(
    entries: &[LicenseEntry],
    filtered: &[&LicenseEntry],
    missing: bool,
    summary: &LicenseSummary,
    color_enabled: bool,
) {
    let bold = output::styler(color_enabled, output::Style::Bold);
    let green = output::styler(color_enabled, output::Style::Green);
    let yellow = output::styler(color_enabled, output::Style::Yellow);
    let red = output::styler(color_enabled, output::Style::Red);

    if filtered.is_empty() {
        if missing {
            println!("All packages have license declarations.");
        } else {
            println!("No license declarations found.");
        }
        return;
    }

    println!(
        "{:24}{:16}{:16}{}",
        bold("Package"),
        bold("License"),
        bold("Source"),
        if missing {
            bold("Status")
        } else {
            String::new()
        }
    );
    println!(
        "{:24}{:16}{:16}{}",
        "────────────────────────",
        "────────────────",
        "────────────────",
        if missing { "──────" } else { "" }
    );
    for entry in filtered {
        let lic_display = match &entry.license {
            Some(l) => green(l),
            None => format!("⚠ {}", yellow("UNDECLARED")),
        };
        let src_short = short_source(entry);
        if missing {
            println!(
                "{:24}{:16}{:16}{}",
                bold(&entry.name),
                lic_display,
                src_short,
                red("MISSING")
            );
        } else {
            println!("{:24}{:16}{}", bold(&entry.name), lic_display, src_short);
        }
    }
    println!();
    println!(
        "Summary: {}/{} declared, {} copyleft, {} permissive, {} undeclared, {} workspace",
        summary.declared,
        entries.len(),
        summary.copyleft,
        summary.permissive,
        summary.undeclared,
        summary.workspace
    );
}

/// Runs the `licenses` command.
pub(crate) fn run(
    file: &Path,
    missing: bool,
    allow: Option<&str>,
    deny: Option<&str>,
    strict: bool,
    format: &str,
    ctx: Ctx,
) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    let lockfile = load_lockfile(file);

    let fmt = output::parse_format(format);

    let allowed_licenses = parse_license_list(allow);
    let denied_licenses = parse_license_list(deny);

    let entries = collect_entries(&lockfile);

    let filtered_entries: Vec<&LicenseEntry> = if missing {
        entries
            .iter()
            .filter(|e| e.license.is_none() && !e.is_workspace)
            .collect()
    } else {
        entries.iter().collect()
    };

    let summary = summarize(&entries);
    let violations = find_violations(&entries, &allowed_licenses, &denied_licenses, strict);
    let has_violations = !violations.is_empty();

    if fmt == output::OutputFormat::Json {
        render_json(&entries, &filtered_entries, &violations, &summary, quiet);
    } else if !quiet {
        render_text(
            &entries,
            &filtered_entries,
            missing,
            &summary,
            color_enabled,
        );
    }

    if has_violations {
        std::process::exit(1);
    }
}
