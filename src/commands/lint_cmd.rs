//! `lint` command implementation.

use super::{Ctx, Path, build_rule_set, deserialize, lint, output, read_input};

/// Runs the `lint` command.
pub(crate) fn run(file: &Path, rule: &[String], severity: &str, format: &str, ctx: Ctx) {
    let Ctx { quiet, verbose, .. } = ctx;

    if verbose {
        eprintln!("[verbose] Reading {}...", file.display());
    }
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

    let rules = build_rule_set(rule);
    if verbose {
        eprintln!("[verbose] Running lint ({} rules)...", rules.len());
    }
    let report = hlock::lint::lint(&lockfile, &rules);
    if verbose {
        eprintln!(
            "[verbose] Lint complete: {} findings",
            report.findings.len()
        );
    }

    let min_sev = match severity {
        "warning" => lint::LintSeverity::Warning,
        "info" => lint::LintSeverity::Info,
        _ => lint::LintSeverity::Error,
    };

    if format == "json" {
        render_json(&report, min_sev, quiet);
    } else {
        render_text(&report, min_sev, ctx);
    }

    if report.has_errors() {
        std::process::exit(1);
    }
}

/// True when a finding is at or above the minimum severity threshold.
fn at_or_above(finding_sev: lint::LintSeverity, min_sev: lint::LintSeverity) -> bool {
    match min_sev {
        lint::LintSeverity::Error => finding_sev == lint::LintSeverity::Error,
        lint::LintSeverity::Warning => matches!(
            finding_sev,
            lint::LintSeverity::Error | lint::LintSeverity::Warning
        ),
        lint::LintSeverity::Info => true,
    }
}

/// Serializes the severity label used in JSON output.
fn severity_name(sev: lint::LintSeverity) -> &'static str {
    match sev {
        lint::LintSeverity::Error => "error",
        lint::LintSeverity::Warning => "warning",
        lint::LintSeverity::Info => "info",
    }
}

/// Renders the lint report as pretty-printed JSON.
fn render_json(report: &hlock::lint::LintReport, min_sev: lint::LintSeverity, quiet: bool) {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .filter(|f| at_or_above(f.severity, min_sev))
        .map(|f| {
            serde_json::json!({
                "rule": f.rule,
                "severity": severity_name(f.severity),
                "package": f.package,
                "message": f.message,
            })
        })
        .collect();
    let error_count = findings.iter().filter(|f| f["severity"] == "error").count();
    let warning_count = findings
        .iter()
        .filter(|f| f["severity"] == "warning")
        .count();
    let info_count = findings.iter().filter(|f| f["severity"] == "info").count();
    if !quiet {
        let data = serde_json::json!({
            "findings": findings,
            "error_count": error_count,
            "warning_count": warning_count,
            "info_count": info_count,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&super::envelope("lint", error_count == 0, &data,))
                .unwrap()
        );
    }
}

/// Renders the lint findings table as human-readable text.
fn render_text(report: &hlock::lint::LintReport, min_sev: lint::LintSeverity, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    for f in &report.findings {
        if !at_or_above(f.severity, min_sev) {
            continue;
        }
        let sev_str = match f.severity {
            lint::LintSeverity::Error => output::C {
                text: "ERROR",
                on: color_enabled,
            }
            .rb(),
            lint::LintSeverity::Warning => output::C {
                text: "WARN",
                on: color_enabled,
            }
            .yb(),
            lint::LintSeverity::Info => output::C {
                text: "INFO",
                on: color_enabled,
            }
            .bl(),
        };
        let pkg = f.package.as_deref().unwrap_or("-");
        if !quiet {
            println!("{:8}{:24}{:12}{}", sev_str, f.rule, pkg, f.message);
        }
    }
}
