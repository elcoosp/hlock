//! `audit` command implementation.

use super::{Ctx, HashSet, Path, deserialize, policy, read_input, severity_label};

/// Runs the `audit` command.
pub(crate) fn run(file: &Path, online: bool, merge: bool, format: &str, timeout: u64, ctx: Ctx) {
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
    if verbose {
        eprintln!("[verbose] Running audit (online={online})...");
    }
    let report = lockfile.audit();
    if verbose {
        eprintln!(
            "[verbose] Audit complete: {} advisories",
            report.total_count()
        );
    }

    let (online_vulns, online_errors) = if online {
        query_online(&lockfile, timeout, verbose)
    } else {
        (Vec::new(), Vec::new())
    };

    if format == "json" {
        owo_colors::set_override(false);
        let json = audit_json(&report, &online_vulns, &online_errors);
        if !quiet {
            println!("{json}");
        }
    } else {
        audit_text(
            &report,
            &lockfile,
            &online_vulns,
            &online_errors,
            merge,
            online,
            ctx,
        );
    }

    let has_critical_or_high =
        report.has_critical_or_high() || online_vulns.iter().any(is_crit_high);
    if has_critical_or_high {
        std::process::exit(1);
    }
}

/// True when the OSV vulnerability is critical or high severity.
fn is_crit_high(v: &hlock::osv::OsvVulnerability) -> bool {
    matches!(
        hlock::osv::osv_severity(v),
        policy::AdvisorySeverity::Critical | policy::AdvisorySeverity::High
    )
}

/// Queries OSV for every package in the lockfile.
fn query_online(
    lockfile: &hlock::Lockfile,
    timeout: u64,
    verbose: bool,
) -> (Vec<hlock::osv::OsvVulnerability>, Vec<String>) {
    let mut vulns = Vec::new();
    let mut errors = Vec::new();
    if verbose {
        eprintln!(
            "[verbose] Querying OSV for {} packages...",
            lockfile.packages.len()
        );
    }
    for pkg in &lockfile.packages {
        let version = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
        match hlock::osv::query_osv(&pkg.name, &version, timeout) {
            Ok(response) => vulns.extend(response.vulns),
            Err(e) => errors.push(format!("{}@{}: {}", pkg.name, version, e)),
        }
    }
    if verbose {
        eprintln!(
            "[verbose] OSV returned {} vulnerabilities, {} errors",
            vulns.len(),
            errors.len()
        );
    }
    (vulns, errors)
}

/// Builds the JSON audit report.
fn audit_json(
    report: &hlock::policy::AuditReport,
    online_vulns: &[hlock::osv::OsvVulnerability],
    online_errors: &[String],
) -> String {
    let embedded: Vec<serde_json::Value> = report
        .all_advisories()
        .map(|a| {
            serde_json::json!({
                "package": a.package, "id": a.advisory_id, "severity": a.severity.as_str(),
                "url": a.url, "affected": a.affected_versions, "source": "embedded"
            })
        })
        .collect();
    let online_json: Vec<serde_json::Value> = online_vulns
        .iter()
        .map(|v| {
            serde_json::json!({
                "id": v.id,
                "summary": v.summary,
                "severity": hlock::osv::osv_severity(v).as_str(),
                "fixed": hlock::osv::find_fixed_version(v),
                "source": "online"
            })
        })
        .collect();
    serde_json::to_string_pretty(&serde_json::json!({
        "critical": report.critical.len(),
        "high": report.high.len(),
        "medium": report.medium.len(),
        "low": report.low.len(),
        "info": report.info.len(),
        "embedded": embedded,
        "online": online_json,
        "online_errors": online_errors,
    }))
    .unwrap_or_else(|e| format!("{{\"error\": \"{e}\"}}"))
}

/// Prints the text audit report.
fn audit_text(
    report: &hlock::policy::AuditReport,
    lockfile: &hlock::Lockfile,
    online_vulns: &[hlock::osv::OsvVulnerability],
    online_errors: &[String],
    merge: bool,
    online: bool,
    ctx: Ctx,
) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    for adv in report.all_advisories() {
        let sev_str = severity_label(adv.severity, color_enabled);
        if !quiet {
            println!(
                "{:10}{:16}{}   {}   (embedded)",
                sev_str, adv.package, adv.advisory_id, adv.affected_versions
            );
        }
    }

    if online {
        let embedded_ids: HashSet<String> = lockfile
            .advisories
            .iter()
            .map(|a| a.advisory_id.clone())
            .collect();
        for vuln in online_vulns {
            if merge && embedded_ids.contains(&vuln.id) {
                continue;
            }
            let sev = hlock::osv::osv_severity(vuln);
            let sev_str = severity_label(sev, color_enabled);
            let fixed = hlock::osv::find_fixed_version(vuln);
            let fixed_str = fixed.as_deref().unwrap_or("—");
            if !quiet {
                println!(
                    "{:10}{}   {}   (online, fixed: {})",
                    sev_str, vuln.id, vuln.summary, fixed_str
                );
            }
        }
    }

    if !quiet {
        println!("---");
        let crit_high = report.critical.len() + report.high.len();
        let online_crit_high = online_vulns.iter().filter(|v| is_crit_high(v)).count();
        println!(
            "Total: {} critical/high, {} medium, {} low, {} info",
            crit_high + online_crit_high,
            report.medium.len(),
            report.low.len(),
            report.info.len()
        );
        println!(
            "Sources: {} embedded, {} online",
            lockfile.advisories.len(),
            online_vulns.len()
        );
        for e in online_errors {
            eprintln!("  Warning: OSV query failed: {e}");
        }
    }
}
