//! `check` command implementation.

use super::{
    Ctx, HashMap, Lockfile, Path, build_rule_set, collect_trusted_keys_or_exit, deserialize, lint,
    now_epoch, output, policy, read_input, severity_label, signature, validate_digest,
    verify_signature,
};

/// Arguments for the `check` command.
pub(crate) struct CheckArgs<'a> {
    pub(crate) file: &'a Path,
    pub(crate) trusted_key: &'a [String],
    pub(crate) time: u64,
    pub(crate) severity: &'a str,
    pub(crate) rule: &'a [String],
    pub(crate) vex: bool,
    pub(crate) format: &'a str,
}

/// Signature verification status for the `check` report.
struct SignatureStatus {
    present: bool,
    valid: bool,
    expired: bool,
    key_id: String,
    algorithm: signature::SignatureAlgorithm,
    expires_epoch: u64,
}

/// Computed results of the `check` analysis, shared by both renderers.
struct CheckReport<'a> {
    lockfile: &'a Lockfile,
    digest_valid: bool,
    signature: SignatureStatus,
    trust_chain_valid: bool,
    lint_report: &'a lint::LintReport,
    min_severity: lint::LintSeverity,
    lint_errors: Vec<&'a lint::LintFinding>,
    audit_report: policy::AuditReport,
    /// 0 = passed, 1 = soft failure, 2 = hard failure.
    exit_code: i32,
}

/// Reports a lockfile parse error in the requested format and exits with status 2.
fn exit_parse_error(
    e: &hlock::Error,
    digest_valid: bool,
    format: &str,
    quiet: bool,
    color_enabled: bool,
) -> ! {
    let fmt = output::parse_format(format);
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
    } else if !quiet {
        println!(
            "{} [{}] parse error: {}",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb(),
            e.error_code(),
            e
        );
    }
    std::process::exit(2);
}

/// Builds the trusted-key map from `KEY_ID:ALGO:HEX` specifications.
fn build_trusted_keys(
    specs: &[String],
) -> HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)> {
    collect_trusted_keys_or_exit(specs)
}

/// Returns the `(key_id, algorithm)` of the first trusted key.
fn first_trusted_key(
    trusted: &HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)>,
) -> (String, signature::SignatureAlgorithm) {
    let key_id = trusted.keys().next().cloned().unwrap_or_default();
    let algorithm = trusted
        .values()
        .next()
        .map_or(signature::SignatureAlgorithm::Ed25519, |(_, a)| *a);
    (key_id, algorithm)
}

/// Verifies the lockfile signature against the trusted keys.
///
/// Gate semantics (v1.0.1):
/// - trusted keys pinned + no `@signature` block → invalid (unsigned file);
/// - no trusted keys + `@signature` block present → invalid (silent skip);
/// - no trusted keys + unsigned → recorded as `present: false` (the file is
///   simply unsigned, nothing to verify);
/// - keys pinned + signature present → the cryptographic verdict.
fn signature_status(
    content: &str,
    trusted: &HashMap<String, (Vec<u8>, signature::SignatureAlgorithm)>,
    now: u64,
) -> SignatureStatus {
    let signed = signature::has_signature_block(content);
    if trusted.is_empty() {
        return SignatureStatus {
            present: false,
            valid: !signed,
            expired: false,
            key_id: String::new(),
            algorithm: signature::SignatureAlgorithm::Ed25519,
            expires_epoch: 0,
        };
    }
    if !signed {
        return SignatureStatus {
            present: false,
            valid: false,
            expired: false,
            key_id: String::new(),
            algorithm: signature::SignatureAlgorithm::Ed25519,
            expires_epoch: 0,
        };
    }
    match verify_signature(content, trusted, now) {
        Ok(()) => {
            let (key_id, algorithm) = first_trusted_key(trusted);
            SignatureStatus {
                present: true,
                valid: true,
                expired: false,
                key_id,
                algorithm,
                expires_epoch: 0,
            }
        }
        Err(signature::SignatureError::SignatureExpired {
            key_id,
            expires_epoch,
        }) => SignatureStatus {
            present: true,
            valid: false,
            expired: true,
            key_id,
            algorithm: signature::SignatureAlgorithm::Ed25519,
            expires_epoch,
        },
        Err(_) => {
            let (key_id, algorithm) = first_trusted_key(trusted);
            SignatureStatus {
                present: true,
                valid: false,
                expired: false,
                key_id,
                algorithm,
                expires_epoch: 0,
            }
        }
    }
}

/// Parses the `--severity` argument into a lint severity floor.
fn parse_min_severity(severity: &str) -> lint::LintSeverity {
    match severity {
        "warning" => lint::LintSeverity::Warning,
        "info" => lint::LintSeverity::Info,
        _ => lint::LintSeverity::Error,
    }
}

/// Returns whether a lint finding meets the configured severity floor.
fn meets_min_severity(finding: &lint::LintFinding, min_severity: lint::LintSeverity) -> bool {
    match min_severity {
        lint::LintSeverity::Error => finding.severity == lint::LintSeverity::Error,
        lint::LintSeverity::Warning => matches!(
            finding.severity,
            lint::LintSeverity::Error | lint::LintSeverity::Warning
        ),
        lint::LintSeverity::Info => true,
    }
}

/// Returns the display name for a signature algorithm.
fn algo_name(algorithm: signature::SignatureAlgorithm) -> &'static str {
    match algorithm {
        signature::SignatureAlgorithm::Ed25519 => "ed25519",
        signature::SignatureAlgorithm::MlDsa65 => "mldsa65",
    }
}

/// Serializes the signature status to the JSON report shape.
fn signature_json(status: &SignatureStatus) -> serde_json::Value {
    serde_json::json!({
        "present": status.present,
        "valid": status.valid,
        "expired": status.expired,
        "key_id": status.key_id,
        "algorithm": algo_name(status.algorithm),
        "expires_epoch": status.expires_epoch,
    })
}

/// Serializes the lint findings that meet the severity floor.
fn lint_findings_json(
    lint_report: &lint::LintReport,
    min_severity: lint::LintSeverity,
) -> Vec<serde_json::Value> {
    lint_report
        .findings
        .iter()
        .filter(|f| meets_min_severity(f, min_severity))
        .map(|f| {
            serde_json::json!({
                "rule": f.rule,
                "severity": match f.severity {
                    lint::LintSeverity::Error => "error",
                    lint::LintSeverity::Warning => "warning",
                    lint::LintSeverity::Info => "info",
                },
                "package": f.package,
                "message": f.message,
            })
        })
        .collect()
}

/// Serializes the lint section of the JSON report.
fn lint_json(report: &CheckReport) -> serde_json::Value {
    serde_json::json!({
        "error_count": report.lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Error).count(),
        "warning_count": report.lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Warning).count(),
        "info_count": report.lint_errors.iter().filter(|f| f.severity == lint::LintSeverity::Info).count(),
        "findings": lint_findings_json(report.lint_report, report.min_severity),
    })
}

/// Serializes one advisory to the JSON report shape.
fn advisory_json(a: &policy::Advisory) -> serde_json::Value {
    serde_json::json!({
        "package": a.package,
        "id": a.advisory_id,
        "severity": a.severity.as_str(),
        "url": a.url,
        "affected": a.affected_versions,
    })
}

/// Lists advisories from the full audit that VEX suppresses (not effective).
fn vex_suppressed(
    lockfile: &Lockfile,
    audit_report: &policy::AuditReport,
) -> Vec<policy::Advisory> {
    let full_audit = lockfile.audit();
    let effective_ids: std::collections::HashSet<String> = audit_report
        .all_advisories()
        .map(|a| a.advisory_id.clone())
        .collect();
    full_audit
        .all_advisories()
        .filter(|a| !effective_ids.contains(&a.advisory_id))
        .cloned()
        .collect()
}

/// Serializes the VEX-suppressed advisories of the JSON report.
fn vex_suppressed_json(
    lockfile: &Lockfile,
    audit_report: &policy::AuditReport,
) -> Vec<serde_json::Value> {
    vex_suppressed(lockfile, audit_report).iter().map(|a| serde_json::json!({
        "package": a.package,
        "id": a.advisory_id,
        "status": lockfile.vex_for(&a.package, &a.advisory_id).map_or("unknown", |v| v.status.as_str()),
    })).collect()
}

/// Serializes the audit section of the JSON report.
fn audit_json(report: &CheckReport, vex: bool) -> serde_json::Value {
    let audit = &report.audit_report;
    serde_json::json!({
        "critical": audit.critical.iter().map(advisory_json).collect::<Vec<_>>(),
        "high": audit.high.iter().map(advisory_json).collect::<Vec<_>>(),
        "medium": audit.medium.iter().map(advisory_json).collect::<Vec<_>>(),
        "low": audit.low.iter().map(advisory_json).collect::<Vec<_>>(),
        "info": audit.info.iter().map(advisory_json).collect::<Vec<_>>(),
        "vex_suppressed": if vex { vec![] } else { vex_suppressed_json(report.lockfile, audit) },
    })
}

/// Renders the `check` report as pretty-printed JSON.
fn render_json(report: &CheckReport, vex: bool, passed: bool, quiet: bool) {
    if !quiet {
        let json = serde_json::json!({
            "digest_valid": report.digest_valid,
            "signature": signature_json(&report.signature),
            "trust_chain_valid": report.trust_chain_valid,
            "lint": lint_json(report),
            "audit": audit_json(report, vex),
            "passed": passed,
        });
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

/// Prints the digest validation line.
fn print_digest_status(digest_valid: bool, color_enabled: bool) {
    if digest_valid {
        println!(
            "{} Digest valid",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb()
        );
    } else {
        println!(
            "{} Digest invalid",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb()
        );
    }
}

/// Prints the signature verification line.
fn print_signature_status(status: &SignatureStatus, color_enabled: bool) {
    if status.present {
        if status.expired {
            println!(
                "{} Signature expired ({}, expired epoch {})",
                output::C {
                    text: "✗",
                    on: color_enabled
                }
                .rb(),
                status.key_id,
                status.expires_epoch
            );
        } else if status.valid {
            println!(
                "{} Signature valid ({}, {})",
                output::C {
                    text: "✓",
                    on: color_enabled
                }
                .gb(),
                status.key_id,
                algo_name(status.algorithm)
            );
        } else {
            println!(
                "{} Signature invalid",
                output::C {
                    text: "✗",
                    on: color_enabled
                }
                .rb()
            );
        }
    } else if status.valid {
        println!("  No signature found (use --trusted-key to verify signatures)");
    } else {
        println!(
            "{} Signature missing but required (trusted keys were pinned)",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb()
        );
    }
}

/// Prints the trust chain validation line.
fn print_trust_chain_status(trust_chain_valid: bool, color_enabled: bool) {
    if trust_chain_valid {
        println!(
            "{} Trust chain valid",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb()
        );
    } else {
        println!(
            "{} Trust chain invalid",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb()
        );
    }
}

/// Prints the lint summary and any findings at or above the severity floor.
fn print_lint_status(lint_errors: &[&lint::LintFinding], color_enabled: bool) {
    let err_count = lint_errors
        .iter()
        .filter(|f| f.severity == lint::LintSeverity::Error)
        .count();
    let warn_count = lint_errors
        .iter()
        .filter(|f| f.severity == lint::LintSeverity::Warning)
        .count();
    let info_count = lint_errors
        .iter()
        .filter(|f| f.severity == lint::LintSeverity::Info)
        .count();
    if err_count == 0 && warn_count == 0 && info_count == 0 {
        println!(
            "{} Lint: 0 errors, 0 warnings, 0 info",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb()
        );
    } else {
        println!("Lint: {err_count} error(s), {warn_count} warning(s), {info_count} info(s)");
        for f in lint_errors {
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
            println!("  {} {:20} {:12} {}", sev_str, f.rule, pkg, f.message);
        }
    }
}

/// Prints the audit summary block of the text report.
fn print_audit_status(report: &CheckReport, vex: bool, color_enabled: bool) {
    let audit = &report.audit_report;
    let suppressed = if vex {
        Vec::new()
    } else {
        vex_suppressed(report.lockfile, audit)
    };

    if !audit.has_critical_or_high() && audit.total_count() == 0 {
        println!(
            "{} Audit: 0 vulnerabilities",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb()
        );
    } else if !audit.has_critical_or_high() {
        println!(
            "{} Audit: {} (no critical/high)",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb(),
            audit.total_count()
        );
    } else {
        let crit_count = audit.critical.len();
        let high_count = audit.high.len();
        let med_count = audit.medium.len();
        let low_count = audit.low.len();
        let info_count = audit.info.len();
        print!(
            "Audit: {crit_count} critical, {high_count} high, {med_count} medium, {low_count} low, {info_count} info"
        );
        if !vex && !suppressed.is_empty() {
            print!(" ({} VEX-suppressed)", suppressed.len());
        }
        println!();
        for adv in audit.all_advisories() {
            println!(
                "  {} {:12} {:16} {}",
                severity_label(adv.severity, color_enabled),
                adv.package,
                adv.advisory_id,
                adv.affected_versions
            );
        }
        if !vex && !suppressed.is_empty() {
            println!(
                "({} advisory suppressed by VEX{})",
                suppressed.len(),
                suppressed
                    .iter()
                    .map(|a| format!(
                        ": {}/{} → {}",
                        a.package,
                        a.advisory_id,
                        report
                            .lockfile
                            .vex_for(&a.package, &a.advisory_id)
                            .map_or("unknown", |v| v.status.as_str())
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

/// Builds the human-readable list of reasons the check failed.
fn failure_reasons(report: &CheckReport) -> Vec<String> {
    let mut fail_parts = Vec::new();
    if !report.digest_valid {
        fail_parts.push("digest invalid".to_string());
    }
    if !report.signature.valid {
        if report.signature.present {
            fail_parts.push("signature invalid".to_string());
        } else {
            fail_parts.push("signature missing but required".to_string());
        }
    }
    if !report.trust_chain_valid {
        fail_parts.push("trust chain invalid".to_string());
    }
    if !report.lint_errors.is_empty() {
        fail_parts.push(format!(
            "{} lint errors",
            report
                .lint_errors
                .iter()
                .filter(|f| f.severity == lint::LintSeverity::Error)
                .count()
        ));
    }
    if report.audit_report.has_critical_or_high() {
        fail_parts.push(format!(
            "{} critical/high advisory",
            report.audit_report.critical.len() + report.audit_report.high.len()
        ));
    }
    fail_parts
}

/// Prints the final failure line listing all failed gates.
fn print_failure_summary(report: &CheckReport, color_enabled: bool) {
    if report.exit_code != 0 {
        println!();
        println!(
            "{} {}",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb(),
            failure_reasons(report).join(", ")
        );
    }
}

/// Renders the `check` report as human-readable text.
fn render_text(report: &CheckReport, vex: bool, color_enabled: bool) {
    print_digest_status(report.digest_valid, color_enabled);
    print_signature_status(&report.signature, color_enabled);
    print_trust_chain_status(report.trust_chain_valid, color_enabled);
    print_lint_status(&report.lint_errors, color_enabled);
    print_audit_status(report, vex, color_enabled);
    print_failure_summary(report, color_enabled);
}

/// Runs the `check` command.
pub(crate) fn run(args: &CheckArgs<'_>, ctx: Ctx) {
    let CheckArgs {
        file,
        trusted_key,
        time,
        severity,
        rule,
        vex,
        format,
    } = args;
    let time = *time;
    let vex = *vex;

    let (content, digest_valid, lockfile) = read_and_parse(file, format, ctx);

    let now = if time > 0 { time } else { now_epoch() };

    let t_trust = std::time::Instant::now();
    let trust_chain_valid = if lockfile.trust_roots.is_empty() {
        true
    } else {
        lockfile.validate_trust_chain(now).is_ok()
    };
    if ctx.verbose {
        eprintln!(
            "[verbose] Trust chain validation... {:?} ({})",
            t_trust.elapsed(),
            if trust_chain_valid { "ok" } else { "FAILED" }
        );
    }

    let trusted = build_trusted_keys(trusted_key);
    let sig_status = signature_status(&content, &trusted, now);

    let t_lint = std::time::Instant::now();
    let rules = build_rule_set(rule);
    if ctx.verbose {
        eprintln!("[verbose] Running lint ({} rules)...", rules.len());
    }
    let lint_report = hlock::lint::lint(&lockfile, &rules);
    if ctx.verbose {
        eprintln!("[verbose] Lint complete... {:?}", t_lint.elapsed());
    }

    let min_severity = parse_min_severity(severity);
    let lint_errors: Vec<&lint::LintFinding> = lint_report
        .findings
        .iter()
        .filter(|f| meets_min_severity(f, min_severity))
        .collect();

    let t_audit = std::time::Instant::now();
    let audit_report = if vex {
        lockfile.audit()
    } else {
        lockfile.effective_advisories()
    };
    if ctx.verbose {
        eprintln!("[verbose] Audit complete... {:?}", t_audit.elapsed());
    }

    let audit_has_critical_or_high = audit_report.has_critical_or_high();
    // Hard failures are verification failures (digest, signature, trust
    // chain) → exit 1 per the CLI contract; parse errors alone exit 2.
    let hard_failure = !digest_valid || !sig_status.valid || !trust_chain_valid;
    let soft_failure = !lint_errors.is_empty() || audit_has_critical_or_high;
    let exit_code = if hard_failure {
        1
    } else {
        i32::from(soft_failure)
    };

    let report = CheckReport {
        lockfile: &lockfile,
        digest_valid,
        signature: sig_status,
        trust_chain_valid,
        lint_report: &lint_report,
        min_severity,
        lint_errors,
        audit_report,
        exit_code,
    };

    let fmt = output::parse_format(format);
    if fmt == output::OutputFormat::Json {
        render_json(&report, vex, exit_code == 0, ctx.quiet);
    } else if !ctx.quiet {
        render_text(&report, vex, ctx.color_enabled);
    }

    if report.exit_code != 0 {
        std::process::exit(report.exit_code);
    }
}

/// Reads the lockfile, validates its digest and parses it.
///
/// Exits the process on read or parse failure.
fn read_and_parse(file: &Path, format: &str, ctx: Ctx) -> (String, bool, hlock::Lockfile) {
    let Ctx {
        quiet,
        verbose,
        color_enabled,
    } = ctx;

    if verbose {
        eprintln!("[verbose] Reading {}...", file.display());
    }
    let t_read = std::time::Instant::now();
    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };
    if verbose {
        eprintln!(
            "[verbose] Read {} bytes in {:?}",
            content.len(),
            t_read.elapsed()
        );
    }

    let t_digest = std::time::Instant::now();
    let digest_valid = validate_digest(&content).is_ok();
    if verbose {
        eprintln!(
            "[verbose] Validating digest... {:?} ({})",
            t_digest.elapsed(),
            if digest_valid { "ok" } else { "FAILED" }
        );
    }

    let lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => exit_parse_error(&e, digest_valid, format, quiet, color_enabled),
    };
    (content, digest_valid, lockfile)
}
