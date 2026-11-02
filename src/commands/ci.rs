//! `ci` command implementation — the one-shot supply-chain gate.
//!
//! Composes the three gates (`verify` + `lint` + `audit`) into a single
//! command that CI pipelines run on every merge:
//!
//! ```text
//! hlock ci package.hlock --trusted-key ci:ed25519:ABCD...
//! ```
//!
//! Exit codes: `0` all gates passed, `1` findings (lint/audit/new-vs-baseline),
//! `2` hard error (unreadable, parse failure, invalid digest or signature).
//! `--no-verify`, `--no-lint` and `--no-audit` skip individual gates; every
//! skipped gate is reported as `skipped` in the JSON report.

use super::{
    Ctx, HashMap, Path, build_rule_set, deserialize, load_baseline_file, output, parse_trusted_key,
    read_input, validate_digest, verify_signature,
};

/// Arguments for the `ci` command.
pub(crate) struct CiArgs<'a> {
    pub(crate) file: &'a Path,
    pub(crate) no_verify: bool,
    pub(crate) no_lint: bool,
    pub(crate) no_audit: bool,
    pub(crate) trusted_key: &'a [String],
    pub(crate) time: u64,
    pub(crate) severity: &'a str,
    pub(crate) rule: &'a [String],
    pub(crate) baseline: Option<&'a Path>,
    pub(crate) format: &'a str,
}

/// Outcome of one gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GateStatus {
    Passed,
    Failed,
    Skipped,
}

impl GateStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// Aggregated result of the `ci` run.
struct CiReport {
    verify: GateStatus,
    lint: GateStatus,
    audit: GateStatus,
    /// Human-readable failure reasons, one per failed check.
    reasons: Vec<String>,
}

impl CiReport {
    fn passed(&self) -> bool {
        self.verify != GateStatus::Failed
            && self.lint != GateStatus::Failed
            && self.audit != GateStatus::Failed
    }

    /// Exit code per the v1.0 contract: findings → 1, hard error → 2.
    fn exit_code(&self) -> i32 {
        i32::from(!self.passed())
    }
}

/// Builds the trusted-key map from `KEY_ID:ALGO:HEX` specifications.
fn build_trusted_keys(
    specs: &[String],
) -> HashMap<String, (Vec<u8>, hlock::signature::SignatureAlgorithm)> {
    let mut trusted = HashMap::new();
    for spec in specs {
        if let Some((key_id, (pubkey, algo))) = parse_trusted_key(spec) {
            trusted.insert(key_id, (pubkey, algo));
        }
    }
    trusted
}

/// Parses the `--severity` argument into a lint severity floor.
fn parse_min_severity(severity: &str) -> hlock::lint::LintSeverity {
    match severity {
        "warning" => hlock::lint::LintSeverity::Warning,
        "info" => hlock::lint::LintSeverity::Info,
        _ => hlock::lint::LintSeverity::Error,
    }
}

/// Whether a lint finding meets the configured severity floor.
fn meets_min_severity(
    finding: &hlock::lint::LintFinding,
    min_severity: hlock::lint::LintSeverity,
) -> bool {
    match min_severity {
        hlock::lint::LintSeverity::Error => finding.severity == hlock::lint::LintSeverity::Error,
        hlock::lint::LintSeverity::Warning => matches!(
            finding.severity,
            hlock::lint::LintSeverity::Error | hlock::lint::LintSeverity::Warning
        ),
        hlock::lint::LintSeverity::Info => true,
    }
}

/// Runs the verify gate: digest + signature + trust chain (incl. rotations).
fn run_verify(
    content: &str,
    lockfile: &hlock::Lockfile,
    trusted: &HashMap<String, (Vec<u8>, hlock::signature::SignatureAlgorithm)>,
    time: u64,
) -> (GateStatus, Vec<String>) {
    let mut reasons = Vec::new();

    if validate_digest(content).is_err() {
        reasons.push("digest missing or invalid (E0205)".to_string());
    }

    let now = if time > 0 {
        time
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    };
    if !lockfile.trust_roots.is_empty()
        && let Err(e) = lockfile.validate_trust_chain(now)
    {
        reasons.push(format!("trust chain: {e} ({})", e.error_code()));
    }

    if !trusted.is_empty()
        && let Err(e) = verify_signature(content, trusted)
    {
        reasons.push(format!("signature: {e}"));
    }

    if reasons.is_empty() {
        (GateStatus::Passed, reasons)
    } else {
        (GateStatus::Failed, reasons)
    }
}

/// Runs the lint gate; returns findings at or above the severity floor.
fn run_lint(
    lockfile: &hlock::Lockfile,
    rule: &[String],
    severity: &str,
) -> (GateStatus, Vec<hlock::lint::LintFinding>) {
    let rules = build_rule_set(rule);
    let report = hlock::lint::lint(lockfile, &rules);
    let min_severity = parse_min_severity(severity);
    let findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| meets_min_severity(f, min_severity))
        .cloned()
        .collect();
    if findings.is_empty() {
        (GateStatus::Passed, findings)
    } else {
        (GateStatus::Failed, findings)
    }
}

/// Runs the audit gate, honoring the optional baseline.
fn run_audit(
    lockfile: &hlock::Lockfile,
    baseline: Option<&Path>,
) -> (GateStatus, usize, Vec<String>) {
    let report = lockfile.audit();
    let total = report.total_count();
    let baseline_ids = baseline.map(load_baseline_file);
    let new_ids: Vec<String> = match &baseline_ids {
        Some(recorded) => super::audit::collect_finding_ids(&report, &[])
            .into_iter()
            .filter(|id| !recorded.contains(id))
            .collect(),
        None => Vec::new(),
    };
    if total == 0 {
        (GateStatus::Passed, total, Vec::new())
    } else if baseline_ids.is_some() {
        if new_ids.is_empty() {
            (GateStatus::Passed, total, Vec::new())
        } else {
            (GateStatus::Failed, total, new_ids)
        }
    } else if report.has_critical_or_high() {
        let crit_high: Vec<String> = report
            .critical
            .iter()
            .chain(report.high.iter())
            .map(|a| format!("{}/{}", a.package, a.advisory_id))
            .collect();
        (GateStatus::Failed, total, crit_high)
    } else {
        (GateStatus::Passed, total, Vec::new())
    }
}

/// Serializes the report to the JSON envelope.
fn report_json(
    report: &CiReport,
    lint_findings: &[hlock::lint::LintFinding],
    audit_new: &[String],
) -> serde_json::Value {
    serde_json::json!({
        "schema": "hlock/v1",
        "command": "ci",
        "ok": report.passed(),
        "data": {
            "gates": {
                "verify": report.verify.as_str(),
                "lint": report.lint.as_str(),
                "audit": report.audit.as_str(),
            },
            "lint_findings": lint_findings.iter().map(|f| serde_json::json!({
                "rule": f.rule,
                "severity": match f.severity {
                    hlock::lint::LintSeverity::Error => "error",
                    hlock::lint::LintSeverity::Warning => "warning",
                    hlock::lint::LintSeverity::Info => "info",
                },
                "package": f.package,
                "message": f.message,
            })).collect::<Vec<_>>(),
            "audit_findings": audit_new,
        },
        "error": serde_json::Value::Null,
    })
}

/// Prints the text report.
fn report_text(
    report: &CiReport,
    lint_findings: &[hlock::lint::LintFinding],
    audit_new: &[String],
    color_enabled: bool,
    quiet: bool,
) {
    if quiet {
        return;
    }
    let ok = |s: GateStatus| match s {
        GateStatus::Passed => output::C {
            text: "✓",
            on: color_enabled,
        }
        .gb(),
        GateStatus::Failed => output::C {
            text: "✗",
            on: color_enabled,
        }
        .rb(),
        GateStatus::Skipped => output::C {
            text: "-",
            on: color_enabled,
        }
        .bl(),
    };
    println!("{} Verify: {}", ok(report.verify), report.verify.as_str());
    for reason in &report.reasons {
        println!("    {reason}");
    }
    println!(
        "{} Lint: {} ({} finding(s))",
        ok(report.lint),
        report.lint.as_str(),
        lint_findings.len()
    );
    for f in lint_findings {
        let pkg = f.package.as_deref().unwrap_or("-");
        println!("    {:8} {:20} {:12} {}", "·", f.rule, pkg, f.message);
    }
    println!(
        "{} Audit: {} ({} finding(s))",
        ok(report.audit),
        report.audit.as_str(),
        audit_new.len()
    );
    for id in audit_new {
        println!("    {id}");
    }
    println!();
    if report.passed() {
        println!(
            "{} ci gate passed",
            output::C {
                text: "✓",
                on: color_enabled
            }
            .gb()
        );
    } else {
        println!(
            "{} ci gate failed",
            output::C {
                text: "✗",
                on: color_enabled
            }
            .rb()
        );
    }
}

/// Runs the `ci` command.
pub(crate) fn run(args: &CiArgs<'_>, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    let content = match read_input(args.file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", args.file.display(), e);
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

    let (verify_status, reasons) = if args.no_verify {
        (GateStatus::Skipped, Vec::new())
    } else {
        let trusted = build_trusted_keys(args.trusted_key);
        run_verify(&content, &lockfile, &trusted, args.time)
    };

    let (lint_status, lint_findings) = if args.no_lint {
        (GateStatus::Skipped, Vec::new())
    } else {
        run_lint(&lockfile, args.rule, args.severity)
    };

    let (audit_status, _total, audit_new) = if args.no_audit {
        (GateStatus::Skipped, 0, Vec::new())
    } else {
        run_audit(&lockfile, args.baseline)
    };

    let report = CiReport {
        verify: verify_status,
        lint: lint_status,
        audit: audit_status,
        reasons,
    };

    if output::parse_format(args.format) == output::OutputFormat::Json {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&report_json(&report, &lint_findings, &audit_new))
                    .unwrap()
            );
        }
    } else {
        report_text(&report, &lint_findings, &audit_new, color_enabled, quiet);
    }

    let code = report.exit_code();
    if code != 0 {
        std::process::exit(code);
    }
}
