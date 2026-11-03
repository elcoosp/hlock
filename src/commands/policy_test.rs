//! `policy-test` command implementation — dry-runs policy directives.

use super::{Ctx, Path, deserialize, output, policy, read_input};

/// Runs the `policy-test` command.
pub(crate) fn run(
    file: &Path,
    package: &str,
    hook: Option<&str>,
    script: Option<&str>,
    format: &str,
    ctx: Ctx,
) {
    let Ctx {
        quiet,
        color_enabled,
        ..
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

    if lockfile.policies.is_empty() {
        eprintln!(
            "Note: lockfile declares no @policy directives; everything is allowed by default."
        );
    }

    let hook_verdict = hook.map(|h| (h, lockfile.hook_allowed(package, h)));
    let script_verdict = script.map(|sc| (sc, lockfile.script_allowed(package, sc)));
    let report = lockfile.evaluate_policies(package);

    if output::parse_format(format) == output::OutputFormat::Json {
        let json = serde_json::json!({
            "package": package,
            "hook": hook_verdict.map(|(h, d)| decision_json(h, d)),
            "script": script_verdict.map(|(sc, d)| decision_json(sc, d)),
            "full_report": {
                "hook_decisions": report.hook_decisions.iter()
                    .map(|(k, v)| serde_json::json!({"hook": k, "decision": decision_str(v)}))
                    .collect::<Vec<_>>(),
                "build_env": report.build_env,
                "engine": report.engine,
                "violations": report.violations.iter().map(violation_json).collect::<Vec<_>>(),
            },
        });
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&super::envelope("policy-test", true, &json)).unwrap()
            );
        }
        return;
    }

    if quiet {
        return;
    }

    println!(
        "Policy evaluation for `{package}` ({} directives loaded):",
        lockfile.policies.len()
    );
    match hook_verdict {
        Some((h, d)) => println!("  hook   {:<14} → {}", h, colored(&d, color_enabled)),
        None => println!("  hook   (not tested — pass --hook)"),
    }
    match script_verdict {
        Some((sc, d)) => println!("  script {:<14} → {}", sc, colored(&d, color_enabled)),
        None => println!("  script (not tested — pass --script)"),
    }
    println!(
        "  build-env → {}",
        report.build_env.as_deref().unwrap_or("(none)")
    );
    println!(
        "  engine    → {}",
        report.engine.as_deref().unwrap_or("(none)")
    );
    if report.violations.is_empty() {
        println!("  full evaluation: no violations");
    } else {
        println!(
            "  full evaluation: {} violation(s)",
            report.violations.len()
        );
        for v in &report.violations {
            println!("    - [{}] {}", v.policy_type.as_str(), v.message);
        }
    }
}

/// JSON rendering of one hook/script decision.
fn decision_json(name: &str, decision: policy::PolicyDecision) -> serde_json::Value {
    match decision {
        policy::PolicyDecision::Denied { reason } => serde_json::json!({
            "name": name, "decision": "denied", "reason": reason,
        }),
        other => serde_json::json!({ "name": name, "decision": decision_str(&other) }),
    }
}

/// JSON rendering of a policy violation.
fn violation_json(v: &policy::PolicyViolation) -> serde_json::Value {
    serde_json::json!({ "policy_type": v.policy_type.as_str(), "message": v.message })
}

/// Human-readable decision with color when enabled.
fn colored(decision: &policy::PolicyDecision, color_enabled: bool) -> String {
    use owo_colors::OwoColorize as _;
    let text = decision_str(decision).to_string();
    if matches!(decision, policy::PolicyDecision::Allowed) {
        if color_enabled {
            text.green().to_string()
        } else {
            text
        }
    } else if color_enabled {
        text.red().to_string()
    } else {
        text
    }
}

fn decision_str(decision: &policy::PolicyDecision) -> &'static str {
    match decision {
        policy::PolicyDecision::Allowed => "allowed",
        policy::PolicyDecision::Denied { .. } => "denied",
        policy::PolicyDecision::NoPolicy => "no policy",
    }
}
