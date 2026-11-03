//! `explain` command implementation.

use super::{
    Ctx, ExplanationKind, Lockfile, Path, deserialize, explain_advisory, explain_rule, output,
    read_input,
};
use hlock::Explanation;

/// Reads and parses the lockfile at `path`, exiting with status 2 on failure.
fn load_lockfile(path: &Path) -> Lockfile {
    let content = match read_input(path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", path.display(), e);
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

/// Serializes a rule explanation to the JSON output shape.
fn rule_json(explanation: &Explanation) -> serde_json::Value {
    serde_json::json!({
        "name": explanation.name,
        "kind": match explanation.kind { ExplanationKind::Rule => "rule", ExplanationKind::Advisory => "advisory" },
        "severity": explanation.severity,
        "category": explanation.category,
        "description": explanation.description,
        "why_it_matters": explanation.why_it_matters,
        "how_to_fix": explanation.how_to_fix,
        "related": explanation.related,
        "references": explanation.references,
    })
}

/// Serializes an advisory explanation to the JSON output shape.
fn advisory_json(explanation: &Explanation) -> serde_json::Value {
    serde_json::json!({
        "name": explanation.name,
        "kind": "advisory",
        "severity": explanation.severity,
        "category": explanation.category,
        "description": explanation.description,
        "why_it_matters": explanation.why_it_matters,
        "how_to_fix": explanation.how_to_fix,
        "references": explanation.references,
    })
}

/// Pretty-prints a JSON explanation, unless output is suppressed.
fn print_json(json: &serde_json::Value, quiet: bool) {
    if !quiet {
        println!(
            "{}",
            serde_json::to_string_pretty(&super::envelope("explain", true, &json.clone())).unwrap()
        );
    }
}

/// Renders a rule explanation as human-readable text.
fn print_rule_text(explanation: &Explanation, rule_or_id: &str, color_enabled: bool) {
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    println!("{}: {}", bold("Rule"), rule_or_id);
    if let Some(ref sev) = explanation.severity {
        println!("{}: {}", bold("Severity"), sev);
    }
    if let Some(ref cat) = explanation.category {
        println!("{}: {}", bold("Category"), cat);
    }
    println!();
    println!("{}", explanation.description);
    println!();
    if !explanation.why_it_matters.is_empty() {
        println!("{}:", bold("Why it matters"));
        for item in &explanation.why_it_matters {
            println!("  - {item}");
        }
        println!();
    }
    if !explanation.how_to_fix.is_empty() {
        println!("{}:", bold("How to fix"));
        for item in &explanation.how_to_fix {
            println!("  - {item}");
        }
        println!();
    }
    if !explanation.related.is_empty() {
        println!(
            "{}: {}",
            bold("Related rules"),
            explanation.related.join(", ")
        );
    }
    if !explanation.references.is_empty() {
        println!("{}:", bold("References"));
        for r in &explanation.references {
            println!("  - {}", cyan(r));
        }
    }
}

/// Renders an advisory explanation as human-readable text.
fn print_advisory_text(explanation: &Explanation, rule_or_id: &str, color_enabled: bool) {
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    println!("{}: {}", bold("Advisory"), rule_or_id);
    if let Some(ref sev) = explanation.severity {
        println!("{}: {}", bold("Severity"), sev);
    }
    println!();
    println!("{}", explanation.description);
    println!();
    if !explanation.how_to_fix.is_empty() {
        println!("{}:", bold("How to fix"));
        for item in &explanation.how_to_fix {
            println!("  - {item}");
        }
    }
    if !explanation.references.is_empty() {
        println!("{}:", bold("References"));
        for r in &explanation.references {
            println!("  - {}", cyan(r));
        }
    }
}

/// Renders a lint-rule explanation in the requested output format.
fn render_rule(
    rule_or_id: &str,
    explanation: &Explanation,
    format: &str,
    quiet: bool,
    color_enabled: bool,
) {
    if output::parse_format(format) == output::OutputFormat::Json {
        print_json(&rule_json(explanation), quiet);
    } else {
        print_rule_text(explanation, rule_or_id, color_enabled);
    }
}

/// Renders an advisory explanation in the requested output format.
fn render_advisory(
    rule_or_id: &str,
    explanation: &Explanation,
    format: &str,
    quiet: bool,
    color_enabled: bool,
) {
    if output::parse_format(format) == output::OutputFormat::Json {
        print_json(&advisory_json(explanation), quiet);
    } else {
        print_advisory_text(explanation, rule_or_id, color_enabled);
    }
}

/// Levenshtein edit distance between two strings (small, allocation-light).
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for (i, ca) in a.iter().enumerate() {
        cur[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Best matching known rule name within edit distance 2, if any.
fn closest_rule(input: &str) -> Option<&'static str> {
    hlock::rule_registry()
        .iter()
        .map(|m| m.name)
        .min_by_key(|name| levenshtein(input, name))
        .filter(|name| levenshtein(input, name) <= 2)
}

/// Renders the rule registry as a table (`explain --list [filter]`).
fn render_rule_list(filter: Option<&str>, format: &str, quiet: bool, color_enabled: bool) {
    let registry = hlock::rule_registry();
    let rules: Vec<_> = registry
        .iter()
        .filter(|m| filter.is_none_or(|f| m.name.contains(f) || m.category.as_str().contains(f)))
        .collect();

    if rules.is_empty() {
        eprintln!("Error: no rule matches filter '{filter:?}'.");
        std::process::exit(1);
    }

    if output::parse_format(format) == output::OutputFormat::Json {
        if !quiet {
            let json = serde_json::json!({
                "count": rules.len(),
                "rules": rules.iter().map(|m| serde_json::json!({
                    "name": m.name,
                    "severity": match m.severity {
                        hlock::lint::LintSeverity::Error => "error",
                        hlock::lint::LintSeverity::Warning => "warning",
                        hlock::lint::LintSeverity::Info => "info",
                    },
                    "category": m.category.as_str(),
                    "summary": m.summary,
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
        return;
    }

    if quiet {
        return;
    }
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    println!("{} ({} rules)", bold("Lint rule registry"), rules.len());
    println!();
    for m in &rules {
        let sev = match m.severity {
            hlock::lint::LintSeverity::Error => "ERROR  ",
            hlock::lint::LintSeverity::Warning => "WARN   ",
            hlock::lint::LintSeverity::Info => "INFO   ",
        };
        println!(
            "  {} {:20} {:16} {}",
            sev,
            bold(m.name),
            cyan(m.category.as_str()),
            m.summary
        );
    }
}

/// Runs the `explain` command.
pub(crate) fn run(
    rule_or_id: Option<&str>,
    list: bool,
    file: Option<&Path>,
    format: &str,
    ctx: Ctx,
) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    if list {
        render_rule_list(rule_or_id, format, quiet, color_enabled);
        return;
    }

    let Some(rule_or_id) = rule_or_id else {
        eprintln!("Error: provide a rule or advisory id, or use --list.");
        std::process::exit(2);
    };

    if let Some(explanation) = explain_rule(rule_or_id) {
        render_rule(rule_or_id, &explanation, format, quiet, color_enabled);
        return;
    }

    if let Some(path) = file {
        let lockfile = load_lockfile(path);
        if let Some(explanation) = explain_advisory(rule_or_id, &lockfile) {
            render_advisory(rule_or_id, &explanation, format, quiet, color_enabled);
            return;
        }
    }

    eprintln!("Error: '{rule_or_id}' not found as a rule or advisory.");
    if let Some(guess) = closest_rule(rule_or_id) {
        eprintln!("Did you mean '{guess}'?");
    }
    eprintln!("Hint: run 'hlock explain --list' to see all rules.");
    std::process::exit(1);
}
