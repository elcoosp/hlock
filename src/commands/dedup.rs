//! `dedup` command implementation.

use super::{Ctx, Path, deserialize, output, read_input};

/// Runs the `dedup` command.
pub(crate) fn run(file: &Path, format: &str, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let yellow = output::styler(color_enabled, output::Style::Yellow);

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

    let opportunities = lockfile.dedup_opportunities();
    let fmt = output::parse_format(format);

    if fmt == output::OutputFormat::Json {
        let json = serde_json::json!({
            "opportunities": opportunities.iter().map(|o| serde_json::json!({"package": o.package_name, "versions": o.versions, "potential_saving_bytes": o.potential_saving_bytes})).collect::<Vec<_>>(),
        });
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    } else if !quiet {
        if opportunities.is_empty() {
            println!("No deduplication opportunities found.");
        } else {
            println!("{}:", bold("Deduplication Opportunities"));
            println!();
            println!(
                "{:12}{:24}{:16}",
                bold("Package"),
                bold("Versions"),
                bold("Est. Saving")
            );
            println!(
                "{:12}{:24}{:16}",
                "---------", "------------------------", "--------------"
            );
            for o in &opportunities {
                println!(
                    "{:12}{:24}{} bytes",
                    bold(&o.package_name),
                    cyan(&o.versions.join(", ")),
                    yellow(&format!("~{}", o.potential_saving_bytes))
                );
            }
        }
    }
}
