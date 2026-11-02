//! `why` command implementation.

use super::{Ctx, Path, deserialize, output, read_input};

/// Runs the `why` command.
pub(crate) fn run(file: &Path, package: &str, format: &str, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);

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

    let Some(pkg) = lockfile.packages.iter().find(|p| p.name == package) else {
        eprintln!("Error: package '{package}' not found in lockfile");
        std::process::exit(1);
    };

    let version = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
    let fmt = output::parse_format(format);

    if fmt == output::OutputFormat::Json {
        let chains = hlock::Graph::new(&lockfile)
            .map(|g| g.all_paths_to_roots(package, 5))
            .unwrap_or_default();
        let json = serde_json::json!({
            "package": package,
            "version": version,
            "chains": chains,
        });
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    } else if !quiet {
        println!("{}@{}", bold(package), cyan(&version));
        let chains = hlock::Graph::new(&lockfile)
            .map(|g| g.all_paths_to_roots(package, 5))
            .unwrap_or_default();
        for chain in &chains {
            let mut rev = chain.clone();
            rev.reverse();
            for (j, name) in rev.iter().enumerate() {
                let indent = "  ".repeat(j);
                println!("{}{}", indent, bold(name));
            }
            println!();
        }
    }
}
