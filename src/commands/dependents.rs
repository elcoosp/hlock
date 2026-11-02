//! `dependents` command implementation.

use super::{Ctx, Path, deserialize, output, read_input};

/// Runs the `dependents` command.
pub(crate) fn run(
    file: &Path,
    package: &str,
    transitive: bool,
    dep_type: &str,
    format: &str,
    ctx: Ctx,
) {
    let Ctx { quiet, .. } = ctx;

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

    let direct: Vec<(String, String, String)> = lockfile
        .packages
        .iter()
        .filter(|p| {
            p.dependencies.iter().any(|d| {
                d.name == package
                    && (dep_type == "all"
                        || match dep_type {
                            "runtime" => matches!(d.dep_type, hlock::DepType::Runtime),
                            "dev" => matches!(d.dep_type, hlock::DepType::Dev),
                            _ => true,
                        })
            })
        })
        .map(|p| {
            let dep = p.dependencies.iter().find(|d| d.name == package).unwrap();
            let dt = match dep.dep_type {
                hlock::DepType::Runtime => "runtime",
                hlock::DepType::Dev => "dev",
                hlock::DepType::Peer => "peer",
                hlock::DepType::Optional => "optional",
                hlock::DepType::OptionalTarget(_, _) => "optional-target",
            };
            (
                p.name.clone(),
                format!("{}.{}.{}", p.major, p.minor, p.patch),
                dt.to_string(),
            )
        })
        .collect();

    let transitive_names: Vec<String> = if transitive {
        let graph = match hlock::Graph::new(&lockfile) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("[{}] Graph error: {}", e.error_code(), e);
                std::process::exit(2);
            }
        };
        match dep_type {
            "runtime" => graph.runtime_dependents_of(package),
            "dev" => graph.dev_dependents_of(package),
            _ => graph.dependents_of(package),
        }
    } else {
        Vec::new()
    };

    let transitive_list: Vec<(String, String)> = transitive_names
        .iter()
        .filter(|name| !direct.iter().any(|(n, _, _)| n == *name))
        .filter_map(|name| {
            lockfile
                .packages
                .iter()
                .find(|p| p.name == *name)
                .map(|p| (name.clone(), format!("{}.{}.{}", p.major, p.minor, p.patch)))
        })
        .collect();

    if fmt == output::OutputFormat::Json {
        let json = serde_json::json!({
            "package": package,
            "version": version,
            "direct": direct.iter().map(|(n, v, dt)| serde_json::json!({"name": n, "version": v, "dep_type": dt})).collect::<Vec<_>>(),
            "transitive": transitive_list.iter().map(|(n, v)| serde_json::json!({"name": n, "version": v})).collect::<Vec<_>>(),
        });
        if !quiet {
            println!("{}", serde_json::to_string_pretty(&json).unwrap());
        }
    } else if !quiet {
        render_text(package, &direct, &transitive_list, transitive, ctx);
    }
}

/// Renders the direct/transitive dependents listing as human-readable text.
fn render_text(
    package: &str,
    direct: &[(String, String, String)],
    transitive_list: &[(String, String)],
    transitive: bool,
    ctx: Ctx,
) {
    let bold = output::styler(ctx.color_enabled, output::Style::Bold);
    let cyan = output::styler(ctx.color_enabled, output::Style::Cyan);
    println!("Direct dependents of {}:", bold(package));
    if direct.is_empty() {
        println!("  (none)");
    } else {
        for (name, ver, dt) in direct {
            println!("  {}@{} ({})", bold(name), cyan(ver), dt);
        }
    }
    if transitive && !transitive_list.is_empty() {
        println!();
        println!("Transitive dependents:");
        for (name, ver) in transitive_list {
            println!("  {}@{}", bold(name), cyan(ver));
        }
    }
}
