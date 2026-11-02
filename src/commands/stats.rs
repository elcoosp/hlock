//! `stats` command implementation — one-shot lockfile metrics.

use super::{Ctx, HashMap, HashSet, Path, deserialize, output, read_input};

/// Aggregate metrics for a lockfile.
struct LockfileStats {
    total_packages: usize,
    runtime: usize,
    dev: usize,
    peer: usize,
    optional: usize,
    workspace: usize,
    duplicate_names: Vec<(String, usize)>,
    deepest_chain: usize,
    license_histogram: Vec<(String, usize)>,
    unlicensed: usize,
    advisories: HashMap<String, usize>,
    sources: usize,
    mirrors: usize,
    policies: usize,
    trust_roots: usize,
    provenance: usize,
    vex_entries: usize,
}

/// Runs the `stats` command.
///
/// With `--dedup` the command reports deduplication opportunities instead of
/// the general metrics (this replaces the 0.x `dedup` command).
pub(crate) fn run(file: &Path, dedup: bool, format: &str, ctx: Ctx) {
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

    if dedup {
        render_dedup(&lockfile, format, ctx);
        return;
    }

    let stats = compute(&lockfile);
    if output::parse_format(format) == output::OutputFormat::Json {
        if !quiet {
            println!(
                "{}",
                serde_json::to_string_pretty(&stats_json(&stats)).unwrap()
            );
        }
    } else {
        print_text(&stats, quiet);
    }
}

/// Renders deduplication opportunities in the requested format.
fn render_dedup(lockfile: &hlock::Lockfile, format: &str, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;
    let bold = output::styler(color_enabled, output::Style::Bold);
    let cyan = output::styler(color_enabled, output::Style::Cyan);
    let yellow = output::styler(color_enabled, output::Style::Yellow);

    let opportunities = lockfile.dedup_opportunities();
    if output::parse_format(format) == output::OutputFormat::Json {
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

/// Computes all metrics for `lockfile`.
fn compute(lockfile: &hlock::Lockfile) -> LockfileStats {
    let mut runtime = 0usize;
    let mut dev = 0usize;
    let mut peer = 0usize;
    let mut optional = 0usize;
    let mut name_counts: HashMap<&str, usize> = HashMap::new();

    for pkg in &lockfile.packages {
        *name_counts.entry(pkg.name.as_str()).or_insert(0) += 1;
        match has_dep_of(pkg) {
            DepKind::Runtime => runtime += 1,
            DepKind::Dev => dev += 1,
            DepKind::Peer => peer += 1,
            DepKind::Optional => optional += 1,
        }
    }
    let workspace = lockfile
        .sources
        .iter()
        .filter(|s| matches!(s, hlock::lockfile::Source::Workspace))
        .count();
    let duplicate_names = {
        let mut dups: Vec<(String, usize)> = name_counts
            .into_iter()
            .filter(|(_, c)| *c > 1)
            .map(|(n, c)| (n.to_string(), c))
            .collect();
        dups.sort();
        dups
    };

    // Deepest dependency chain via the memoized reachability closure
    // (O(V+E + V·V/64) total; 0.x ran a full BFS per package, O(V·E)).
    let deepest_chain = hlock::Graph::new(lockfile)
        .ok()
        .and_then(|g| {
            g.reachability()
                .ok()
                .map(|r| (0..g.len()).map(|i| r.closure_size(i)).max().unwrap_or(0))
        })
        .unwrap_or(0);

    let mut lic_hist: HashMap<String, usize> = HashMap::new();
    for pkg in &lockfile.packages {
        if let Some(expr) = lockfile.license_for(&pkg.name) {
            *lic_hist.entry(expr.to_string()).or_insert(0) += 1;
        }
    }
    let mut license_histogram: Vec<(String, usize)> = lic_hist.into_iter().collect();
    license_histogram.sort();
    let licensed: HashSet<&str> = lockfile
        .licenses
        .iter()
        .map(|l| l.package.as_str())
        .collect();
    let unlicensed = lockfile
        .packages
        .iter()
        .filter(|p| !licensed.contains(p.name.as_str()))
        .count();

    let mut advisories: HashMap<String, usize> = HashMap::new();
    for adv in &lockfile.advisories {
        *advisories
            .entry(adv.severity.as_str().to_string())
            .or_insert(0) += 1;
    }

    LockfileStats {
        total_packages: lockfile.packages.len(),
        runtime,
        dev,
        peer,
        optional,
        workspace,
        duplicate_names,
        deepest_chain,
        license_histogram,
        unlicensed,
        advisories,
        sources: lockfile.sources.len(),
        mirrors: lockfile.mirrors.len(),
        policies: lockfile.policies.len(),
        trust_roots: lockfile.trust_roots.len(),
        provenance: lockfile.provenance.len(),
        vex_entries: lockfile.vex_entries.len(),
    }
}

enum DepKind {
    Runtime,
    Dev,
    Peer,
    Optional,
}

/// Classifies a package by its most significant dependency role.
fn has_dep_of(pkg: &hlock::lockfile::Package) -> DepKind {
    if pkg.dependencies.iter().any(|d| {
        matches!(
            d.dep_type,
            hlock::DepType::Optional | hlock::DepType::OptionalTarget(_, _)
        )
    }) {
        DepKind::Optional
    } else if pkg
        .dependencies
        .iter()
        .any(|d| matches!(d.dep_type, hlock::DepType::Peer))
    {
        DepKind::Peer
    } else if pkg
        .dependencies
        .iter()
        .any(|d| matches!(d.dep_type, hlock::DepType::Dev))
    {
        DepKind::Dev
    } else {
        DepKind::Runtime
    }
}

/// JSON rendering of the stats.
fn stats_json(s: &LockfileStats) -> serde_json::Value {
    serde_json::json!({
        "total_packages": s.total_packages,
        "by_kind": { "runtime": s.runtime, "dev": s.dev, "peer": s.peer, "optional": s.optional },
        "workspace_sources": s.workspace,
        "duplicate_names": s.duplicate_names.iter().map(|(n, c)| serde_json::json!({"name": n, "count": c})).collect::<Vec<_>>(),
        "deepest_chain": s.deepest_chain,
        "license_histogram": s.license_histogram.iter().map(|(l, c)| serde_json::json!({"license": l, "count": c})).collect::<Vec<_>>(),
        "unlicensed_packages": s.unlicensed,
        "advisories_by_severity": s.advisories,
        "sources": s.sources,
        "mirrors": s.mirrors,
        "policies": s.policies,
        "trust_roots": s.trust_roots,
        "provenance": s.provenance,
        "vex_entries": s.vex_entries,
    })
}

/// Text rendering of the stats.
fn print_text(s: &LockfileStats, quiet: bool) {
    if quiet {
        return;
    }
    println!("Lockfile statistics");
    println!("-------------------");
    println!(
        "Packages:           {} (runtime {}, dev {}, peer {}, optional {})",
        s.total_packages, s.runtime, s.dev, s.peer, s.optional
    );
    println!("Workspace sources:  {}", s.workspace);
    println!("Deepest chain:      {} transitive deps", s.deepest_chain);
    if s.duplicate_names.is_empty() {
        println!("Duplicate names:    none");
    } else {
        println!(
            "Duplicate names:    {}",
            s.duplicate_names
                .iter()
                .map(|(n, c)| format!("{n}×{c}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    println!(
        "Licenses declared:  {} distinct, {} packages without license",
        s.license_histogram.len(),
        s.unlicensed
    );
    for (lic, count) in &s.license_histogram {
        println!("  {lic:<30}{count}");
    }
    let adv_total: usize = s.advisories.values().sum();
    println!("Advisories:         {adv_total} embedded");
    for (sev, count) in &s.advisories {
        println!("  {sev:<10}{count}");
    }
    println!(
        "Directives:         sources {}, mirrors {}, policies {}, trust-roots {}, provenance {}, vex {}",
        s.sources, s.mirrors, s.policies, s.trust_roots, s.provenance, s.vex_entries
    );
}
