//! `info` command implementation.

use super::{Ctx, Lockfile, Path, deserialize, output, read_input, validate_digest};

/// Per-source-type package counts shown by the `info` report.
struct SourceCounts {
    registry: usize,
    git: usize,
    workspace: usize,
    local: usize,
    cas_http: usize,
    ipfs: usize,
}

/// Counts packages by the kind of source they resolve from.
fn count_by_source(lockfile: &Lockfile) -> SourceCounts {
    let mut counts = SourceCounts {
        registry: 0,
        git: 0,
        workspace: 0,
        local: 0,
        cas_http: 0,
        ipfs: 0,
    };
    for pkg in &lockfile.packages {
        if let Some(source) = lockfile.sources.get(pkg.source_idx) {
            match source {
                hlock::Source::Registry(_) => counts.registry += 1,
                hlock::Source::Git(_) => counts.git += 1,
                hlock::Source::Workspace => counts.workspace += 1,
                hlock::Source::Local(_) => counts.local += 1,
                hlock::Source::CasHttp(_) => counts.cas_http += 1,
                hlock::Source::Ipfs(_) => counts.ipfs += 1,
            }
        }
    }
    counts
}

/// Serializes one source entry with its index, URL and type.
fn source_json(idx: usize, source: &hlock::Source) -> serde_json::Value {
    let mut obj = serde_json::json!({"index": idx});
    match source {
        hlock::Source::Registry(u) => {
            obj["url"] = serde_json::Value::String(u.clone());
            obj["type"] = serde_json::Value::String("registry".to_string());
        }
        hlock::Source::Git(u) => {
            obj["url"] = serde_json::Value::String(u.clone());
            obj["type"] = serde_json::Value::String("git".to_string());
        }
        hlock::Source::Local(u) => {
            obj["url"] = serde_json::Value::String(u.clone());
            obj["type"] = serde_json::Value::String("local".to_string());
        }
        hlock::Source::Workspace => {
            obj["type"] = serde_json::Value::String("workspace".to_string());
        }
        hlock::Source::CasHttp(u) => {
            obj["url"] = serde_json::Value::String(u.clone());
            obj["type"] = serde_json::Value::String("cas-http".to_string());
        }
        hlock::Source::Ipfs(u) => {
            obj["url"] = serde_json::Value::String(u.clone());
            obj["type"] = serde_json::Value::String("ipfs".to_string());
        }
    }
    obj
}

/// Serializes the package-count-per-source map, omitting zero entries.
fn packages_by_source_json(counts: &SourceCounts) -> serde_json::Value {
    let mut pbs_map = serde_json::Map::new();
    if counts.registry > 0 {
        pbs_map.insert(
            "registry".into(),
            serde_json::Value::Number(counts.registry.into()),
        );
    }
    if counts.git > 0 {
        pbs_map.insert("git".into(), serde_json::Value::Number(counts.git.into()));
    }
    if counts.workspace > 0 {
        pbs_map.insert(
            "workspace".into(),
            serde_json::Value::Number(counts.workspace.into()),
        );
    }
    if counts.local > 0 {
        pbs_map.insert(
            "local".into(),
            serde_json::Value::Number(counts.local.into()),
        );
    }
    if counts.cas_http > 0 {
        pbs_map.insert(
            "cas_http".into(),
            serde_json::Value::Number(counts.cas_http.into()),
        );
    }
    if counts.ipfs > 0 {
        pbs_map.insert("ipfs".into(), serde_json::Value::Number(counts.ipfs.into()));
    }
    serde_json::Value::Object(pbs_map)
}

/// Renders the `info` report as pretty-printed JSON.
fn render_json(lockfile: &Lockfile, digest_valid: bool, counts: &SourceCounts, quiet: bool) {
    let sources_json: Vec<serde_json::Value> = lockfile
        .sources
        .iter()
        .enumerate()
        .map(|(idx, source)| source_json(idx, source))
        .collect();

    let policies_json: Vec<serde_json::Value> = lockfile.policies.iter().map(|p| serde_json::json!({"type": p.policy_type.as_str(), "pattern": p.package_pattern, "value": p.value})).collect();
    let trust_roots_json: Vec<serde_json::Value> = lockfile.trust_roots.iter().map(|tr| serde_json::json!({"key_id": tr.key_id, "algorithm": match tr.algorithm { hlock::signature::SignatureAlgorithm::Ed25519 => "ed25519", hlock::signature::SignatureAlgorithm::MlDsa65 => "mldsa65" }, "role": tr.role.as_str(), "expires_epoch": tr.expires_epoch})).collect();
    let overrides_json: Vec<serde_json::Value> = lockfile
        .overrides
        .iter()
        .map(|o| serde_json::json!({"name": o.name, "from": o.from_version, "to": o.to_version}))
        .collect();
    let features_json: Vec<serde_json::Value> = lockfile
        .features
        .iter()
        .map(|(n, f)| serde_json::json!({"name": n, "flags": f}))
        .collect();

    let adv_report = lockfile.audit();
    let advisory_summary = serde_json::json!({"critical": adv_report.critical.len(), "high": adv_report.high.len(), "medium": adv_report.medium.len(), "low": adv_report.low.len(), "info": adv_report.info.len()});

    let vex_json: Vec<serde_json::Value> = lockfile.vex_entries.iter().map(|v| serde_json::json!({"package": v.package, "advisory_id": v.advisory_id, "status": v.status.as_str()})).collect();

    let json = serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "package_count": lockfile.packages.len(),
        "packages_by_source": packages_by_source_json(counts),
        "sources": sources_json,
        "mirrors": lockfile.mirrors.iter().map(|m| serde_json::json!({"scope": m.scope, "url": m.url})).collect::<Vec<_>>(),
        "policy_count": lockfile.policies.len(),
        "policies": policies_json,
        "trust_roots": trust_roots_json,
        "overrides": overrides_json,
        "features": features_json,
        "advisory_summary": advisory_summary,
        "vex_entries": vex_json,
        "license_summary": {"declared": lockfile.licenses.len(), "total": lockfile.packages.len()},
        "workspace_root": lockfile.workspace_root,
        "workspace_pkgs": lockfile.workspace_pkgs.iter().map(|wp| serde_json::json!({"name": wp.name, "manifest_path": wp.manifest_path})).collect::<Vec<_>>(),
        "hoist_boundaries": lockfile.hoist_boundaries.iter().map(|hb| serde_json::json!({"consumer": hb.cosine, "allowed_deps": hb.allowed_deps})).collect::<Vec<_>>(),
        "digest_valid": digest_valid,
    });

    if !quiet {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    }
}

/// Prints the title, package summary and per-source package list.
fn print_text_summary(lockfile: &Lockfile, counts: &SourceCounts, color_enabled: bool) {
    let b = output::styler(color_enabled, output::Style::Bold);
    println!(
        "{} v{} lockfile",
        output::C {
            text: "hlock",
            on: color_enabled
        }
        .b(),
        env!("CARGO_PKG_VERSION")
    );
    println!("────────────────────────");

    let mut parts = Vec::new();
    if counts.registry > 0 {
        parts.push(format!("{} registry", counts.registry));
    }
    if counts.git > 0 {
        parts.push(format!("{} git", counts.git));
    }
    if counts.workspace > 0 {
        parts.push(format!("{} workspace", counts.workspace));
    }
    if counts.local > 0 {
        parts.push(format!("{} local", counts.local));
    }
    if counts.cas_http > 0 {
        parts.push(format!("{} cas-http", counts.cas_http));
    }
    if counts.ipfs > 0 {
        parts.push(format!("{} ipfs", counts.ipfs));
    }
    let pkg_detail = if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    };
    println!(
        "{}:       {}{}",
        b("Packages"),
        lockfile.packages.len(),
        pkg_detail
    );

    println!("{}:        {}", b("Sources"), lockfile.sources.len());
    for (idx, source) in lockfile.sources.iter().enumerate() {
        let (url, type_str) = match source {
            hlock::Source::Registry(u) => (u.as_str(), "registry"),
            hlock::Source::Git(u) => (u.as_str(), "git"),
            hlock::Source::Local(u) => (u.as_str(), "local"),
            hlock::Source::Workspace => ("", "workspace"),
            hlock::Source::CasHttp(u) => (u.as_str(), "cas-http"),
            hlock::Source::Ipfs(u) => (u.as_str(), "ipfs"),
        };
        if url.is_empty() {
            println!("  [{idx}] {type_str}");
        } else {
            println!("  [{idx}] {url} ({type_str})");
        }
    }
}

/// Prints the mirrors, policies, trust roots, overrides and features sections.
fn print_text_directives(lockfile: &Lockfile, color_enabled: bool) {
    let b = output::styler(color_enabled, output::Style::Bold);

    if !lockfile.mirrors.is_empty() {
        println!("{}:        {}", b("Mirrors"), lockfile.mirrors.len());
        for m in &lockfile.mirrors {
            println!("  {} -> {}", m.scope, m.url);
        }
    }

    if !lockfile.policies.is_empty() {
        println!("{}:       {}", b("Policies"), lockfile.policies.len());
        for p in &lockfile.policies {
            println!(
                "  {} {} {}",
                p.policy_type.as_str(),
                p.package_pattern,
                p.value
            );
        }
    }

    if !lockfile.trust_roots.is_empty() {
        println!("{}:    {}", b("Trust Roots"), lockfile.trust_roots.len());
        for tr in &lockfile.trust_roots {
            let algo_str = match tr.algorithm {
                hlock::signature::SignatureAlgorithm::Ed25519 => "ed25519",
                hlock::signature::SignatureAlgorithm::MlDsa65 => "mldsa65",
            };
            let expires_str = if tr.expires_epoch == 0 {
                "never expires".to_string()
            } else {
                format!("expires epoch {}", tr.expires_epoch)
            };
            println!(
                "  {} ({}, {}, {})",
                tr.key_id,
                algo_str,
                tr.role.as_str(),
                expires_str
            );
        }
    }

    if !lockfile.overrides.is_empty() {
        println!("{}:      {}", b("Overrides"), lockfile.overrides.len());
        for o in &lockfile.overrides {
            println!("  {} {} -> {}", b(&o.name), o.from_version, o.to_version);
        }
    }

    if !lockfile.features.is_empty() {
        println!("{}:       {}", b("Features"), lockfile.features.len());
        for (name, flags) in &lockfile.features {
            println!("  {} -> {}", b(name), flags.join(", "));
        }
    }
}

/// Prints the advisories, VEX, licenses, workspace, hoist and digest sections.
fn print_text_reports(lockfile: &Lockfile, digest_valid: bool, color_enabled: bool) {
    let b = output::styler(color_enabled, output::Style::Bold);

    let adv_report = lockfile.audit();
    if adv_report.total_count() > 0 {
        println!(
            "{}:     {} ({} critical, {} high, {} medium, {} low, {} info)",
            b("Advisories"),
            adv_report.total_count(),
            adv_report.critical.len(),
            adv_report.high.len(),
            adv_report.medium.len(),
            adv_report.low.len(),
            adv_report.info.len()
        );
        println!("  Run `hlock audit` for details.");
    }

    if !lockfile.vex_entries.is_empty() {
        println!("{}:    {}", b("VEX Entries"), lockfile.vex_entries.len());
        for v in &lockfile.vex_entries {
            println!(
                "  {} / {} -> {}",
                v.package,
                v.advisory_id,
                v.status.as_str()
            );
        }
    }

    let declared = lockfile.licenses.len();
    let total = lockfile.packages.len();
    println!("{}:       {}/{} declared", b("Licenses"), declared, total);
    if declared < total {
        println!("  Run `hlock licenses` for details.");
    }

    if let Some(ref root) = lockfile.workspace_root {
        println!("{}:      {}", b("Workspace"), root);
        for wp in &lockfile.workspace_pkgs {
            println!("  └── {} ({})", b(&wp.name), wp.manifest_path);
        }
    }

    if !lockfile.hoist_boundaries.is_empty() {
        println!(
            "{}: {}",
            b("Hoist Boundaries"),
            lockfile.hoist_boundaries.len()
        );
        for hb in &lockfile.hoist_boundaries {
            println!("  {} -> [{}]", b(&hb.cosine), hb.allowed_deps.join(", "));
        }
    }

    if digest_valid {
        println!(
            "{} Digest valid (blake3)",
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

/// Runs the `info` command.
pub(crate) fn run(file: &Path, format: &str, ctx: Ctx) {
    let Ctx {
        quiet,
        verbose,
        color_enabled,
    } = ctx;

    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };

    let digest_valid = validate_digest(&content).is_ok();

    let lockfile = match deserialize(&content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    if verbose {
        eprintln!(
            "[verbose] Parsed lockfile: {} packages, {} sources",
            lockfile.packages.len(),
            lockfile.sources.len()
        );
    }

    let counts = count_by_source(&lockfile);

    let fmt = output::parse_format(format);

    if fmt == output::OutputFormat::Json {
        render_json(&lockfile, digest_valid, &counts, quiet);
    } else if !quiet {
        print_text_summary(&lockfile, &counts, color_enabled);
        print_text_directives(&lockfile, color_enabled);
        print_text_reports(&lockfile, digest_valid, color_enabled);
    }
}
