//! Performance budget bench (spec §10).
//!
//! Generates a synthetic 5 000-package / ~20 000-edge lockfile and times the
//! hot operations of v1.0. No individual operation may exceed 250 ms on a
//! regular CI runner; run with:
//!
//! ```text
//! cargo run --release --example bench
//! ```
//!
//! The table is for regression eyeballing between commits.

use hlock::{Dependency, Graph, Lockfile, Package, Source, deserialize, serialize};
use std::time::Instant;

/// Builds a synthetic lockfile: `n` packages, each depending on the previous
/// 4 (plus a few cross edges) → ~4n edges.
fn synthetic_lockfile(n: usize) -> Lockfile {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        ..Lockfile::default()
    };
    lockfile.packages.reserve(n);
    for i in 0..n {
        let mut deps = Vec::with_capacity(4);
        for d in 1..=4 {
            let target = i.checked_sub(d).unwrap_or(i ^ d);
            if target != i {
                deps.push(Dependency {
                    name: format!("pkg-{target:06}"),
                    dep_type: hlock::DepType::Runtime,
                    requested_features: vec![],
                });
            }
        }
        lockfile.packages.push(Package {
            name: format!("pkg-{i:06}"),
            logical_name: None,
            source_idx: 0,
            major: 1,
            minor: (i % 100) as u64,
            patch: (i % 97) as u64,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            dependencies: deps,
            ..Package::default()
        });
    }
    lockfile
}

/// Formats one row of the results table.
fn row(name: &str, elapsed: std::time::Duration, budget: std::time::Duration) {
    let ms = elapsed.as_secs_f64() * 1000.0;
    let status = if elapsed <= budget {
        "ok"
    } else {
        "OVER BUDGET"
    };
    println!(
        "{:<22}{:>10.2} ms   {:>6} ms   {}",
        name,
        ms,
        budget.as_millis(),
        status
    );
}

fn main() {
    println!("hlock v1.0 perf bench");
    println!("=====================");
    println!();

    let n = 5_000;
    let lockfile = synthetic_lockfile(n);
    let edges: usize = lockfile.packages.iter().map(|p| p.dependencies.len()).sum();
    println!("lockfile: {n} packages, {edges} edges");
    println!();
    println!(
        "{:<22}{:>13}   {:>9}   status",
        "operation", "measured", "budget"
    );
    println!("{}", "-".repeat(64));

    let budget_250 = std::time::Duration::from_millis(250);
    let budget_100 = std::time::Duration::from_millis(100);

    // serialize
    let t = Instant::now();
    let serialized = serialize(&lockfile).expect("serialize");
    row("serialize", t.elapsed(), budget_250);

    // deserialize
    let t = Instant::now();
    let parsed = deserialize(&serialized).expect("deserialize");
    row("deserialize", t.elapsed(), budget_250);

    // Graph::new (CSR build)
    let t = Instant::now();
    let graph = Graph::new(&parsed).expect("graph");
    row("graph::new (CSR)", t.elapsed(), budget_100);

    // extract_subgraph from the deepest root
    let root_cid = hlock::cid::package_cid(&parsed.packages[n - 1]);
    let t = Instant::now();
    let sub = graph.extract_subgraph(&[root_cid]).expect("extract");
    row("extract_subgraph", t.elapsed(), budget_100);
    drop(sub);

    // reachability + deepest chain (stats hot path)
    let t = Instant::now();
    let reach = graph.reachability().expect("reachability");
    let deepest = (0..graph.len())
        .map(|i| reach.closure_size(i))
        .max()
        .unwrap_or(0);
    row("reachability (stats)", t.elapsed(), budget_250);
    drop(reach);
    println!();
    println!("deepest chain: {deepest}");

    // SBOM
    let t = Instant::now();
    let _ = hlock::generate_sbom(
        &parsed,
        hlock::SbomFormat::SpdxJson,
        "https://bench.local/ns",
    )
    .expect("sbom");
    row("sbom (spdx-json)", t.elapsed(), budget_250);

    // Lazy get_package
    let lazy = hlock::LazyLockfile::scan(&serialized).expect("lazy");
    let t = Instant::now();
    let mut touched = 0usize;
    for i in 0..n {
        let name = format!("pkg-{i:06}");
        if lazy.get_package(&name).is_ok_and(|p| p.is_some()) {
            touched += 1;
        }
    }
    row("lazy_get_package ×n", t.elapsed(), budget_250);
    drop(lazy);
    println!();
    println!("lazy touched {touched}/{n} packages");

    println!();
    println!("All operations at or under budget = perf gate green.");
}
