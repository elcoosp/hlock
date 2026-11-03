//! `graph` command implementation.

use super::{Ctx, Path, deserialize, parse_platform, read_input, serialize};

/// Runs the `graph` command.
pub(crate) fn run(
    file: &Path,
    root: &[String],
    platform: Option<&str>,
    output: Option<&Path>,
    dot: bool,
    ctx: Ctx,
) {
    let Ctx { quiet, verbose, .. } = ctx;

    if verbose {
        eprintln!("[verbose] Reading {}...", file.display());
    }
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

    if dot {
        let rendered = match hlock::Graph::new(&lockfile) {
            Ok(g) => g.export_dot(),
            Err(e) => {
                eprintln!("[{}] Graph error: {}", e.error_code(), e);
                std::process::exit(2);
            }
        };
        if let Some(out) = output {
            if let Err(e) = std::fs::write(out, &rendered) {
                eprintln!("Error writing {}: {}", out.display(), e);
                std::process::exit(1);
            }
        } else if !quiet {
            print!("{rendered}");
        }
        return;
    }

    let root_cids: Vec<u64> = root
        .iter()
        .filter_map(|name| {
            lockfile
                .packages
                .iter()
                .find(|p| p.name == *name)
                .map(hlock::cid::package_cid)
        })
        .collect();

    if root_cids.len() != root.len() {
        eprintln!("Some root packages not found in lockfile");
        std::process::exit(1);
    }

    let result = if let Some(plat) = platform {
        if let Some((os, arch)) = parse_platform(plat) {
            hlock::Graph::new(&lockfile)
                .and_then(|g| g.extract_subgraph_platform(&root_cids, os, arch))
        } else {
            eprintln!("Invalid platform format. Use <os>-<arch> (e.g. linux-x86_64)");
            std::process::exit(1);
        }
    } else {
        hlock::Graph::new(&lockfile).and_then(|g| g.extract_subgraph(&root_cids))
    };

    match result {
        Ok(sub) => {
            let serialized = match serialize(&sub) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[{}] Serialize error: {}", e.error_code(), e);
                    std::process::exit(1);
                }
            };
            if let Some(out) = output {
                if let Err(e) = std::fs::write(out, &serialized) {
                    eprintln!("Error writing {}: {}", out.display(), e);
                    std::process::exit(1);
                }
            } else if !quiet {
                print!("{serialized}");
            }
        }
        Err(e) => {
            eprintln!("[{}] Extraction error: {}", e.error_code(), e);
            std::process::exit(1);
        }
    }
}
