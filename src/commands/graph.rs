//! `graph` command implementation.

use super::{
    Ctx, Path, deserialize, extract_subgraph, extract_subgraph_platform, fnv, parse_platform,
    read_input, serialize,
};

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
        let rendered = hlock::graph::export_dot(&lockfile);
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

    let root_cids: Vec<u64> =
        root.iter()
            .filter_map(|name| {
                lockfile.packages.iter().find(|p| p.name == *name).map(|p| {
                    fnv::calculate(&format!("{}@{}.{}.{}", p.name, p.major, p.minor, p.patch))
                })
            })
            .collect();

    if root_cids.len() != root.len() {
        eprintln!("Some root packages not found in lockfile");
        std::process::exit(1);
    }

    let result = if let Some(plat) = platform {
        if let Some((os, arch)) = parse_platform(plat) {
            extract_subgraph_platform(&lockfile, &root_cids, os, arch)
        } else {
            eprintln!("Invalid platform format. Use <os>-<arch> (e.g. linux-x86_64)");
            std::process::exit(1);
        }
    } else {
        extract_subgraph(&lockfile, &root_cids)
    };

    match result {
        Ok(mut sub) => {
            let serialized = serialize(&mut sub).unwrap();
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
