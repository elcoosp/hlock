//! `sbom` command implementation.

use super::{Ctx, Path, deserialize, generate_sbom, read_input, sbom};

/// Runs the `sbom` command.
pub(crate) fn run(file: &Path, namespace: &str, format: &str, ctx: Ctx) {
    let Ctx { quiet, verbose, .. } = ctx;

    owo_colors::set_override(false);
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
    let fmt = match format {
        "cyclonedx-json" => sbom::SbomFormat::CycloneDxJson,
        _ => sbom::SbomFormat::SpdxJson,
    };
    match generate_sbom(&lockfile, fmt, namespace) {
        Ok(s) => {
            if !quiet {
                print!("{s}");
            }
        }
        Err(e) => {
            eprintln!("[{}] SBOM generation error: {}", e.error_code(), e);
            std::process::exit(1);
        }
    }
}
