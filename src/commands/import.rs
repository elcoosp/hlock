//! `import` command implementation.

use super::{Ctx, ImportFormat, Path, import_npm, import_yarn, serialize};

/// Runs the `import` command.
pub(crate) fn run(source: &Path, from: &str, output: Option<&Path>, registry: &str, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;

    let source_content = match std::fs::read_to_string(source) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", source.display(), e);
            std::process::exit(2);
        }
    };

    let format = match from {
        "yarn" => ImportFormat::Yarn,
        "npm" => ImportFormat::Npm,
        "pnpm" => ImportFormat::Pnpm,
        _ => {
            eprintln!("Error: unknown format '{from}'. Supported: yarn, npm, pnpm");
            std::process::exit(2);
        }
    };

    let (mut lockfile, result) = match format {
        ImportFormat::Yarn | ImportFormat::Pnpm => match import_yarn(&source_content, registry) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[{}] Import failed: {}", e.error_code(), e);
                std::process::exit(2);
            }
        },
        ImportFormat::Npm => match import_npm(&source_content, registry) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("[{}] Import failed: {}", e.error_code(), e);
                std::process::exit(2);
            }
        },
    };

    let serialized = match serialize(&mut lockfile) {
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
        if !quiet {
            eprintln!("Imported {} packages to {}", result.imported, out.display());
        }
    } else {
        print!("{serialized}");
    }

    if !quiet && output.is_none() {
        eprintln!(
            "Imported {} packages from {} ({})",
            result.imported,
            source.display(),
            result.source_format
        );
        if !result.warnings.is_empty() {
            eprintln!("Warnings:");
            for w in &result.warnings {
                eprintln!("  - {w}");
            }
        }
    }
}
