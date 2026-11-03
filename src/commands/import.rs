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

    if format == ImportFormat::Pnpm {
        // A pnpm-lock.yaml fed to the yarn parser yields silently wrong
        // versions; a security gate refuses rather than guesses.
        eprintln!(
            "Error: pnpm import is not supported yet (the yarn parser produces wrong versions); convert with 'pnpm import' to npm first"
        );
        std::process::exit(2);
    }
    let (lockfile, result) = match format {
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

    let serialized = match serialize(&lockfile) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[{}] Serialize error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    if let Some(out) = output {
        if let Err(e) = super::atomic_write(out, &serialized) {
            eprintln!("Error writing {}: {}", out.display(), e);
            std::process::exit(1);
        }
        if !quiet {
            eprintln!("Imported {} packages to {}", result.imported, out.display());
        }
    } else {
        print!("{serialized}");
    }

    // Warnings (dropped entries, odd sources) always reach stderr — they are
    // part of the security inventory even when the lockfile goes to a file.
    if !quiet {
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
