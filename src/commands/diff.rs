//! `diff` command implementation.

use super::{Ctx, Path, deserialize, diff_lockfiles, lockfile, read_input, serialize_diff};

/// Runs the `diff` command.
pub(crate) fn run(old_file: &Path, new_file: &Path, format: &str, ctx: Ctx) {
    let Ctx { quiet, verbose, .. } = ctx;

    if verbose {
        eprintln!(
            "[verbose] Reading {} and {}...",
            old_file.display(),
            new_file.display()
        );
    }
    let old_content = match read_input(old_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", old_file.display(), e);
            std::process::exit(2);
        }
    };
    let new_content = match read_input(new_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", new_file.display(), e);
            std::process::exit(2);
        }
    };
    let old_lf = match deserialize(&old_content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error in old file: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };
    let new_lf = match deserialize(&new_content) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("[{}] Parse error in new file: {}", e.error_code(), e);
            std::process::exit(2);
        }
    };

    let diff = diff_lockfiles(&old_lf, &new_lf);
    if verbose {
        eprintln!(
            "[verbose] Diff: {} changes, {} unchanged",
            diff.changes.len(),
            diff.unchanged_count
        );
    }
    let fmt = match format {
        "json" => {
            owo_colors::set_override(false);
            lockfile::DiffFormat::Json
        }
        _ => lockfile::DiffFormat::Text,
    };
    if !quiet {
        print!("{}", serialize_diff(&diff, &fmt));
    }
}
