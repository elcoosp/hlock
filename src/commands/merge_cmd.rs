//! `merge` command implementation.

use super::{Ctx, Lockfile, Path, deserialize, merge, merge_lockfiles, read_input, serialize};

/// Runs the `merge` command.
pub(crate) fn run(
    base: &Path,
    ours: &Path,
    theirs: &Path,
    strategy: &str,
    output: Option<&Path>,
    ctx: Ctx,
) {
    let Ctx { quiet, .. } = ctx;

    let read_file = |path: &Path| -> Result<Lockfile, String> {
        let content =
            read_input(path).map_err(|e| format!("Error reading {}: {}", path.display(), e))?;
        deserialize(&content).map_err(|e| {
            format!(
                "[{}] Parse error in {}: {}",
                e.error_code(),
                path.display(),
                e
            )
        })
    };

    let base_lf = match read_file(base) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let ours_lf = match read_file(ours) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    let theirs_lf = match read_file(theirs) {
        Ok(lf) => lf,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };

    let strat = match strategy {
        "ours" => merge::ConflictStrategy::Ours,
        "theirs" => merge::ConflictStrategy::Theirs,
        _ => merge::ConflictStrategy::Fail,
    };

    match merge_lockfiles(&base_lf, &ours_lf, &theirs_lf, strat) {
        Ok(result) => {
            for conflict in &result.conflicts {
                eprintln!(
                    "CONFLICT: {} (base: {:?}, ours: {}.{}, theirs: {}.{})",
                    conflict.package_name,
                    conflict.base.as_ref().map(|b| b.name.clone()),
                    conflict.ours.major,
                    conflict.ours.minor,
                    conflict.theirs.major,
                    conflict.theirs.minor
                );
            }
            let mut merged = result.lockfile;
            let serialized = serialize(&mut merged).unwrap();
            if let Some(out) = output {
                if let Err(e) = std::fs::write(out, &serialized) {
                    eprintln!("Error writing {}: {}", out.display(), e);
                    std::process::exit(1);
                }
            } else if !quiet {
                print!("{serialized}");
            }
            if !result.conflicts.is_empty() && strat == merge::ConflictStrategy::Fail {
                std::process::exit(2);
            } else if !result.conflicts.is_empty() {
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("[{}] Merge error: {}", e.error_code(), e);
            std::process::exit(2);
        }
    }
}
