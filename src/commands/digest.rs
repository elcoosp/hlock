//! `digest` command implementation — prints or checks the whole-lockfile digest.

use super::{Ctx, Path, output, read_input};

/// Runs the `digest` command.
pub(crate) fn run(file: &Path, check: bool, ctx: Ctx) {
    let Ctx {
        quiet,
        color_enabled,
        ..
    } = ctx;

    let content = match read_input(file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error reading {}: {}", file.display(), e);
            std::process::exit(2);
        }
    };

    let digest_hex = hlock::lockfile::digest::digest_hex(&content);

    if !check {
        if !quiet {
            println!("{digest_hex}");
        }
        return;
    }

    match hlock::validate_digest(&content) {
        Ok(()) => {
            if !quiet {
                println!(
                    "{} {digest_hex} digest OK",
                    output::C {
                        text: "✓",
                        on: color_enabled
                    }
                    .gb()
                );
            }
        }
        Err(e) => {
            eprintln!(
                "{} {digest_hex} digest MISMATCH: {e}",
                output::C {
                    text: "✗",
                    on: color_enabled
                }
                .rb()
            );
            std::process::exit(1);
        }
    }
}
