//! `completions` command implementation.

use super::{Cli, Ctx};
use clap::CommandFactory as _;
use clap_complete::{Shell, generate};

/// Runs the `completions` command.
pub(crate) fn run(shell: &str, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;
    let shell_type = match shell {
        "bash" => Shell::Bash,
        "zsh" => Shell::Zsh,
        "fish" => Shell::Fish,
        "elvish" => Shell::Elvish,
        "powershell" => Shell::PowerShell,
        _ => {
            eprintln!(
                "Error: unknown shell '{shell}'. Supported: bash, zsh, fish, elvish, powershell"
            );
            std::process::exit(2);
        }
    };
    let mut cmd = Cli::command();
    let name = "hlock";
    if !quiet {
        generate(shell_type, &mut cmd, name, &mut std::io::stdout());
    }
}
