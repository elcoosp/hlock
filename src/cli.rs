use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "hlock", version, about = "Supply-chain lockfile integrity tool")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(short, long, global = true, help = "Suppress non-error output")]
    pub quiet: bool,

    #[arg(short, long, global = true, help = "Show extra diagnostic information")]
    pub verbose: bool,

    #[arg(long, global = true, help = "Disable colored output")]
    pub no_color: bool,

    #[arg(long, default_value = "auto", global = true, help = "When to colorize: auto, always, never")]
    pub color: String,
}

#[derive(Subcommand)]
pub enum Commands {
    Verify {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        pub trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0)]
        pub time: u64,
    },
    Lint {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long)]
        pub rule: Vec<String>,
        #[arg(long, default_value = "error")]
        pub severity: String,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Diff {
        #[arg(value_name = "OLD_FILE")]
        pub old_file: PathBuf,
        #[arg(value_name = "NEW_FILE")]
        pub new_file: PathBuf,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Audit {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Sbom {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long)]
        pub namespace: String,
        #[arg(long, default_value = "spdx-json")]
        pub format: String,
    },
    Sign {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long)]
        pub key_id: String,
        #[arg(long, default_value = "ed25519")]
        pub algorithm: String,
        #[arg(long)]
        pub private_key: String,
        #[arg(long, default_value_t = 0)]
        pub expires: u64,
        #[arg(long)]
        pub in_place: bool,
    },
    Graph {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long)]
        pub root: Vec<String>,
        #[arg(long)]
        pub platform: Option<String>,
        #[arg(long)]
        pub output: Option<PathBuf>,
    },
    Merge {
        #[arg(long)]
        pub base: PathBuf,
        #[arg(long)]
        pub ours: PathBuf,
        #[arg(long)]
        pub theirs: PathBuf,
        #[arg(long, default_value = "fail")]
        pub strategy: String,
        #[arg(long)]
        pub output: Option<PathBuf>,
    },
    Completions {
        #[arg(value_name = "SHELL")]
        pub shell: String,
    },
    Info {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Dedup {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Why {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        pub package: String,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Deps {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        pub package: String,
        #[arg(long)]
        pub transitive: bool,
        #[arg(long, default_value = "all")]
        pub dep_type: String,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Dependents {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(value_name = "PACKAGE")]
        pub package: String,
        #[arg(long)]
        pub transitive: bool,
        #[arg(long, default_value = "all")]
        pub dep_type: String,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Check {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, value_name = "KEY_ID:ALGO:HEX")]
        pub trusted_key: Vec<String>,
        #[arg(long, default_value_t = 0)]
        pub time: u64,
        #[arg(long, default_value = "error")]
        pub severity: String,
        #[arg(long)]
        pub rule: Vec<String>,
        #[arg(long)]
        pub vex: bool,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Tree {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long, required = true)]
        pub root: Vec<String>,
        #[arg(long)]
        pub depth: Option<u32>,
        #[arg(long, default_value = "all")]
        pub dep_type: String,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
    Licenses {
        #[arg(value_name = "FILE")]
        pub file: PathBuf,
        #[arg(long)]
        pub missing: bool,
        #[arg(long)]
        pub allow: Option<String>,
        #[arg(long)]
        pub deny: Option<String>,
        #[arg(long)]
        pub strict: bool,
        #[arg(long, default_value = "text")]
        pub format: String,
    },
}
