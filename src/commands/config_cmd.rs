//! `config` command implementation — print the resolved configuration.
//!
//! The precedence is: CLI flags > `--config <file>` > `.hlockrc` (walked up
//! from the working directory) > `~/.config/hlock/config.toml` > defaults.
//! An invalid TOML or an explicit `--config` path that does not exist is a
//! hard `E0901`/`E0902` config error.

use super::{Ctx, HlockConfig, output};

/// Runs the `config` command: prints the resolved configuration as TOML or JSON.
pub(crate) fn run(config: &HlockConfig, source: &str, format: &str, ctx: Ctx) {
    let Ctx { quiet, .. } = ctx;
    if quiet {
        return;
    }

    let json = serde_json::json!({
        "schema": "hlock/v1",
        "command": "config",
        "ok": true,
        "data": {
            "source": source,
            "config": {
                "audit": {
                    "online": config.audit.online,
                    "severity": config.audit.severity,
                },
                "lint": {
                    "rules": config.lint.rules,
                    "exclude_rules": config.lint.exclude_rules,
                },
                "verify": {
                    "trusted_keys": config.verify.trusted_keys,
                    "sigstore": config.verify.sigstore,
                },
                "licenses": {
                    "allow": config.licenses.allow,
                    "deny": config.licenses.deny,
                    "strict": config.licenses.strict,
                },
                "outdated": {
                    "check_major": config.outdated.check_major,
                    "timeout": config.outdated.timeout,
                },
                "policy": {
                    "deny_hooks": config.policy.deny_hooks,
                    "build_env": config.policy.build_env,
                },
                "import": {
                    "default_registry": config.import.default_registry,
                },
                "output": {
                    "color": config.output.color,
                    "format": config.output.format,
                    "quiet": config.output.quiet,
                    "verbose": config.output.verbose,
                },
            },
        },
        "error": serde_json::Value::Null,
    });

    if output::parse_format(format) == output::OutputFormat::Json {
        println!("{}", serde_json::to_string_pretty(&json).unwrap());
    } else {
        println!("# resolved configuration (source: {source})");
        println!("[audit]");
        println!("online = {}", config.audit.online);
        println!("severity = {:?}", config.audit.severity);
        println!();
        println!("[lint]");
        println!("rules = {:?}", config.lint.rules);
        println!("exclude_rules = {:?}", config.lint.exclude_rules);
        println!();
        println!("[verify]");
        println!("trusted_keys = {:?}", config.verify.trusted_keys);
        println!("sigstore = {}", config.verify.sigstore);
        println!();
        println!("[licenses]");
        println!("allow = {:?}", config.licenses.allow);
        println!("deny = {:?}", config.licenses.deny);
        println!("strict = {}", config.licenses.strict);
        println!();
        println!("[outdated]");
        println!("check_major = {}", config.outdated.check_major);
        println!("timeout = {}", config.outdated.timeout);
        println!();
        println!("[policy]");
        println!("deny_hooks = {:?}", config.policy.deny_hooks);
        println!("build_env = {:?}", config.policy.build_env);
        println!();
        println!("[import]");
        println!("default_registry = {:?}", config.import.default_registry);
        println!();
        println!("[output]");
        println!("color = {:?}", config.output.color);
        println!("format = {:?}", config.output.format);
        println!("quiet = {}", config.output.quiet);
        println!("verbose = {}", config.output.verbose);
    }
}
