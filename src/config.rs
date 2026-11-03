//! Configuration file support (.hlockrc / config.toml)

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
#[serde(deny_unknown_fields)]
pub struct HlockConfig {
    pub audit: AuditConfig,
    pub lint: LintConfig,
    pub verify: VerifyConfig,
    pub licenses: LicensesConfig,
    pub outdated: OutdatedConfig,
    pub import: ImportConfig,
    pub policy: PolicyConfig,
    pub output: OutputConfig,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    pub online: bool,
    pub severity: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
#[serde(deny_unknown_fields)]
pub struct LintConfig {
    pub rules: Vec<String>,
    pub exclude_rules: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
#[serde(deny_unknown_fields)]
pub struct VerifyConfig {
    pub trusted_keys: Vec<String>,
    #[serde(default)]
    pub sigstore: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
#[serde(deny_unknown_fields)]
pub struct LicensesConfig {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub strict: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct OutdatedConfig {
    pub check_major: bool,
    pub timeout: u64,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct ImportConfig {
    pub default_registry: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[derive(Default)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    pub deny_hooks: Vec<String>,
    pub build_env: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
#[serde(deny_unknown_fields)]
pub struct OutputConfig {
    pub color: String,
    pub format: String,
    pub quiet: bool,
    pub verbose: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            online: false,
            severity: "error".to_string(),
        }
    }
}

impl Default for OutdatedConfig {
    fn default() -> Self {
        Self {
            check_major: false,
            timeout: 30,
        }
    }
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self {
            default_registry: "https://registry.npmjs.org/".to_string(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            color: "auto".to_string(),
            format: "text".to_string(),
            quiet: false,
            verbose: false,
        }
    }
}

impl HlockConfig {
    #[must_use]
    pub fn load(cli_config_path: Option<&Path>) -> Self {
        if let Some(path) = cli_config_path
            && let Some(config) = Self::load_from_file(path)
        {
            return config;
        }

        if let Some(config) = Self::load_from_file(Path::new(".hlockrc")) {
            return config;
        }

        if let Some(config) = Self::find_project_config() {
            return config;
        }

        if let Some(config) = Self::load_xdg_config() {
            return config;
        }

        Self::default()
    }

    fn load_from_file(path: &Path) -> Option<Self> {
        let content = std::fs::read_to_string(path).ok()?;
        toml::from_str(&content).ok()
    }

    fn find_project_config() -> Option<Self> {
        let mut dir = std::env::current_dir().ok()?;
        loop {
            let config_path = dir.join(".hlockrc");
            if config_path.exists()
                && let Some(config) = Self::load_from_file(&config_path)
            {
                return Some(config);
            }
            if dir.join(".git").exists() {
                break;
            }
            if !dir.pop() {
                break;
            }
        }
        None
    }

    fn load_xdg_config() -> Option<Self> {
        let xdg_dir = if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg)
        } else if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(".config")
        } else {
            return None;
        };
        let path = xdg_dir.join("hlock").join("config.toml");
        Self::load_from_file(&path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HlockConfig::default();
        assert!(!config.audit.online);
        assert_eq!(config.audit.severity, "error");
        assert_eq!(config.outdated.timeout, 30);
        assert_eq!(
            config.import.default_registry,
            "https://registry.npmjs.org/"
        );
        assert_eq!(config.output.color, "auto");
    }

    #[test]
    fn test_parse_toml() {
        let toml = r#"
[audit]
online = true
severity = "medium"

[outdated]
check_major = true
timeout = 60

[output]
color = "never"
"#;
        let config: HlockConfig = toml::from_str(toml).unwrap();
        assert!(config.audit.online);
        assert_eq!(config.audit.severity, "medium");
        assert!(config.outdated.check_major);
        assert_eq!(config.outdated.timeout, 60);
        assert_eq!(config.output.color, "never");
    }

    #[test]
    fn test_parse_empty_toml() {
        let config: HlockConfig = toml::from_str("").unwrap();
        assert!(!config.audit.online);
    }

    fn temp_config_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("hlock_config_tests");
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    #[test]
    fn test_load_explicit_file_wins() {
        let path = temp_config_path("explicit.toml");
        std::fs::write(
            &path,
            "[audit]\nonline = true\nseverity = \"low\"\n[outdated]\ntimeout = 5\n",
        )
        .unwrap();
        let config = HlockConfig::load(Some(&path));
        assert!(config.audit.online);
        assert_eq!(config.audit.severity, "low");
        assert_eq!(config.outdated.timeout, 5);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_load_missing_explicit_file_falls_back_to_defaults() {
        let missing = temp_config_path("does-not-exist-9f11.toml");
        let config = HlockConfig::load(Some(&missing));
        // Whatever fallback path is taken, the config must stay well-formed.
        assert_eq!(config.outdated.timeout, 30);
        assert_eq!(config.output.format, "text");
    }

    #[test]
    fn test_load_from_file_rejects_invalid_toml() {
        let path = temp_config_path("broken.toml");
        std::fs::write(&path, "[[[not valid toml").unwrap();
        // Invalid TOML must be ignored rather than panicking.
        let _config = HlockConfig::load(Some(&path));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_deserialize_partial_sections_fill_defaults() {
        let config: HlockConfig = toml::from_str("[licenses]\nstrict = true\n").unwrap();
        assert!(config.licenses.strict);
        assert_eq!(config.licenses.allow.len(), 0);
        assert!(!config.audit.online);
        assert_eq!(
            config.import.default_registry,
            "https://registry.npmjs.org/"
        );
        assert_eq!(config.output.color, "auto");
    }

    #[test]
    fn test_deserialize_all_sections() {
        let toml = r#"
[lint]
rules = ["no-sha1"]
exclude_rules = ["max-depth"]

[verify]
trusted_keys = ["ci:ed25519:ab"]
sigstore = true

[licenses]
allow = ["MIT"]
deny = ["GPL-3.0"]
strict = false

[policy]
deny_hooks = ["preinstall"]
build_env = "ci"

[import]
default_registry = "https://mirror.example/"

[output]
quiet = true
verbose = false
format = "json"
"#;
        let config: HlockConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.lint.rules, vec!["no-sha1".to_string()]);
        assert_eq!(config.lint.exclude_rules, vec!["max-depth".to_string()]);
        assert_eq!(config.verify.trusted_keys.len(), 1);
        assert!(config.verify.sigstore);
        assert!(config.licenses.allow.contains(&"MIT".to_string()));
        assert!(config.licenses.deny.contains(&"GPL-3.0".to_string()));
        assert!(!config.licenses.strict);
        assert_eq!(config.policy.deny_hooks, vec!["preinstall".to_string()]);
        assert_eq!(config.policy.build_env, "ci");
        assert_eq!(config.import.default_registry, "https://mirror.example/");
        assert!(config.output.quiet);
        assert!(!config.output.verbose);
        assert_eq!(config.output.format, "json");
    }
}
