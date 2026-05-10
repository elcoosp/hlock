//! Configuration file support (.hlockrc / config.toml)

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
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
pub struct AuditConfig {
    pub online: bool,
    pub severity: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct LintConfig {
    pub rules: Vec<String>,
    pub exclude_rules: Vec<String>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct VerifyConfig {
    pub trusted_keys: Vec<String>,
    #[serde(default)]
    pub sigstore: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct LicensesConfig {
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub strict: bool,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct OutdatedConfig {
    pub check_major: bool,
    pub timeout: u64,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct ImportConfig {
    pub default_registry: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct PolicyConfig {
    pub deny_hooks: Vec<String>,
    pub build_env: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(default)]
pub struct OutputConfig {
    pub color: String,
    pub format: String,
    pub quiet: bool,
    pub verbose: bool,
}

impl Default for HlockConfig {
    fn default() -> Self {
        Self {
            audit: AuditConfig::default(),
            lint: LintConfig::default(),
            verify: VerifyConfig::default(),
            licenses: LicensesConfig::default(),
            outdated: OutdatedConfig::default(),
            import: ImportConfig::default(),
            policy: PolicyConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self { online: false, severity: "error".to_string() }
    }
}

impl Default for LintConfig {
    fn default() -> Self {
        Self { rules: vec![], exclude_rules: vec![] }
    }
}

impl Default for VerifyConfig {
    fn default() -> Self {
        Self { trusted_keys: vec![], sigstore: false }
    }
}

impl Default for LicensesConfig {
    fn default() -> Self {
        Self { allow: vec![], deny: vec![], strict: false }
    }
}

impl Default for OutdatedConfig {
    fn default() -> Self {
        Self { check_major: false, timeout: 30 }
    }
}

impl Default for ImportConfig {
    fn default() -> Self {
        Self { default_registry: "https://registry.npmjs.org/".to_string() }
    }
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self { deny_hooks: vec![], build_env: String::new() }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self { color: "auto".to_string(), format: "text".to_string(), quiet: false, verbose: false }
    }
}

impl HlockConfig {
    pub fn load(cli_config_path: Option<&Path>) -> Self {
        if let Some(path) = cli_config_path {
            if let Some(config) = Self::load_from_file(path) {
                return config;
            }
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
            if config_path.exists() {
                if let Some(config) = Self::load_from_file(&config_path) {
                    return Some(config);
                }
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
        assert_eq!(config.import.default_registry, "https://registry.npmjs.org/");
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
}
