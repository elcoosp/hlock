//! Outdated package checking via npm registry queries

use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub struct NpmAbbreviatedResponse {
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OutdatedInfo {
    pub package: String,
    pub current: String,
    pub latest: Option<String>,
    pub update_type: UpdateType,
    pub source_type: SourceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateType {
    Major,
    Minor,
    Patch,
}

impl std::fmt::Display for UpdateType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UpdateType::Major => write!(f, "major"),
            UpdateType::Minor => write!(f, "minor"),
            UpdateType::Patch => write!(f, "patch"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    Registry,
    Git,
    Workspace,
    Local,
    Other,
}

impl SourceType {
    pub fn from_source(source: Option<&crate::lockfile::Source>) -> Self {
        match source {
            Some(crate::lockfile::Source::Registry(_)) => SourceType::Registry,
            Some(crate::lockfile::Source::Git(_)) => SourceType::Git,
            Some(crate::lockfile::Source::Workspace) => SourceType::Workspace,
            Some(crate::lockfile::Source::Local(_)) => SourceType::Local,
            Some(crate::lockfile::Source::CasHttp(_)) => SourceType::Other,
            Some(crate::lockfile::Source::Ipfs(_)) => SourceType::Other,
            None => SourceType::Other,
        }
    }

    pub fn skip_label(&self) -> Option<&'static str> {
        match self {
            SourceType::Git => Some("git"),
            SourceType::Workspace => Some("workspace"),
            SourceType::Local => Some("local"),
            _ => None,
        }
    }
}

/// Check a single package for newer versions via the npm registry.
pub fn check_outdated(
    name: &str,
    current_version: &str,
    source_type: SourceType,
    timeout_secs: u64,
) -> Result<OutdatedInfo, String> {
    if !matches!(source_type, SourceType::Registry) {
        return Ok(OutdatedInfo {
            package: name.to_string(),
            current: current_version.to_string(),
            latest: None,
            update_type: UpdateType::Patch,
            source_type,
        });
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    let url = format!("https://registry.npmjs.org/{}/latest", name);
    let response = match client.get(&url).send() {
        Ok(r) => r,
        Err(_e) => {
            return Ok(OutdatedInfo {
                package: name.to_string(),
                current: current_version.to_string(),
                latest: None,
                update_type: UpdateType::Patch,
                source_type,
            });
        }
    };

    if !response.status().is_success() {
        return Ok(OutdatedInfo {
            package: name.to_string(),
            current: current_version.to_string(),
            latest: None,
            update_type: UpdateType::Patch,
            source_type,
        });
    }

    let abbreviated: NpmAbbreviatedResponse = response
        .json()
        .map_err(|e| format!("Failed to parse registry response for {}: {}", name, e))?;

    let latest = abbreviated.version;
    let update_type = if let Some(ref lat) = latest {
        compare_versions(current_version, lat).unwrap_or(UpdateType::Patch)
    } else {
        UpdateType::Patch
    };

    Ok(OutdatedInfo {
        package: name.to_string(),
        current: current_version.to_string(),
        latest,
        update_type,
        source_type,
    })
}

/// Compare two semver versions and return the type of update.
pub fn compare_versions(current: &str, latest: &str) -> Option<UpdateType> {
    let cur_parts: Vec<u64> = current.split('.').filter_map(|s| s.parse().ok()).collect();
    let lat_parts: Vec<u64> = latest.split('.').filter_map(|s| s.parse().ok()).collect();

    if cur_parts.len() < 3 || lat_parts.len() < 3 {
        return None;
    }

    if cur_parts == lat_parts {
        return None;
    }

    if cur_parts[0] != lat_parts[0] {
        Some(UpdateType::Major)
    } else if cur_parts[1] != lat_parts[1] {
        Some(UpdateType::Minor)
    } else {
        Some(UpdateType::Patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compare_major() {
        assert_eq!(compare_versions("1.0.0", "2.0.0"), Some(UpdateType::Major));
    }

    #[test]
    fn test_compare_minor() {
        assert_eq!(compare_versions("1.0.0", "1.1.0"), Some(UpdateType::Minor));
    }

    #[test]
    fn test_compare_patch() {
        assert_eq!(compare_versions("1.0.0", "1.0.1"), Some(UpdateType::Patch));
    }

    #[test]
    fn test_compare_equal() {
        assert_eq!(compare_versions("1.0.0", "1.0.0"), None);
    }

    #[test]
    fn test_compare_short_version() {
        assert_eq!(compare_versions("1.0", "1.0.1"), None);
    }

    #[test]
    fn test_source_type_from_source() {
        assert_eq!(SourceType::from_source(Some(&crate::lockfile::Source::Registry("r".to_string()))), SourceType::Registry);
        assert_eq!(SourceType::from_source(Some(&crate::lockfile::Source::Git("g".to_string()))), SourceType::Git);
        assert_eq!(SourceType::from_source(Some(&crate::lockfile::Source::Workspace)), SourceType::Workspace);
    }

    #[test]
    fn test_source_type_skip_label() {
        assert_eq!(SourceType::Git.skip_label(), Some("git"));
        assert_eq!(SourceType::Workspace.skip_label(), Some("workspace"));
        assert_eq!(SourceType::Registry.skip_label(), None);
    }
}
