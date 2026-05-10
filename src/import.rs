//! Import lockfiles from other formats (yarn.lock, package-lock.json)

use crate::error::Error;
use crate::lockfile::{
    Attestation, HashAlgorithm, IntegrityHash, Lockfile, Package, Source,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportFormat {
    Yarn,
    Npm,
    Pnpm,
}

impl std::fmt::Display for ImportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImportFormat::Yarn => write!(f, "yarn"),
            ImportFormat::Npm => write!(f, "npm"),
            ImportFormat::Pnpm => write!(f, "pnpm"),
        }
    }
}

#[derive(Debug, Default)]
pub struct ImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub warnings: Vec<String>,
    pub source_format: String,
    pub source_file: String,
}

/// Parse a yarn.lock v1 file into hlock Lockfile.
pub fn import_yarn(content: &str, default_registry: &str) -> Result<(Lockfile, ImportResult), Error> {
    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut sources = vec![Source::Registry(default_registry.to_string())];
    let mut current_key = String::new();
    let mut current_version = String::new();
    let mut current_resolved = String::new();
    let mut current_integrity = String::new();
    let mut in_entry = false;

    for line in content.lines() {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("__metadata:") {
            continue;
        }

        if !trimmed.starts_with(' ') && !trimmed.starts_with('\t') && trimmed.ends_with(':') {
            if in_entry && !current_key.is_empty() {
                if let Some(pkg) = build_package_from_yarn(
                    &current_key,
                    &current_version,
                    &current_resolved,
                    &current_integrity,
                    &mut sources,
                    &mut warnings,
                ) {
                    packages.push(pkg);
                }
            }

            current_key = trimmed.trim_end_matches(':').to_string();
            current_key = current_key.trim_matches('"').to_string();
            current_version.clear();
            current_resolved.clear();
            current_integrity.clear();
            in_entry = true;
            continue;
        }

        if !in_entry {
            continue;
        }

        if let Some(rest) = trimmed.strip_prefix("version ") {
            current_version = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("version") {
            current_version = rest.trim().trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("resolved ") {
            current_resolved = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("resolved") {
            current_resolved = rest.trim().trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("integrity ") {
            current_integrity = rest.trim_matches('"').to_string();
        } else if let Some(rest) = trimmed.strip_prefix("integrity") {
            current_integrity = rest.trim().trim_matches('"').to_string();
        }
    }

    if in_entry && !current_key.is_empty() {
        if let Some(pkg) = build_package_from_yarn(
            &current_key,
            &current_version,
            &current_resolved,
            &current_integrity,
            &mut sources,
            &mut warnings,
        ) {
            packages.push(pkg);
        }
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let imported = packages.len();
    let result = ImportResult {
        imported,
        skipped: 0,
        warnings,
        source_format: "yarn-v1".to_string(),
        source_file: String::new(),
    };

    Ok((
        Lockfile {
            sources,
            packages,
            ..Lockfile::default()
        },
        result,
    ))
}

fn build_package_from_yarn(
    key: &str,
    version: &str,
    resolved: &str,
    integrity: &str,
    sources: &mut Vec<Source>,
    warnings: &mut Vec<String>,
) -> Option<Package> {
    let name = extract_name_from_yarn_key(key);
    if name.is_empty() || version.is_empty() {
        return None;
    }

    let ver_parts: Vec<u64> = version.split('.').filter_map(|s| s.parse().ok()).collect();
    let (major, minor, patch) = match ver_parts.as_slice() {
        [maj, min, pat] => (*maj, *min, *pat),
        [maj, min] => (*maj, *min, 0),
        [maj] => (*maj, 0, 0),
        _ => return None,
    };

    let source_idx = if resolved.starts_with("git+") || resolved.starts_with("git://") {
        let idx = sources.len();
        sources.push(Source::Git(resolved.to_string()));
        warnings.push(format!("{}: git dependency, included as-is", name));
        idx
    } else {
        0
    };

    let hashes = parse_integrity(integrity);

    Some(Package {
        name,
        source_idx,
        major,
        minor,
        patch,
        hashes,
        ..Package::default()
    })
}

fn extract_name_from_yarn_key(key: &str) -> String {
    let key = key.trim_matches('"');
    let at_count = key.chars().filter(|&c| c == '@').count();

    if key.starts_with('@') && at_count >= 2 {
        let second_at = key[1..].find('@').map(|i| i + 1).unwrap_or(key.len());
        key[..second_at].to_string()
    } else if let Some(at_pos) = key.find('@') {
        key[..at_pos].to_string()
    } else {
        key.to_string()
    }
}

fn parse_integrity(integrity: &str) -> Vec<IntegrityHash> {
    if integrity.is_empty() {
        return vec![];
    }

    let parts: Vec<&str> = integrity.splitn(2, '-').collect();
    if parts.len() != 2 {
        return vec![];
    }

    let algo = match parts[0] {
        "sha1" => HashAlgorithm::Sha1,
        "sha256" => HashAlgorithm::Sha256,
        "sha512" => HashAlgorithm::Sha512,
        _ => return vec![],
    };

    let digest = crate::base64url::decode(parts[1].as_bytes())
        .unwrap_or_else(|_| parts[1].as_bytes().to_vec());

    vec![IntegrityHash {
        algo,
        digest,
        attestation: Attestation::None,
    }]
}

/// Parse a package-lock.json file into hlock Lockfile.
pub fn import_npm(content: &str, default_registry: &str) -> Result<(Lockfile, ImportResult), Error> {
    let json: serde_json::Value = serde_json::from_str(content).map_err(|e| Error::ImportFailed {
        format: "npm".to_string(),
        reason: format!("Invalid JSON: {}", e),
    })?;

    let mut packages = Vec::new();
    let mut warnings = Vec::new();
    let mut sources = vec![Source::Registry(default_registry.to_string())];

    let packages_obj = if let Some(p) = json.get("packages").and_then(|p| p.as_object()) {
        p
    } else if let Some(d) = json.get("dependencies").and_then(|d| d.as_object()) {
        d
    } else {
        return Err(Error::ImportFailed {
            format: "npm".to_string(),
            reason: "No 'packages' or 'dependencies' key found".to_string(),
        });
    };

    for (path, value) in packages_obj {
        let obj = match value.as_object() {
            Some(o) => o,
            None => continue,
        };

        let name = path
            .trim_start_matches("node_modules/")
            .trim_start_matches("node_modules\\")
            .to_string();

        if name.is_empty() || name == "." || path.is_empty() {
            continue;
        }

        let version = obj.get("version").and_then(|v| v.as_str()).unwrap_or("");
        if version.is_empty() {
            continue;
        }

        let ver_parts: Vec<u64> = version.split('.').filter_map(|s| s.parse().ok()).collect();
        let (major, minor, patch) = match ver_parts.as_slice() {
            [maj, min, pat] => (*maj, *min, *pat),
            [maj, min] => (*maj, *min, 0),
            [maj] => (*maj, 0, 0),
            _ => continue,
        };

        let resolved = obj.get("resolved").and_then(|v| v.as_str()).unwrap_or("");
        let integrity = obj.get("integrity").and_then(|v| v.as_str()).unwrap_or("");

        let source_idx = if resolved.starts_with("git+") || resolved.starts_with("git://") {
            let idx = sources.len();
            sources.push(Source::Git(resolved.to_string()));
            warnings.push(format!("{}: git dependency, included as-is", name));
            idx
        } else {
            0
        };

        let hashes = parse_integrity(integrity);

        packages.push(Package {
            name,
            source_idx,
            major,
            minor,
            patch,
            hashes,
            ..Package::default()
        });
    }

    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let imported = packages.len();
    let result = ImportResult {
        imported,
        skipped: 0,
        warnings,
        source_format: "npm".to_string(),
        source_file: String::new(),
    };

    Ok((
        Lockfile {
            sources,
            packages,
            ..Lockfile::default()
        },
        result,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_name_from_yarn_key_simple() {
        assert_eq!(extract_name_from_yarn_key("lodash@^4.17.0"), "lodash");
    }

    #[test]
    fn test_extract_name_from_yarn_key_scoped() {
        assert_eq!(extract_name_from_yarn_key("@babel/core@^7.0.0"), "@babel/core");
    }

    #[test]
    fn test_extract_name_from_yarn_key_no_version() {
        assert_eq!(extract_name_from_yarn_key("lodash"), "lodash");
    }

    #[test]
    fn test_parse_integrity_sha512() {
        let hashes = parse_integrity("sha512-abc123");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algo, HashAlgorithm::Sha512);
    }

    #[test]
    fn test_parse_integrity_sha256() {
        let hashes = parse_integrity("sha256-abc123");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algo, HashAlgorithm::Sha256);
    }

    #[test]
    fn test_parse_integrity_sha1() {
        let hashes = parse_integrity("sha1-abc123");
        assert_eq!(hashes.len(), 1);
        assert_eq!(hashes[0].algo, HashAlgorithm::Sha1);
    }

    #[test]
    fn test_parse_integrity_empty() {
        let hashes = parse_integrity("");
        assert!(hashes.is_empty());
    }

    #[test]
    fn test_import_npm_basic() {
        let content = r#"{
            "name": "test",
            "version": "1.0.0",
            "lockfileVersion": 3,
            "packages": {
                "node_modules/lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LqbZVGltjneNN6gqNMdvA=="
                },
                "node_modules/react": {
                    "version": "18.3.1",
                    "resolved": "https://registry.npmjs.org/react/-/react-18.3.1.tgz",
                    "integrity": "sha512-glPovid8eU4VjXGhj5CwsFjk8g9Vclj1eF4mqE5iTJm5C8bVFcCUkZmrcELQD4l4M7T3eH0hPm9j8O3e1e3w=="
                }
            }
        }"#;
        let (lockfile, result) = import_npm(content, "https://registry.npmjs.org/").unwrap();
        assert_eq!(result.imported, 2);
        assert_eq!(lockfile.packages.len(), 2);
        let names: Vec<&str> = lockfile.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"lodash"));
        assert!(names.contains(&"react"));
    }

    #[test]
    fn test_import_npm_git_dependency() {
        let content = r#"{
            "packages": {
                "node_modules/evil": {
                    "version": "1.0.0",
                    "resolved": "git+https://github.com/evil/pkg.git#abc123"
                }
            }
        }"#;
        let (lockfile, result) = import_npm(content, "https://registry.npmjs.org/").unwrap();
        assert_eq!(result.imported, 1);
        assert_eq!(lockfile.sources.len(), 2);
        assert!(matches!(lockfile.sources[1], Source::Git(_)));
    }
}
