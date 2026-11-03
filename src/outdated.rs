//! Outdated package checking via npm registry queries.
//!
//! v1.0.1 hardening:
//! - **Network failures no longer masquerade as "up to date"** (spec §7):
//!   connection errors and non-2xx responses return `Err`; the CLI renders
//!   them as an explicit `unknown` bucket instead of a clean report;
//! - one **shared, pooled HTTP client** with per-request timeouts (one TLS
//!   handshake per process, not per package);
//! - package names are **percent-encoded** into the registry path, so a
//!   hostile name cannot rewrite the request URL;
//! - `compare_versions` understands semver prerelease ordering (a release
//!   is always newer than its own `-beta.1`).
use serde::Deserialize;
use std::sync::OnceLock;

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
    #[must_use]
    pub fn from_source(source: Option<&crate::lockfile::Source>) -> Self {
        match source {
            Some(crate::lockfile::Source::Registry(_)) => SourceType::Registry,
            Some(crate::lockfile::Source::Git(_)) => SourceType::Git,
            Some(crate::lockfile::Source::Workspace) => SourceType::Workspace,
            Some(crate::lockfile::Source::Local(_)) => SourceType::Local,
            Some(crate::lockfile::Source::CasHttp(_) | crate::lockfile::Source::Ipfs(_)) | None => {
                SourceType::Other
            }
        }
    }

    #[must_use]
    pub fn skip_label(&self) -> Option<&'static str> {
        match self {
            SourceType::Git => Some("git"),
            SourceType::Workspace => Some("workspace"),
            SourceType::Local => Some("local"),
            _ => None,
        }
    }
}

/// The shared pooled HTTP client. One TLS config, one connection pool for
/// the whole process; timeouts are attached per request.
fn shared_client() -> Result<&'static reqwest::blocking::Client, String> {
    static CLIENT: OnceLock<Option<reqwest::blocking::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::limited(3))
                .build()
                .ok()
        })
        .as_ref()
        .ok_or_else(|| "Failed to create HTTP client".to_string())
}

/// Percent-encodes a package name for the registry URL path.
///
/// Scoped names keep their separators encoded (`@scope/pkg` becomes
/// `@scope%2Fpkg`, the canonical abbreviated-document form), so `/`, `?`,
/// `#` or `..` in a name can never rewrite the request path.
#[must_use]
pub fn registry_path_segment(name: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(name.len());
    for &b in name.as_bytes() {
        match b {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'@' => {
                out.push(b);
            }
            _ => {
                out.push(b'%');
                out.push(HEX[usize::from(b >> 4)]);
                out.push(HEX[usize::from(b & 0x0F)]);
            }
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

///
/// # Errors
///
/// Returns `Err` with a human-readable reason when the package cannot be
/// checked (network failure, non-2xx registry response, bad payload).
/// Non-registry sources are skipped without touching the network and return
/// `Ok` with `latest: None`.
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

    let client = shared_client()?;
    let url = format!(
        "https://registry.npmjs.org/{}/latest",
        registry_path_segment(name)
    );
    let response = client
        .get(&url)
        .timeout(std::time::Duration::from_secs(timeout_secs.max(1)))
        .send()
        .map_err(|e| format!("{name}: request failed: {e}"))?;

    let status = response.status();
    if !status.is_success() {
        return Err(format!("{name}: registry returned HTTP {status}"));
    }

    let abbreviated: NpmAbbreviatedResponse = response
        .json()
        .map_err(|e| format!("{name}: failed to parse registry response: {e}"))?;

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
///
/// Prerelease ordering is respected: `2.0.0-beta.1 < 2.0.0`, so a package on
/// a beta is reported as outdated by the release. Unparseable inputs return
/// `None` (caller decides the fallback).
#[must_use]
pub fn compare_versions(current: &str, latest: &str) -> Option<UpdateType> {
    let (cur_core, cur_pre) = split_prerelease(current);
    let (lat_core, lat_pre) = split_prerelease(latest);
    let cur_parts = parse_triple(cur_core)?;
    let lat_parts = parse_triple(lat_core)?;

    if cur_parts == lat_parts {
        return match (cur_pre, lat_pre) {
            (true, false) => Some(UpdateType::Patch), // release beats its own prerelease
            _ => None,
        };
    }

    if cur_parts[0] != lat_parts[0] {
        Some(UpdateType::Major)
    } else if cur_parts[1] != lat_parts[1] {
        Some(UpdateType::Minor)
    } else {
        Some(UpdateType::Patch)
    }
}

/// Splits `1.2.3-beta.1` into `("1.2.3", true)` and `1.2.3` into `("1.2.3", false)`.
fn split_prerelease(v: &str) -> (&str, bool) {
    match v.split_once('-') {
        Some((core, pre)) if !pre.is_empty() => (core, true),
        _ => (v, false),
    }
}

fn parse_triple(core: &str) -> Option<[u64; 3]> {
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next()?.parse().ok()?;
    let c = it.next()?.parse().ok()?;
    Some([a, b, c])
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
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::Registry("r".to_string()))),
            SourceType::Registry
        );
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::Git("g".to_string()))),
            SourceType::Git
        );
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::Workspace)),
            SourceType::Workspace
        );
    }

    #[test]
    fn test_source_type_from_all_source_kinds() {
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::Local("./v".to_string()))),
            SourceType::Local
        );
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::CasHttp(
                "https://c".to_string()
            ))),
            SourceType::Other
        );
        assert_eq!(
            SourceType::from_source(Some(&crate::lockfile::Source::Ipfs("ipfs://x".to_string()))),
            SourceType::Other
        );
        assert_eq!(SourceType::from_source(None), SourceType::Other);
    }

    #[test]
    fn test_source_type_skip_label_all_kinds() {
        assert_eq!(SourceType::Git.skip_label(), Some("git"));
        assert_eq!(SourceType::Workspace.skip_label(), Some("workspace"));
        assert_eq!(SourceType::Local.skip_label(), Some("local"));
        assert_eq!(SourceType::Registry.skip_label(), None);
        assert_eq!(SourceType::Other.skip_label(), None);
    }

    #[test]
    fn test_check_outdated_skips_non_registry_sources_without_network() {
        for source in [
            SourceType::Git,
            SourceType::Workspace,
            SourceType::Local,
            SourceType::Other,
        ] {
            let info = check_outdated("pkg", "1.2.3", source, 1).unwrap();
            assert_eq!(info.package, "pkg");
            assert_eq!(info.current, "1.2.3");
            assert_eq!(
                info.latest, None,
                "non-registry sources never hit the network"
            );
            assert_eq!(info.update_type, UpdateType::Patch);
            assert_eq!(info.source_type, source);
        }
    }

    #[test]
    fn test_update_type_display() {
        assert_eq!(UpdateType::Major.to_string(), "major");
        assert_eq!(UpdateType::Minor.to_string(), "minor");
        assert_eq!(UpdateType::Patch.to_string(), "patch");
    }

    #[test]
    fn test_compare_versions_handles_prerelease_suffixes() {
        assert_eq!(
            compare_versions("1.0.0-rc.1", "1.1.0"),
            Some(UpdateType::Minor)
        );
        // Two-part latest is rejected outright.
        assert_eq!(compare_versions("1.0.0", "2.0"), None);
        // Non-numeric junk drops below three parts.
        assert_eq!(compare_versions("x.y.z", "1.0.0"), None);
    }

    #[test]
    fn test_compare_prerelease_release_ordering() {
        // A release is newer than its own prerelease.
        assert_eq!(
            compare_versions("2.0.0-beta.1", "2.0.0"),
            Some(UpdateType::Patch)
        );
        // Staying on the same prerelease is not an update.
        assert_eq!(compare_versions("2.0.0-beta.1", "2.0.0-beta.1"), None);
    }

    #[test]
    fn test_registry_path_segment_encodes_metacharacters() {
        assert_eq!(registry_path_segment("lodash"), "lodash");
        assert_eq!(registry_path_segment("@scope/pkg"), "@scope%2Fpkg");
        assert_eq!(registry_path_segment("a?b#c"), "a%3Fb%23c");
        assert_eq!(registry_path_segment("../etc"), "..%2Fetc");
    }
}
