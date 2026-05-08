use crate::error::Error;
use crate::lockfile::{
    ArtifactDirective, DepType, HoistBoundary, Lockfile, Override, PatchDirective, Source,
    TargetArch, TargetOS, WorkspacePkg,
};
use crate::provenance::{ProvenanceSourceType, ResolutionProvenance};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileHeader {
    pub sources: Vec<Source>,
    pub overrides: Vec<Override>,
    pub features: Vec<(String, Vec<String>)>,
    pub metadata: Vec<(String, String)>,
    pub workspace_root: Option<String>,
    pub workspace_pkgs: Vec<WorkspacePkg>,
    pub hoist_boundaries: Vec<HoistBoundary>,
    pub artifacts: Vec<ArtifactDirective>,
    pub patches: Vec<PatchDirective>,
}

#[derive(Debug, Clone)]
struct IndexEntry {
    name: String,
    line_start: usize,
    line_end: usize,
}

#[derive(Debug, Clone)]
pub struct LazyLockfile {
    content: Arc<str>,
    header: LockfileHeader,
    index: Vec<IndexEntry>,
    provenance: Vec<ResolutionProvenance>,
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
}

impl LazyLockfile {
    pub fn scan(content: &str) -> Result<LazyLockfile, Error> {
        let (header, pkg_start_offset) = scan_header(content)?;

        let mut index = Vec::new();
        let mut provenance = Vec::new();
        let mut line_start = pkg_start_offset;

        for line in content[pkg_start_offset..].lines() {
            let line_end = line_start + line.len();

            if line.trim().is_empty() {
                line_start = line_end + 1;
                continue;
            }

            if line.starts_with("@artifact ") || line.starts_with("@patch ") || line.starts_with("@digest ") || line.starts_with("@signature ") {
                line_start = line_end + 1;
                continue;
            }

            if line.starts_with("@provenance ") {
                if let Ok(prov) = parse_provenance_line(line) {
                    if let Some(existing) = provenance.iter().position(|p: &ResolutionProvenance| p.package_name == prov.package_name) {
                        provenance[existing] = prov;
                    } else {
                        provenance.push(prov);
                    }
                }
                line_start = line_end + 1;
                continue;
            }

            if let Some(tab_pos) = line.find('\t') {
                let name = line[..tab_pos].to_string();

                if index.iter().any(|e: &IndexEntry| e.name == name) {
                    let line_num = content[..line_start].lines().count();
                    return Err(Error::LazyIndexCorrupt {
                        line_number: line_num,
                        reason: format!("duplicate package name: {}", name),
                    });
                }

                index.push(IndexEntry {
                    name,
                    line_start,
                    line_end,
                });
            }

            line_start = line_end + 1;
        }

        Ok(LazyLockfile {
            content: Arc::from(content),
            header,
            index,
            provenance,
        })
    }

    pub fn package_count(&self) -> usize {
        self.index.len()
    }

    pub fn package_names(&self) -> impl Iterator<Item = &str> {
        self.index.iter().map(|e| e.name.as_str())
    }

    pub fn header(&self) -> &LockfileHeader {
        &self.header
    }

    pub fn get_package(&self, name: &str) -> Result<Option<crate::lockfile::Package>, Error> {
        let pos = self.index.binary_search_by(|e| e.name.as_str().cmp(name));
        let idx = match pos {
            Ok(i) => i,
            Err(_) => return Ok(None),
        };
        let entry = &self.index[idx];
        let line = &self.content[entry.line_start..entry.line_end];
        let (_name_str, encoded) = line.split_once('\t')
            .ok_or_else(|| Error::MissingDelimiter { line_number: 0 })?;
        let binary = crate::base64url::decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidBase64 { line_number: 0 })?;
        let payload = crate::payload::unpack_payload(&binary, 0)?;

        let mut id_map: std::collections::HashMap<u64, (String, Vec<String>)> = std::collections::HashMap::new();
        for entry in &self.index {
            let line = &self.content[entry.line_start..entry.line_end];
            if let Some((_name_str, encoded)) = line.split_once('\t') {
                if let Ok(binary) = crate::base64url::decode(encoded.as_bytes()) {
                    if let Ok(pl) = crate::payload::unpack_payload(&binary, 0) {
                        let cid = crate::fnv::calculate(&format!("{}@{}.{}.{}", entry.name, pl.major, pl.minor, pl.patch));
                        id_map.insert(cid, (entry.name.clone(), pl.features.clone()));
                    }
                }
            }
        }

        let mut pkg = payload_to_package(&payload, &self.header.sources, &id_map)?;
        pkg.name = entry.name.clone();
        Ok(Some(pkg))
    }

    pub fn get_packages_by_source(&self, source_idx: usize) -> Result<Vec<crate::lockfile::Package>, Error> {
        let mut result = Vec::new();
        for entry in &self.index {
            if let Some(pkg) = self.get_package(&entry.name)? {
                if pkg.source_idx == source_idx {
                    result.push(pkg);
                }
            }
        }
        Ok(result)
    }

    pub fn get_packages_where(
        &self,
        predicate: impl Fn(&str) -> bool,
    ) -> Result<Vec<crate::lockfile::Package>, Error> {
        let mut result = Vec::new();
        for entry in &self.index {
            if predicate(&entry.name) {
                if let Some(pkg) = self.get_package(&entry.name)? {
                    result.push(pkg);
                }
            }
        }
        Ok(result)
    }

    pub fn validate_digest(&self) -> Result<(), Error> {
        crate::lockfile::validate_digest(&self.content)
    }

    pub fn into_full(self) -> Result<Lockfile, Error> {
        let mut packages = Vec::with_capacity(self.index.len());
        for entry in &self.index {
            if let Some(pkg) = self.get_package(&entry.name)? {
                packages.push(pkg);
            }
        }
        Ok(Lockfile {
            sources: self.header.sources,
            overrides: self.header.overrides,
            features: self.header.features,
            metadata: self.header.metadata,
            workspace_root: self.header.workspace_root,
            workspace_pkgs: self.header.workspace_pkgs,
            hoist_boundaries: self.header.hoist_boundaries,
            packages,
            artifacts: self.header.artifacts,
            patches: self.header.patches,
            provenance: self.provenance,
        })
    },
                        advisories: vec![],
                        licenses: vec![],
                        policies: vec![],
                        trust_roots: vec![],
                        mirrors: vec![],
                        compat: None,
}

fn payload_to_package(
    payload: &crate::payload::PayloadData,
    _sources: &[Source],
    id_map: &std::collections::HashMap<u64, (String, Vec<String>)>,
) -> Result<crate::lockfile::Package, Error> {
    use crate::lockfile::*;

    let hashes: Vec<IntegrityHash> = payload.hashes.iter().map(|h| {
        let algo = match h.algo_id { 0 => HashAlgorithm::Sha1, 1 => HashAlgorithm::Sha256, 2 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 };
        IntegrityHash { algo, digest: h.digest.clone(), attestation: h.attestation.clone() }
    }).collect();

    let mut dependencies = Vec::new();
    for dep in &payload.deps {
        let (dep_name, dep_features) = id_map.get(&dep.content_id)
            .ok_or_else(|| Error::MissingContentId {
                package: String::new(),
                content_id: dep.content_id,
            })?;
        let req_feats: Vec<String> = dep.req_feat_indices.iter()
            .map(|i| dep_features.get(*i).cloned().unwrap_or_default())
            .collect();
        let ty = match dep.dep_type {
            0 => DepType::Runtime,
            1 => DepType::Dev,
            2 => DepType::Peer,
            3 => DepType::Optional,
            4 => {
                let os = dep.target_os.map(|o| match o {
                    0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS,
                    0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android,
                    0x06 => TargetOS::IOS, _ => TargetOS::Unknown,
                }).unwrap_or(TargetOS::Any);
                let arch = dep.target_arch.map(|a| match a {
                    0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64,
                    0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x,
                    0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown,
                }).unwrap_or(TargetArch::Any);
                DepType::OptionalTarget(os, arch)
            }
            _ => DepType::Runtime,
        };
        dependencies.push(Dependency {
            name: dep_name.clone(),
            dep_type: ty,
            requested_features: req_feats,
        });
    }

    Ok(Package {
        name: String::new(),
        logical_name: payload.logical_name.clone(),
        source_idx: payload.source_idx,
        major: payload.major,
        minor: payload.minor,
        patch: payload.patch,
        hashes,
        features: payload.features.clone(),
        resolved_peers: payload.resolved_peers.clone(),
        dependencies,
        peer_requirements: payload.peer_requirements.iter().map(|r| {
            PeerRequirement { peer_name: r.peer_name.clone(), version_range: r.version_range.clone(), is_optional: r.is_optional }
        }).collect(),
        platform_tags: payload.platform_tags.iter().map(|t| {
            let os = match t.os_id {
                0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS,
                0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android,
                0x06 => TargetOS::IOS, _ => TargetOS::Unknown,
            };
            let arch = match t.arch_id {
                0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64,
                0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x,
                0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown,
            };
            PlatformTag { os, arch }
        }).collect(),
        exports: payload.exports.iter().map(|ex| {
            let algo = match ex.hash_algo {
                0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256,
                0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3,
            };
            Export { identifier: ex.identifier.clone(), hash_algo: algo, digest: ex.digest.clone() }
        }).collect(),
        artifacts: payload.artifacts.iter().map(|art| {
            let algo = match art.hash_algo {
                0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256,
                0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3,
            };
            Artifact { os_id: art.os_id, arch_id: art.arch_id, hash_algo: algo, digest: art.digest.clone() }
        }).collect(),
        hook_hashes: payload.hook_hashes.iter().map(|sh| {
            let algo = match sh.hash_algo {
                0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256,
                0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3,
            };
            HookHash { hook_type: sh.hook_type.clone(), hash_algo: algo, digest: sh.digest.clone() }
        }).collect(),
        patch_hash: payload.patch_hash.as_ref().map(|(algo, digest)| {
            let a = match algo {
                0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256,
                0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3,
            };
            (a, digest.clone())
        }),
        ..Package::default()
    })
}

fn scan_header(content: &str) -> Result<(LockfileHeader, usize), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let mut features = Vec::new();
    let mut metadata = Vec::new();
    let mut workspace_root = None;
    let mut workspace_pkgs = Vec::new();
    let mut hoist_boundaries = Vec::new();
    let artifacts = Vec::new();
    let patches = Vec::new();

    let mut offset = 0;
    for (line_num, line) in content.lines().enumerate() {
        if line.is_empty() {
            let pkg_start = offset + 1;
            return Ok((
                LockfileHeader {
                    sources, overrides, features, metadata,
                    workspace_root, workspace_pkgs, hoist_boundaries,
                    artifacts, patches,
                },
                pkg_start,
            ));
        }

        if let Some(rest) = line.strip_prefix("@source ") {
            let mut parts = rest.splitn(2, ' ');
            let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source index".to_string() })?;
            let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader { line_number: line_num, reason: "Invalid source index".to_string() })?;
            let val = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source value".to_string() })?;
            let source = classify_source(val);
            if idx != sources.len() {
                return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Source index {} is out of order", idx) });
            }
            sources.push(source);
        } else if let Some(rest) = line.strip_prefix("@override ") {
            let mut parts = rest.split(" -> ");
            let left = parts.next().unwrap_or("");
            let to_ver = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing '->' in override".to_string() })?;
            let mut left_parts = left.splitn(2, ' ');
            let name = left_parts.next().unwrap_or("").to_string();
            let from_ver = left_parts.next().unwrap_or("").to_string();
            overrides.push(Override { name, from_version: from_ver, ty: DepType::Runtime, to_version: to_ver.to_string() });
        } else if let Some(rest) = line.strip_prefix("@feature ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().unwrap_or("").to_string();
            let flags_str = parts.next().unwrap_or("").to_string();
            let flags = if flags_str.is_empty() { vec![] } else { flags_str.split(',').map(|s| s.trim().to_string()).collect() };
            features.push((name, flags));
        } else if let Some(rest) = line.strip_prefix("@workspace-root ") {
            workspace_root = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("@workspace-pkg ") {
            let (name, manifest_path) = rest.split_once(' ').unwrap_or((rest, ""));
            workspace_pkgs.push(WorkspacePkg { name: name.to_string(), manifest_path: manifest_path.to_string() });
        } else if let Some(rest) = line.strip_prefix("@hoist-boundary ") {
            let mut parts = rest.splitn(2, "->");
            let cosine = parts.next().unwrap_or("").trim().to_string();
            let deps_str = parts.next().unwrap_or("").trim();
            let deps_str = deps_str.strip_prefix("[").unwrap_or(deps_str);
            let deps_str = deps_str.strip_suffix("]").unwrap_or(deps_str);
            let allowed_deps = if deps_str.is_empty() { vec![] } else { deps_str.split(',').map(|s| s.trim().to_string()).collect() };
            hoist_boundaries.push(HoistBoundary { cosine, allowed_deps });
        } else if let Some(rest) = line.strip_prefix("@metadata ") {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            metadata.push((key.to_string(), value.to_string()));
        } else {
            return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }

        offset += line.len() + 1;
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}

fn classify_source(val: &str) -> Source {
    if val == "workspace" {
        Source::Workspace
    } else if val.starts_with("file://") || val.starts_with('/') {
        Source::Local(val.to_string())
    } else if val.starts_with("git://") || (val.starts_with("https://") && val.contains(".git")) {
        Source::Git(val.to_string())
    } else if val.starts_with("cas+http://") || val.starts_with("cas+https://") {
        Source::CasHttp(val.strip_prefix("cas+").unwrap_or(val).to_string())
    } else if val.starts_with("ipfs://") {
        Source::Ipfs(val.to_string())
    } else {
        Source::Registry(val.to_string())
    }
}

fn parse_provenance_line(line: &str) -> Result<ResolutionProvenance, Error> {
    let rest = line.strip_prefix("@provenance ").ok_or_else(|| Error::InvalidHeader {
        line_number: 0,
        reason: "missing @provenance prefix".to_string(),
    })?;
    let mut parts = rest.splitn(6, ' ');
    let pkg_name = parts.next().unwrap_or("").to_string();
    let constraint = parts.next().unwrap_or("").to_string();
    let constrained_by = parts.next().unwrap_or("").to_string();
    let dep_type_str = parts.next().unwrap_or("");
    let source_type_str = parts.next().unwrap_or("");
    let depth_str = parts.next().unwrap_or("0");

    let dep_type_id: u8 = dep_type_str.parse().map_err(|_| Error::UnknownProvenanceDepType { type_id: 255 })?;
    let dep_type = match dep_type_id {
        0 => DepType::Runtime,
        1 => DepType::Dev,
        2 => DepType::Peer,
        3 => DepType::Optional,
        4 => DepType::OptionalTarget(TargetOS::Any, TargetArch::Any),
        _ => return Err(Error::UnknownProvenanceDepType { type_id: dep_type_id }),
    };

    let source_type_id: u8 = source_type_str.parse().map_err(|_| Error::UnknownProvenanceSourceType { type_id: 255 })?;
    let source_type = match source_type_id {
        0 => ProvenanceSourceType::Registry,
        1 => ProvenanceSourceType::Local,
        2 => ProvenanceSourceType::Git,
        3 => ProvenanceSourceType::Workspace,
        4 => ProvenanceSourceType::CasHttp,
        5 => ProvenanceSourceType::Ipfs,
        _ => return Err(Error::UnknownProvenanceSourceType { type_id: source_type_id }),
    };

    let depth: u32 = depth_str.parse().unwrap_or(0);

    Ok(ResolutionProvenance {
        package_name: pkg_name,
        constraint,
        constrained_by,
        dep_type,
        source_type,
        depth,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Package, Source};

    fn simple_lockfile_content() -> String {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    ..Package::default()
                },
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 2, minor: 0, patch: 0,
                    ..Package::default()
                },
            ],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
        };
        crate::lockfile::serialize(&mut lf).unwrap()
    }

    #[test]
    fn test_lazy_scan_counts() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert_eq!(lazy.package_count(), 2);
    }

    #[test]
    fn test_lazy_scan_package_names() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let names: Vec<&str> = lazy.package_names().collect();
        assert_eq!(names, vec!["alpha", "beta"]);
    }

    #[test]
    fn test_lazy_scan_empty() {
        let content = "@source 0 https://r.com/\n\n";
        let lazy = LazyLockfile::scan(content).unwrap();
        assert_eq!(lazy.package_count(), 0);
    }

    #[test]
    fn test_lazy_header_sources() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert_eq!(lazy.header().sources.len(), 1);
    }

    #[test]
    fn test_lazy_get_existing() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let pkg = lazy.get_package("alpha").unwrap().unwrap();
        assert_eq!(pkg.name, "alpha");
        assert_eq!(pkg.major, 1);
    }

    #[test]
    fn test_lazy_get_missing() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert!(lazy.get_package("nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_lazy_get_packages_by_source() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let pkgs = lazy.get_packages_by_source(0).unwrap();
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn test_lazy_get_packages_where() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let pkgs = lazy.get_packages_where(|name| name.starts_with("alp")).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "alpha");
    }

    #[test]
    fn test_lazy_validate_digest_valid() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert!(lazy.validate_digest().is_ok());
    }

    #[test]
    fn test_lazy_into_full() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let full = lazy.into_full().unwrap();
        assert_eq!(full.packages.len(), 2);
        assert_eq!(full.packages[0].name, "alpha");
        assert_eq!(full.packages[1].name, "beta");
    }

    #[test]
    fn test_lockfile_header_construction() {
        let header = LockfileHeader {
            sources: vec![Source::Registry("https://r.com".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
        };
        assert_eq!(header.sources.len(), 1);
    }
}
