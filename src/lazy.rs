use crate::error::Error;
use crate::lockfile::Lockfile;
use crate::lockfile::types::{
    ArtifactDirective, DepType, HoistBoundary, Override, Package, PatchDirective, Source,
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
    pub policies: Vec<crate::policy::Policy>,
    pub trust_roots: Vec<crate::policy::TrustRoot>,
    pub mirrors: Vec<crate::lockfile::Mirror>,
    pub root_rotations: Vec<crate::lockfile::TrustRootRotation>,
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
}

impl LazyLockfile {
    /// Scans a lockfile's header and builds a lazy, line-based index of its packages
    /// without decoding any package payloads up front.
    ///
    /// # Errors
    /// Returns [`Error::InvalidHeader`] when `content` does not start with a valid
    /// lockfile header (propagated from the header parser), and
    /// [`Error::LazyIndexCorrupt`] when two package lines carry the same name.
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

            if line.starts_with("@artifact ")
                || line.starts_with("@patch ")
                || line.starts_with("@digest ")
                || line.starts_with("@signature ")
            {
                line_start = line_end + 1;
                continue;
            }

            if line.starts_with("@provenance ") {
                if let Ok(prov) = parse_provenance_line(line) {
                    if let Some(existing) = provenance
                        .iter()
                        .position(|p: &ResolutionProvenance| p.package_name == prov.package_name)
                    {
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
                        reason: format!("duplicate package name: {name}"),
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

    #[must_use]
    pub fn package_count(&self) -> usize {
        self.index.len()
    }

    pub fn package_names(&self) -> impl Iterator<Item = &str> {
        self.index.iter().map(|e| e.name.as_str())
    }

    #[must_use]
    pub fn header(&self) -> &LockfileHeader {
        &self.header
    }

    /// Decodes and returns the package with the given name, or `None` when the
    /// name is not present in the index.
    ///
    /// # Errors
    /// Returns [`Error::MissingDelimiter`] or [`Error::InvalidBase64`] when the
    /// package's line is not a well-formed payload line, any payload-decoding
    /// error (e.g. [`Error::UnknownPayloadVersion`], [`Error::UnknownDepType`],
    /// [`Error::PayloadDigestMismatch`]) when its payload is malformed, and
    /// [`Error::MissingContentId`] when a dependency references a content ID that
    /// no indexed package provides.
    pub fn get_package(&self, name: &str) -> Result<Option<Package>, Error> {
        let Ok(idx) = self.index.binary_search_by(|e| e.name.as_str().cmp(name)) else {
            return Ok(None);
        };
        let entry = &self.index[idx];
        let line = &self.content[entry.line_start..entry.line_end];
        let (_name_str, encoded) = line
            .split_once('\t')
            .ok_or(Error::MissingDelimiter { line_number: 0 })?;
        let binary = crate::base64url::decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidBase64 { line_number: 0 })?;
        let payload = crate::payload::unpack_payload(&binary, 0)?;

        let mut id_map: std::collections::HashMap<u64, (String, Vec<String>)> =
            std::collections::HashMap::new();
        for entry in &self.index {
            let line = &self.content[entry.line_start..entry.line_end];
            if let Some((_name_str, encoded)) = line.split_once('\t')
                && let Ok(binary) = crate::base64url::decode(encoded.as_bytes())
                && let Ok(pl) = crate::payload::unpack_payload(&binary, 0)
            {
                let cid = crate::fnv::calculate(&format!(
                    "{}@{}.{}.{}",
                    entry.name, pl.major, pl.minor, pl.patch
                ));
                id_map.insert(cid, (entry.name.clone(), pl.features.clone()));
            }
        }

        let mut pkg = payload_to_package(&payload, &self.header.sources, &id_map)?;
        pkg.name.clone_from(&entry.name);
        Ok(Some(pkg))
    }

    /// Returns every indexed package whose source index matches `source_idx`.
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::get_package`] while decoding the
    /// matching packages.
    pub fn get_packages_by_source(&self, source_idx: usize) -> Result<Vec<Package>, Error> {
        let mut result = Vec::new();
        for entry in &self.index {
            if let Some(pkg) = self.get_package(&entry.name)?
                && pkg.source_idx == source_idx
            {
                result.push(pkg);
            }
        }
        Ok(result)
    }

    /// Returns every indexed package whose name satisfies `predicate`.
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::get_package`] while decoding the
    /// matching packages.
    pub fn get_packages_where(
        &self,
        predicate: impl Fn(&str) -> bool,
    ) -> Result<Vec<Package>, Error> {
        let mut result = Vec::new();
        for entry in &self.index {
            if predicate(&entry.name)
                && let Some(pkg) = self.get_package(&entry.name)?
            {
                result.push(pkg);
            }
        }
        Ok(result)
    }

    /// Validates the `@digest` directive covering the whole lockfile content.
    ///
    /// # Errors
    /// Returns [`Error::DuplicateDigestDirective`] when more than one `@digest`
    /// directive is present, and [`Error::DigestMismatch`] when the directive is
    /// malformed or does not match the recomputed BLAKE3 hash of the content.
    pub fn validate_digest(&self) -> Result<(), Error> {
        crate::lockfile::digest::validate_digest(&self.content)
    }

    /// Eagerly decodes every indexed package into a full in-memory [`Lockfile`].
    ///
    /// # Errors
    /// Propagates any error returned by [`Self::get_package`] while decoding the
    /// indexed packages.
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
            advisories: vec![],
            licenses: vec![],
            policies: self.header.policies,
            trust_roots: self.header.trust_roots,
            mirrors: self.header.mirrors,
            root_rotations: self.header.root_rotations,
            vex_entries: vec![],
            compat: None,
        })
    }
}

fn payload_to_package(
    payload: &crate::payload::PayloadData,
    _sources: &[Source],
    id_map: &std::collections::HashMap<u64, (String, Vec<String>)>,
) -> Result<Package, Error> {
    Ok(Package {
        name: String::new(),
        logical_name: payload.logical_name.clone(),
        source_idx: payload.source_idx,
        major: payload.major,
        minor: payload.minor,
        patch: payload.patch,
        hashes: crate::lockfile::build_integrity_hashes(&payload.hashes),
        features: payload.features.clone(),
        resolved_peers: payload.resolved_peers.clone(),
        dependencies: crate::lockfile::build_dependencies("", payload, id_map)?,
        peer_requirements: crate::lockfile::build_peer_requirements(&payload.peer_requirements),
        platform_tags: crate::lockfile::build_platform_tags(&payload.platform_tags),
        exports: crate::lockfile::build_exports(&payload.exports),
        artifacts: crate::lockfile::build_artifacts(&payload.artifacts),
        hook_hashes: crate::lockfile::build_hook_hashes(&payload.hook_hashes),
        patch_hash: crate::lockfile::build_patch_hash(payload.patch_hash.as_ref()),
    })
}

fn scan_header(content: &str) -> Result<(LockfileHeader, usize), Error> {
    let (lockfile, remaining) = crate::lockfile::header::parse_header(content)?;

    let header_end = content.len() - remaining.len();
    let pkg_start = header_end;

    let header = LockfileHeader {
        sources: lockfile.sources,
        overrides: lockfile.overrides,
        features: lockfile.features,
        metadata: lockfile.metadata,
        workspace_root: lockfile.workspace_root,
        workspace_pkgs: lockfile.workspace_pkgs,
        hoist_boundaries: lockfile.hoist_boundaries,
        artifacts: lockfile.artifacts,
        patches: lockfile.patches,
        policies: lockfile.policies,
        trust_roots: lockfile.trust_roots,
        mirrors: lockfile.mirrors,
        root_rotations: lockfile.root_rotations,
    };

    Ok((header, pkg_start))
}

fn parse_provenance_line(line: &str) -> Result<ResolutionProvenance, Error> {
    let rest = line
        .strip_prefix("@provenance ")
        .ok_or_else(|| Error::InvalidHeader {
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

    let dep_type_id: u8 = dep_type_str
        .parse()
        .map_err(|_| Error::UnknownProvenanceDepType { type_id: 255 })?;
    let dep_type = match dep_type_id {
        0 => DepType::Runtime,
        1 => DepType::Dev,
        2 => DepType::Peer,
        3 => DepType::Optional,
        4 => DepType::OptionalTarget(TargetOS::Any, TargetArch::Any),
        _ => {
            return Err(Error::UnknownProvenanceDepType {
                type_id: dep_type_id,
            });
        }
    };

    let source_type_id: u8 = source_type_str
        .parse()
        .map_err(|_| Error::UnknownProvenanceSourceType { type_id: 255 })?;
    let source_type = match source_type_id {
        0 => ProvenanceSourceType::Registry,
        1 => ProvenanceSourceType::Local,
        2 => ProvenanceSourceType::Git,
        3 => ProvenanceSourceType::Workspace,
        4 => ProvenanceSourceType::CasHttp,
        5 => ProvenanceSourceType::Ipfs,
        _ => {
            return Err(Error::UnknownProvenanceSourceType {
                type_id: source_type_id,
            });
        }
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
    use crate::lockfile::types::{Lockfile, Package, Source};

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
                    major: 1,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 2,
                    minor: 0,
                    patch: 0,
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
            root_rotations: vec![],
            vex_entries: vec![],
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
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
        };
        assert_eq!(header.sources.len(), 1);
    }

    #[test]
    fn test_lazy_scan_matches_deserialize_header() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let full = crate::lockfile::deserialize(&content).unwrap();

        assert_eq!(lazy.header().sources.len(), full.sources.len());
        for (i, (ls, fs)) in lazy
            .header()
            .sources
            .iter()
            .zip(full.sources.iter())
            .enumerate()
        {
            assert_eq!(ls, fs, "source mismatch at index {i}");
        }
        assert_eq!(lazy.header().mirrors.len(), full.mirrors.len());
        assert_eq!(lazy.header().policies.len(), full.policies.len());
        assert_eq!(lazy.header().trust_roots.len(), full.trust_roots.len());
        assert_eq!(lazy.header().overrides.len(), full.overrides.len());
        assert_eq!(lazy.header().features.len(), full.features.len());
        assert_eq!(lazy.header().metadata.len(), full.metadata.len());
        assert_eq!(lazy.header().workspace_root, full.workspace_root);
        assert_eq!(
            lazy.header().workspace_pkgs.len(),
            full.workspace_pkgs.len()
        );
        assert_eq!(
            lazy.header().hoist_boundaries.len(),
            full.hoist_boundaries.len()
        );
        assert_eq!(lazy.header().artifacts.len(), full.artifacts.len());
        assert_eq!(lazy.header().patches.len(), full.patches.len());
        assert_eq!(
            lazy.header().root_rotations.len(),
            full.root_rotations.len()
        );
    }

    fn lockfile_with_provenance_and_directives() -> String {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 2,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };
        let mut content = crate::lockfile::serialize(&mut lf).unwrap();
        // Append extra provenance lines before the trailing @digest and fix the digest.
        content = content.replace(
            "@digest ",
            "@provenance alpha ^1.0.0 app 0 0 0\n@provenance beta ^2.0.0 app 4 3 1\n@digest ",
        );
        let mut parsed = crate::lockfile::deserialize(&content).unwrap();
        crate::lockfile::serialize(&mut parsed).unwrap()
    }

    #[test]
    fn test_lazy_scan_indexes_provenance_lines() {
        let content = lockfile_with_provenance_and_directives();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert_eq!(lazy.package_count(), 2);
        let full = lazy.into_full().unwrap();
        assert_eq!(full.provenance.len(), 2);
        let alpha = full
            .provenance
            .iter()
            .find(|p| p.package_name == "alpha")
            .unwrap();
        assert_eq!(alpha.constraint, "^1.0.0");
        assert_eq!(
            alpha.source_type,
            crate::provenance::ProvenanceSourceType::Registry
        );
        let beta = full
            .provenance
            .iter()
            .find(|p| p.package_name == "beta")
            .unwrap();
        assert_eq!(
            beta.dep_type,
            DepType::OptionalTarget(TargetOS::Any, TargetArch::Any)
        );
        assert_eq!(beta.depth, 1);
    }

    #[test]
    fn test_lazy_scan_replaces_duplicate_provenance() {
        let base = simple_lockfile_content();
        let doubled = base.replace(
            "@digest ",
            "@provenance alpha ^1 one 1 2 5\n@provenance alpha ^2 two 2 2 6\n@digest ",
        );
        let lazy = LazyLockfile::scan(&doubled).unwrap();
        let full = lazy.into_full().unwrap();
        assert_eq!(
            full.provenance.len(),
            1,
            "later @provenance wins: {:?}",
            full.provenance
        );
        assert_eq!(full.provenance[0].constraint, "^2");
    }

    #[test]
    fn test_lazy_scan_rejects_duplicate_package_names() {
        let content = "@source 0 https://r.com/\n\nalpha\tAAAA\nalpha\tBBBB\n";
        let err = LazyLockfile::scan(content).unwrap_err();
        match err {
            Error::LazyIndexCorrupt {
                line_number,
                reason,
            } => {
                assert!(reason.contains("alpha"), "reason: {reason}");
                assert!(
                    line_number >= 2,
                    "line number should point at the duplicate: {line_number}"
                );
            }
            other => panic!("expected LazyIndexCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn test_lazy_scan_ignores_directive_lines_after_header() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        // @digest / @signature / @artifact / @patch lines must not become packages.
        assert_eq!(lazy.package_count(), 2);
    }

    #[test]
    fn test_lazy_scan_bad_header_propagates() {
        let err = LazyLockfile::scan("not a header\n\npkg\tAAAA\n").unwrap_err();
        assert!(matches!(err, Error::InvalidHeader { .. }));
    }

    #[test]
    fn test_lazy_get_missing_package_is_none() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert!(lazy.get_package("nope").unwrap().is_none());
    }

    #[test]
    fn test_lazy_get_packages_by_source() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let from_zero = lazy.get_packages_by_source(0).unwrap();
        assert_eq!(from_zero.len(), 2);
        let from_one = lazy.get_packages_by_source(1).unwrap();
        assert_eq!(from_one.len(), 0);
    }

    #[test]
    fn test_lazy_get_packages_where_predicate() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let betas = lazy.get_packages_where(|n| n.starts_with('b')).unwrap();
        assert_eq!(betas.len(), 1);
        assert_eq!(betas[0].name, "beta");
        let none = lazy.get_packages_where(|_| false).unwrap();
        assert_eq!(none.len(), 0);
    }

    #[test]
    fn test_lazy_validate_digest_detects_tampering() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        assert!(lazy.validate_digest().is_ok());
        let tampered = LazyLockfile::scan(&content.replace("beta", "gama")).unwrap();
        assert!(matches!(
            tampered.validate_digest(),
            Err(Error::DigestMismatch { .. })
        ));
    }

    #[test]
    fn test_lazy_into_full_preserves_header_fields() {
        let content = simple_lockfile_content();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let full = lazy.into_full().unwrap();
        assert_eq!(full.packages.len(), 2);
        assert_eq!(full.packages[0].name, "alpha");
        assert_eq!(
            full.sources,
            vec![Source::Registry("https://r.com/".to_string())]
        );
        assert_eq!(full.advisories.len(), 0);
        assert_eq!(full.vex_entries.len(), 0);
        assert_eq!(full.licenses.len(), 0);
        assert!(full.compat.is_none());
    }

    #[test]
    fn test_lazy_get_package_decodes_dependencies_and_features() {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![
                Package {
                    name: "lib".to_string(),
                    source_idx: 0,
                    major: 1,
                    minor: 2,
                    patch: 3,
                    features: vec!["serde".to_string()],
                    hashes: vec![crate::lockfile::IntegrityHash {
                        algo: crate::lockfile::HashAlgorithm::Sha256,
                        digest: vec![1, 2, 3],
                        attestation: crate::lockfile::Attestation::None,
                    }],
                    hook_hashes: vec![crate::lockfile::HookHash {
                        hook_type: "postinstall".to_string(),
                        hash_algo: crate::lockfile::HashAlgorithm::Sha512,
                        digest: vec![4, 5],
                    }],
                    exports: vec![crate::lockfile::Export {
                        identifier: "main".to_string(),
                        hash_algo: crate::lockfile::HashAlgorithm::Blake3,
                        digest: vec![6, 7],
                    }],
                    artifacts: vec![crate::lockfile::Artifact {
                        os_id: 1,
                        arch_id: 2,
                        hash_algo: crate::lockfile::HashAlgorithm::Sha1,
                        digest: vec![8],
                    }],
                    platform_tags: vec![crate::lockfile::PlatformTag {
                        os: TargetOS::Linux,
                        arch: TargetArch::Aarch64,
                    }],
                    peer_requirements: vec![crate::lockfile::PeerRequirement {
                        peer_name: "react".to_string(),
                        version_range: "^18".to_string(),
                        is_optional: true,
                    }],
                    patch_hash: Some((crate::lockfile::HashAlgorithm::Sha512, vec![9; 32])),
                    ..Package::default()
                },
                Package {
                    name: "app".to_string(),
                    source_idx: 0,
                    major: 3,
                    features: vec!["serde".to_string()],
                    dependencies: vec![crate::lockfile::Dependency {
                        name: "lib".to_string(),
                        dep_type: DepType::OptionalTarget(TargetOS::Windows, TargetArch::S390x),
                        requested_features: vec!["serde".to_string()],
                    }],
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };
        let content = crate::lockfile::serialize(&mut lf).unwrap();
        let lazy = LazyLockfile::scan(&content).unwrap();
        let app = lazy.get_package("app").unwrap().unwrap();
        assert_eq!(app.dependencies.len(), 1);
        assert_eq!(app.dependencies[0].name, "lib");
        assert_eq!(
            app.dependencies[0].dep_type,
            DepType::OptionalTarget(TargetOS::Windows, TargetArch::S390x)
        );
        assert_eq!(
            app.dependencies[0].requested_features,
            vec!["serde".to_string()]
        );
        let lib = lazy.get_package("lib").unwrap().unwrap();
        assert_eq!(lib.features, vec!["serde".to_string()]);
        assert_eq!(lib.hashes[0].algo, crate::lockfile::HashAlgorithm::Sha256);
        assert_eq!(lib.hook_hashes[0].hook_type, "postinstall");
        assert_eq!(lib.exports[0].identifier, "main");
        assert_eq!(lib.artifacts[0].os_id, 1);
        assert_eq!(lib.platform_tags[0].os, TargetOS::Linux);
        assert_eq!(lib.peer_requirements[0].peer_name, "react");
        assert_eq!(
            lib.patch_hash,
            Some((crate::lockfile::HashAlgorithm::Sha512, vec![9; 32]))
        );
    }

    #[test]
    fn test_lazy_get_package_reports_missing_dependency() {
        // Rename the dependency's line after serialization: its content id no
        // longer matches any indexed package, so decoding the consumer fails.
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![
                Package {
                    name: "lib".to_string(),
                    source_idx: 0,
                    major: 1,
                    minor: 2,
                    patch: 3,
                    ..Package::default()
                },
                Package {
                    name: "app".to_string(),
                    source_idx: 0,
                    major: 4,
                    dependencies: vec![crate::lockfile::Dependency {
                        name: "lib".to_string(),
                        dep_type: DepType::Runtime,
                        requested_features: vec![],
                    }],
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };
        let content = crate::lockfile::serialize(&mut lf).unwrap();
        let renamed = content.replace("\nlib\t", "\ngone\t");
        assert_ne!(content, renamed, "the lib package line must be renamed");
        let lazy = LazyLockfile::scan(&renamed).unwrap();
        let err = lazy.get_package("app").unwrap_err();
        match err {
            Error::MissingContentId { package, .. } => assert_eq!(package, ""),
            other => panic!("expected MissingContentId, got {other:?}"),
        }
    }

    #[test]
    fn test_lazy_get_package_invalid_base64() {
        let content = "@source 0 https://r.com/\n\napp\t!!!not-base64!!!\n";
        let lazy = LazyLockfile::scan(content).unwrap();
        let err = lazy.get_package("app").unwrap_err();
        assert!(matches!(err, Error::InvalidBase64 { .. }), "got: {err:?}");
    }
}
