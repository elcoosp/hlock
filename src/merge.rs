use crate::error::Error;
use crate::lockfile::{Lockfile, Override, Package, Source};
use crate::provenance::ResolutionProvenance;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergeConflict {
    pub package_name: String,
    pub base: Option<Package>,
    pub ours: Package,
    pub theirs: Package,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictStrategy {
    Ours,
    Theirs,
    Fail,
}

#[derive(Debug, Clone)]
pub struct MergeResult {
    pub lockfile: Lockfile,
    pub conflicts: Vec<MergeConflict>,
}

pub fn merge_lockfiles(
    base: &Lockfile,
    ours: &Lockfile,
    theirs: &Lockfile,
    strategy: ConflictStrategy,
) -> Result<MergeResult, Error> {
    let mut conflicts: Vec<MergeConflict> = Vec::new();

    let (merged_sources, ours_source_map, theirs_source_map) = merge_sources(base, ours, theirs)?;

    let (merged_packages, pkg_conflicts) = merge_packages(
        base, ours, theirs,
        &ours_source_map, &theirs_source_map,
        strategy,
    );
    conflicts.extend(pkg_conflicts);

    let merged_overrides = merge_overrides(base, ours, theirs);

    let merged_features = merge_features(base, ours, theirs);

    let merged_metadata = merge_metadata(base, ours, theirs);

    let merged_workspace_root = ours.workspace_root.clone().or(theirs.workspace_root.clone());

    let merged_workspace_pkgs = merge_workspace_pkgs(ours, theirs);

    let merged_hoist_boundaries = merge_hoist_boundaries(base, ours, theirs);

    let merged_artifacts = merge_artifacts(base, ours, theirs);

    let merged_patches = merge_patches(base, ours, theirs);

    let merged_pkg_names: HashSet<String> = merged_packages.iter().map(|p| p.name.clone()).collect();
    let mut merged_provenance: Vec<ResolutionProvenance> = Vec::new();
    for prov in base.provenance.iter().chain(ours.provenance.iter()).chain(theirs.provenance.iter()) {
        if merged_pkg_names.contains(&prov.package_name) {
            if let Some(existing) = merged_provenance.iter().position(|p| p.package_name == prov.package_name) {
                if !base.provenance.iter().any(|bp| bp.package_name == prov.package_name) {
                    merged_provenance[existing] = prov.clone();
                }
            } else {
                merged_provenance.push(prov.clone());
            }
        }
    }

    if strategy == ConflictStrategy::Fail && !conflicts.is_empty() {
        return Err(Error::MergeFailed { count: conflicts.len() });
    }

    let mut merged_packages = merged_packages;
    merged_packages.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(MergeResult {
        lockfile: Lockfile {
            sources: merged_sources,
            overrides: merged_overrides,
            features: merged_features,
            metadata: merged_metadata,
            workspace_root: merged_workspace_root,
            workspace_pkgs: merged_workspace_pkgs,
            hoist_boundaries: merged_hoist_boundaries,
            packages: merged_packages,
            artifacts: merged_artifacts,
            patches: merged_patches,
            provenance: merged_provenance,
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
        },
        conflicts,
    })
}

#[allow(clippy::type_complexity)]
fn merge_sources(
    base: &Lockfile,
    ours: &Lockfile,
    theirs: &Lockfile,
) -> Result<(Vec<Source>, HashMap<usize, usize>, HashMap<usize, usize>), Error> {
    let mut merged = base.sources.clone();
    let mut ours_map: HashMap<usize, usize> = (0..ours.sources.len()).map(|i| (i, i)).collect();
    let mut theirs_map: HashMap<usize, usize> = (0..theirs.sources.len()).map(|i| (i, i)).collect();

    for i in base.sources.len()..ours.sources.len() {
        ours_map.insert(i, merged.len());
        merged.push(ours.sources[i].clone());
    }

    for i in base.sources.len()..theirs.sources.len() {
        theirs_map.insert(i, merged.len());
        merged.push(theirs.sources[i].clone());
    }

    Ok((merged, ours_map, theirs_map))
}

fn remap_package(pkg: &Package, source_map: &HashMap<usize, usize>) -> Package {
    let mut p = pkg.clone();
    if let Some(&new_idx) = source_map.get(&pkg.source_idx) {
        p.source_idx = new_idx;
    }
    p
}

fn merge_packages(
    base: &Lockfile,
    ours: &Lockfile,
    theirs: &Lockfile,
    ours_source_map: &HashMap<usize, usize>,
    theirs_source_map: &HashMap<usize, usize>,
    strategy: ConflictStrategy,
) -> (Vec<Package>, Vec<MergeConflict>) {
    let base_map: BTreeMap<&str, &Package> = base.packages.iter().map(|p| (p.name.as_str(), p)).collect();
    let ours_map: BTreeMap<&str, &Package> = ours.packages.iter().map(|p| (p.name.as_str(), p)).collect();
    let theirs_map: BTreeMap<&str, &Package> = theirs.packages.iter().map(|p| (p.name.as_str(), p)).collect();

    let all_keys: BTreeSet<&str> = base_map.keys()
        .chain(ours_map.keys())
        .chain(theirs_map.keys())
        .copied()
        .collect();

    let mut result = Vec::new();
    let mut conflicts = Vec::new();

    for key in all_keys {
        let in_base = base_map.get(key).copied();
        let in_ours = ours_map.get(key).copied();
        let in_theirs = theirs_map.get(key).copied();

        match (in_base, in_ours, in_theirs) {
            (Some(b), Some(o), Some(t)) if o == b && t == b => {
                result.push(remap_package(o, ours_source_map));
            }
            (Some(_b), Some(o), Some(t)) if t == _b => {
                result.push(remap_package(o, ours_source_map));
            }
            (Some(_b), Some(o), Some(t)) if o == _b => {
                result.push(remap_package(t, theirs_source_map));
            }
            (Some(_b), Some(o), Some(t)) if o == t => {
                result.push(remap_package(o, ours_source_map));
            }
            (Some(b), Some(o), Some(t)) => {
                let resolved = match strategy {
                    ConflictStrategy::Ours => remap_package(o, ours_source_map),
                    ConflictStrategy::Theirs => remap_package(t, theirs_source_map),
                    ConflictStrategy::Fail => remap_package(o, ours_source_map),
                };
                conflicts.push(MergeConflict {
                    package_name: key.to_string(),
                    base: Some(b.clone()),
                    ours: remap_package(o, ours_source_map),
                    theirs: remap_package(t, theirs_source_map),
                });
                result.push(resolved);
            }
            (Some(_b), None, Some(t)) if t == _b => { }
            (Some(_b), Some(o), None) if o == _b => { }
            (Some(_), None, None) => { }
            (Some(b), None, Some(t)) => {
                let resolved = match strategy {
                    ConflictStrategy::Theirs => remap_package(t, theirs_source_map),
                    _ => {
                        conflicts.push(MergeConflict {
                            package_name: key.to_string(),
                            base: Some(b.clone()),
                            ours: Package::default(),
                            theirs: remap_package(t, theirs_source_map),
                        });
                        continue;
                    }
                };
                conflicts.push(MergeConflict {
                    package_name: key.to_string(),
                    base: Some(b.clone()),
                    ours: Package::default(),
                    theirs: remap_package(t, theirs_source_map),
                });
                result.push(resolved);
            }
            (Some(b), Some(o), None) => {
                let resolved = match strategy {
                    ConflictStrategy::Ours => remap_package(o, ours_source_map),
                    _ => {
                        conflicts.push(MergeConflict {
                            package_name: key.to_string(),
                            base: Some(b.clone()),
                            ours: remap_package(o, ours_source_map),
                            theirs: Package::default(),
                        });
                        continue;
                    }
                };
                conflicts.push(MergeConflict {
                    package_name: key.to_string(),
                    base: Some(b.clone()),
                    ours: remap_package(o, ours_source_map),
                    theirs: Package::default(),
                });
                result.push(resolved);
            }
            (None, Some(o), None) => {
                result.push(remap_package(o, ours_source_map));
            }
            (None, None, Some(t)) => {
                result.push(remap_package(t, theirs_source_map));
            }
            (None, Some(o), Some(t)) if o == t => {
                result.push(remap_package(o, ours_source_map));
            }
            (None, Some(o), Some(t)) => {
                let resolved = match strategy {
                    ConflictStrategy::Ours => remap_package(o, ours_source_map),
                    ConflictStrategy::Theirs => remap_package(t, theirs_source_map),
                    ConflictStrategy::Fail => remap_package(o, ours_source_map),
                };
                conflicts.push(MergeConflict {
                    package_name: key.to_string(),
                    base: None,
                    ours: remap_package(o, ours_source_map),
                    theirs: remap_package(t, theirs_source_map),
                });
                result.push(resolved);
            }
            (None, None, None) => { }
        }
    }

    (result, conflicts)
}

fn merge_overrides(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<Override> {
    let mut result = base.overrides.clone();
    for ovr in ours.overrides.iter().chain(theirs.overrides.iter()) {
        if !result.iter().any(|o| o.name == ovr.name && o.from_version == ovr.from_version) {
            result.push(ovr.clone());
        }
    }
    result
}

fn merge_features(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<(String, Vec<String>)> {
    let mut result = base.features.clone();
    for (name, flags) in ours.features.iter().chain(theirs.features.iter()) {
        if !result.iter().any(|(n, _)| n == name) {
            result.push((name.clone(), flags.clone()));
        }
    }
    result
}

fn merge_metadata(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<(String, String)> {
    let mut result = base.metadata.clone();
    for (k, v) in ours.metadata.iter().chain(theirs.metadata.iter()) {
        if !result.iter().any(|(mk, _)| mk == k) {
            result.push((k.clone(), v.clone()));
        }
    }
    result
}

fn merge_workspace_pkgs(ours: &Lockfile, theirs: &Lockfile) -> Vec<crate::lockfile::WorkspacePkg> {
    let mut result = ours.workspace_pkgs.clone();
    for wp in &theirs.workspace_pkgs {
        if !result.iter().any(|w| w.name == wp.name) {
            result.push(wp.clone());
        }
    }
    result
}

fn merge_hoist_boundaries(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<crate::lockfile::HoistBoundary> {
    let mut result = base.hoist_boundaries.clone();
    for hb in ours.hoist_boundaries.iter().chain(theirs.hoist_boundaries.iter()) {
        if let Some(existing) = result.iter_mut().find(|h| h.cosine == hb.cosine) {
            existing.allowed_deps = existing.allowed_deps.iter()
                .filter(|d| hb.allowed_deps.contains(d))
                .cloned()
                .collect();
        } else {
            result.push(hb.clone());
        }
    }
    result
}

fn merge_artifacts(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<crate::lockfile::ArtifactDirective> {
    let mut result = base.artifacts.clone();
    for art in ours.artifacts.iter().chain(theirs.artifacts.iter()) {
        if !result.iter().any(|a| a.content_id == art.content_id && a.os_id == art.os_id && a.arch_id == art.arch_id) {
            result.push(art.clone());
        }
    }
    result
}

fn merge_patches(base: &Lockfile, ours: &Lockfile, theirs: &Lockfile) -> Vec<crate::lockfile::PatchDirective> {
    let mut result = base.patches.clone();
    for p in ours.patches.iter().chain(theirs.patches.iter()) {
        if !result.iter().any(|r| r.content_id == p.content_id && r.patch_type == p.patch_type) {
            result.push(p.clone());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{DepType, Source};
    use crate::provenance::{ProvenanceSourceType, ResolutionProvenance};

    fn base_lockfile() -> Lockfile {
        Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![
                Package {
                    name: "core".to_string(),
                    source_idx: 0,
                    major: 1,
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
        }
    }

    #[test]
    fn test_merge_no_changes() {
        let base = base_lockfile();
        let ours = base.clone();
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert_eq!(result.lockfile.packages.len(), 1);
        assert_eq!(result.lockfile.packages[0].name, "core");
    }

    #[test]
    fn test_merge_ours_altered() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages[0].major = 2;
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert_eq!(result.lockfile.packages[0].major, 2);
    }

    #[test]
    fn test_merge_theirs_altered() {
        let base = base_lockfile();
        let ours = base.clone();
        let mut theirs = base.clone();
        theirs.packages[0].major = 3;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert_eq!(result.lockfile.packages[0].major, 3);
    }

    #[test]
    fn test_merge_both_altered_same() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages[0].major = 2;
        let mut theirs = base.clone();
        theirs.packages[0].major = 2;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert_eq!(result.lockfile.packages[0].major, 2);
    }

    #[test]
    fn test_merge_both_altered_different() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages[0].major = 2;
        let mut theirs = base.clone();
        theirs.packages[0].major = 3;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Ours).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].package_name, "core");
        assert_eq!(result.lockfile.packages[0].major, 2);
    }

    #[test]
    fn test_merge_both_altered_different_theirs() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages[0].major = 2;
        let mut theirs = base.clone();
        theirs.packages[0].major = 3;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Theirs).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.lockfile.packages[0].major, 3);
    }

    #[test]
    fn test_merge_both_altered_different_fail() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages[0].major = 2;
        let mut theirs = base.clone();
        theirs.packages[0].major = 3;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail);
        assert!(matches!(result, Err(Error::MergeFailed { count: 1 })));
    }

    #[test]
    fn test_merge_ours_added() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        let names: Vec<&str> = result.lockfile.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"utils"));
    }

    #[test]
    fn test_merge_theirs_added() {
        let base = base_lockfile();
        let ours = base.clone();
        let mut theirs = base.clone();
        theirs.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        let names: Vec<&str> = result.lockfile.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"utils"));
    }

    #[test]
    fn test_merge_both_added_same() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let mut theirs = base.clone();
        theirs.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
    }

    #[test]
    fn test_merge_both_added_different() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let mut theirs = base.clone();
        theirs.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 2, minor: 0, patch: 0,
            ..Package::default()
        });
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Ours).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.conflicts[0].base, None);
    }

    #[test]
    fn test_merge_ours_removed() {
        let base = base_lockfile();
        let ours = Lockfile {
            packages: vec![],
            ..base.clone()
        };
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert!(result.lockfile.packages.is_empty());
    }

    #[test]
    fn test_merge_both_removed() {
        let base = base_lockfile();
        let ours = Lockfile {
            packages: vec![],
            ..base.clone()
        };
        let theirs = Lockfile {
            packages: vec![],
            ..base.clone()
        };
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        assert!(result.conflicts.is_empty());
        assert!(result.lockfile.packages.is_empty());
    }

    #[test]
    fn test_merge_remove_alter_conflict() {
        let base = base_lockfile();
        let ours = Lockfile {
            packages: vec![],
            ..base.clone()
        };
        let mut theirs = base.clone();
        theirs.packages[0].major = 2;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Ours).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert!(result.lockfile.packages.is_empty());
    }

    #[test]
    fn test_merge_remove_alter_theirs_strategy() {
        let base = base_lockfile();
        let ours = Lockfile {
            packages: vec![],
            ..base.clone()
        };
        let mut theirs = base.clone();
        theirs.packages[0].major = 2;
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Theirs).unwrap();
        assert_eq!(result.conflicts.len(), 1);
        assert_eq!(result.lockfile.packages.len(), 1);
        assert_eq!(result.lockfile.packages[0].major, 2);
    }

    #[test]
    fn test_merge_provenance_cleanup() {
        let base = base_lockfile();
        let ours = Lockfile {
            packages: vec![],
            provenance: vec![ResolutionProvenance {
                package_name: "core".to_string(),
                constraint: "^1.0.0".to_string(),
                constrained_by: String::new(),
                dep_type: DepType::Runtime,
                source_type: ProvenanceSourceType::Registry,
                depth: 0,
            }],
            ..base.clone()
        };
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Ours).unwrap();
        assert!(result.lockfile.provenance.is_empty());
    }

    #[test]
    fn test_merge_roundtrip() {
        let base = base_lockfile();
        let mut ours = base.clone();
        ours.packages.push(Package {
            name: "utils".to_string(),
            source_idx: 0,
            major: 1, minor: 0, patch: 0,
            ..Package::default()
        });
        let theirs = base.clone();
        let result = merge_lockfiles(&base, &ours, &theirs, ConflictStrategy::Fail).unwrap();
        let mut merged = result.lockfile;
        let serialized = crate::lockfile::serialize(&mut merged).unwrap();
        let deserialized = crate::lockfile::deserialize(&serialized).unwrap();
        assert_eq!(deserialized.packages.len(), 2);
    }

    #[test]
    fn test_conflict_strategy_variants() {
        let _ = ConflictStrategy::Ours;
        let _ = ConflictStrategy::Theirs;
        let _ = ConflictStrategy::Fail;
    }

    #[test]
    fn test_merge_conflict_construction() {
        let mc = MergeConflict {
            package_name: "react".to_string(),
            base: None,
            ours: Package::default(),
            theirs: Package::default(),
        };
        assert_eq!(mc.package_name, "react");
        assert!(mc.base.is_none());
    }

    #[test]
    fn test_merge_result_construction() {
        let mr = MergeResult {
            lockfile: base_lockfile(),
            conflicts: vec![],
        };
        assert!(mr.conflicts.is_empty());
    }
}
