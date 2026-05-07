use crate::error::Error;
use crate::fnv;
use crate::lockfile::{
    Lockfile, LockfileDiff, Package, PackageChange, PlatformTag, TargetArch, TargetOS,
};
use std::collections::{HashMap, HashSet};

fn build_cid_map(lockfile: &Lockfile) -> HashMap<u64, (usize, &Package)> {
    let mut map = HashMap::new();
    for (idx, pkg) in lockfile.packages.iter().enumerate() {
        let ver_str = format!("{}@{}.{}.{}", pkg.name, pkg.major, pkg.minor, pkg.patch);
        let cid = fnv::calculate(&ver_str);
        map.insert(cid, (idx, pkg));
    }
    map
}

pub fn diff_lockfiles(old: &Lockfile, new: &Lockfile) -> LockfileDiff {
    let mut changes = Vec::new();
    let mut unchanged_count = 0;
    let mut i = 0;
    let mut j = 0;

    while i < old.packages.len() && j < new.packages.len() {
        let old_pkg = &old.packages[i];
        let new_pkg = &new.packages[j];

        match old_pkg.name.cmp(&new_pkg.name) {
            std::cmp::Ordering::Less => {
                changes.push(PackageChange::Removed(old_pkg.clone()));
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                changes.push(PackageChange::Added(new_pkg.clone()));
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                if old_pkg.major == new_pkg.major
                    && old_pkg.minor == new_pkg.minor
                    && old_pkg.patch == new_pkg.patch
                    && old_pkg.hashes == new_pkg.hashes
                {
                    unchanged_count += 1;
                } else {
                    changes.push(PackageChange::Altered(old_pkg.clone(), new_pkg.clone()));
                }
                i += 1;
                j += 1;
            }
        }
    }

    while i < old.packages.len() {
        changes.push(PackageChange::Removed(old.packages[i].clone()));
        i += 1;
    }

    while j < new.packages.len() {
        changes.push(PackageChange::Added(new.packages[j].clone()));
        j += 1;
    }

    LockfileDiff {
        changes,
        unchanged_count,
    }
}

pub fn extract_subgraph(lockfile: &Lockfile, root_content_ids: &[u64]) -> Result<Lockfile, Error> {
    let cid_map = build_cid_map(lockfile);

    for root_id in root_content_ids {
        if !cid_map.contains_key(root_id) {
            return Err(Error::RootContentIdMissing {
                content_id: *root_id,
            });
        }
    }

    let mut allowed_ids: HashSet<u64> = root_content_ids.iter().cloned().collect();
    let mut output_indices: HashSet<usize> = HashSet::new();
    let mut changed = true;

    while changed {
        changed = false;
        for (idx, pkg) in lockfile.packages.iter().enumerate() {
            let ver_str = format!("{}@{}.{}.{}", pkg.name, pkg.major, pkg.minor, pkg.patch);
            let cid = fnv::calculate(&ver_str);

            if allowed_ids.contains(&cid) && !output_indices.contains(&idx) {
                output_indices.insert(idx);
                for dep in &pkg.dependencies {
                    if let Some((dep_idx, _)) = cid_map.values().find(|(_, p)| p.name == dep.name) {
                        let dep_ver_str = format!(
                            "{}@{}.{}.{}",
                            dep.name,
                            lockfile.packages[*dep_idx].major,
                            lockfile.packages[*dep_idx].minor,
                            lockfile.packages[*dep_idx].patch
                        );
                        let dep_cid = fnv::calculate(&dep_ver_str);
                        if allowed_ids.insert(dep_cid) {
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    let mut extracted_packages: Vec<Package> = output_indices
        .into_iter()
        .map(|i| lockfile.packages[i].clone())
        .collect();
    extracted_packages.sort_by(|a, b| a.name.cmp(&b.name));

    let used_source_indices: HashSet<usize> =
        extracted_packages.iter().map(|p| p.source_idx).collect();
    let mut source_mapping: HashMap<usize, usize> = HashMap::new();
    let mut new_sources = Vec::new();

    for (orig_idx, source) in lockfile.sources.iter().enumerate() {
        if used_source_indices.contains(&orig_idx) {
            source_mapping.insert(orig_idx, new_sources.len());
            new_sources.push(source.clone());
        }
    }

    for pkg in &mut extracted_packages {
        if let Some(&new_idx) = source_mapping.get(&pkg.source_idx) {
            pkg.source_idx = new_idx;
        }
    }

    Ok(Lockfile {
        sources: new_sources,
        overrides: lockfile.overrides.clone(),
        features: lockfile.features.clone(),
        workspace_root: lockfile.workspace_root.clone(),
        workspace_pkgs: lockfile.workspace_pkgs.clone(),
        hoist_boundaries: lockfile.hoist_boundaries.clone(),
        packages: extracted_packages,
        patches: lockfile.patches.clone(),
    })
}

fn platform_matches(tag: &PlatformTag, target_os: &TargetOS, target_arch: &TargetArch) -> bool {
    let os_match = matches!(tag.os, TargetOS::Any) || tag.os == *target_os;
    let arch_match = matches!(tag.arch, TargetArch::Any) || tag.arch == *target_arch;
    os_match && arch_match
}

fn package_matches_platform(pkg: &Package, target_os: &TargetOS, target_arch: &TargetArch) -> bool {
    if pkg.platform_tags.is_empty() {
        return true;
    }
    pkg.platform_tags
        .iter()
        .any(|t| platform_matches(t, target_os, target_arch))
}

pub fn extract_subgraph_platform(
    lockfile: &Lockfile,
    root_content_ids: &[u64],
    target_os: TargetOS,
    target_arch: TargetArch,
) -> Result<Lockfile, Error> {
    let cid_map = build_cid_map(lockfile);

    for root_id in root_content_ids {
        if !cid_map.contains_key(root_id) {
            return Err(Error::RootContentIdMissing {
                content_id: *root_id,
            });
        }
    }

    let mut candidate_ids: HashSet<u64> = HashSet::new();
    let mut changed = true;

    while changed {
        changed = false;

        let mut reachable: HashSet<u64> = HashSet::new();
        let mut queue: Vec<u64> = root_content_ids.to_vec();
        while let Some(cid) = queue.pop() {
            if reachable.insert(cid) {
                if let Some((_, pkg)) = cid_map.get(&cid) {
                    for dep in &pkg.dependencies {
                        if let Some((dep_idx, _)) =
                            cid_map.values().find(|(_, p)| p.name == dep.name)
                        {
                            let dep_ver_str = format!(
                                "{}@{}.{}.{}",
                                dep.name,
                                lockfile.packages[*dep_idx].major,
                                lockfile.packages[*dep_idx].minor,
                                lockfile.packages[*dep_idx].patch
                            );
                            let dep_cid = fnv::calculate(&dep_ver_str);
                            queue.push(dep_cid);
                        }
                    }
                }
            }
        }

        let filtered: HashSet<u64> = reachable
            .into_iter()
            .filter(|cid| {
                if let Some((_, pkg)) = cid_map.get(cid) {
                    package_matches_platform(pkg, &target_os, &target_arch)
                } else {
                    false
                }
            })
            .collect();

        if filtered != candidate_ids {
            candidate_ids = filtered;
            changed = true;
        }
    }

    if candidate_ids.is_empty() && !root_content_ids.is_empty() {
        return Err(Error::NoPackagesForPlatform {
            os: format!("{:?}", target_os),
            arch: format!("{:?}", target_arch),
        });
    }

    let mut output_indices: HashSet<usize> = HashSet::new();
    for (idx, pkg) in lockfile.packages.iter().enumerate() {
        let ver_str = format!("{}@{}.{}.{}", pkg.name, pkg.major, pkg.minor, pkg.patch);
        let cid = fnv::calculate(&ver_str);
        if candidate_ids.contains(&cid) {
            output_indices.insert(idx);
        }
    }

    let mut extracted_packages: Vec<Package> = output_indices
        .into_iter()
        .map(|i| lockfile.packages[i].clone())
        .collect();
    extracted_packages.sort_by(|a, b| a.name.cmp(&b.name));

    let used_source_indices: HashSet<usize> =
        extracted_packages.iter().map(|p| p.source_idx).collect();
    let mut source_mapping: HashMap<usize, usize> = HashMap::new();
    let mut new_sources = Vec::new();

    for (orig_idx, source) in lockfile.sources.iter().enumerate() {
        if used_source_indices.contains(&orig_idx) {
            source_mapping.insert(orig_idx, new_sources.len());
            new_sources.push(source.clone());
        }
    }

    for pkg in &mut extracted_packages {
        if let Some(&new_idx) = source_mapping.get(&pkg.source_idx) {
            pkg.source_idx = new_idx;
        }
    }

    Ok(Lockfile {
        sources: new_sources,
        overrides: lockfile.overrides.clone(),
        features: lockfile.features.clone(),
        workspace_root: lockfile.workspace_root.clone(),
        workspace_pkgs: lockfile.workspace_pkgs.clone(),
        hoist_boundaries: lockfile.hoist_boundaries.clone(),
        packages: extracted_packages,
        patches: lockfile.patches.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{DepType, Dependency};

    fn mock_pkg(
        name: &str,
        maj: u64,
        min: u64,
        pat: u64,
        deps: Vec<(&str, DepType)>,
        tags: Vec<PlatformTag>,
    ) -> Package {
        Package {
            name: name.to_string(),
            logical_name: None,
            source_idx: 0,
            major: maj,
            minor: min,
            patch: pat,
            hashes: vec![],
            features: vec![],
            resolved_peers: vec![],
            dependencies: deps
                .iter()
                .map(|(n, ty)| Dependency {
                    name: n.to_string(),
                    dep_type: ty.clone(),
                    requested_features: vec![],
                })
                .collect(),
            peer_requirements: vec![],
            platform_tags: tags,
            exports: vec![],
            artifacts: vec![],
            hook_hashes: vec![],
            patch_hash: None,
        }
    }

    #[test]
    fn test_platform_filter_excludes_non_matching() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![
                mock_pkg(
                    "app",
                    1,
                    0,
                    0,
                    vec![("native-lib", DepType::Runtime)],
                    vec![],
                ),
                mock_pkg(
                    "native-lib",
                    1,
                    0,
                    0,
                    vec![],
                    vec![PlatformTag {
                        os: TargetOS::Linux,
                        arch: TargetArch::X86_64,
                    }],
                ),
                mock_pkg(
                    "other-lib",
                    1,
                    0,
                    0,
                    vec![],
                    vec![PlatformTag {
                        os: TargetOS::MacOS,
                        arch: TargetArch::Aarch64,
                    }],
                ),
            ],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::X86_64)
                .unwrap();
        assert_eq!(res.packages.len(), 2);
        let names: Vec<&str> = res.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"app"));
        assert!(names.contains(&"native-lib"));
        assert!(!names.contains(&"other-lib"));
    }

    #[test]
    fn test_platform_filter_agnostic_included() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![
                mock_pkg("app", 1, 0, 0, vec![("pure-lib", DepType::Runtime)], vec![]),
                mock_pkg("pure-lib", 1, 0, 0, vec![], vec![]),
            ],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Windows, TargetArch::X86_64)
                .unwrap();
        assert_eq!(res.packages.len(), 2);
    }

    #[test]
    fn test_platform_filter_any_arch() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![
                mock_pkg("app", 1, 0, 0, vec![("napi", DepType::Runtime)], vec![]),
                mock_pkg(
                    "napi",
                    1,
                    0,
                    0,
                    vec![],
                    vec![PlatformTag {
                        os: TargetOS::Linux,
                        arch: TargetArch::Any,
                    }],
                ),
            ],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::Aarch64)
                .unwrap();
        assert_eq!(res.packages.len(), 2);
    }

    #[test]
    fn test_platform_filter_multiple_tags() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![
                mock_pkg("app", 1, 0, 0, vec![("multi", DepType::Runtime)], vec![]),
                mock_pkg(
                    "multi",
                    1,
                    0,
                    0,
                    vec![],
                    vec![
                        PlatformTag {
                            os: TargetOS::Linux,
                            arch: TargetArch::X86_64,
                        },
                        PlatformTag {
                            os: TargetOS::MacOS,
                            arch: TargetArch::Aarch64,
                        },
                    ],
                ),
            ],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res_linux =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::X86_64)
                .unwrap();
        assert_eq!(res_linux.packages.len(), 2);
        let res_mac =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::MacOS, TargetArch::Aarch64)
                .unwrap();
        assert_eq!(res_mac.packages.len(), 2);
        let res_win =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Windows, TargetArch::X86_64)
                .unwrap();
        assert_eq!(res_win.packages.len(), 1);
    }

    #[test]
    fn test_platform_filter_excludes_transitive_non_matching() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![
                mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
                mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
                mock_pkg(
                    "leaf",
                    1,
                    0,
                    0,
                    vec![],
                    vec![PlatformTag {
                        os: TargetOS::MacOS,
                        arch: TargetArch::Aarch64,
                    }],
                ),
            ],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::X86_64)
                .unwrap();
        assert_eq!(res.packages.len(), 2);
        let names: Vec<&str> = res.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"app"));
        assert!(names.contains(&"mid"));
        assert!(!names.contains(&"leaf"));
    }

    #[test]
    fn test_platform_filter_no_packages_error() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            patches: vec![],
            packages: vec![mock_pkg(
                "app",
                1,
                0,
                0,
                vec![],
                vec![PlatformTag {
                    os: TargetOS::MacOS,
                    arch: TargetArch::Aarch64,
                }],
            )],
        };
        let app_cid = fnv::calculate("app@1.0.0");
        let res =
            extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::X86_64);
        assert!(matches!(res, Err(Error::NoPackagesForPlatform { .. })));
    }
}
