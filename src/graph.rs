use crate::error::Error;
use crate::fnv;
use crate::lockfile::{
    DepType, Dependency, Lockfile, LockfileDiff, Package, PackageChange, PlatformTag, TargetArch, TargetOS,
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

    let subgraph_names: HashSet<&str> = extracted_packages.iter().map(|p| p.name.as_str()).collect();
    let filtered_provenance: Vec<crate::provenance::ResolutionProvenance> = lockfile.provenance.iter()
        .filter(|p| subgraph_names.contains(p.package_name.as_str()))
        .cloned()
        .collect();

    Ok(Lockfile {
        sources: new_sources,
        overrides: lockfile.overrides.clone(),
        features: lockfile.features.clone(),
        metadata: vec![],
        workspace_root: lockfile.workspace_root.clone(),
        workspace_pkgs: lockfile.workspace_pkgs.clone(),
        hoist_boundaries: lockfile.hoist_boundaries.clone(),
        packages: extracted_packages,
        artifacts: vec![],
        patches: lockfile.patches.clone(),
        provenance: filtered_provenance,
    }),
        advisories: vec![],
        licenses: vec![],
        policies: vec![],
        trust_roots: vec![],
        mirrors: vec![],
        compat: None,
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
        metadata: vec![],
        workspace_root: lockfile.workspace_root.clone(),
        workspace_pkgs: lockfile.workspace_pkgs.clone(),
        hoist_boundaries: lockfile.hoist_boundaries.clone(),
        packages: extracted_packages,
        artifacts: vec![],
        patches: lockfile.patches.clone(),
        provenance: lockfile.provenance.clone(),
    }),
        advisories: vec![],
        licenses: vec![],
        policies: vec![],
        trust_roots: vec![],
        mirrors: vec![],
        compat: None,
}

pub fn topological_sort(lockfile: &Lockfile) -> Result<Vec<usize>, Vec<String>> {
    use std::collections::BTreeSet;

    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let n = lockfile.packages.len();
    let mut in_degree = vec![0usize; n];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); n];

    for (i, pkg) in lockfile.packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                in_degree[i] += 1;
                dependents[dep_idx].push(i);
            }
        }
    }

    let mut queue: BTreeSet<(&str, usize)> = BTreeSet::new();
    for i in 0..n {
        if in_degree[i] == 0 {
            queue.insert((lockfile.packages[i].name.as_str(), i));
        }
    }

    let mut result = Vec::with_capacity(n);
    while let Some(&(_, idx)) = queue.iter().next() {
        queue.remove(&(lockfile.packages[idx].name.as_str(), idx));
        result.push(idx);
        for &dep_idx in &dependents[idx] {
            in_degree[dep_idx] -= 1;
            if in_degree[dep_idx] == 0 {
                queue.insert((lockfile.packages[dep_idx].name.as_str(), dep_idx));
            }
        }
    }

    if result.len() != n {
        if let Some(cycle) = detect_cycle(lockfile) {
            return Err(cycle);
        }
        return Err(vec!["unknown cycle".to_string()]);
    }

    Ok(result)
}

pub fn dependents_of(lockfile: &Lockfile, package_name: &str) -> Vec<String> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let mut reverse_adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, pkg) in lockfile.packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                reverse_adj.entry(dep_idx).or_default().push(i);
            }
        }
    }

    let start_idx = match name_to_idx.get(package_name) {
        Some(&idx) => idx,
        None => return Vec::new(),
    };

    let mut visited = HashSet::new();
    let mut queue = vec![start_idx];
    visited.insert(start_idx);
    let mut result = Vec::new();

    while let Some(idx) = queue.pop() {
        if let Some(deps) = reverse_adj.get(&idx) {
            for &dep_idx in deps {
                if visited.insert(dep_idx) {
                    queue.push(dep_idx);
                    result.push(lockfile.packages[dep_idx].name.clone());
                }
            }
        }
    }

    result.sort();
    result
}

pub fn transitive_deps(lockfile: &Lockfile, package_name: &str) -> HashSet<String> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let start_idx = match name_to_idx.get(package_name) {
        Some(&idx) => idx,
        None => return HashSet::new(),
    };

    let mut visited = HashSet::new();
    let mut queue = vec![start_idx];
    visited.insert(start_idx);

    while let Some(idx) = queue.pop() {
        for dep in &lockfile.packages[idx].dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                if visited.insert(dep_idx) {
                    queue.push(dep_idx);
                }
            }
        }
    }

    visited.into_iter()
        .filter_map(|i| {
            if i != start_idx {
                Some(lockfile.packages[i].name.clone())
            } else {
                None
            }
        })
        .collect()
}

pub fn leaf_packages(lockfile: &Lockfile) -> Vec<&Package> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let mut has_dependents: HashSet<usize> = HashSet::new();
    for (_i, pkg) in lockfile.packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                has_dependents.insert(dep_idx);
            }
        }
    }

    let mut leaves: Vec<&Package> = lockfile.packages.iter()
        .enumerate()
        .filter(|(i, _)| !has_dependents.contains(i))
        .map(|(_, p)| p)
        .collect();
    leaves.sort_by_key(|p| &p.name);
    leaves
}

fn follows_edge(dep: &Dependency, query_type: DepType) -> bool {
    match query_type {
        DepType::Runtime => dep.dep_type == DepType::Runtime,
        DepType::Dev => dep.dep_type == DepType::Dev,
        _ => false,
    }
}

fn typed_transitive_deps(lockfile: &Lockfile, package_name: &str, query_type: DepType) -> HashSet<String> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let start_idx = match name_to_idx.get(package_name) {
        Some(&idx) => idx,
        None => return HashSet::new(),
    };

    let mut visited = HashSet::new();
    let mut queue = vec![start_idx];
    visited.insert(start_idx);

    while let Some(idx) = queue.pop() {
        for dep in &lockfile.packages[idx].dependencies {
            if follows_edge(dep, query_type.clone()) {
                if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                    if visited.insert(dep_idx) {
                        queue.push(dep_idx);
                    }
                }
            }
        }
    }

    visited.into_iter()
        .filter_map(|i| {
            if i != start_idx {
                Some(lockfile.packages[i].name.clone())
            } else {
                None
            }
        })
        .collect()
}

pub fn runtime_deps(lockfile: &Lockfile, package_name: &str) -> HashSet<String> {
    typed_transitive_deps(lockfile, package_name, DepType::Runtime)
}

pub fn dev_deps(lockfile: &Lockfile, package_name: &str) -> HashSet<String> {
    typed_transitive_deps(lockfile, package_name, DepType::Dev)
}

fn typed_dependents_of(lockfile: &Lockfile, package_name: &str, query_type: DepType) -> Vec<String> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let mut reverse_adj: HashMap<usize, Vec<usize>> = HashMap::new();
    for (i, pkg) in lockfile.packages.iter().enumerate() {
        for dep in &pkg.dependencies {
            if follows_edge(dep, query_type.clone()) {
                if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                    reverse_adj.entry(dep_idx).or_default().push(i);
                }
            }
        }
    }

    let start_idx = match name_to_idx.get(package_name) {
        Some(&idx) => idx,
        None => return Vec::new(),
    };

    let mut visited = HashSet::new();
    let mut queue = vec![start_idx];
    visited.insert(start_idx);
    let mut result = Vec::new();

    while let Some(idx) = queue.pop() {
        if let Some(deps) = reverse_adj.get(&idx) {
            for &dep_idx in deps {
                if visited.insert(dep_idx) {
                    queue.push(dep_idx);
                    result.push(lockfile.packages[dep_idx].name.clone());
                }
            }
        }
    }

    result.sort();
    result
}

pub fn runtime_dependents_of(lockfile: &Lockfile, package_name: &str) -> Vec<String> {
    typed_dependents_of(lockfile, package_name, DepType::Runtime)
}

pub fn dev_dependents_of(lockfile: &Lockfile, package_name: &str) -> Vec<String> {
    typed_dependents_of(lockfile, package_name, DepType::Dev)
}

pub fn has_dep_path(lockfile: &Lockfile, package_name: &str, target: &str, dep_type: DepType) -> bool {
    if package_name == target {
        let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
            .enumerate()
            .map(|(i, p)| (p.name.as_str(), i))
            .collect();
        return name_to_idx.contains_key(package_name);
    }

    let reachable = typed_transitive_deps(lockfile, package_name, dep_type);
    reachable.contains(target)
}

pub fn dep_count(lockfile: &Lockfile, package_name: &str, dep_type: DepType) -> usize {
    let pkg = match lockfile.packages.iter().find(|p| p.name == package_name) {
        Some(p) => p,
        None => return 0,
    };
    pkg.dependencies.iter().filter(|d| d.dep_type == dep_type).count()
}

pub fn detect_cycle(lockfile: &Lockfile) -> Option<Vec<String>> {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let n = lockfile.packages.len();
    let mut color = vec![0u8; n];
    let mut parent: Vec<Option<usize>> = vec![None; n];

    fn dfs(
        idx: usize,
        packages: &[Package],
        name_to_idx: &HashMap<&str, usize>,
        color: &mut [u8],
        parent: &mut [Option<usize>],
    ) -> Option<Vec<String>> {
        color[idx] = 1;
        for dep in &packages[idx].dependencies {
            if let Some(&dep_idx) = name_to_idx.get(dep.name.as_str()) {
                if dep_idx == idx {
                    return Some(vec![packages[idx].name.clone()]);
                }
                match color[dep_idx] {
                    0 => {
                        parent[dep_idx] = Some(idx);
                        if let Some(cycle) = dfs(dep_idx, packages, name_to_idx, color, parent) {
                            return Some(cycle);
                        }
                    }
                    1 => {
                        let mut cycle = Vec::new();
                        let mut cur = Some(idx);
                        while let Some(c) = cur {
                            cycle.push(packages[c].name.clone());
                            if c == dep_idx {
                                break;
                            }
                            cur = parent[c];
                        }
                        cycle.reverse();
                        return Some(cycle);
                    }
                    _ => {}
                }
            }
        }
        color[idx] = 2;
        None
    }

    for i in 0..n {
        if color[i] == 0 {
            if let Some(cycle) = dfs(i, &lockfile.packages, &name_to_idx, &mut color, &mut parent) {
                return Some(cycle);
            }
        }
    }

    None
}

pub fn would_create_cycle(
    lockfile: &Lockfile,
    package_name: &str,
    new_deps: &[String],
) -> bool {
    let name_to_idx: HashMap<&str, usize> = lockfile.packages.iter()
        .enumerate()
        .map(|(i, p)| (p.name.as_str(), i))
        .collect();

    let start_idx = match name_to_idx.get(package_name) {
        Some(&idx) => idx,
        None => return false,
    };

    for new_dep in new_deps {
        if new_dep == package_name {
            return true;
        }
        let dep_idx = match name_to_idx.get(new_dep.as_str()) {
            Some(&idx) => idx,
            None => continue,
        };

        let mut visited = HashSet::new();
        let mut queue = vec![dep_idx];
        visited.insert(dep_idx);

        while let Some(idx) = queue.pop() {
            if idx == start_idx {
                return true;
            }
            for dep in &lockfile.packages[idx].dependencies {
                if let Some(&next_idx) = name_to_idx.get(dep.name.as_str()) {
                    if visited.insert(next_idx) {
                        queue.push(next_idx);
                    }
                }
            }
        }
    }

    false
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
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

    fn make_graph_lockfile(packages: Vec<Package>) -> Lockfile {
        Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![], provenance: vec![],
    advisories: vec![],
    licenses: vec![],
    policies: vec![],
    trust_roots: vec![],
    mirrors: vec![],
    compat: None,
            packages,
        }
    }

    #[test]
    fn test_topological_sort_simple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("c", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("a", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, vec![], vec![]),
        ]);
        let order = topological_sort(&lockfile).unwrap();
        let names: Vec<&str> = order.iter().map(|&i| lockfile.packages[i].name.as_str()).collect();
        let b_pos = names.iter().position(|&n| n == "b").unwrap();
        let a_pos = names.iter().position(|&n| n == "a").unwrap();
        let c_pos = names.iter().position(|&n| n == "c").unwrap();
        assert!(b_pos < a_pos);
        assert!(b_pos < c_pos);
    }

    #[test]
    fn test_topological_sort_lexicographic_tiebreak() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("z", 1, 0, 0, vec![], vec![]),
            mock_pkg("a", 1, 0, 0, vec![], vec![]),
            mock_pkg("m", 1, 0, 0, vec![], vec![]),
        ]);
        let order = topological_sort(&lockfile).unwrap();
        let names: Vec<&str> = order.iter().map(|&i| lockfile.packages[i].name.as_str()).collect();
        assert_eq!(names, vec!["a", "m", "z"]);
    }

    #[test]
    fn test_topological_sort_detects_cycle() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, vec![("a", DepType::Runtime)], vec![]),
        ]);
        let res = topological_sort(&lockfile);
        assert!(res.is_err());
        let cycle = res.unwrap_err();
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_topological_sort_self_dependency() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("a", DepType::Runtime)], vec![]),
        ]);
        let res = topological_sort(&lockfile);
        assert!(res.is_err());
    }

    #[test]
    fn test_dependents_of_direct() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = dependents_of(&lockfile, "lib");
        assert_eq!(deps, vec!["app"]);
    }

    #[test]
    fn test_dependents_of_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = dependents_of(&lockfile, "leaf");
        assert_eq!(deps, vec!["app", "mid"]);
    }

    #[test]
    fn test_dependents_of_no_dependents() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = dependents_of(&lockfile, "app");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_dependents_of_unknown_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = dependents_of(&lockfile, "nonexistent");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_transitive_deps_direct() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = transitive_deps(&lockfile, "app");
        assert_eq!(deps, HashSet::from(["lib".to_string()]));
    }

    #[test]
    fn test_transitive_deps_deep() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = transitive_deps(&lockfile, "app");
        assert_eq!(deps, HashSet::from(["mid".to_string(), "leaf".to_string()]));
    }

    #[test]
    fn test_transitive_deps_excludes_self() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = transitive_deps(&lockfile, "app");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_transitive_deps_unknown_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = transitive_deps(&lockfile, "nonexistent");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_leaf_packages_basic() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let leaves = leaf_packages(&lockfile);
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn test_leaf_packages_multiple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("a", DepType::Runtime), ("b", DepType::Runtime)], vec![]),
            mock_pkg("a", 1, 0, 0, vec![], vec![]),
            mock_pkg("b", 1, 0, 0, vec![], vec![]),
        ]);
        let leaves = leaf_packages(&lockfile);
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["app"]);
    }

    #[test]
    fn test_leaf_packages_sorted() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("z", 1, 0, 0, vec![], vec![]),
            mock_pkg("a", 1, 0, 0, vec![], vec![]),
        ]);
        let leaves = leaf_packages(&lockfile);
        let names: Vec<&str> = leaves.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["a", "z"]);
    }

    #[test]
    fn test_detect_cycle_no_cycle() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(detect_cycle(&lockfile).is_none());
    }

    #[test]
    fn test_detect_cycle_simple() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, vec![("a", DepType::Runtime)], vec![]),
        ]);
        let cycle = detect_cycle(&lockfile).unwrap();
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_detect_cycle_self() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("a", DepType::Runtime)], vec![]),
        ]);
        let cycle = detect_cycle(&lockfile).unwrap();
        assert_eq!(cycle, vec!["a"]);
    }

    #[test]
    fn test_detect_cycle_three_node() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![("b", DepType::Runtime)], vec![]),
            mock_pkg("b", 1, 0, 0, vec![("c", DepType::Runtime)], vec![]),
            mock_pkg("c", 1, 0, 0, vec![("a", DepType::Runtime)], vec![]),
        ]);
        let cycle = detect_cycle(&lockfile).unwrap();
        assert_eq!(cycle.len(), 3);
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
        assert!(cycle.contains(&"c".to_string()));
    }

    #[test]
    fn test_detect_cycle_isolated_component() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("a", 1, 0, 0, vec![], vec![]),
            mock_pkg("x", 1, 0, 0, vec![("y", DepType::Runtime)], vec![]),
            mock_pkg("y", 1, 0, 0, vec![("x", DepType::Runtime)], vec![]),
        ]);
        let cycle = detect_cycle(&lockfile).unwrap();
        assert!(cycle.contains(&"x".to_string()));
        assert!(cycle.contains(&"y".to_string()));
    }

    #[test]
    fn test_would_create_cycle_no() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
            mock_pkg("new-dep", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!would_create_cycle(&lockfile, "app", &["new-dep".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_yes() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![("app", DepType::Runtime)], vec![]),
        ]);
        assert!(would_create_cycle(&lockfile, "lib", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_self() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(would_create_cycle(&lockfile, "app", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(would_create_cycle(&lockfile, "leaf", &["app".to_string()]));
    }

    #[test]
    fn test_would_create_cycle_unknown_dep() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!would_create_cycle(&lockfile, "app", &["nonexistent".to_string()]));
    }

    #[test]
    fn test_extract_subgraph_preserves_provenance() {
        let lockfile = Lockfile {
            sources: vec![crate::lockfile::Source::Registry("r".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![
                crate::provenance::ResolutionProvenance {
                    package_name: "app".to_string(),
                    constraint: "".to_string(),
                    constrained_by: String::new(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 0,
                },
                crate::provenance::ResolutionProvenance {
                    package_name: "lib".to_string(),
                    constraint: "^1.0.0".to_string(),
                    constrained_by: "app".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 1,
                },
                crate::provenance::ResolutionProvenance {
                    package_name: "unused".to_string(),
                    constraint: "^1.0.0".to_string(),
                    constrained_by: "other".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 1,
                },
            ],
            packages: vec![
                mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
                mock_pkg("lib", 1, 0, 0, vec![], vec![]),
                mock_pkg("unused", 1, 0, 0, vec![], vec![]),
            ],
        };,
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            compat: None,
        let app_cid = fnv::calculate("app@1.0.0");
        let sub = extract_subgraph(&lockfile, &[app_cid]).unwrap();
        let prov_names: Vec<&str> = sub.provenance.iter().map(|p| p.package_name.as_str()).collect();
        assert!(prov_names.contains(&"app"));
        assert!(prov_names.contains(&"lib"));
        assert!(!prov_names.contains(&"unused"));
    }

    #[test]
    fn test_would_create_cycle_unknown_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!would_create_cycle(&lockfile, "nonexistent", &["app".to_string()]));
    }

    #[test]
    fn test_runtime_deps_only_follows_runtime() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("rt-lib", DepType::Runtime), ("dev-lib", DepType::Dev)], vec![]),
            mock_pkg("rt-lib", 1, 0, 0, vec![("deep-rt", DepType::Runtime)], vec![]),
            mock_pkg("dev-lib", 1, 0, 0, vec![], vec![]),
            mock_pkg("deep-rt", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = runtime_deps(&lockfile, "app");
        assert!(deps.contains("rt-lib"));
        assert!(deps.contains("deep-rt"));
        assert!(!deps.contains("dev-lib"));
    }

    #[test]
    fn test_dev_deps_only_follows_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("rt-lib", DepType::Runtime), ("dev-lib", DepType::Dev)], vec![]),
            mock_pkg("rt-lib", 1, 0, 0, vec![], vec![]),
            mock_pkg("dev-lib", 1, 0, 0, vec![("deep-dev", DepType::Dev)], vec![]),
            mock_pkg("deep-dev", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = dev_deps(&lockfile, "app");
        assert!(deps.contains("dev-lib"));
        assert!(deps.contains("deep-dev"));
        assert!(!deps.contains("rt-lib"));
    }

    #[test]
    fn test_runtime_deps_ignores_peer() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("peer-lib", DepType::Peer)], vec![]),
            mock_pkg("peer-lib", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = runtime_deps(&lockfile, "app");
        assert!(!deps.contains("peer-lib"));
    }

    #[test]
    fn test_runtime_deps_unknown_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        let deps = runtime_deps(&lockfile, "nonexistent");
        assert!(deps.is_empty());
    }

    #[test]
    fn test_runtime_dependents_of() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("test-util", 1, 0, 0, vec![("lib", DepType::Dev)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let dependents = runtime_dependents_of(&lockfile, "lib");
        assert!(dependents.contains(&"app".to_string()));
        assert!(!dependents.contains(&"test-util".to_string()));
    }

    #[test]
    fn test_dev_dependents_of() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("lib", DepType::Runtime)], vec![]),
            mock_pkg("test-util", 1, 0, 0, vec![("lib", DepType::Dev)], vec![]),
            mock_pkg("lib", 1, 0, 0, vec![], vec![]),
        ]);
        let dependents = dev_dependents_of(&lockfile, "lib");
        assert!(dependents.contains(&"test-util".to_string()));
        assert!(!dependents.contains(&"app".to_string()));
    }

    #[test]
    fn test_runtime_dependents_of_transitive() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("top", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        let dependents = runtime_dependents_of(&lockfile, "leaf");
        assert!(dependents.contains(&"mid".to_string()));
        assert!(dependents.contains(&"top".to_string()));
    }

    #[test]
    fn test_has_dep_path_runtime_true() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Runtime)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(has_dep_path(&lockfile, "app", "leaf", DepType::Runtime));
    }

    #[test]
    fn test_has_dep_path_runtime_false_via_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![("mid", DepType::Dev)], vec![]),
            mock_pkg("mid", 1, 0, 0, vec![("leaf", DepType::Runtime)], vec![]),
            mock_pkg("leaf", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!has_dep_path(&lockfile, "app", "leaf", DepType::Runtime));
    }

    #[test]
    fn test_has_dep_path_same_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(has_dep_path(&lockfile, "app", "app", DepType::Runtime));
    }

    #[test]
    fn test_has_dep_path_unknown_source() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!has_dep_path(&lockfile, "nonexistent", "app", DepType::Runtime));
    }

    #[test]
    fn test_has_dep_path_unknown_target() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert!(!has_dep_path(&lockfile, "app", "nonexistent", DepType::Runtime));
    }

    #[test]
    fn test_dep_count_runtime() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![
                ("lib1", DepType::Runtime),
                ("lib2", DepType::Runtime),
                ("dev1", DepType::Dev),
            ], vec![]),
            mock_pkg("lib1", 1, 0, 0, vec![], vec![]),
            mock_pkg("lib2", 1, 0, 0, vec![], vec![]),
            mock_pkg("dev1", 1, 0, 0, vec![], vec![]),
        ]);
        assert_eq!(dep_count(&lockfile, "app", DepType::Runtime), 2);
    }

    #[test]
    fn test_dep_count_dev() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![
                ("lib1", DepType::Runtime),
                ("dev1", DepType::Dev),
                ("dev2", DepType::Dev),
            ], vec![]),
            mock_pkg("lib1", 1, 0, 0, vec![], vec![]),
            mock_pkg("dev1", 1, 0, 0, vec![], vec![]),
            mock_pkg("dev2", 1, 0, 0, vec![], vec![]),
        ]);
        assert_eq!(dep_count(&lockfile, "app", DepType::Dev), 2);
    }

    #[test]
    fn test_dep_count_peer() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![
                ("peer1", DepType::Peer),
            ], vec![]),
            mock_pkg("peer1", 1, 0, 0, vec![], vec![]),
        ]);
        assert_eq!(dep_count(&lockfile, "app", DepType::Peer), 1);
    }

    #[test]
    fn test_dep_count_unknown_package() {
        let lockfile = make_graph_lockfile(vec![
            mock_pkg("app", 1, 0, 0, vec![], vec![]),
        ]);
        assert_eq!(dep_count(&lockfile, "nonexistent", DepType::Runtime), 0);
    }

}
