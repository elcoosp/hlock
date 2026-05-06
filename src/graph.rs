use crate::error::Error;
use crate::fnv;
use crate::lockfile::{Lockfile, Package, PackageChange, LockfileDiff};
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
                if old_pkg.major == new_pkg.major && old_pkg.minor == new_pkg.minor && old_pkg.patch == new_pkg.patch && old_pkg.hashes == new_pkg.hashes {
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

    LockfileDiff { changes, unchanged_count }
}

pub fn extract_subgraph(lockfile: &Lockfile, root_content_ids: &[u64]) -> Result<Lockfile, Error> {
    let cid_map = build_cid_map(lockfile);

    for root_id in root_content_ids {
        if !cid_map.contains_key(root_id) {
            return Err(Error::RootContentIdMissing { content_id: *root_id });
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
                        let dep_ver_str = format!("{}@{}.{}.{}", dep.name, lockfile.packages[*dep_idx].major, lockfile.packages[*dep_idx].minor, lockfile.packages[*dep_idx].patch);
                        let dep_cid = fnv::calculate(&dep_ver_str);
                        if allowed_ids.insert(dep_cid) {
                            changed = true;
                        }
                    }
                }
            }
        }
    }

    let mut extracted_packages: Vec<Package> = output_indices.into_iter().map(|i| lockfile.packages[i].clone()).collect();
    extracted_packages.sort_by(|a, b| a.name.cmp(&b.name));

    Ok(Lockfile {
        sources: lockfile.sources.clone(),
        overrides: lockfile.overrides.clone(),
        features: lockfile.features.clone(),
        packages: extracted_packages,
    })
}
