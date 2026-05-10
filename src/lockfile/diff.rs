//! Lockfile diff functionality

use super::types::{Package, PackageChange, LockfileDiff, DiffFormat};
use owo_colors::OwoColorize;

fn version_string(pkg: &Package) -> String {
    format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch)
}

fn serialize_diff_text(diff: &LockfileDiff) -> String {
    let mut out = String::new();
    out.push_str("LOCKFILE DIFF\n");
    out.push_str(&format!("  unchanged: {} packages\n", diff.unchanged_count));

    let added: Vec<&Package> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Added(p) => Some(p),
        _ => None,
    }).collect();
    let removed: Vec<&Package> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Removed(p) => Some(p),
        _ => None,
    }).collect();
    let altered: Vec<(&Package, &Package)> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Altered(old, new) => Some((old, new)),
        _ => None,
    }).collect();

    out.push_str(&format!("  added: {}\n", added.len()));
    for p in &added {
        out.push_str(&format!("    + {}@{}\n", p.name.green().bold(), version_string(p).cyan()));
    }
    out.push_str(&format!("  removed: {}\n", removed.len()));
    for p in &removed {
        out.push_str(&format!("    - {}@{}\n", p.name.red().bold(), version_string(p).cyan()));
    }
    out.push_str(&format!("  altered: {}\n", altered.len()));
    for (old, new) in &altered {
        out.push_str(&format!("    ~ {}@{} -> {}@{}\n", old.name.yellow().bold(), version_string(old).cyan(), new.name.yellow().bold(), version_string(new).cyan()));
    }
    out
}

fn serialize_diff_json(diff: &LockfileDiff) -> String {
    let mut changes = Vec::new();
    for change in &diff.changes {
        match change {
            PackageChange::Added(p) => {
                changes.push(serde_json::json!({
                    "type": "added",
                    "name": p.name,
                    "version": version_string(p),
                }));
            }
            PackageChange::Removed(p) => {
                changes.push(serde_json::json!({
                    "type": "removed",
                    "name": p.name,
                    "version": version_string(p),
                }));
            }
            PackageChange::Altered(old, new) => {
                changes.push(serde_json::json!({
                    "type": "altered",
                    "name": new.name,
                    "old_version": version_string(old),
                    "new_version": version_string(new),
                }));
            }
        }
    }
    serde_json::to_string(&serde_json::json!({
        "unchanged_count": diff.unchanged_count,
        "changes": changes,
    })).unwrap()
}

pub fn serialize_diff(diff: &LockfileDiff, format: DiffFormat) -> String {
    match format {
        DiffFormat::Text => serialize_diff_text(diff),
        DiffFormat::Json => serialize_diff_json(diff),
    }
}
