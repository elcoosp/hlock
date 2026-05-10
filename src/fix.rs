//! Auto-remediate vulnerabilities and outdated packages

use crate::lockfile::Lockfile;
use crate::osv;

#[derive(Debug, Clone)]
pub struct FixPlan {
    pub fixes: Vec<FixEntry>,
    pub total_vulnerabilities: usize,
}

#[derive(Debug, Clone)]
pub struct FixEntry {
    pub package: String,
    pub current: String,
    pub fixed: String,
    pub advisory_id: String,
    pub advisory_summary: String,
    pub fix_type: FixType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixType {
    Audit,
    Outdated,
}

/// Build a fix plan by querying OSV for fixed versions of vulnerable packages.
pub fn build_fix_plan(
    lockfile: &Lockfile,
    fix_type: FixType,
    timeout_secs: u64,
) -> Result<FixPlan, String> {
    let mut fixes = Vec::new();

    match fix_type {
        FixType::Audit => {
            for adv in &lockfile.advisories {
                let pkg = lockfile.packages.iter().find(|p| p.name == adv.package);
                let pkg = match pkg {
                    Some(p) => p,
                    None => continue,
                };

                let current = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);

                match osv::query_osv(&adv.package, &current, timeout_secs) {
                    Ok(response) => {
                        for vuln in &response.vulns {
                            if let Some(fixed) = osv::find_fixed_version(vuln) {
                                fixes.push(FixEntry {
                                    package: adv.package.clone(),
                                    current: current.clone(),
                                    fixed,
                                    advisory_id: vuln.id.clone(),
                                    advisory_summary: vuln.summary.clone(),
                                    fix_type: FixType::Audit,
                                });
                                break;
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
        FixType::Outdated => {
            for pkg in &lockfile.packages {
                let current = format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch);
                match crate::outdated::check_outdated(
                    &pkg.name,
                    &current,
                    crate::outdated::SourceType::from_source(lockfile.sources.get(pkg.source_idx)),
                    timeout_secs,
                ) {
                    Ok(info) => {
                        if let Some(latest) = info.latest {
                            if info.update_type != crate::outdated::UpdateType::Major || true {
                                fixes.push(FixEntry {
                                    package: pkg.name.clone(),
                                    current: current.clone(),
                                    fixed: latest,
                                    advisory_id: String::new(),
                                    advisory_summary: String::new(),
                                    fix_type: FixType::Outdated,
                                });
                            }
                        }
                    }
                    Err(_) => {}
                }
            }
        }
    }

    let total_vulnerabilities = match fix_type {
        FixType::Audit => lockfile.advisories.len(),
        FixType::Outdated => fixes.len(),
    };

    Ok(FixPlan {
        fixes,
        total_vulnerabilities,
    })
}

/// Apply fixes to a lockfile, returning a modified copy.
pub fn apply_fixes(lockfile: &mut Lockfile, plan: &FixPlan, selected: &[bool]) -> usize {
    let mut applied = 0;

    for (i, fix) in plan.fixes.iter().enumerate() {
        if !selected.get(i).copied().unwrap_or(false) {
            continue;
        }

        let ver_parts: Vec<u64> = fix
            .fixed
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();
        let (major, minor, patch) = match ver_parts.as_slice() {
            [maj, min, pat] => (*maj, *min, *pat),
            [maj, min] => (*maj, *min, 0),
            [maj] => (*maj, 0, 0),
            _ => continue,
        };

        if let Some(pkg) = lockfile.packages.iter_mut().find(|p| p.name == fix.package) {
            pkg.major = major;
            pkg.minor = minor;
            pkg.patch = patch;
            applied += 1;
        }
    }

    applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Package, Source};

    #[test]
    fn test_fix_plan_empty() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com".to_string())],
            advisories: vec![],
            ..Lockfile::default()
        };
        let plan = build_fix_plan(&lockfile, FixType::Audit, 5);
        assert!(plan.is_ok());
        assert!(plan.unwrap().fixes.is_empty());
    }

    #[test]
    fn test_apply_fixes() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com".to_string())],
            packages: vec![Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4,
                minor: 17,
                patch: 21,
                ..Package::default()
            }],
            ..Lockfile::default()
        };

        let plan = FixPlan {
            fixes: vec![FixEntry {
                package: "lodash".to_string(),
                current: "4.17.21".to_string(),
                fixed: "4.17.22".to_string(),
                advisory_id: "TEST-001".to_string(),
                advisory_summary: "Test fix".to_string(),
                fix_type: FixType::Audit,
            }],
            total_vulnerabilities: 1,
        };

        let applied = apply_fixes(&mut lockfile, &plan, &[true]);
        assert_eq!(applied, 1);
        assert_eq!(lockfile.packages[0].patch, 22);
    }

    #[test]
    fn test_apply_fixes_selective() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com".to_string())],
            packages: vec![
                Package {
                    name: "lodash".to_string(),
                    source_idx: 0,
                    major: 4,
                    minor: 17,
                    patch: 21,
                    ..Package::default()
                },
                Package {
                    name: "react".to_string(),
                    source_idx: 0,
                    major: 18,
                    minor: 3,
                    patch: 1,
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };

        let plan = FixPlan {
            fixes: vec![
                FixEntry {
                    package: "lodash".to_string(),
                    current: "4.17.21".to_string(),
                    fixed: "4.17.22".to_string(),
                    advisory_id: "TEST-001".to_string(),
                    advisory_summary: String::new(),
                    fix_type: FixType::Audit,
                },
                FixEntry {
                    package: "react".to_string(),
                    current: "18.3.1".to_string(),
                    fixed: "19.0.0".to_string(),
                    advisory_id: "TEST-002".to_string(),
                    advisory_summary: String::new(),
                    fix_type: FixType::Audit,
                },
            ],
            total_vulnerabilities: 2,
        };

        let applied = apply_fixes(&mut lockfile, &plan, &[true, false]);
        assert_eq!(applied, 1);
        assert_eq!(lockfile.packages[0].patch, 22);
        assert_eq!(lockfile.packages[1].major, 18); // Not updated
    }
}
