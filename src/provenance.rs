use crate::lockfile::DepType;
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvenanceSourceType {
    Registry,
    Local,
    Git,
    Workspace,
    CasHttp,
    Ipfs,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolutionProvenance {
    pub package_name: String,
    pub constraint: String,
    pub constrained_by: String,
    pub dep_type: DepType,
    pub source_type: ProvenanceSourceType,
    pub depth: u32,
}

impl crate::lockfile::Lockfile {
    pub fn provenance_for(&self, package_name: &str) -> Option<&ResolutionProvenance> {
        self.provenance.iter().find(|p| p.package_name == package_name)
    }

    pub fn packages_at_depth(&self, depth: u32) -> Vec<&ResolutionProvenance> {
        self.provenance.iter()
            .filter(|p| p.depth == depth)
            .collect()
    }

    pub fn dependency_chain(&self, package_name: &str) -> Vec<ResolutionProvenance> {
        let mut chain = Vec::new();
        let mut current = package_name;
        let mut visited = HashSet::new();

        while let Some(prov) = self.provenance.iter().find(|p| p.package_name == current) {
            if !visited.insert(current.to_string()) {
                break;
            }
            chain.push(prov.clone());
            if prov.constrained_by.is_empty() {
                break;
            }
            current = &prov.constrained_by;
        }

        chain.reverse();
        chain
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Lockfile, Source};

    fn sample_lockfile() -> Lockfile {
        Lockfile {
            sources: vec![Source::Registry("https://r.com".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![],
            artifacts: vec![],
            patches: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
            provenance: vec![
                ResolutionProvenance {
                    package_name: "app".to_string(),
                    constraint: "".to_string(),
                    constrained_by: String::new(),
                    dep_type: DepType::Runtime,
                    source_type: ProvenanceSourceType::Workspace,
                    depth: 0,
                },
                ResolutionProvenance {
                    package_name: "react".to_string(),
                    constraint: "^18.0.0".to_string(),
                    constrained_by: "app".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: ProvenanceSourceType::Registry,
                    depth: 1,
                },
                ResolutionProvenance {
                    package_name: "lodash".to_string(),
                    constraint: "^4.17.0".to_string(),
                    constrained_by: "react".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: ProvenanceSourceType::Registry,
                    depth: 2,
                },
                ResolutionProvenance {
                    package_name: "jest".to_string(),
                    constraint: "^29.0.0".to_string(),
                    constrained_by: "app".to_string(),
                    dep_type: DepType::Dev,
                    source_type: ProvenanceSourceType::Registry,
                    depth: 1,
                },
            ],
        }
    }

    #[test]
    fn test_provenance_source_type_equality() {
        assert_eq!(ProvenanceSourceType::Registry, ProvenanceSourceType::Registry);
        assert_ne!(ProvenanceSourceType::Registry, ProvenanceSourceType::Git);
    }

    #[test]
    fn test_resolution_provenance_construction() {
        let p = ResolutionProvenance {
            package_name: "lodash".to_string(),
            constraint: "^4.17.0".to_string(),
            constrained_by: "app".to_string(),
            dep_type: DepType::Runtime,
            source_type: ProvenanceSourceType::Registry,
            depth: 1,
        };
        assert_eq!(p.package_name, "lodash");
        assert_eq!(p.depth, 1);
    }

    #[test]
    fn test_provenance_direct_dep() {
        let p = ResolutionProvenance {
            package_name: "react".to_string(),
            constraint: "^18.0.0".to_string(),
            constrained_by: String::new(),
            dep_type: DepType::Runtime,
            source_type: ProvenanceSourceType::Registry,
            depth: 0,
        };
        assert!(p.constrained_by.is_empty());
    }

    #[test]
    fn test_provenance_for_found() {
        let lf = sample_lockfile();
        let p = lf.provenance_for("react").unwrap();
        assert_eq!(p.constraint, "^18.0.0");
        assert_eq!(p.constrained_by, "app");
    }

    #[test]
    fn test_provenance_for_missing() {
        let lf = sample_lockfile();
        assert!(lf.provenance_for("nonexistent").is_none());
    }

    #[test]
    fn test_packages_at_depth_0() {
        let lf = sample_lockfile();
        let at_zero = lf.packages_at_depth(0);
        assert_eq!(at_zero.len(), 1);
        assert_eq!(at_zero[0].package_name, "app");
    }

    #[test]
    fn test_packages_at_depth_1() {
        let lf = sample_lockfile();
        let at_one = lf.packages_at_depth(1);
        assert_eq!(at_one.len(), 2);
        let names: Vec<&str> = at_one.iter().map(|p| p.package_name.as_str()).collect();
        assert!(names.contains(&"react"));
        assert!(names.contains(&"jest"));
    }

    #[test]
    fn test_dependency_chain_from_leaf() {
        let lf = sample_lockfile();
        let chain = lf.dependency_chain("lodash");
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].package_name, "app");
        assert_eq!(chain[1].package_name, "react");
        assert_eq!(chain[2].package_name, "lodash");
    }

    #[test]
    fn test_dependency_chain_direct_dep() {
        let lf = sample_lockfile();
        let chain = lf.dependency_chain("react");
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[0].package_name, "app");
        assert_eq!(chain[1].package_name, "react");
    }

    #[test]
    fn test_dependency_chain_root() {
        let lf = sample_lockfile();
        let chain = lf.dependency_chain("app");
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].package_name, "app");
    }

    #[test]
    fn test_dependency_chain_missing() {
        let lf = sample_lockfile();
        let chain = lf.dependency_chain("nonexistent");
        assert!(chain.is_empty());
    }

    #[test]
    fn test_dependency_chain_cycle_safe() {
        let mut lf = sample_lockfile();
        lf.provenance.push(ResolutionProvenance {
            package_name: "app".to_string(),
            constraint: "^1.0.0".to_string(),
            constrained_by: "lodash".to_string(),
            dep_type: DepType::Runtime,
            source_type: ProvenanceSourceType::Registry,
            depth: 3,
        });
        let chain = lf.dependency_chain("lodash");
        assert!(!chain.is_empty());
    }
}
