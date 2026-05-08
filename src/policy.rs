use crate::signature::SignatureAlgorithm;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvisorySeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl AdvisorySeverity {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "critical" => Some(AdvisorySeverity::Critical),
            "high" => Some(AdvisorySeverity::High),
            "medium" => Some(AdvisorySeverity::Medium),
            "low" => Some(AdvisorySeverity::Low),
            "info" => Some(AdvisorySeverity::Info),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            AdvisorySeverity::Critical => "critical",
            AdvisorySeverity::High => "high",
            AdvisorySeverity::Medium => "medium",
            AdvisorySeverity::Low => "low",
            AdvisorySeverity::Info => "info",
        }
    }

    pub fn ordinal(&self) -> u8 {
        match self {
            AdvisorySeverity::Critical => 0,
            AdvisorySeverity::High => 1,
            AdvisorySeverity::Medium => 2,
            AdvisorySeverity::Low => 3,
            AdvisorySeverity::Info => 4,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub package: String,
    pub advisory_id: String,
    pub severity: AdvisorySeverity,
    pub url: String,
    pub affected_versions: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseEntry {
    pub package: String,
    pub expression: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyType {
    AllowHook,
    DenyHook,
    AllowScript,
    DenyScript,
    BuildEnv,
    Engine,
}

impl PolicyType {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "allow-hook" => Some(PolicyType::AllowHook),
            "deny-hook" => Some(PolicyType::DenyHook),
            "allow-script" => Some(PolicyType::AllowScript),
            "deny-script" => Some(PolicyType::DenyScript),
            "build-env" => Some(PolicyType::BuildEnv),
            "engine" => Some(PolicyType::Engine),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyType::AllowHook => "allow-hook",
            PolicyType::DenyHook => "deny-hook",
            PolicyType::AllowScript => "allow-script",
            PolicyType::DenyScript => "deny-script",
            PolicyType::BuildEnv => "build-env",
            PolicyType::Engine => "engine",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub policy_type: PolicyType,
    pub package_pattern: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustRole {
    Root,
    Targets,
    Snapshot,
    Delegation,
}

impl TrustRole {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "root" => Some(TrustRole::Root),
            "targets" => Some(TrustRole::Targets),
            "snapshot" => Some(TrustRole::Snapshot),
            "delegation" => Some(TrustRole::Delegation),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TrustRole::Root => "root",
            TrustRole::Targets => "targets",
            TrustRole::Snapshot => "snapshot",
            TrustRole::Delegation => "delegation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    pub key_id: String,
    pub algorithm: SignatureAlgorithm,
    pub public_key: Vec<u8>,
    pub expires_epoch: u64,
    pub role: TrustRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub scope: String,
    pub url: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub critical: Vec<Advisory>,
    pub high: Vec<Advisory>,
    pub medium: Vec<Advisory>,
    pub low: Vec<Advisory>,
    pub info: Vec<Advisory>,
}

impl AuditReport {
    pub fn has_vulnerabilities(&self) -> bool {
        !self.critical.is_empty() || !self.high.is_empty()
            || !self.medium.is_empty() || !self.low.is_empty()
    }

    pub fn has_critical_or_high(&self) -> bool {
        !self.critical.is_empty() || !self.high.is_empty()
    }

    pub fn total_count(&self) -> usize {
        self.critical.len() + self.high.len() + self.medium.len()
            + self.low.len() + self.info.len()
    }

    pub fn all_advisories(&self) -> impl Iterator<Item = &Advisory> {
        self.critical.iter()
            .chain(self.high.iter())
            .chain(self.medium.iter())
            .chain(self.low.iter())
            .chain(self.info.iter())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allowed,
    Denied { reason: String },
    NoPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyViolation {
    pub policy_type: PolicyType,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct PolicyReport {
    pub package: String,
    pub hook_decisions: HashMap<String, PolicyDecision>,
    pub build_env: Option<String>,
    pub engine: Option<String>,
    pub violations: Vec<PolicyViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DedupOpportunity {
    pub package_name: String,
    pub versions: Vec<String>,
    pub potential_saving_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct TrustVerification {
    pub verified_by: Vec<String>,
    pub algorithm: SignatureAlgorithm,
    pub role: TrustRole,
}

fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        return name.starts_with(prefix);
    }
    pattern == name
}

impl crate::lockfile::Lockfile {
    pub fn audit(&self) -> AuditReport {
        let mut critical = Vec::new();
        let mut high = Vec::new();
        let mut medium = Vec::new();
        let mut low = Vec::new();
        let mut info = Vec::new();

        for adv in &self.advisories {
            match adv.severity {
                AdvisorySeverity::Critical => critical.push(adv.clone()),
                AdvisorySeverity::High => high.push(adv.clone()),
                AdvisorySeverity::Medium => medium.push(adv.clone()),
                AdvisorySeverity::Low => low.push(adv.clone()),
                AdvisorySeverity::Info => info.push(adv.clone()),
            }
        }

        AuditReport { critical, high, medium, low, info }
    }

    pub fn advisories_for(&self, package_name: &str) -> Vec<&Advisory> {
        self.advisories.iter().filter(|a| a.package == package_name).collect()
    }

    pub fn has_critical_advisory(&self, package_name: &str) -> bool {
        self.advisories.iter().any(|a| {
            a.package == package_name
                && matches!(a.severity, AdvisorySeverity::Critical | AdvisorySeverity::High)
        })
    }

    pub fn license_for(&self, package_name: &str) -> Option<&str> {
        self.licenses.iter()
            .find(|l| l.package == package_name)
            .map(|l| l.expression.as_str())
    }

    pub fn unlicensed_packages(&self) -> Vec<&crate::lockfile::Package> {
        let licensed: std::collections::HashSet<&str> = self.licenses.iter()
            .map(|l| l.package.as_str())
            .collect();
        self.packages.iter()
            .filter(|p| !licensed.contains(p.name.as_str()))
            .collect()
    }

    pub fn hook_allowed(&self, package_name: &str, hook_name: &str) -> PolicyDecision {
        let mut allowed = false;
        let mut denied = false;
        let mut deny_reason = String::new();

        for policy in &self.policies {
            match policy.policy_type {
                PolicyType::AllowHook => {
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == hook_name
                    {
                        allowed = true;
                    }
                }
                PolicyType::DenyHook => {
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == hook_name
                    {
                        denied = true;
                        deny_reason = format!("Hook '{}' denied for '{}' by policy", hook_name, package_name);
                    }
                }
                _ => {}
            }
        }

        if denied {
            PolicyDecision::Denied { reason: deny_reason }
        } else if allowed {
            PolicyDecision::Allowed
        } else {
            PolicyDecision::NoPolicy
        }
    }

    pub fn script_allowed(&self, package_name: &str, script_name: &str) -> PolicyDecision {
        let mut allowed = false;
        let mut denied = false;
        let mut deny_reason = String::new();

        for policy in &self.policies {
            match policy.policy_type {
                PolicyType::AllowScript => {
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == script_name
                    {
                        allowed = true;
                    }
                }
                PolicyType::DenyScript => {
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == script_name
                    {
                        denied = true;
                        deny_reason = format!("Script '{}' denied for '{}' by policy", script_name, package_name);
                    }
                }
                _ => {}
            }
        }

        if denied {
            PolicyDecision::Denied { reason: deny_reason }
        } else if allowed {
            PolicyDecision::Allowed
        } else {
            PolicyDecision::NoPolicy
        }
    }

    pub fn build_env_for(&self, package_name: &str) -> Option<&str> {
        self.policies.iter()
            .filter(|p| p.policy_type == PolicyType::BuildEnv)
            .find(|p| pattern_matches(&p.package_pattern, package_name))
            .map(|p| p.value.as_str())
    }

    pub fn engine_for(&self, package_name: &str) -> Option<&str> {
        self.policies.iter()
            .filter(|p| p.policy_type == PolicyType::Engine)
            .find(|p| pattern_matches(&p.package_pattern, package_name))
            .map(|p| p.value.as_str())
    }

    pub fn evaluate_policies(&self, package_name: &str) -> PolicyReport {
        let mut hook_decisions = HashMap::new();
        let mut violations = Vec::new();

        for pkg in &self.packages {
            if pkg.name == package_name {
                for sh in &pkg.hook_hashes {
                    let decision = self.hook_allowed(package_name, &sh.hook_type);
                    if let PolicyDecision::Denied { ref reason } = decision {
                        violations.push(PolicyViolation {
                            policy_type: PolicyType::DenyHook,
                            message: reason.clone(),
                        });
                    }
                    hook_decisions.insert(sh.hook_type.clone(), decision);
                }
                break;
            }
        }

        PolicyReport {
            package: package_name.to_string(),
            hook_decisions,
            build_env: self.build_env_for(package_name).map(String::from),
            engine: self.engine_for(package_name).map(String::from),
            violations,
        }
    }

    pub fn trust_roots_for_role(&self, role: TrustRole) -> Vec<&TrustRoot> {
        self.trust_roots.iter().filter(|t| t.role == role).collect()
    }

    pub fn has_expired_root_key(&self, now_epoch: u64) -> bool {
        self.trust_roots.iter()
            .filter(|t| t.role == TrustRole::Root)
            .any(|t| t.expires_epoch != 0 && t.expires_epoch < now_epoch)
    }

    pub fn validate_trust_chain(&self, now_epoch: u64) -> Result<(), crate::error::Error> {
        let roots: Vec<&TrustRoot> = self.trust_roots_for_role(TrustRole::Root);
        if roots.is_empty() {
            return Err(crate::error::Error::MissingTrustRoot);
        }
        for root in roots {
            if root.expires_epoch != 0 && root.expires_epoch < now_epoch {
                return Err(crate::error::Error::TrustRootExpired {
                    key_id: root.key_id.clone(),
                    expires_epoch: root.expires_epoch,
                });
            }
        }
        Ok(())
    }

    pub fn registry_for(&self, package_name: &str) -> &str {
        let scope = if package_name.starts_with('@') {
            package_name.split('/').next().unwrap_or("*")
        } else {
            "*"
        };

        for mirror in &self.mirrors {
            if mirror.scope == scope {
                return &mirror.url;
            }
        }

        for mirror in &self.mirrors {
            if mirror.scope == "*" {
                return &mirror.url;
            }
        }

        self.sources.first().map_or("", |s| match s {
            crate::lockfile::Source::Registry(url) => url.as_str(),
            _ => "",
        })
    }

    pub fn dedup_opportunities(&self) -> Vec<DedupOpportunity> {
        use std::collections::BTreeMap;
        let mut by_name: BTreeMap<&str, Vec<&crate::lockfile::Package>> = BTreeMap::new();
        for pkg in &self.packages {
            by_name.entry(&pkg.name).or_default().push(pkg);
        }

        let mut opportunities = Vec::new();
        for (name, versions) in &by_name {
            if versions.len() > 1 {
                let ver_strings: Vec<String> = versions.iter()
                    .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
                    .collect();
                opportunities.push(DedupOpportunity {
                    package_name: name.to_string(),
                    versions: ver_strings,
                    potential_saving_bytes: 0,
                });
            }
        }
        opportunities
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{Lockfile, Package, Source};

    fn empty_lockfile() -> Lockfile {
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
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            compat: None,
        }
    }

    #[test]
    fn test_advisory_severity_roundtrip() {
        for s in &["critical", "high", "medium", "low", "info"] {
            let sev = AdvisorySeverity::from_str(s).unwrap();
            assert_eq!(sev.as_str(), *s);
        }
    }

    #[test]
    fn test_advisory_severity_invalid() {
        assert!(AdvisorySeverity::from_str("urgent").is_none());
    }

    #[test]
    fn test_policy_type_roundtrip() {
        for s in &["allow-hook", "deny-hook", "allow-script", "deny-script", "build-env", "engine"] {
            let pt = PolicyType::from_str(s).unwrap();
            assert_eq!(pt.as_str(), *s);
        }
    }

    #[test]
    fn test_trust_role_roundtrip() {
        for s in &["root", "targets", "snapshot", "delegation"] {
            let role = TrustRole::from_str(s).unwrap();
            assert_eq!(role.as_str(), *s);
        }
    }

    #[test]
    fn test_audit_report_empty() {
        let report = AuditReport {
            critical: vec![], high: vec![], medium: vec![], low: vec![], info: vec![],
        };
        assert!(!report.has_vulnerabilities());
        assert!(!report.has_critical_or_high());
        assert_eq!(report.total_count(), 0);
    }

    #[test]
    fn test_audit_report_with_critical() {
        let report = AuditReport {
            critical: vec![Advisory {
                package: "lodash".to_string(),
                advisory_id: "CVE-2024-12345".to_string(),
                severity: AdvisorySeverity::Critical,
                url: String::new(),
                affected_versions: "<4.17.21".to_string(),
            }],
            high: vec![], medium: vec![], low: vec![], info: vec![],
        };
        assert!(report.has_vulnerabilities());
        assert!(report.has_critical_or_high());
        assert_eq!(report.total_count(), 1);
    }

    #[test]
    fn test_pattern_matches_wildcard() {
        assert!(pattern_matches("*", "anything"));
        assert!(pattern_matches("*", "@scope/pkg"));
    }

    #[test]
    fn test_pattern_matches_scope_glob() {
        assert!(pattern_matches("@internal/*", "@internal/auth"));
        assert!(!pattern_matches("@internal/*", "@other/auth"));
        assert!(!pattern_matches("@internal/*", "internal"));
    }

    #[test]
    fn test_pattern_matches_exact() {
        assert!(pattern_matches("lodash", "lodash"));
        assert!(!pattern_matches("lodash", "underscore"));
    }

    #[test]
    fn test_hook_allowed_no_policy() {
        let lf = empty_lockfile();
        assert!(matches!(lf.hook_allowed("pkg", "postinstall"), PolicyDecision::NoPolicy));
    }

    #[test]
    fn test_hook_allowed_deny_wins() {
        let lf = Lockfile {
            policies: vec![
                Policy { policy_type: PolicyType::AllowHook, package_pattern: "*".to_string(), value: "postinstall".to_string() },
                Policy { policy_type: PolicyType::DenyHook, package_pattern: "evil".to_string(), value: "postinstall".to_string() },
            ],
            ..empty_lockfile()
        };
        assert!(matches!(lf.hook_allowed("evil", "postinstall"), PolicyDecision::Denied { .. }));
    }

    #[test]
    fn test_hook_allowed_allow() {
        let lf = Lockfile {
            policies: vec![
                Policy { policy_type: PolicyType::DenyHook, package_pattern: "*".to_string(), value: "postinstall".to_string() },
                Policy { policy_type: PolicyType::AllowHook, package_pattern: "lodash".to_string(), value: "postinstall".to_string() },
            ],
            ..empty_lockfile()
        };
        assert!(matches!(lf.hook_allowed("lodash", "postinstall"), PolicyDecision::Allowed));
    }

    #[test]
    fn test_build_env_for() {
        let lf = Lockfile {
            policies: vec![
                Policy { policy_type: PolicyType::BuildEnv, package_pattern: "*".to_string(), value: "node>=20.11.0".to_string() },
            ],
            ..empty_lockfile()
        };
        assert_eq!(lf.build_env_for("any-pkg"), Some("node>=20.11.0"));
    }

    #[test]
    fn test_engine_for() {
        let lf = Lockfile {
            policies: vec![
                Policy { policy_type: PolicyType::Engine, package_pattern: "app".to_string(), value: "node>=22.0.0".to_string() },
            ],
            ..empty_lockfile()
        };
        assert_eq!(lf.engine_for("app"), Some("node>=22.0.0"));
        assert_eq!(lf.engine_for("other"), None);
    }

    #[test]
    fn test_license_for() {
        let lf = Lockfile {
            licenses: vec![LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() }],
            ..empty_lockfile()
        };
        assert_eq!(lf.license_for("lodash"), Some("MIT"));
        assert_eq!(lf.license_for("unknown"), None);
    }

    #[test]
    fn test_unlicensed_packages() {
        let lf = Lockfile {
            licenses: vec![LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() }],
            packages: vec![
                Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 21, ..Package::default() },
                Package { name: "react".to_string(), source_idx: 0, major: 18, minor: 0, patch: 0, ..Package::default() },
            ],
            ..empty_lockfile()
        };
        let unlicensed = lf.unlicensed_packages();
        assert_eq!(unlicensed.len(), 1);
        assert_eq!(unlicensed[0].name, "react");
    }

    #[test]
    fn test_registry_for_mirror() {
        let lf = Lockfile {
            mirrors: vec![
                Mirror { scope: "@internal".to_string(), url: "https://npm.company.com/".to_string() },
                Mirror { scope: "*".to_string(), url: "https://registry.npmmirror.org/".to_string() },
            ],
            ..empty_lockfile()
        };
        assert_eq!(lf.registry_for("@internal/auth"), "https://npm.company.com/");
        assert_eq!(lf.registry_for("lodash"), "https://registry.npmmirror.org/");
    }

    #[test]
    fn test_trust_chain_no_root() {
        let lf = empty_lockfile();
        assert!(lf.validate_trust_chain(0).is_err());
    }

    #[test]
    fn test_trust_chain_expired() {
        let lf = Lockfile {
            trust_roots: vec![TrustRoot {
                key_id: "old@key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![0u8; 32],
                expires_epoch: 1000,
                role: TrustRole::Root,
            }],
            ..empty_lockfile()
        };
        assert!(lf.validate_trust_chain(2000).is_err());
    }

    #[test]
    fn test_dedup_no_opportunities() {
        let lf = Lockfile {
            packages: vec![
                Package { name: "a".to_string(), source_idx: 0, major: 1, minor: 0, patch: 0, ..Package::default() },
                Package { name: "b".to_string(), source_idx: 0, major: 2, minor: 0, patch: 0, ..Package::default() },
            ],
            ..empty_lockfile()
        };
        assert!(lf.dedup_opportunities().is_empty());
    }

    #[test]
    fn test_dedup_single_opportunity() {
        let lf = Lockfile {
            packages: vec![
                Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 20, ..Package::default() },
                Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 21, ..Package::default() },
            ],
            ..empty_lockfile()
        };
        let opps = lf.dedup_opportunities();
        assert_eq!(opps.len(), 1);
        assert_eq!(opps[0].package_name, "lodash");
        assert_eq!(opps[0].versions.len(), 2);
    }
}
