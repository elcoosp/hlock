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

impl std::str::FromStr for AdvisorySeverity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "critical" => Ok(AdvisorySeverity::Critical),
            "high" => Ok(AdvisorySeverity::High),
            "medium" => Ok(AdvisorySeverity::Medium),
            "low" => Ok(AdvisorySeverity::Low),
            "info" => Ok(AdvisorySeverity::Info),
            _ => Err(()),
        }
    }
}

impl AdvisorySeverity {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            AdvisorySeverity::Critical => "critical",
            AdvisorySeverity::High => "high",
            AdvisorySeverity::Medium => "medium",
            AdvisorySeverity::Low => "low",
            AdvisorySeverity::Info => "info",
        }
    }

    #[must_use]
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

impl std::str::FromStr for PolicyType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "allow-hook" => Ok(PolicyType::AllowHook),
            "deny-hook" => Ok(PolicyType::DenyHook),
            "allow-script" => Ok(PolicyType::AllowScript),
            "deny-script" => Ok(PolicyType::DenyScript),
            "build-env" => Ok(PolicyType::BuildEnv),
            "engine" => Ok(PolicyType::Engine),
            _ => Err(()),
        }
    }
}

impl PolicyType {
    #[must_use]
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

impl std::str::FromStr for TrustRole {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "root" => Ok(TrustRole::Root),
            "targets" => Ok(TrustRole::Targets),
            "snapshot" => Ok(TrustRole::Snapshot),
            "delegation" => Ok(TrustRole::Delegation),
            _ => Err(()),
        }
    }
}

impl TrustRole {
    #[must_use]
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
pub struct AuditReport {
    pub critical: Vec<Advisory>,
    pub high: Vec<Advisory>,
    pub medium: Vec<Advisory>,
    pub low: Vec<Advisory>,
    pub info: Vec<Advisory>,
}

impl AuditReport {
    #[must_use]
    pub fn has_vulnerabilities(&self) -> bool {
        !self.critical.is_empty()
            || !self.high.is_empty()
            || !self.medium.is_empty()
            || !self.low.is_empty()
    }

    #[must_use]
    pub fn has_critical_or_high(&self) -> bool {
        !self.critical.is_empty() || !self.high.is_empty()
    }

    #[must_use]
    pub fn total_count(&self) -> usize {
        self.critical.len() + self.high.len() + self.medium.len() + self.low.len() + self.info.len()
    }

    pub fn all_advisories(&self) -> impl Iterator<Item = &Advisory> {
        self.critical
            .iter()
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

/// Glob matching for policy package patterns (spec §3):
/// - `*` matches everything;
/// - `prefix/*` matches names under `prefix/` — the `/` boundary is
///   required, so `@internal/*` matches `@internal/lodash` but **not**
///   `@internalx/y`;
/// - anything else is an exact match.
fn pattern_matches(pattern: &str, name: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return name.len() > prefix.len()
            && name.starts_with(prefix)
            && name.as_bytes()[prefix.len()] == b'/';
    }
    pattern == name
}

impl crate::lockfile::Lockfile {
    #[must_use]
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

        AuditReport {
            critical,
            high,
            medium,
            low,
            info,
        }
    }

    #[must_use]
    pub fn advisories_for(&self, package_name: &str) -> Vec<&Advisory> {
        self.advisories
            .iter()
            .filter(|a| a.package == package_name)
            .collect()
    }

    #[must_use]
    pub fn has_critical_advisory(&self, package_name: &str) -> bool {
        self.advisories.iter().any(|a| {
            a.package == package_name
                && matches!(
                    a.severity,
                    AdvisorySeverity::Critical | AdvisorySeverity::High
                )
        })
    }

    #[must_use]
    pub fn license_for(&self, package_name: &str) -> Option<&str> {
        self.licenses
            .iter()
            .find(|l| l.package == package_name)
            .map(|l| l.expression.as_str())
    }

    #[must_use]
    pub fn unlicensed_packages(&self) -> Vec<&crate::lockfile::Package> {
        let licensed: std::collections::HashSet<&str> =
            self.licenses.iter().map(|l| l.package.as_str()).collect();
        self.packages
            .iter()
            .filter(|p| !licensed.contains(p.name.as_str()))
            .collect()
    }

    #[must_use]
    pub fn hook_allowed(&self, package_name: &str, hook_name: &str) -> PolicyDecision {
        let mut specific_allow = false;
        let mut specific_deny = false;
        let mut wildcard_deny = false;
        let mut wildcard_allow = false;
        let mut deny_reason = String::new();

        for policy in &self.policies {
            match policy.policy_type {
                PolicyType::AllowHook => {
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == hook_name
                    {
                        if policy.package_pattern == "*" {
                            wildcard_allow = true;
                        } else {
                            specific_allow = true;
                        }
                    }
                }
                PolicyType::DenyHook
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == hook_name =>
                {
                    if policy.package_pattern == "*" {
                        wildcard_deny = true;
                        deny_reason = format!(
                            "Hook '{hook_name}' denied for '{package_name}' by wildcard policy"
                        );
                    } else {
                        specific_deny = true;
                        deny_reason = format!(
                            "Hook '{hook_name}' denied for '{package_name}' by specific policy"
                        );
                    }
                }
                _ => {}
            }
        }

        if specific_deny {
            return PolicyDecision::Denied {
                reason: deny_reason,
            };
        }

        if specific_allow {
            return PolicyDecision::Allowed;
        }

        if wildcard_deny {
            return PolicyDecision::Denied {
                reason: deny_reason,
            };
        }

        if wildcard_allow {
            return PolicyDecision::Allowed;
        }

        PolicyDecision::NoPolicy
    }

    /// Script policy decision.
    ///
    /// Uses the same precedence ladder as [`Self::hook_allowed`] (spec §3):
    /// specific-deny > specific-allow > wildcard-deny > wildcard-allow >
    /// no-policy.
    #[must_use]
    pub fn script_allowed(&self, package_name: &str, script_name: &str) -> PolicyDecision {
        let mut specific_allow = false;
        let mut specific_deny = false;
        let mut wildcard_deny = false;
        let mut wildcard_allow = false;
        let mut deny_reason = String::new();

        for policy in &self.policies {
            match policy.policy_type {
                PolicyType::AllowScript
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == script_name =>
                {
                    if policy.package_pattern == "*" {
                        wildcard_allow = true;
                    } else {
                        specific_allow = true;
                    }
                }
                PolicyType::DenyScript
                    if pattern_matches(&policy.package_pattern, package_name)
                        && policy.value == script_name =>
                {
                    if policy.package_pattern == "*" {
                        wildcard_deny = true;
                    } else {
                        specific_deny = true;
                    }
                    deny_reason =
                        format!("Script '{script_name}' denied for '{package_name}' by policy");
                }
                _ => {}
            }
        }

        if specific_deny {
            PolicyDecision::Denied {
                reason: deny_reason,
            }
        } else if specific_allow {
            PolicyDecision::Allowed
        } else if wildcard_deny {
            PolicyDecision::Denied {
                reason: deny_reason,
            }
        } else if wildcard_allow {
            PolicyDecision::Allowed
        } else {
            PolicyDecision::NoPolicy
        }
    }

    #[must_use]
    pub fn build_env_for(&self, package_name: &str) -> Option<&str> {
        self.policies
            .iter()
            .filter(|p| p.policy_type == PolicyType::BuildEnv)
            .find(|p| pattern_matches(&p.package_pattern, package_name))
            .map(|p| p.value.as_str())
    }

    #[must_use]
    pub fn engine_for(&self, package_name: &str) -> Option<&str> {
        self.policies
            .iter()
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

    #[must_use]
    pub fn trust_roots_for_role(&self, role: TrustRole) -> Vec<&TrustRoot> {
        self.trust_roots.iter().filter(|t| t.role == role).collect()
    }

    #[must_use]
    pub fn has_expired_root_key(&self, now_epoch: u64) -> bool {
        self.trust_roots
            .iter()
            .filter(|t| t.role == TrustRole::Root)
            .any(|t| t.expires_epoch != 0 && t.expires_epoch < now_epoch)
    }

    ///
    /// # Errors
    ///
    /// Returns `Err` if `MissingTrustRoot` occurs; if `TrustRootExpired` occurs;
    /// or if `TrustRootRotationInvalid` / `RotationSignatureInvalid` occurs for
    /// any attached rotation record.
    pub fn validate_trust_chain(&self, now_epoch: u64) -> Result<(), crate::error::Error> {
        self.validate_root_only_chain(now_epoch)?;
        self.validate_root_rotation(now_epoch)
    }

    /// Validates that root trust roots exist and are unexpired.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `MissingTrustRoot` or `TrustRootExpired` occurs.
    fn validate_root_only_chain(&self, now_epoch: u64) -> Result<(), crate::error::Error> {
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

    #[must_use]
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

    ///
    /// # Errors
    ///
    /// Returns `Err` if `TrustRootRotationInvalid` occurs, if `TrustRootExpired`
    /// occurs, or if `RotationSignatureInvalid` occurs when the rotation record
    /// is not signed by the old root key.
    pub fn validate_root_rotation(&self, now_epoch: u64) -> Result<(), crate::error::Error> {
        for rotation in &self.root_rotations {
            let Some(old_root) = self
                .trust_roots
                .iter()
                .find(|t| t.key_id == rotation.old_key_id && t.role == TrustRole::Root)
            else {
                return Err(crate::error::Error::TrustRootRotationInvalid {
                    reason: format!("old key '{}' not found as root", rotation.old_key_id),
                });
            };
            if old_root.expires_epoch != 0 && old_root.expires_epoch < now_epoch {
                return Err(crate::error::Error::TrustRootExpired {
                    key_id: old_root.key_id.clone(),
                    expires_epoch: old_root.expires_epoch,
                });
            }
            if rotation.new_expires_epoch != 0 && rotation.new_expires_epoch < now_epoch {
                return Err(crate::error::Error::TrustRootExpired {
                    key_id: rotation.new_key_id.clone(),
                    expires_epoch: rotation.new_expires_epoch,
                });
            }
            // The record must attribute its signature to the outgoing root;
            // a record claiming a different signer is malformed.
            if rotation.rotation_signature_key_id != rotation.old_key_id {
                return Err(crate::error::Error::RotationSignerMismatch {
                    claimed: rotation.rotation_signature_key_id.clone(),
                    expected: rotation.old_key_id.clone(),
                });
            }
            // v1.0: the rotation record itself must be signed by the old root
            // key over the canonical rotation payload (spec §2.3).
            crate::signature::verify_rotation_signature(
                rotation,
                &old_root.public_key,
                old_root.algorithm,
            )
            .map_err(|_| crate::error::Error::RotationSignatureInvalid {
                key_id: rotation.old_key_id.clone(),
            })?;
        }
        Ok(())
    }

    #[must_use]
    pub fn vex_for(
        &self,
        package_name: &str,
        advisory_id: &str,
    ) -> Option<&crate::lockfile::VexEntry> {
        self.vex_entries
            .iter()
            .find(|v| v.package == package_name && v.advisory_id == advisory_id)
    }

    #[must_use]
    pub fn effective_advisories(&self) -> AuditReport {
        let report = self.audit();
        let mut filtered = AuditReport {
            critical: Vec::new(),
            high: Vec::new(),
            medium: Vec::new(),
            low: Vec::new(),
            info: Vec::new(),
        };
        for adv in report.all_advisories() {
            let vex = self.vex_for(&adv.package, &adv.advisory_id);
            if let Some(
                crate::lockfile::VexStatus::NotAffected | crate::lockfile::VexStatus::Fixed,
            ) = vex.map(|v| &v.status)
            {
                continue;
            }
            match adv.severity {
                AdvisorySeverity::Critical => filtered.critical.push(adv.clone()),
                AdvisorySeverity::High => filtered.high.push(adv.clone()),
                AdvisorySeverity::Medium => filtered.medium.push(adv.clone()),
                AdvisorySeverity::Low => filtered.low.push(adv.clone()),
                AdvisorySeverity::Info => filtered.info.push(adv.clone()),
            }
        }
        filtered
    }

    #[must_use]
    pub fn dedup_opportunities(&self) -> Vec<DedupOpportunity> {
        use std::collections::BTreeMap;
        let mut by_name: BTreeMap<&str, Vec<&crate::lockfile::Package>> = BTreeMap::new();
        for pkg in &self.packages {
            by_name.entry(&pkg.name).or_default().push(pkg);
        }

        let mut opportunities = Vec::new();
        for (name, versions) in &by_name {
            if versions.len() > 1 {
                let ver_strings: Vec<String> = versions
                    .iter()
                    .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
                    .collect();
                let ver_count = ver_strings.len();
                let estimated_size: usize = ver_strings
                    .iter()
                    .map(|v| v.len() + 120 + 80 + 30)
                    .sum::<usize>()
                    / ver_count.max(1);
                opportunities.push(DedupOpportunity {
                    package_name: name.to_string(),
                    versions: ver_strings,
                    potential_saving_bytes: estimated_size.saturating_sub(232)
                        * ver_count.saturating_sub(1),
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
            root_rotations: vec![],
            vex_entries: vec![],
            compat: None,
        }
    }

    #[test]
    fn test_advisory_severity_roundtrip() {
        for s in &["critical", "high", "medium", "low", "info"] {
            let sev: AdvisorySeverity = s.parse().unwrap();
            assert_eq!(sev.as_str(), *s);
        }
    }

    #[test]
    fn test_advisory_severity_invalid() {
        assert!("urgent".parse::<AdvisorySeverity>().is_err());
    }

    #[test]
    fn test_policy_type_roundtrip() {
        for s in &[
            "allow-hook",
            "deny-hook",
            "allow-script",
            "deny-script",
            "build-env",
            "engine",
        ] {
            let pt: PolicyType = s.parse().unwrap();
            assert_eq!(pt.as_str(), *s);
        }
    }

    #[test]
    fn test_trust_role_roundtrip() {
        for s in &["root", "targets", "snapshot", "delegation"] {
            let role: TrustRole = s.parse().unwrap();
            assert_eq!(role.as_str(), *s);
        }
    }

    #[test]
    fn test_audit_report_empty() {
        let report = AuditReport {
            critical: vec![],
            high: vec![],
            medium: vec![],
            low: vec![],
            info: vec![],
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
            high: vec![],
            medium: vec![],
            low: vec![],
            info: vec![],
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
        assert!(matches!(
            lf.hook_allowed("pkg", "postinstall"),
            PolicyDecision::NoPolicy
        ));
    }

    #[test]
    fn test_hook_allowed_deny_wins() {
        let lf = Lockfile {
            policies: vec![
                Policy {
                    policy_type: PolicyType::DenyHook,
                    package_pattern: "evil".to_string(),
                    value: "postinstall".to_string(),
                },
                Policy {
                    policy_type: PolicyType::AllowHook,
                    package_pattern: "*".to_string(),
                    value: "postinstall".to_string(),
                },
            ],
            ..empty_lockfile()
        };
        assert!(matches!(
            lf.hook_allowed("evil", "postinstall"),
            PolicyDecision::Denied { .. }
        ));
        assert!(matches!(
            lf.hook_allowed("good", "postinstall"),
            PolicyDecision::Allowed
        ));
    }

    #[test]
    fn test_hook_allowed_allow() {
        let lf = Lockfile {
            policies: vec![
                Policy {
                    policy_type: PolicyType::AllowHook,
                    package_pattern: "lodash".to_string(),
                    value: "postinstall".to_string(),
                },
                Policy {
                    policy_type: PolicyType::DenyHook,
                    package_pattern: "*".to_string(),
                    value: "postinstall".to_string(),
                },
            ],
            ..empty_lockfile()
        };
        assert!(matches!(
            lf.hook_allowed("lodash", "postinstall"),
            PolicyDecision::Allowed
        ));
    }

    #[test]
    fn test_build_env_for() {
        let lf = Lockfile {
            policies: vec![Policy {
                policy_type: PolicyType::BuildEnv,
                package_pattern: "*".to_string(),
                value: "node>=20.11.0".to_string(),
            }],
            ..empty_lockfile()
        };
        assert_eq!(lf.build_env_for("any-pkg"), Some("node>=20.11.0"));
    }

    #[test]
    fn test_engine_for() {
        let lf = Lockfile {
            policies: vec![Policy {
                policy_type: PolicyType::Engine,
                package_pattern: "app".to_string(),
                value: "node>=22.0.0".to_string(),
            }],
            ..empty_lockfile()
        };
        assert_eq!(lf.engine_for("app"), Some("node>=22.0.0"));
        assert_eq!(lf.engine_for("other"), None);
    }

    #[test]
    fn test_license_for() {
        let lf = Lockfile {
            licenses: vec![LicenseEntry {
                package: "lodash".to_string(),
                expression: "MIT".to_string(),
            }],
            ..empty_lockfile()
        };
        assert_eq!(lf.license_for("lodash"), Some("MIT"));
        assert_eq!(lf.license_for("unknown"), None);
    }

    #[test]
    fn test_unlicensed_packages() {
        let lf = Lockfile {
            licenses: vec![LicenseEntry {
                package: "lodash".to_string(),
                expression: "MIT".to_string(),
            }],
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
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
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
                crate::lockfile::Mirror {
                    scope: "@internal".to_string(),
                    url: "https://npm.company.com/".to_string(),
                },
                crate::lockfile::Mirror {
                    scope: "*".to_string(),
                    url: "https://registry.npmmirror.org/".to_string(),
                },
            ],
            ..empty_lockfile()
        };
        assert_eq!(
            lf.registry_for("@internal/auth"),
            "https://npm.company.com/"
        );
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
                Package {
                    name: "a".to_string(),
                    source_idx: 0,
                    major: 1,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
                Package {
                    name: "b".to_string(),
                    source_idx: 0,
                    major: 2,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
            ],
            ..empty_lockfile()
        };
        assert!(
            lf.dedup_opportunities().is_empty(),
            "expected empty, got: {:?}",
            lf.dedup_opportunities()
        );
    }

    #[test]
    fn test_dedup_single_opportunity() {
        let lf = Lockfile {
            packages: vec![
                Package {
                    name: "lodash".to_string(),
                    source_idx: 0,
                    major: 4,
                    minor: 17,
                    patch: 20,
                    ..Package::default()
                },
                Package {
                    name: "lodash".to_string(),
                    source_idx: 0,
                    major: 4,
                    minor: 17,
                    patch: 21,
                    ..Package::default()
                },
            ],
            ..empty_lockfile()
        };
        let opps = lf.dedup_opportunities();
        assert_eq!(opps.len(), 1);
        assert_eq!(opps[0].package_name, "lodash");
        assert_eq!(opps[0].versions.len(), 2);
    }

    #[test]
    fn test_root_rotation_rejects_non_root() {
        let lf = Lockfile {
            trust_roots: vec![TrustRoot {
                key_id: "targets@key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![0u8; 32],
                expires_epoch: 0,
                role: TrustRole::Targets,
            }],
            root_rotations: vec![crate::lockfile::TrustRootRotation {
                old_key_id: "targets@key".to_string(),
                new_key_id: "new@key".to_string(),
                threshold: 1,
                new_algorithm: SignatureAlgorithm::Ed25519,
                new_public_key: vec![0u8; 32],
                new_expires_epoch: 0,
                new_role: TrustRole::Root,
                rotation_signature_key_id: "targets@key".to_string(),
                rotation_signature: vec![],
            }],
            ..empty_lockfile()
        };
        let result = lf.validate_root_rotation(0);
        assert!(
            result.is_err(),
            "expected rotation from non-root key to be rejected"
        );
        match result.unwrap_err() {
            crate::error::Error::TrustRootRotationInvalid { reason } => {
                assert!(
                    reason.contains("targets@key"),
                    "reason should mention the key: {reason}"
                );
            }
            other => panic!("expected TrustRootRotationInvalid, got {other:?}"),
        }
    }
}
