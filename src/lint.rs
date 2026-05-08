use crate::lockfile::Lockfile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintFinding {
    pub rule: String,
    pub severity: LintSeverity,
    pub package: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct LintReport {
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    pub fn has_errors(&self) -> bool {
        self.findings.iter().any(|f| f.severity == LintSeverity::Error)
    }

    pub fn errors(&self) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter().filter(|f| f.severity == LintSeverity::Error)
    }

    pub fn warnings(&self) -> impl Iterator<Item = &LintFinding> {
        self.findings.iter().filter(|f| f.severity == LintSeverity::Warning)
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

pub trait LintRule: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding>;
}

pub fn lint(lockfile: &Lockfile, rules: &[Box<dyn LintRule>]) -> LintReport {
    let mut findings = Vec::new();
    for rule in rules {
        findings.extend(rule.check(lockfile));
    }
    findings.sort_by(|a, b| {
        let sev_ord = |s: &LintSeverity| match s {
            LintSeverity::Error => 0,
            LintSeverity::Warning => 1,
            LintSeverity::Info => 2,
        };
        sev_ord(&a.severity).cmp(&sev_ord(&b.severity))
            .then_with(|| a.package.cmp(&b.package))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    LintReport { findings }
}

pub struct NoGitUrls;

impl LintRule for NoGitUrls {
    fn name(&self) -> &str { "no-git-urls" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            if let Some(crate::lockfile::Source::Git(_)) = lockfile.sources.get(pkg.source_idx) {
                findings.push(LintFinding {
                    rule: "no-git-urls".to_string(),
                    severity: LintSeverity::Error,
                    package: Some(pkg.name.clone()),
                    message: format!("Package '{}' uses a git URL source which is non-reproducible", pkg.name),
                });
            }
        }
        findings
    }
}

pub struct RequireIntegrity;

impl LintRule for RequireIntegrity {
    fn name(&self) -> &str { "require-integrity" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            if let Some(source) = lockfile.sources.get(pkg.source_idx) {
                if !matches!(source, crate::lockfile::Source::Workspace) && pkg.hashes.is_empty() {
                    findings.push(LintFinding {
                        rule: "require-integrity".to_string(),
                        severity: LintSeverity::Error,
                        package: Some(pkg.name.clone()),
                        message: format!("Package '{}' has no integrity hashes", pkg.name),
                    });
                }
            }
        }
        findings
    }
}

pub struct NoSha1;

impl LintRule for NoSha1 {
    fn name(&self) -> &str { "no-sha1" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            for h in &pkg.hashes {
                if matches!(h.algo, crate::lockfile::HashAlgorithm::Sha1) {
                    findings.push(LintFinding {
                        rule: "no-sha1".to_string(),
                        severity: LintSeverity::Warning,
                        package: Some(pkg.name.clone()),
                        message: format!("Package '{}' uses deprecated SHA-1 hash", pkg.name),
                    });
                }
            }
        }
        findings
    }
}

pub struct NoPeerAsRuntime;

impl LintRule for NoPeerAsRuntime {
    fn name(&self) -> &str { "no-peer-as-runtime" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            for dep in &pkg.dependencies {
                if matches!(dep.dep_type, crate::lockfile::DepType::Peer) {
                    findings.push(LintFinding {
                        rule: "no-peer-as-runtime".to_string(),
                        severity: LintSeverity::Warning,
                        package: Some(pkg.name.clone()),
                        message: format!(
                            "Package '{}' has a peer dependency '{}' declared as a runtime dependency",
                            pkg.name, dep.name
                        ),
                    });
                }
            }
        }
        findings
    }
}

pub struct MaxDepth {
    pub max: u32,
}

impl LintRule for MaxDepth {
    fn name(&self) -> &str { "max-depth" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for prov in &lockfile.provenance {
            if prov.depth > self.max {
                findings.push(LintFinding {
                    rule: "max-depth".to_string(),
                    severity: LintSeverity::Warning,
                    package: Some(prov.package_name.clone()),
                    message: format!(
                        "Package '{}' is at depth {}, exceeding maximum {}",
                        prov.package_name, prov.depth, self.max
                    ),
                });
            }
        }
        findings
    }
}

pub struct RequireAttestation;

impl LintRule for RequireAttestation {
    fn name(&self) -> &str { "require-attestation" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            if let Some(source) = lockfile.sources.get(pkg.source_idx) {
                if matches!(source, crate::lockfile::Source::Workspace) {
                    continue;
                }
                if !pkg.hashes.is_empty() {
                    let has_attestation = pkg.hashes.iter().any(|h| !matches!(h.attestation, crate::lockfile::Attestation::None));
                    if !has_attestation {
                        findings.push(LintFinding {
                            rule: "require-attestation".to_string(),
                            severity: LintSeverity::Info,
                            package: Some(pkg.name.clone()),
                            message: format!("Package '{}' has no supply chain attestation", pkg.name),
                        });
                    }
                }
            }
        }
        findings
    }
}

pub fn lint_default(lockfile: &Lockfile) -> LintReport {
    let rules: Vec<Box<dyn LintRule>> = vec![
        Box::new(NoGitUrls),
        Box::new(RequireIntegrity),
        Box::new(NoSha1),
        Box::new(NoPeerAsRuntime),
        Box::new(MaxDepth { max: 5 }),
        Box::new(RequireAttestation),
        Box::new(NoKnownVulnerabilities),
        Box::new(RequireLicense),
        Box::new(DenyCopyleft),
        Box::new(RequireTrustRoot),
        Box::new(NoExpiredKeys),
        Box::new(DenyPostinstall),
    ];
    lint(lockfile, &rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{
        Attestation, DepType, HashAlgorithm, IntegrityHash, Package, Source,
    };
    use crate::provenance::{ProvenanceSourceType, ResolutionProvenance};

    fn empty_lockfile() -> Lockfile {
        Lockfile {
            sources: vec![Source::Registry("r".to_string())],
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
            licenses: vec![crate::policy::LicenseEntry { package: "pkg".to_string(), expression: "MIT".to_string() }],
            policies: vec![],
            trust_roots: vec![crate::policy::TrustRoot {
                key_id: "test@key".to_string(),
                algorithm: crate::signature::SignatureAlgorithm::Ed25519,
                public_key: vec![0u8; 32],
                expires_epoch: 0,
                role: crate::policy::TrustRole::Root,
            }],
            mirrors: vec![],
            compat: None,
        }
    }

    struct AlwaysError;
    impl LintRule for AlwaysError {
        fn name(&self) -> &str { "always-error" }
        fn check(&self, _lockfile: &Lockfile) -> Vec<LintFinding> {
            vec![LintFinding {
                rule: "always-error".to_string(),
                severity: LintSeverity::Error,
                package: None,
                message: "always fails".to_string(),
            }]
        }
    }

    struct AlwaysWarning;
    impl LintRule for AlwaysWarning {
        fn name(&self) -> &str { "always-warning" }
        fn check(&self, _lockfile: &Lockfile) -> Vec<LintFinding> {
            vec![LintFinding {
                rule: "always-warning".to_string(),
                severity: LintSeverity::Warning,
                package: Some("pkg".to_string()),
                message: "warning msg".to_string(),
            }]
        }
    }

    #[test]
    fn test_lint_custom_rule() {
        let lf = empty_lockfile();
        let rules: Vec<Box<dyn LintRule>> = vec![Box::new(AlwaysError)];
        let report = lint(&lf, &rules);
        assert!(report.has_errors());
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn test_lint_report_empty() {
        let report = LintReport { findings: vec![] };
        assert!(report.is_empty());
        assert!(!report.has_errors());
    }

    #[test]
    fn test_lint_report_sorted() {
        let lf = empty_lockfile();
        let rules: Vec<Box<dyn LintRule>> = vec![
            Box::new(AlwaysWarning),
            Box::new(AlwaysError),
        ];
        let report = lint(&lf, &rules);
        assert_eq!(report.findings[0].severity, LintSeverity::Error);
        assert_eq!(report.findings[1].severity, LintSeverity::Warning);
    }

    fn lockfile_with_git_source() -> Lockfile {
        Lockfile {
            sources: vec![Source::Git("git+https://github.com/pkg.git".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                ..Package::default()
            }],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![crate::policy::LicenseEntry { package: "pkg".to_string(), expression: "MIT".to_string() }],
            policies: vec![],
            trust_roots: vec![crate::policy::TrustRoot {
                key_id: "test@key".to_string(),
                algorithm: crate::signature::SignatureAlgorithm::Ed25519,
                public_key: vec![0u8; 32],
                expires_epoch: 0,
                role: crate::policy::TrustRole::Root,
            }],
            mirrors: vec![],
            compat: None,
        }
    }

    #[test]
    fn test_lint_no_git_urls_pass() {
        let lf = empty_lockfile();
        let rule = NoGitUrls;
        assert!(rule.check(&lf).is_empty());
    }

    #[test]
    fn test_lint_no_git_urls_fail() {
        let lf = lockfile_with_git_source();
        let rule = NoGitUrls;
        let findings = rule.check(&lf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Error);
    }

    #[test]
    fn test_lint_require_integrity_pass() {
        let lf = Lockfile {
            sources: vec![Source::Registry("r".to_string())],
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![0u8; 32],
                    attestation: Attestation::None,
                }],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = RequireIntegrity;
        assert!(rule.check(&lf).is_empty());
    }

    #[test]
    fn test_lint_require_integrity_fail() {
        let lf = Lockfile {
            sources: vec![Source::Registry("r".to_string())],
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = RequireIntegrity;
        let findings = rule.check(&lf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Error);
    }

    #[test]
    fn test_lint_require_integrity_workspace_ok() {
        let lf = Lockfile {
            sources: vec![Source::Workspace],
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = RequireIntegrity;
        assert!(rule.check(&lf).is_empty());
    }

    #[test]
    fn test_lint_no_sha1_pass() {
        let lf = Lockfile {
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![0u8; 32],
                    attestation: Attestation::None,
                }],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = NoSha1;
        assert!(rule.check(&lf).is_empty());
    }

    #[test]
    fn test_lint_no_sha1_fail() {
        let lf = Lockfile {
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha1,
                    digest: vec![0u8; 20],
                    attestation: Attestation::None,
                }],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = NoSha1;
        let findings = rule.check(&lf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn test_lint_max_depth_pass() {
        let lf = Lockfile {
            provenance: vec![ResolutionProvenance {
                package_name: "pkg".to_string(),
                constraint: "^1.0.0".to_string(),
                constrained_by: String::new(),
                dep_type: DepType::Runtime,
                source_type: ProvenanceSourceType::Registry,
                depth: 3,
            }],
            ..empty_lockfile()
        };
        let rule = MaxDepth { max: 5 };
        assert!(rule.check(&lf).is_empty());
    }

    #[test]
    fn test_lint_max_depth_fail() {
        let lf = Lockfile {
            provenance: vec![ResolutionProvenance {
                package_name: "pkg".to_string(),
                constraint: "^1.0.0".to_string(),
                constrained_by: String::new(),
                dep_type: DepType::Runtime,
                source_type: ProvenanceSourceType::Registry,
                depth: 10,
            }],
            ..empty_lockfile()
        };
        let rule = MaxDepth { max: 5 };
        let findings = rule.check(&lf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Warning);
    }

    #[test]
    fn test_lint_require_attestation_info() {
        let lf = Lockfile {
            packages: vec![Package {
                name: "pkg".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![0u8; 32],
                    attestation: Attestation::None,
                }],
                ..Package::default()
            }],
            ..empty_lockfile()
        };
        let rule = RequireAttestation;
        let findings = rule.check(&lf);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, LintSeverity::Info);
    }

    #[test]
    fn test_lint_default_ruleset() {
        let lf = empty_lockfile();
        let report = lint_default(&lf);
        assert!(!report.has_errors());
    }
}
// New v0.15 lint rules - add to existing file

pub struct NoKnownVulnerabilities;

impl LintRule for NoKnownVulnerabilities {
    fn name(&self) -> &str { "no-known-vulnerabilities" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        let report = lockfile.audit();

        for adv in report.critical.iter().chain(report.high.iter()) {
            findings.push(LintFinding {
                rule: "no-known-vulnerabilities".to_string(),
                severity: LintSeverity::Error,
                package: Some(adv.package.clone()),
                message: format!("Package '{}' has {} severity vulnerability: {}",
                    adv.package,
                    adv.severity.as_str(),
                    adv.advisory_id
                ),
            });
        }
        findings
    }
}

pub struct RequireLicense;

impl LintRule for RequireLicense {
    fn name(&self) -> &str { "require-license" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        lockfile.unlicensed_packages().iter().map(|pkg| {
            LintFinding {
                rule: "require-license".to_string(),
                severity: LintSeverity::Error,
                package: Some(pkg.name.clone()),
                message: format!("Package '{}' has no license declaration", pkg.name),
            }
        }).collect()
    }
}

pub struct DenyCopyleft;

impl LintRule for DenyCopyleft {
    fn name(&self) -> &str { "deny-copyleft" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        let copyleft_licenses = vec!["GPL", "AGPL", "LGPL", "CC-BY-SA"];

        for pkg in &lockfile.packages {
            if let Some(license) = lockfile.license_for(&pkg.name) {
                for copyleft in &copyleft_licenses {
                    if license.contains(copyleft) {
                        findings.push(LintFinding {
                            rule: "deny-copyleft".to_string(),
                            severity: LintSeverity::Warning,
                            package: Some(pkg.name.clone()),
                            message: format!("Package '{}' uses copyleft license: {}", pkg.name, license),
                        });
                        break;
                    }
                }
            }
        }
        findings
    }
}

pub struct RequireTrustRoot;

impl LintRule for RequireTrustRoot {
    fn name(&self) -> &str { "require-trust-root" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let roots = lockfile.trust_roots_for_role(crate::policy::TrustRole::Root);
        if roots.is_empty() {
            vec![LintFinding {
                rule: "require-trust-root".to_string(),
                severity: LintSeverity::Error,
                package: None,
                message: "No trust root keys found. At least one @trust-root with role=root is required".to_string(),
            }]
        } else {
            vec![]
        }
    }
}

pub struct NoExpiredKeys;

impl LintRule for NoExpiredKeys {
    fn name(&self) -> &str { "no-expired-keys" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        for root in &lockfile.trust_roots {
            if root.expires_epoch != 0 && root.expires_epoch < now {
                findings.push(LintFinding {
                    rule: "no-expired-keys".to_string(),
                    severity: LintSeverity::Error,
                    package: None,
                    message: format!("Trust root key '{}' expired at epoch {}", root.key_id, root.expires_epoch),
                });
            }
        }
        findings
    }
}

pub struct DenyPostinstall;

impl LintRule for DenyPostinstall {
    fn name(&self) -> &str { "deny-postinstall" }
    fn check(&self, lockfile: &Lockfile) -> Vec<LintFinding> {
        let mut findings = Vec::new();
        for pkg in &lockfile.packages {
            for hook in &pkg.hook_hashes {
                if hook.hook_type == "postinstall" {
                    findings.push(LintFinding {
                        rule: "deny-postinstall".to_string(),
                        severity: LintSeverity::Warning,
                        package: Some(pkg.name.clone()),
                        message: format!("Package '{}' declares a postinstall hook", pkg.name),
                    });
                }
            }
        }
        findings
    }
}
