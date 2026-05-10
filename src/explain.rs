//! Explain lint rules and advisories in detail

use crate::lockfile::Lockfile;

#[derive(Debug, Clone)]
pub struct Explanation {
    pub name: String,
    pub kind: ExplanationKind,
    pub severity: Option<String>,
    pub category: Option<String>,
    pub description: String,
    pub why_it_matters: Vec<String>,
    pub how_to_fix: Vec<String>,
    pub related: Vec<String>,
    pub references: Vec<String>,
    pub example_before: Option<String>,
    pub example_after: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExplanationKind {
    Rule,
    Advisory,
}

/// Get explanation for a lint rule by name.
pub fn explain_rule(name: &str) -> Option<Explanation> {
    match name {
        "no-git-urls" => Some(Explanation {
            name: "no-git-urls".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("supply-chain".to_string()),
            description: "Packages resolved from git URLs are non-reproducible and bypass registry integrity checks.".to_string(),
            why_it_matters: vec![
                "Git commits can be rewritten (force push)".to_string(),
                "No integrity guarantee (no hash verification)".to_string(),
                "Network-dependent at build time".to_string(),
                "Violates SLSA Level 1 requirements".to_string(),
            ],
            how_to_fix: vec![
                "Use a registry version instead: lodash@4.17.21".to_string(),
                "If using a fork, publish to a private registry".to_string(),
                "If using a specific commit, pin with git+https://...#<commit>".to_string(),
            ],
            related: vec!["require-integrity".to_string(), "require-attestation".to_string()],
            references: vec![
                "https://slsa.dev/spec/v1.0/requirements".to_string(),
                "https://github.com/ossf/scorecard/blob/main/docs/checks.md".to_string(),
            ],
            example_before: Some("@source 0 git+https://github.com/pkg.git\nlodash  <base64>".to_string()),
            example_after: Some("@source 0 https://registry.npmjs.org/\nlodash  <base64>".to_string()),
        }),
        "require-integrity" => Some(Explanation {
            name: "require-integrity".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("integrity".to_string()),
            description: "Packages from non-workspace sources must have integrity hashes.".to_string(),
            why_it_matters: vec![
                "Without integrity hashes, package contents cannot be verified".to_string(),
                "Tampered packages would go undetected".to_string(),
                "Required for reproducible builds".to_string(),
            ],
            how_to_fix: vec![
                "Ensure the lockfile was generated with integrity verification enabled".to_string(),
                "Regenerate the lockfile to include integrity hashes".to_string(),
            ],
            related: vec!["no-sha1".to_string(), "no-git-urls".to_string()],
            references: vec![
                "https://owasp.org/www-community/attacks/Supply_Chain_Attacks".to_string(),
            ],
            example_before: Some("lodash  <base64>  # no integrity hash".to_string()),
            example_after: Some("lodash  <base64>  # with sha256 integrity".to_string()),
        }),
        "no-sha1" => Some(Explanation {
            name: "no-sha1".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("warning".to_string()),
            category: Some("integrity".to_string()),
            description: "SHA-1 is deprecated for integrity verification due to collision attacks.".to_string(),
            why_it_matters: vec![
                "SHA-1 collisions can be crafted (SHAttered attack, 2017)".to_string(),
                "NIST deprecated SHA-1 in 2011".to_string(),
                "npm registry now provides sha512 hashes".to_string(),
            ],
            how_to_fix: vec![
                "Regenerate the lockfile to use sha256 or sha512 hashes".to_string(),
                "If importing from another format, re-resolve packages".to_string(),
            ],
            related: vec!["require-integrity".to_string()],
            references: vec![
                "https://shattered.io/".to_string(),
            ],
            example_before: None,
            example_after: None,
        }),
        "deny-postinstall" => Some(Explanation {
            name: "deny-postinstall".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("warning".to_string()),
            category: Some("supply-chain".to_string()),
            description: "Packages with postinstall hooks are flagged because they execute arbitrary code during installation.".to_string(),
            why_it_matters: vec![
                "Postinstall scripts run with full user privileges".to_string(),
                "Common vector for supply chain attacks (event-stream incident)".to_string(),
                "Can exfiltrate environment variables or credentials".to_string(),
            ],
            how_to_fix: vec![
                "Add an allow-hook policy for trusted packages: @policy allow-hook lodash postinstall".to_string(),
                "Use --ignore-scripts when installing if possible".to_string(),
                "Audit postinstall scripts before allowing them".to_string(),
            ],
            related: vec!["no-git-urls".to_string()],
            references: vec![
                "https://blog.npmjs.org/post/185570710760/the-event-stream-incident".to_string(),
            ],
            example_before: None,
            example_after: None,
        }),
        "require-license" => Some(Explanation {
            name: "require-license".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("compliance".to_string()),
            description: "All packages must declare a license.".to_string(),
            why_it_matters: vec![
                "Undeclared licenses create legal risk".to_string(),
                "Required for SEC SBOM compliance (March 2026)".to_string(),
                "EU Cyber Resilience Act requires license disclosure".to_string(),
            ],
            how_to_fix: vec![
                "Add a @license directive for each package".to_string(),
                "Check the package's package.json or README for license info".to_string(),
            ],
            related: vec!["deny-copyleft".to_string()],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        "require-attestation" => Some(Explanation {
            name: "require-attestation".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("info".to_string()),
            category: Some("supply-chain".to_string()),
            description: "Packages should have supply chain attestations (SLSA provenance).".to_string(),
            why_it_matters: vec![
                "Attestations verify where and how a package was built".to_string(),
                "SLSA Level 3+ requires provenance".to_string(),
                "Detects tampered build pipelines".to_string(),
            ],
            how_to_fix: vec![
                "Use packages that publish SLSA provenance".to_string(),
                "Generate attestations during your own build process".to_string(),
            ],
            related: vec!["no-git-urls".to_string(), "require-integrity".to_string()],
            references: vec![
                "https://slsa.dev/spec/v1.0/requirements".to_string(),
            ],
            example_before: None,
            example_after: None,
        }),
        "no-known-vulnerabilities" => Some(Explanation {
            name: "no-known-vulnerabilities".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("vulnerability".to_string()),
            description: "Packages with known critical or high severity vulnerabilities.".to_string(),
            why_it_matters: vec![
                "Known vulnerabilities are actively exploited in the wild".to_string(),
                "Supply chain attacks have increased 742% since 2019".to_string(),
            ],
            how_to_fix: vec![
                "Update the package to a fixed version".to_string(),
                "Run: hlock fix --audit <file>".to_string(),
                "If no fix is available, consider removing the dependency".to_string(),
            ],
            related: vec!["deny-postinstall".to_string()],
            references: vec![
                "https://osv.dev/".to_string(),
            ],
            example_before: None,
            example_after: None,
        }),
        "deny-copyleft" => Some(Explanation {
            name: "deny-copyleft".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("warning".to_string()),
            category: Some("compliance".to_string()),
            description: "Packages with copyleft licenses (GPL, AGPL, etc.) are flagged.".to_string(),
            why_it_matters: vec![
                "Copyleft licenses may require source code disclosure".to_string(),
                "Can affect proprietary software distribution".to_string(),
            ],
            how_to_fix: vec![
                "Replace the package with a permissively-licensed alternative".to_string(),
                "Accept the license if your use case is compatible".to_string(),
            ],
            related: vec!["require-license".to_string()],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        "require-trust-root" => Some(Explanation {
            name: "require-trust-root".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("trust".to_string()),
            description: "Lockfiles should have at least one trust root key with role 'root'.".to_string(),
            why_it_matters: vec![
                "Trust roots establish the root of trust for signature verification".to_string(),
                "Without trust roots, signatures cannot be verified".to_string(),
            ],
            how_to_fix: vec![
                "Add a @trust-root directive with a root key".to_string(),
                "Use: hlock sign --key-id <id> --algorithm ed25519 --private-key <hex>".to_string(),
            ],
            related: vec!["no-expired-keys".to_string()],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        "no-expired-keys" => Some(Explanation {
            name: "no-expired-keys".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("error".to_string()),
            category: Some("trust".to_string()),
            description: "Trust root keys that have expired.".to_string(),
            why_it_matters: vec![
                "Expired keys can no longer be used for verification".to_string(),
                "An expired root key could indicate a compromised rotation".to_string(),
            ],
            how_to_fix: vec![
                "Rotate the expired key using @trust-root-rotation".to_string(),
                "Update the key with a new expiry epoch".to_string(),
            ],
            related: vec!["require-trust-root".to_string()],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        "no-peer-as-runtime" => Some(Explanation {
            name: "no-peer-as-runtime".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("warning".to_string()),
            category: Some("dependencies".to_string()),
            description: "Peer dependencies declared as runtime dependencies.".to_string(),
            why_it_matters: vec![
                "Peer dependencies should be provided by the consumer, not bundled".to_string(),
                "Bundling peer deps can cause duplicate package instances".to_string(),
            ],
            how_to_fix: vec![
                "Move the dependency from peerDependencies to dependencies, or vice versa".to_string(),
            ],
            related: vec![],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        "max-depth" => Some(Explanation {
            name: "max-depth".to_string(),
            kind: ExplanationKind::Rule,
            severity: Some("warning".to_string()),
            category: Some("dependencies".to_string()),
            description: "Dependency depth exceeds the maximum allowed.".to_string(),
            why_it_matters: vec![
                "Deep dependency trees are harder to audit".to_string(),
                "More transitive dependencies = larger attack surface".to_string(),
                "Can indicate diamond dependency issues".to_string(),
            ],
            how_to_fix: vec![
                "Consider using fewer dependencies".to_string(),
                "Flatten the dependency tree with overrides".to_string(),
            ],
            related: vec![],
            references: vec![],
            example_before: None,
            example_after: None,
        }),
        _ => None,
    }
}

/// Get explanation for an advisory ID.
pub fn explain_advisory(id: &str, lockfile: &Lockfile) -> Option<Explanation> {
    let adv = lockfile.advisories.iter().find(|a| a.advisory_id == id)?;

    let pkg_version = lockfile.packages.iter()
        .find(|p| p.name == adv.package)
        .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
        .unwrap_or_default();

    Some(Explanation {
        name: id.to_string(),
        kind: ExplanationKind::Advisory,
        severity: Some(adv.severity.as_str().to_string()),
        category: Some("vulnerability".to_string()),
        description: if adv.url.is_empty() {
            format!("Vulnerability {} affects {}@{}", id, adv.package, pkg_version)
        } else {
            format!("Vulnerability {} affects {}@{}. See {} for details.", id, adv.package, pkg_version, adv.url)
        },
        why_it_matters: vec![
            "Known vulnerabilities can be exploited by attackers".to_string(),
            "This package is affected: ".to_string() + &adv.affected_versions,
        ],
        how_to_fix: vec![
            format!("Update {} to a fixed version", adv.package),
            "Run: hlock fix --audit <file>".to_string(),
        ],
        related: vec![],
        references: if adv.url.is_empty() { vec![] } else { vec![adv.url.clone()] },
        example_before: None,
        example_after: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_explain_no_git_urls() {
        let exp = explain_rule("no-git-urls").unwrap();
        assert_eq!(exp.name, "no-git-urls");
        assert_eq!(exp.kind, ExplanationKind::Rule);
        assert!(!exp.why_it_matters.is_empty());
        assert!(!exp.how_to_fix.is_empty());
    }

    #[test]
    fn test_explain_require_integrity() {
        let exp = explain_rule("require-integrity").unwrap();
        assert_eq!(exp.name, "require-integrity");
    }

    #[test]
    fn test_explain_unknown() {
        assert!(explain_rule("nonexistent-rule").is_none());
    }

    #[test]
    fn test_explain_advisory() {
        let lockfile = crate::lockfile::Lockfile {
            sources: vec![crate::lockfile::Source::Registry("https://r.com".to_string())],
            packages: vec![crate::lockfile::Package {
                name: "old-dep".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                ..Default::default()
            }],
            advisories: vec![crate::policy::Advisory {
                package: "old-dep".to_string(),
                advisory_id: "CVE-2024-0001".to_string(),
                severity: crate::policy::AdvisorySeverity::Critical,
                url: "https://example.com".to_string(),
                affected_versions: "*".to_string(),
            }],
            ..Default::default()
        };
        let exp = explain_advisory("CVE-2024-0001", &lockfile).unwrap();
        assert_eq!(exp.name, "CVE-2024-0001");
        assert_eq!(exp.kind, ExplanationKind::Advisory);
    }

    #[test]
    fn test_explain_advisory_not_found() {
        let lockfile = crate::lockfile::Lockfile::default();
        assert!(explain_advisory("CVE-NONEXISTENT", &lockfile).is_none());
    }
}
