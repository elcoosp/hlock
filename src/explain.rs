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

/// Starts an [`Explanation`] for a lint rule with the common fields filled in.
fn rule(name: &str, severity: &str, category: &str, description: &str) -> Explanation {
    Explanation {
        name: name.to_string(),
        kind: ExplanationKind::Rule,
        severity: Some(severity.to_string()),
        category: Some(category.to_string()),
        description: description.to_string(),
        why_it_matters: Vec::new(),
        how_to_fix: Vec::new(),
        related: Vec::new(),
        references: Vec::new(),
        example_before: None,
        example_after: None,
    }
}

/// Explanation for the `no-git-urls` rule.
fn no_git_urls() -> Explanation {
    Explanation {
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
        related: vec![
            "require-integrity".to_string(),
            "require-attestation".to_string(),
        ],
        references: vec![
            "https://slsa.dev/spec/v1.0/requirements".to_string(),
            "https://github.com/ossf/scorecard/blob/main/docs/checks.md".to_string(),
        ],
        example_before: Some(
            "@source 0 git+https://github.com/pkg.git\nlodash  <base64>".to_string(),
        ),
        example_after: Some("@source 0 https://registry.npmjs.org/\nlodash  <base64>".to_string()),
        ..rule(
            "no-git-urls",
            "error",
            "supply-chain",
            "Packages resolved from git URLs are non-reproducible and bypass registry integrity checks.",
        )
    }
}

/// Explanation for the `require-integrity` rule.
fn require_integrity() -> Explanation {
    Explanation {
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
        ..rule(
            "require-integrity",
            "error",
            "integrity",
            "Packages from non-workspace sources must have integrity hashes.",
        )
    }
}

/// Explanation for the `no-sha1` rule.
fn no_sha1() -> Explanation {
    Explanation {
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
        references: vec!["https://shattered.io/".to_string()],
        ..rule(
            "no-sha1",
            "warning",
            "integrity",
            "SHA-1 is deprecated for integrity verification due to collision attacks.",
        )
    }
}

/// Explanation for the `deny-postinstall` rule.
fn deny_postinstall() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Postinstall scripts run with full user privileges".to_string(),
            "Common vector for supply chain attacks (event-stream incident)".to_string(),
            "Can exfiltrate environment variables or credentials".to_string(),
        ],
        how_to_fix: vec![
            "Add an allow-hook policy for trusted packages: @policy allow-hook lodash postinstall"
                .to_string(),
            "Use --ignore-scripts when installing if possible".to_string(),
            "Audit postinstall scripts before allowing them".to_string(),
        ],
        related: vec!["no-git-urls".to_string()],
        references: vec![
            "https://blog.npmjs.org/post/185570710760/the-event-stream-incident".to_string(),
        ],
        ..rule(
            "deny-postinstall",
            "warning",
            "supply-chain",
            "Packages with postinstall hooks are flagged because they execute arbitrary code during installation.",
        )
    }
}

/// Explanation for the `require-license` rule.
fn require_license() -> Explanation {
    Explanation {
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
        ..rule(
            "require-license",
            "error",
            "compliance",
            "All packages must declare a license.",
        )
    }
}

/// Explanation for the `require-attestation` rule.
fn require_attestation() -> Explanation {
    Explanation {
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
        references: vec!["https://slsa.dev/spec/v1.0/requirements".to_string()],
        ..rule(
            "require-attestation",
            "info",
            "supply-chain",
            "Packages should have supply chain attestations (SLSA provenance).",
        )
    }
}

/// Explanation for the `no-known-vulnerabilities` rule.
fn no_known_vulnerabilities() -> Explanation {
    Explanation {
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
        references: vec!["https://osv.dev/".to_string()],
        ..rule(
            "no-known-vulnerabilities",
            "error",
            "vulnerability",
            "Packages with known critical or high severity vulnerabilities.",
        )
    }
}

/// Explanation for the `deny-copyleft` rule.
fn deny_copyleft() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Copyleft licenses may require source code disclosure".to_string(),
            "Can affect proprietary software distribution".to_string(),
        ],
        how_to_fix: vec![
            "Replace the package with a permissively-licensed alternative".to_string(),
            "Accept the license if your use case is compatible".to_string(),
        ],
        related: vec!["require-license".to_string()],
        ..rule(
            "deny-copyleft",
            "warning",
            "compliance",
            "Packages with copyleft licenses (GPL, AGPL, etc.) are flagged.",
        )
    }
}

/// Explanation for the `require-trust-root` rule.
fn require_trust_root() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Trust roots establish the root of trust for signature verification".to_string(),
            "Without trust roots, signatures cannot be verified".to_string(),
        ],
        how_to_fix: vec![
            "Add a @trust-root directive with a root key".to_string(),
            "Use: hlock sign --key-id <id> --algorithm ed25519 --private-key <hex>".to_string(),
        ],
        related: vec!["no-expired-keys".to_string()],
        ..rule(
            "require-trust-root",
            "error",
            "trust",
            "Lockfiles should have at least one trust root key with role 'root'.",
        )
    }
}

/// Explanation for the `no-expired-keys` rule.
fn no_expired_keys() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Expired keys can no longer be used for verification".to_string(),
            "An expired root key could indicate a compromised rotation".to_string(),
        ],
        how_to_fix: vec![
            "Rotate the expired key using @trust-root-rotation".to_string(),
            "Update the key with a new expiry epoch".to_string(),
        ],
        related: vec!["require-trust-root".to_string()],
        ..rule(
            "no-expired-keys",
            "error",
            "trust",
            "Trust root keys that have expired.",
        )
    }
}

/// Explanation for the `no-peer-as-runtime` rule.
fn no_peer_as_runtime() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Peer dependencies should be provided by the consumer, not bundled".to_string(),
            "Bundling peer deps can cause duplicate package instances".to_string(),
        ],
        how_to_fix: vec![
            "Move the dependency from peerDependencies to dependencies, or vice versa".to_string(),
        ],
        ..rule(
            "no-peer-as-runtime",
            "warning",
            "dependencies",
            "Peer dependencies declared as runtime dependencies.",
        )
    }
}

/// Explanation for the `max-depth` rule.
fn max_depth() -> Explanation {
    Explanation {
        why_it_matters: vec![
            "Deep dependency trees are harder to audit".to_string(),
            "More transitive dependencies = larger attack surface".to_string(),
            "Can indicate diamond dependency issues".to_string(),
        ],
        how_to_fix: vec![
            "Consider using fewer dependencies".to_string(),
            "Flatten the dependency tree with overrides".to_string(),
        ],
        ..rule(
            "max-depth",
            "warning",
            "dependencies",
            "Dependency depth exceeds the maximum allowed.",
        )
    }
}

/// Get explanation for a lint rule by name.
#[must_use]
pub fn explain_rule(name: &str) -> Option<Explanation> {
    let builder = match name {
        "no-git-urls" => no_git_urls,
        "require-integrity" => require_integrity,
        "no-sha1" => no_sha1,
        "deny-postinstall" => deny_postinstall,
        "require-license" => require_license,
        "require-attestation" => require_attestation,
        "no-known-vulnerabilities" => no_known_vulnerabilities,
        "deny-copyleft" => deny_copyleft,
        "require-trust-root" => require_trust_root,
        "no-expired-keys" => no_expired_keys,
        "no-peer-as-runtime" => no_peer_as_runtime,
        "max-depth" => max_depth,
        _ => return None,
    };
    Some(builder())
}

/// Get explanation for an advisory ID.
#[must_use]
pub fn explain_advisory(id: &str, lockfile: &Lockfile) -> Option<Explanation> {
    let adv = lockfile.advisories.iter().find(|a| a.advisory_id == id)?;

    let pkg_version = lockfile
        .packages
        .iter()
        .find(|p| p.name == adv.package)
        .map(|p| format!("{}.{}.{}", p.major, p.minor, p.patch))
        .unwrap_or_default();

    Some(Explanation {
        name: id.to_string(),
        kind: ExplanationKind::Advisory,
        severity: Some(adv.severity.as_str().to_string()),
        category: Some("vulnerability".to_string()),
        description: if adv.url.is_empty() {
            format!(
                "Vulnerability {} affects {}@{}",
                id, adv.package, pkg_version
            )
        } else {
            format!(
                "Vulnerability {} affects {}@{}. See {} for details.",
                id, adv.package, pkg_version, adv.url
            )
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
        references: if adv.url.is_empty() {
            vec![]
        } else {
            vec![adv.url.clone()]
        },
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
        assert!(
            !exp.why_it_matters.is_empty(),
            "expected empty, got: {:?}",
            exp.why_it_matters
        );
        assert!(
            !exp.how_to_fix.is_empty(),
            "expected empty, got: {:?}",
            exp.how_to_fix
        );
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
            sources: vec![crate::lockfile::Source::Registry(
                "https://r.com".to_string(),
            )],
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

    const ALL_RULES: &[&str] = &[
        "no-git-urls",
        "require-integrity",
        "no-sha1",
        "deny-postinstall",
        "require-license",
        "require-attestation",
        "no-known-vulnerabilities",
        "deny-copyleft",
        "require-trust-root",
        "no-expired-keys",
        "no-peer-as-runtime",
        "max-depth",
    ];

    #[test]
    fn every_rule_round_trips_with_expected_fields() {
        for name in ALL_RULES {
            let exp = explain_rule(name).unwrap_or_else(|| panic!("no explanation for {name}"));
            assert_eq!(exp.name, *name);
            assert_eq!(exp.kind, ExplanationKind::Rule);
            assert!(exp.description.len() > 10, "{name} description too short");
            let severity = exp
                .severity
                .as_deref()
                .unwrap_or_else(|| panic!("{name} has no severity"));
            assert!(
                ["error", "warning", "info"].contains(&severity),
                "{name} unexpected severity {severity}"
            );
            assert!(exp.category.is_some(), "{name} has no category");
            assert!(
                !exp.why_it_matters.is_empty(),
                "{name} has empty why_it_matters"
            );
            assert!(!exp.how_to_fix.is_empty(), "{name} has empty how_to_fix");
            for r in &exp.references {
                assert!(
                    r.starts_with("https://"),
                    "{name} reference {r} should be a URL"
                );
            }
        }
    }

    #[test]
    fn rule_severities_and_categories_match_spec() {
        let expectations: &[(&str, &str, &str)] = &[
            ("no-git-urls", "error", "supply-chain"),
            ("require-integrity", "error", "integrity"),
            ("no-sha1", "warning", "integrity"),
            ("deny-postinstall", "warning", "supply-chain"),
            ("require-license", "error", "compliance"),
            ("require-attestation", "info", "supply-chain"),
            ("no-known-vulnerabilities", "error", "vulnerability"),
            ("deny-copyleft", "warning", "compliance"),
            ("require-trust-root", "error", "trust"),
            ("no-expired-keys", "error", "trust"),
            ("no-peer-as-runtime", "warning", "dependencies"),
            ("max-depth", "warning", "dependencies"),
        ];
        for (name, severity, category) in expectations {
            let exp = explain_rule(name).unwrap();
            assert_eq!(exp.severity.as_deref(), Some(*severity), "{name}");
            assert_eq!(exp.category.as_deref(), Some(*category), "{name}");
        }
    }

    #[test]
    fn rules_carry_examples_and_related_links() {
        let with_examples = ["no-git-urls", "require-integrity"];
        for name in with_examples {
            let exp = explain_rule(name).unwrap();
            assert!(
                exp.example_before.is_some(),
                "{name} missing example_before"
            );
            assert!(exp.example_after.is_some(), "{name} missing example_after");
        }
        // Cross links must point at real rules.
        for name in ALL_RULES {
            let exp = explain_rule(name).unwrap();
            for rel in &exp.related {
                assert!(
                    ALL_RULES.contains(&rel.as_str()),
                    "{name} links to unknown rule {rel}"
                );
            }
        }
    }

    #[test]
    fn advisory_explanation_handles_empty_url() {
        let lockfile = crate::lockfile::Lockfile {
            packages: vec![crate::lockfile::Package {
                name: "bare".to_string(),
                major: 2,
                minor: 3,
                patch: 4,
                ..crate::lockfile::Package::default()
            }],
            advisories: vec![crate::policy::Advisory {
                package: "bare".to_string(),
                advisory_id: "GHSA-no-url".to_string(),
                severity: crate::policy::AdvisorySeverity::Low,
                url: String::new(),
                affected_versions: "<2.5.0".to_string(),
            }],
            ..crate::lockfile::Lockfile::default()
        };
        let exp = explain_advisory("GHSA-no-url", &lockfile).unwrap();
        assert_eq!(exp.kind, ExplanationKind::Advisory);
        assert_eq!(exp.severity.as_deref(), Some("low"));
        assert_eq!(exp.category.as_deref(), Some("vulnerability"));
        let desc = exp.description.clone();
        assert!(
            desc.contains("bare@2.3.4"),
            "description should embed version: {desc}"
        );
        assert!(
            !desc.contains("See"),
            "empty url must not append a See link: {desc}"
        );
        assert!(exp.references.is_empty(), "no url means no references");
        assert!(exp.why_it_matters.iter().any(|w| w.contains("<2.5.0")));
        assert!(exp.how_to_fix.iter().any(|h| h.contains("bare")));
    }

    #[test]
    fn advisory_explanation_with_url_includes_reference() {
        let lockfile = crate::lockfile::Lockfile {
            advisories: vec![crate::policy::Advisory {
                package: "gone".to_string(),
                advisory_id: "CVE-1".to_string(),
                severity: crate::policy::AdvisorySeverity::High,
                url: "https://adv.example/1".to_string(),
                affected_versions: "*".to_string(),
            }],
            ..crate::lockfile::Lockfile::default()
        };
        let exp = explain_advisory("CVE-1", &lockfile).unwrap();
        assert!(exp.description.contains("https://adv.example/1"));
        assert_eq!(exp.references, vec!["https://adv.example/1"]);
        // Package missing from `packages` yields the empty version suffix.
        assert!(exp.description.contains("@."));
    }
}
