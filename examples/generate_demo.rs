//! Generate a demo lockfile for testing the hlock CLI.
//!
//! Run: cargo run --example generate_demo > demo.hlock

use hlock::*;

fn main() {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];

    let pub_key = {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        (*signing_key.verifying_key().as_bytes()).to_vec()
    };

    let mut lockfile = Lockfile {
        sources: vec![
            Source::Registry("https://registry.npmjs.org/".to_string()),
            Source::Git("git+https://github.com/internal/pkg.git".to_string()),
            Source::Workspace,
        ],
        mirrors: vec![
            Mirror { scope: "@internal".to_string(), url: "https://npm.company.com/".to_string() },
            Mirror { scope: "*".to_string(), url: "https://registry.npmmirror.org/".to_string() },
        ],
        policies: vec![
            policy::Policy { policy_type: policy::PolicyType::DenyHook, package_pattern: "*".to_string(), value: "postinstall".to_string() },
            policy::Policy { policy_type: policy::PolicyType::AllowHook, package_pattern: "lodash".to_string(), value: "postinstall".to_string() },
            policy::Policy { policy_type: policy::PolicyType::BuildEnv, package_pattern: "*".to_string(), value: "node>=20.11.0".to_string() },
            policy::Policy { policy_type: policy::PolicyType::Engine, package_pattern: "my-app".to_string(), value: "node>=22.0.0".to_string() },
        ],
        trust_roots: vec![
            policy::TrustRoot {
                key_id: "ci@company.com".to_string(),
                algorithm: signature::SignatureAlgorithm::Ed25519,
                public_key: pub_key,
                expires_epoch: 1800000000,
                role: policy::TrustRole::Root,
            },
        ],
        overrides: vec![
            Override { name: "react".to_string(), from_version: "^18.0.0".to_string(), ty: DepType::Runtime, to_version: "18.3.1".to_string() },
        ],
        features: vec![
            ("esm".to_string(), vec!["tree-shaking".to_string(), "async-import".to_string()]),
        ],
        metadata: vec![
            ("generator".to_string(), "hlock-cli@0.16.0".to_string()),
        ],
        workspace_root: Some("/home/dev/my-app".to_string()),
        workspace_pkgs: vec![
            WorkspacePkg { name: "my-app".to_string(), manifest_path: "packages/app/package.json".to_string() },
        ],
        hoist_boundaries: vec![
            HoistBoundary { cosine: "my-app".to_string(), allowed_deps: vec!["lodash".to_string(), "react".to_string()] },
        ],
        packages: vec![
            Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                    attestation: Attestation::None,
                }],
                features: vec!["esm".to_string()],
                dependencies: vec![],
                ..Default::default()
            },
            Package {
                name: "react".to_string(),
                source_idx: 0,
                major: 18, minor: 3, patch: 1,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![43u8; 32],
                    attestation: Attestation::InlineSlsa(SlsaPredicate {
                        builder: "github.com/actions".to_string(),
                        source: "git+https://github.com/facebook/react".to_string(),
                    }),
                }],
                dependencies: vec![Dependency {
                    name: "lodash".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec![],
                }],
                ..Default::default()
            },
            Package {
                name: "express".to_string(),
                source_idx: 0,
                major: 4, minor: 21, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![44u8; 32],
                    attestation: Attestation::None,
                }],
                dependencies: vec![],
                ..Default::default()
            },
            Package {
                name: "old-dep".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha1,
                    digest: vec![0xAA; 20],
                    attestation: Attestation::None,
                }],
                ..Default::default()
            },
            Package {
                name: "pkg-git".to_string(),
                source_idx: 1,
                major: 2, minor: 0, patch: 0,
                ..Default::default()
            },
            Package {
                name: "my-app".to_string(),
                source_idx: 2,
                major: 1, minor: 0, patch: 0,
                dependencies: vec![
                    Dependency { name: "react".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                    Dependency { name: "express".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                    Dependency { name: "old-dep".to_string(), dep_type: DepType::Dev, requested_features: vec![] },
                ],
                hook_hashes: vec![HookHash {
                    hook_type: "postinstall".to_string(),
                    hash_algo: HashAlgorithm::Blake3,
                    digest: vec![0xBB; 32],
                }],
                ..Default::default()
            },
        ],
        artifacts: vec![],
        patches: vec![],
        provenance: vec![
            provenance::ResolutionProvenance {
                package_name: "my-app".to_string(),
                constraint: String::new(),
                constrained_by: String::new(),
                dep_type: DepType::Runtime,
                source_type: provenance::ProvenanceSourceType::Workspace,
                depth: 0,
            },
            provenance::ResolutionProvenance {
                package_name: "react".to_string(),
                constraint: "^18.0.0".to_string(),
                constrained_by: "my-app".to_string(),
                dep_type: DepType::Runtime,
                source_type: provenance::ProvenanceSourceType::Registry,
                depth: 1,
            },
            provenance::ResolutionProvenance {
                package_name: "lodash".to_string(),
                constraint: "^4.17.0".to_string(),
                constrained_by: "react".to_string(),
                dep_type: DepType::Runtime,
                source_type: provenance::ProvenanceSourceType::Registry,
                depth: 2,
            },
        ],
        advisories: vec![
            policy::Advisory {
                package: "old-dep".to_string(),
                advisory_id: "CVE-2024-0001".to_string(),
                severity: policy::AdvisorySeverity::Critical,
                url: "https://github.com/advisories/CVE-2024-0001".to_string(),
                affected_versions: "*".to_string(),
            },
            policy::Advisory {
                package: "express".to_string(),
                advisory_id: "GHSA-2024-abcd".to_string(),
                severity: policy::AdvisorySeverity::Medium,
                url: "https://github.com/advisories/GHSA-2024-abcd".to_string(),
                affected_versions: ">=4.0.0 <4.22.0".to_string(),
            },
        ],
        licenses: vec![
            policy::LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() },
            policy::LicenseEntry { package: "react".to_string(), expression: "MIT".to_string() },
            policy::LicenseEntry { package: "express".to_string(), expression: "MIT".to_string() },
        ],
        vex_entries: vec![
            VexEntry {
                package: "express".to_string(),
                advisory_id: "GHSA-2024-abcd".to_string(),
                status: VexStatus::NotAffected,
                justification: "vulnerable_code_not_in_execute_path".to_string(),
                impact_statement: "not_applicable".to_string(),
            },
        ],
        root_rotations: vec![],
        compat: None,
    };

    let serialized = serialize(&mut lockfile).unwrap();
    print!("{}", serialized);
}
