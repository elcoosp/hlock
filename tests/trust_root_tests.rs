use hlock::lockfile::{self, Lockfile, Source};
use hlock::policy::{TrustRoot, TrustRole};
use hlock::signature::SignatureAlgorithm;

#[test]
fn test_trust_root_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        trust_roots: vec![
            TrustRoot {
                key_id: "ci@company.com".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![42u8; 32],
                expires_epoch: 1735689600,
                role: TrustRole::Root,
            },
            TrustRoot {
                key_id: "bot@github.com".to_string(),
                algorithm: SignatureAlgorithm::MlDsa65,
                public_key: vec![43u8; 65],
                expires_epoch: 0,
                role: TrustRole::Targets,
            },
        ],
        ..Lockfile::default()
    };

    let serialized = lockfile::serialize(&mut lockfile).unwrap();
    let deserialized = lockfile::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.trust_roots.len(), 2);
    assert_eq!(deserialized.trust_roots[0].key_id, "ci@company.com");
    assert_eq!(deserialized.trust_roots[0].role, TrustRole::Root);
    assert_eq!(deserialized.trust_roots[1].role, TrustRole::Targets);
}

#[test]
fn test_trust_root_parse_in_header() {
    let content = "@source 0 https://registry.npmjs.org/
@trust-root ci@company.com 00 2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a 1735689600 root
@trust-root bot@github.com 02 2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b 0 targets

";
    let (lockfile, _) = lockfile::parse_header(content).unwrap();
    assert_eq!(lockfile.trust_roots.len(), 2);
}

#[test]
fn test_trust_root_validation() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        trust_roots: vec![
            TrustRoot {
                key_id: "valid@key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![42u8; 32],
                expires_epoch: 1735689600, // Future date
                role: TrustRole::Root,
            },
        ],
        ..Lockfile::default()
    };

    // Should validate successfully (not expired)
    assert!(lockfile.validate_trust_chain(1735689500).is_ok());

    // Should fail if expired
    assert!(lockfile.validate_trust_chain(1735689700).is_err());
}

#[test]
fn test_trust_root_missing_root() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        trust_roots: vec![
            TrustRoot {
                key_id: "targets@key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![42u8; 32],
                expires_epoch: 0,
                role: TrustRole::Targets,
            },
        ],
        ..Lockfile::default()
    };

    assert!(lockfile.validate_trust_chain(0).is_err());
}

#[test]
fn test_trust_roots_for_role() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        trust_roots: vec![
            TrustRoot {
                key_id: "root1".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![42u8; 32],
                expires_epoch: 0,
                role: TrustRole::Root,
            },
            TrustRoot {
                key_id: "root2".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![43u8; 32],
                expires_epoch: 0,
                role: TrustRole::Root,
            },
            TrustRoot {
                key_id: "targets1".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![44u8; 32],
                expires_epoch: 0,
                role: TrustRole::Targets,
            },
        ],
        ..Lockfile::default()
    };

    let roots = lockfile.trust_roots_for_role(TrustRole::Root);
    assert_eq!(roots.len(), 2);

    let targets = lockfile.trust_roots_for_role(TrustRole::Targets);
    assert_eq!(targets.len(), 1);
}
