use hlock::lockfile::{self, Lockfile, Source};
use hlock::policy::{Policy, PolicyType};

#[test]
fn test_policy_directive_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
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
            Policy {
                policy_type: PolicyType::BuildEnv,
                package_pattern: "*".to_string(),
                value: "node>=20.11.0".to_string(),
            },
        ],
        ..Lockfile::default()
    };

    let serialized = lockfile::serialize(&mut lockfile).unwrap();
    let deserialized = lockfile::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.policies.len(), 3);
    assert_eq!(deserialized.policies[0].policy_type, PolicyType::AllowHook);
    assert_eq!(deserialized.policies[1].policy_type, PolicyType::DenyHook);
}

#[test]
fn test_policy_parse_in_header() {
    let content = "@source 0 https://registry.npmjs.org/
@policy allow-hook lodash postinstall
@policy deny-hook * postinstall
@policy build-env * node>=20.11.0

";
    let (lockfile, _) = lockfile::parse_header(content).unwrap();
    assert_eq!(lockfile.policies.len(), 3);
}

#[test]
fn test_policy_hook_allowed_with_directives() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
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
        ..Lockfile::default()
    };

    // Specific allow should beat wildcard deny
    assert!(matches!(lockfile.hook_allowed("lodash", "postinstall"),
                     hlock::policy::PolicyDecision::Allowed));

    // Other packages should be denied
    assert!(matches!(lockfile.hook_allowed("other", "postinstall"),
                     hlock::policy::PolicyDecision::Denied { .. }));
}
