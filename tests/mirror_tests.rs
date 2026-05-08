use hlock::lockfile::{self, Lockfile, Mirror, Source};

#[test]
fn test_mirror_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        mirrors: vec![
            Mirror { scope: "@internal".to_string(), url: "https://npm.company.com/".to_string() },
            Mirror { scope: "*".to_string(), url: "https://registry.npmmirror.org/".to_string() },
        ],
        ..Lockfile::default()
    };

    let serialized = lockfile::serialize(&mut lockfile).unwrap();
    let deserialized = lockfile::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.mirrors.len(), 2);
    assert_eq!(deserialized.mirrors[0].scope, "@internal");
    assert_eq!(deserialized.mirrors[0].url, "https://npm.company.com/");
}

#[test]
fn test_mirror_registry_for() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        mirrors: vec![
            Mirror { scope: "@internal".to_string(), url: "https://npm.company.com/".to_string() },
            Mirror { scope: "*".to_string(), url: "https://registry.npmmirror.org/".to_string() },
        ],
        ..Lockfile::default()
    };

    // Test scoped package resolves to specific mirror
    assert_eq!(lockfile.registry_for("@internal/foo"), "https://npm.company.com/");

    // Test unscoped package resolves to default mirror
    assert_eq!(lockfile.registry_for("lodash"), "https://registry.npmmirror.org/");
}

#[test]
fn test_mirror_parse_in_header() {
    let content = "@source 0 https://registry.npmjs.org/\n@mirror @internal https://npm.company.com/\n@mirror * https://registry.npmmirror.org/\n\n";
    let (lockfile, _) = lockfile::parse_header(content).unwrap();
    assert_eq!(lockfile.mirrors.len(), 2);
    assert_eq!(lockfile.mirrors[0].scope, "@internal");
    assert_eq!(lockfile.mirrors[1].scope, "*");
}
