use hlock::lockfile::{self, Lockfile, Source};
use hlock::policy::LicenseEntry;

#[test]
fn test_license_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        licenses: vec![
            LicenseEntry {
                package: "lodash".to_string(),
                expression: "MIT".to_string(),
            },
            LicenseEntry {
                package: "express".to_string(),
                expression: "MIT".to_string(),
            },
        ],
        packages: vec![
            hlock::lockfile::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4,
                minor: 17,
                patch: 21,
                ..Default::default()
            },
        ],
        ..Lockfile::default()
    };

    let serialized = lockfile::serialize(&mut lockfile).unwrap();
    println!("Serialized:\n{}", serialized);

    // The serialized output should have an empty line after header
    // Our serialize function should produce that automatically

    let deserialized = lockfile::deserialize(&serialized).unwrap();
    assert_eq!(deserialized.licenses.len(), 2);
    assert_eq!(deserialized.licenses[0].package, "lodash");
    assert_eq!(deserialized.licenses[1].package, "express");
}

#[test]
fn test_license_parse_in_header() {
    // Note: license directives belong after the empty line (in package section)
    let content = "@source 0 https://registry.npmjs.org/\n\n@license lodash MIT\n@license express MIT\n";
    let lockfile = lockfile::deserialize(content).unwrap();
    assert_eq!(lockfile.licenses.len(), 2);
    assert_eq!(lockfile.licenses[0].expression, "MIT");
}

#[test]
fn test_license_for_api() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        licenses: vec![
            LicenseEntry {
                package: "lodash".to_string(),
                expression: "MIT".to_string(),
            },
        ],
        ..Lockfile::default()
    };

    assert_eq!(lockfile.license_for("lodash"), Some("MIT"));
    assert_eq!(lockfile.license_for("unknown"), None);
}

#[test]
fn test_unlicensed_packages_api() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::lockfile::Package {
                name: "licensed-pkg".to_string(),
                ..Default::default()
            },
            hlock::lockfile::Package {
                name: "unlicensed-pkg".to_string(),
                ..Default::default()
            },
        ],
        licenses: vec![
            LicenseEntry {
                package: "licensed-pkg".to_string(),
                expression: "MIT".to_string(),
            },
        ],
        ..Lockfile::default()
    };

    let unlicensed = lockfile.unlicensed_packages();
    assert_eq!(unlicensed.len(), 1);
    assert_eq!(unlicensed[0].name, "unlicensed-pkg");
}
