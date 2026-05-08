use hlock::lockfile::{Lockfile, Source};
use hlock::policy::LicenseEntry;
use hlock::sbom::{SbomFormat, generate_sbom};

#[test]
fn test_sbom_spdx_includes_license() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::lockfile::Package {
                name: "licensed-pkg".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
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

    let sbom = generate_sbom(&lockfile, SbomFormat::SpdxJson, "test-ns").unwrap();
    assert!(sbom.contains("licenseConcluded"));
    assert!(sbom.contains("MIT"));
}

#[test]
fn test_sbom_cyclonedx_includes_license() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::lockfile::Package {
                name: "licensed-pkg".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
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

    let sbom = generate_sbom(&lockfile, SbomFormat::CycloneDxJson, "test-ns").unwrap();
    assert!(sbom.contains("licenses"));
    assert!(sbom.contains("MIT"));
}
