use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_why_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_chain() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package {
                name: "my-app".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                dependencies: vec![
                    hlock::Dependency { name: "react".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
                ],
                ..Default::default()
            },
            hlock::Package {
                name: "react".to_string(),
                source_idx: 0,
                major: 18, minor: 3, patch: 1,
                dependencies: vec![
                    hlock::Dependency { name: "lodash".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
                ],
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                    attestation: hlock::Attestation::None,
                }],
                ..Default::default()
            },
            hlock::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha256,
                    digest: vec![43u8; 32],
                    attestation: hlock::Attestation::None,
                }],
                ..Default::default()
            },
        ],
        provenance: vec![
            hlock::provenance::ResolutionProvenance {
                package_name: "my-app".to_string(),
                constraint: String::new(),
                constrained_by: String::new(),
                dep_type: hlock::DepType::Runtime,
                source_type: hlock::ProvenanceSourceType::Workspace,
                depth: 0,
            },
            hlock::provenance::ResolutionProvenance {
                package_name: "react".to_string(),
                constraint: "^18.0.0".to_string(),
                constrained_by: "my-app".to_string(),
                dep_type: hlock::DepType::Runtime,
                source_type: hlock::ProvenanceSourceType::Registry,
                depth: 1,
            },
            hlock::provenance::ResolutionProvenance {
                package_name: "lodash".to_string(),
                constraint: "^4.17.0".to_string(),
                constrained_by: "react".to_string(),
                dep_type: hlock::DepType::Runtime,
                source_type: hlock::ProvenanceSourceType::Registry,
                depth: 2,
            },
        ],
        licenses: vec![
            hlock::policy::LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() },
            hlock::policy::LicenseEntry { package: "react".to_string(), expression: "MIT".to_string() },
        ],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

#[test]
fn test_why_text() {
    let serialized = make_lockfile_with_chain();
    let path = write_temp_file("why_text.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color")
        .arg("never")
        .arg("why")
        .arg(&path)
        .arg("lodash")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "why should succeed, stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lodash"), "should mention lodash, got: {}", stdout);
    assert!(stdout.contains("react"), "should mention react in chain");
    assert!(stdout.contains("my-app"), "should mention my-app in chain");
}

#[test]
fn test_why_json() {
    let serialized = make_lockfile_with_chain();
    let path = write_temp_file("why_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("why")
        .arg(&path)
        .arg("lodash")
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "why --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["package"].is_string(), "should have package field");
    assert!(parsed["chains"].is_array(), "should have chains array");
}

#[test]
fn test_why_not_found() {
    let serialized = make_lockfile_with_chain();
    let path = write_temp_file("why_notfound.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("why")
        .arg(&path)
        .arg("nonexistent")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "why with nonexistent package should fail");
}
