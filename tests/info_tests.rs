use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_info_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_packages() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![
            hlock::Source::Registry("https://registry.npmjs.org/".to_string()),
            hlock::Source::Git("git+https://github.com/internal/pkg.git".to_string()),
            hlock::Source::Workspace,
        ],
        mirrors: vec![
            hlock::Mirror { scope: "@internal".to_string(), url: "https://npm.company.com/".to_string() },
        ],
        policies: vec![
            hlock::policy::Policy {
                policy_type: hlock::policy::PolicyType::DenyHook,
                package_pattern: "*".to_string(),
                value: "postinstall".to_string(),
            },
        ],
        trust_roots: vec![
            hlock::policy::TrustRoot {
                key_id: "ci@company.com".to_string(),
                algorithm: hlock::signature::SignatureAlgorithm::Ed25519,
                public_key: vec![42u8; 32],
                expires_epoch: 1800000000,
                role: hlock::policy::TrustRole::Root,
            },
        ],
        overrides: vec![
            hlock::Override {
                name: "react".to_string(),
                from_version: "^18.0.0".to_string(),
                ty: hlock::DepType::Runtime,
                to_version: "18.3.1".to_string(),
            },
        ],
        licenses: vec![
            hlock::policy::LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() },
        ],
        packages: vec![
            hlock::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                    attestation: hlock::Attestation::None,
                }],
                ..Default::default()
            },
            hlock::Package {
                name: "pkg-git".to_string(),
                source_idx: 1,
                major: 2, minor: 0, patch: 0,
                ..Default::default()
            },
            hlock::Package {
                name: "my-app".to_string(),
                source_idx: 2,
                major: 1, minor: 0, patch: 0,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

#[test]
fn test_info_text_output() {
    let serialized = make_lockfile_with_packages();
    let path = write_temp_file("info_text.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("info")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "info should succeed, stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(stdout.contains("Packages:"), "should contain Packages header, got: {}", stdout);
    assert!(stdout.contains("Sources:"), "should contain Sources header");
    assert!(stdout.contains("Mirrors:"), "should contain Mirrors header");
    assert!(stdout.contains("Policies:"), "should contain Policies header");
    assert!(stdout.contains("Trust Roots:"), "should contain Trust Roots header");
    assert!(stdout.contains("Overrides:"), "should contain Overrides header");
    assert!(stdout.contains("Licenses:"), "should contain Licenses header");
    assert!(stdout.contains("Digest:"), "should contain Digest header");
}

#[test]
fn test_info_json_output() {
    let serialized = make_lockfile_with_packages();
    let path = write_temp_file("info_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("info")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "info --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["package_count"].is_number(), "should have package_count");
    assert!(parsed["sources"].is_array(), "should have sources array");
    assert!(parsed["digest_valid"].is_boolean(), "should have digest_valid");
}

#[test]
fn test_info_nonexistent_file() {
    let output = Command::new(hlock_bin())
        .arg("info")
        .arg("/tmp/hlock_nonexistent_file_xyz.hlock")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "info with nonexistent file should fail");
}
