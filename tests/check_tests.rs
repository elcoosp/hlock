use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_check_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_clean_lockfile() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
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
        ],
        licenses: vec![hlock::policy::LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() }],
        trust_roots: vec![hlock::policy::TrustRoot {
            key_id: "ci@key".to_string(),
            algorithm: hlock::signature::SignatureAlgorithm::Ed25519,
            public_key: vec![0u8; 32],
            expires_epoch: 0,
            role: hlock::policy::TrustRole::Root,
        }],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

fn make_dirty_lockfile() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![
            hlock::Source::Registry("https://registry.npmjs.org/".to_string()),
            hlock::Source::Git("git+https://github.com/evil/pkg.git".to_string()),
        ],
        packages: vec![
            hlock::Package {
                name: "evil".to_string(),
                source_idx: 1,
                major: 1, minor: 0, patch: 0,
                ..Default::default()
            },
        ],
        advisories: vec![hlock::policy::Advisory {
            package: "evil".to_string(),
            advisory_id: "CVE-2024-0001".to_string(),
            severity: hlock::policy::AdvisorySeverity::Critical,
            url: String::new(),
            affected_versions: "*".to_string(),
        }],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

#[test]
fn test_check_clean() {
    let serialized = make_clean_lockfile();
    let path = write_temp_file("check_clean.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("check")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "check on clean lockfile should succeed, stdout: {}, stderr: {}", stdout, stderr);
    assert!(stdout.contains("digest") || stdout.contains("Digest"), "should mention digest, got: {}", stdout);
}

#[test]
fn test_check_dirty() {
    let serialized = make_dirty_lockfile();
    let path = write_temp_file("check_dirty.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("check")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "check on dirty lockfile should fail");
}

#[test]
fn test_check_json() {
    let serialized = make_clean_lockfile();
    let path = write_temp_file("check_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("check")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "check --format json should succeed on clean lockfile, stderr: {}", String::from_utf8_lossy(&output.stderr));
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect(&format!("should be valid JSON, got: {}", stdout));
    assert!(parsed["digest_valid"].is_boolean(), "should have digest_valid boolean");
    assert!(parsed["result"].is_string(), "should have result string");
    assert_eq!(parsed["result"].as_str(), Some("pass"), "result should be 'pass'");
    assert!(parsed["passed"].is_array(), "should have passed array");
    assert!(parsed["failed"].is_array(), "should have failed array");
}
