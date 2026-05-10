use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_lint_rule_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_issues() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![
            hlock::Source::Git("git+https://github.com/evil/pkg.git".to_string()),
            hlock::Source::Registry("https://registry.npmjs.org/".to_string()),
        ],
        packages: vec![
            hlock::Package {
                name: "evil".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                ..Default::default()
            },
            hlock::Package {
                name: "old-dep".to_string(),
                source_idx: 1,
                major: 1, minor: 0, patch: 0,
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha1,
                    digest: vec![0xAA; 20],
                    attestation: hlock::Attestation::None,
                }],
                ..Default::default()
            },
            hlock::Package {
                name: "clean".to_string(),
                source_idx: 1,
                major: 1, minor: 0, patch: 0,
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                    attestation: hlock::Attestation::InlineSlsa(hlock::SlsaPredicate {
                        builder: "github.com/actions".to_string(),
                        source: "git+https://github.com/clean".to_string(),
                    }),
                }],
                ..Default::default()
            },
        ],
        licenses: vec![
            hlock::policy::LicenseEntry { package: "clean".to_string(), expression: "MIT".to_string() },
        ],
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

#[test]
fn test_lint_rule_include_only() {
    let serialized = make_lockfile_with_issues();
    let path = write_temp_file("lint_include.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("lint")
        .arg(&path)
        .arg("--rule=no-git-urls")
        .arg("--severity=info")
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no-git-urls"), "should contain no-git-urls, got: {}", stdout);
    assert!(!stdout.contains("no-sha1"), "should NOT contain no-sha1, got: {}", stdout);
    assert!(!stdout.contains("require-integrity"), "should NOT contain require-integrity, got: {}", stdout);
}

#[test]
fn test_lint_rule_exclude() {
    let serialized = make_lockfile_with_issues();
    let path = write_temp_file("lint_exclude.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("lint")
        .arg(&path)
        .arg("--rule=-no-git-urls")
        .arg("--severity=info")
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("no-git-urls"), "should NOT contain no-git-urls when excluded, got: {}", stdout);
    assert!(stdout.contains("no-sha1") || stdout.contains("require-integrity"), "should contain other rules, got: {}", stdout);
}

#[test]
fn test_lint_rule_unknown() {
    let serialized = make_lockfile_with_issues();
    let path = write_temp_file("lint_unknown.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("lint")
        .arg(&path)
        .arg("--rule=nonexistent-rule")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "unknown rule should cause error exit");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown rule"), "stderr should mention unknown rule, got: {}", stderr);
}
