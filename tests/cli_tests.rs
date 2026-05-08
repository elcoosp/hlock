use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_cli_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_simple_lockfile() -> String {
    let lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        ..Default::default()
    };
    hlock::serialize(&mut lf.clone()).unwrap()
}

#[test]
fn test_cli_verify_valid() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("verify_valid.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("verify")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "expected exit 0, got {}\nstdout: {}\nstderr: {}", output.status, stdout, stderr);
    assert!(stdout.contains("digest valid"), "stdout should mention digest valid");
}

#[test]
fn test_cli_verify_tampered() {
    let serialized = make_simple_lockfile();
    let tampered = serialized.replace("registry.npmjs.org", "evil.example.com");
    let path = write_temp_file("verify_tampered.hlock", &tampered);
    let output = Command::new(hlock_bin())
        .arg("verify")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "expected non-zero exit for tampered lockfile");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("digest") || stderr.contains("DigestMismatch"), "stderr should mention digest failure");
}

#[test]
fn test_cli_lint_errors() {
    let lf = hlock::Lockfile {
        sources: vec![hlock::Source::Git("git+https://github.com/pkg.git".to_string())],
        packages: vec![hlock::Package {
            name: "pkg-git".to_string(),
            source_idx: 0,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut lf_mut = lf;
    let serialized = hlock::serialize(&mut lf_mut).unwrap();
    let path = write_temp_file("lint_errors.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("lint")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "expected non-zero exit for lint errors");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no-git-urls") || stdout.contains("ERROR"), "stdout should report lint errors");
}

#[test]
fn test_cli_diff_text() {
    let s1 = make_simple_lockfile();
    let lf2 = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![hlock::Package {
            name: "added-pkg".to_string(),
            source_idx: 0,
            ..Default::default()
        }],
        ..Default::default()
    };
    let mut lf2_mut = lf2;
    let s2 = hlock::serialize(&mut lf2_mut).unwrap();

    let path1 = write_temp_file("diff_old.hlock", &s1);
    let path2 = write_temp_file("diff_new.hlock", &s2);

    let output = Command::new(hlock_bin())
        .arg("diff")
        .arg(&path1)
        .arg(&path2)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "expected exit 0 for diff");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("LOCKFILE DIFF"), "stdout should contain LOCKFILE DIFF header");
}

#[test]
fn test_cli_audit_clean() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("audit_clean.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("audit")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "expected exit 0 for clean audit");
}

#[test]
fn test_cli_sbom_spdx() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("sbom_spdx.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("sbom")
        .arg(&path)
        .arg("--namespace")
        .arg("test-namespace")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "expected exit 0 for sbom generation");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SPDX"), "stdout should contain SPDX");
    let parsed: Result<serde_json::Value, _> = serde_json::from_str(&stdout);
    assert!(parsed.is_ok(), "output should be valid JSON");
}
