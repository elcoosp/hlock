use std::process::{Command, Stdio};
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_stdin_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_simple_lockfile() -> String {
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

fn run_with_stdin(args: &[&str], input: &str) -> (bool, String, String) {
    let mut cmd = Command::new(hlock_bin());
    for arg in args {
        cmd.arg(arg);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("failed to spawn hlock");
    use std::io::Write;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes()).unwrap();
    }
    let output = child.wait_with_output().expect("failed to wait");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (output.status.success(), stdout, stderr)
}

#[test]
fn test_stdin_verify() {
    let content = make_simple_lockfile();
    let (success, stdout, _) = run_with_stdin(&["verify", "-"], &content);
    assert!(success, "verify from stdin should succeed, stderr: {}", run_with_stdin(&["verify", "-"], &content).2);
    assert!(stdout.contains("digest valid"), "stdout should mention digest valid, got: {}", stdout);
}

#[test]
fn test_stdin_lint() {
    let content = make_simple_lockfile();
    let (success, _stdout, _) = run_with_stdin(&["lint", "-"], &content);
    assert!(success, "lint from stdin should succeed, stderr: {}", run_with_stdin(&["lint", "-"], &content).2);
}

#[test]
fn test_stdin_audit() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["audit", "-"], &content);
    assert!(success, "audit from stdin should succeed, stderr: {}", run_with_stdin(&["audit", "-"], &content).2);
}

#[test]
fn test_stdin_info() {
    let content = make_simple_lockfile();
    let (success, stdout, _) = run_with_stdin(&["info", "-"], &content);
    assert!(success, "info from stdin should succeed, stderr: {}", run_with_stdin(&["info", "-"], &content).2);
    assert!(stdout.contains("Packages:"), "should contain Packages header, got: {}", stdout);
}

#[test]
fn test_stdin_info_json() {
    let content = make_simple_lockfile();
    let (success, stdout, _) = run_with_stdin(&["info", "-", "--format", "json"], &content);
    assert!(success, "info --format json from stdin should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["package_count"].is_number(), "should have package_count");
}

#[test]
fn test_stdin_check() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["check", "-"], &content);
    assert!(success, "check from stdin should succeed, stderr: {}", run_with_stdin(&["check", "-"], &content).2);
}

#[test]
fn test_stdin_check_json() {
    let content = make_simple_lockfile();
    let (success, stdout, _) = run_with_stdin(&["check", "-", "--format", "json"], &content);
    assert!(success, "check --format json from stdin should succeed");
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["passed"].is_boolean(), "should have passed boolean");
}

#[test]
fn test_stdin_sbom() {
    let content = make_simple_lockfile();
    let (success, stdout, _) = run_with_stdin(&["sbom", "-", "--namespace", "test-ns"], &content);
    assert!(success, "sbom from stdin should succeed, stderr: {}", run_with_stdin(&["sbom", "-", "--namespace", "test-ns"], &content).2);
    assert!(stdout.contains("SPDX"), "should contain SPDX, got: {}", stdout);
}

#[test]
fn test_stdin_dedup() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["dedup", "-"], &content);
    assert!(success, "dedup from stdin should succeed, stderr: {}", run_with_stdin(&["dedup", "-"], &content).2);
}

#[test]
fn test_stdin_why() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["why", "-", "lodash"], &content);
    assert!(success, "why from stdin should succeed, stderr: {}", run_with_stdin(&["why", "-", "lodash"], &content).2);
}

#[test]
fn test_stdin_deps() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["deps", "-", "lodash"], &content);
    assert!(success, "deps from stdin should succeed, stderr: {}", run_with_stdin(&["deps", "-", "lodash"], &content).2);
}

#[test]
fn test_stdin_dependents() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["dependents", "-", "lodash"], &content);
    assert!(success, "dependents from stdin should succeed, stderr: {}", run_with_stdin(&["dependents", "-", "lodash"], &content).2);
}

#[test]
fn test_stdin_tree() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["tree", "-", "--root", "lodash"], &content);
    assert!(success, "tree from stdin should succeed, stderr: {}", run_with_stdin(&["tree", "-", "--root", "lodash"], &content).2);
}

#[test]
fn test_stdin_licenses() {
    let content = make_simple_lockfile();
    let (success, _, _) = run_with_stdin(&["licenses", "-"], &content);
    assert!(success, "licenses from stdin should succeed, stderr: {}", run_with_stdin(&["licenses", "-"], &content).2);
}

#[test]
fn test_stdin_diff_old() {
    let content = make_simple_lockfile();
    let file_path = write_temp_file("diff_new.hlock", &content);
    let (success, stdout, _) = run_with_stdin(&["diff", "-", &file_path.to_string_lossy()], &content);
    assert!(success, "diff with stdin as old should succeed, stderr: {}", run_with_stdin(&["diff", "-", &file_path.to_string_lossy()], &content).2);
    assert!(stdout.contains("LOCKFILE DIFF"), "should contain LOCKFILE DIFF, got: {}", stdout);
}

#[test]
fn test_stdin_diff_new() {
    let content = make_simple_lockfile();
    let file_path = write_temp_file("diff_old.hlock", &content);
    let (success, stdout, _) = run_with_stdin(&["diff", &file_path.to_string_lossy(), "-"], &content);
    assert!(success, "diff with stdin as new should succeed, stderr: {}", run_with_stdin(&["diff", &file_path.to_string_lossy(), "-"], &content).2);
    assert!(stdout.contains("LOCKFILE DIFF"), "should contain LOCKFILE DIFF, got: {}", stdout);
}

#[test]
fn test_stdin_sign_rejects_in_place() {
    let content = make_simple_lockfile();
    let key_hex = "00".repeat(32);
    let (success, _, stderr) = run_with_stdin(&["sign", "-", "--key-id", "test", "--algorithm", "ed25519", "--private-key", &key_hex, "--in-place"], &content);
    assert!(!success, "sign --in-place with stdin should fail");
    assert!(stderr.contains("in-place") || stderr.contains("stdin"), "should mention in-place or stdin, got: {}", stderr);
}

#[test]
fn test_stdin_color_never_no_ansi() {
    let content = make_simple_lockfile();
    let (_, stdout, _) = run_with_stdin(&["--color", "never", "info", "-"], &content);
    assert!(!stdout.contains("\x1b["), "should have no ANSI escapes with --color never, got: {:?}", stdout.chars().take(200).collect::<String>());
}

#[test]
fn test_stdin_json_no_ansi() {
    let content = make_simple_lockfile();
    let (_, stdout, _) = run_with_stdin(&["--color", "always", "check", "-", "--format", "json"], &content);
    assert!(!stdout.contains("\x1b["), "JSON output should have no ANSI escapes even with --color always, got: {:?}", stdout.chars().take(200).collect::<String>());
}
