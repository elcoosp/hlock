use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_licenses_cmd_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_licenses() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                ..Default::default()
            },
            hlock::Package {
                name: "react".to_string(),
                source_idx: 0,
                major: 18, minor: 3, patch: 1,
                ..Default::default()
            },
            hlock::Package {
                name: "undocumented".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                ..Default::default()
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
fn test_licenses_text() {
    let serialized = make_lockfile_with_licenses();
    let path = write_temp_file("licenses_text.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("licenses")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "licenses should succeed, stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("MIT"), "should contain MIT, got: {}", stdout);
    assert!(stdout.contains("lodash"), "should contain lodash");
}

#[test]
fn test_licenses_json() {
    let serialized = make_lockfile_with_licenses();
    let path = write_temp_file("licenses_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("licenses")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "licenses --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["licenses"].is_array(), "should have licenses array");
}

#[test]
fn test_licenses_missing() {
    let serialized = make_lockfile_with_licenses();
    let path = write_temp_file("licenses_missing.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("licenses")
        .arg(&path)
        .arg("--missing")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "licenses --missing should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("undocumented"), "should list undocumented package, got: {}", stdout);
}
