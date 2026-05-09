use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_dedup_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_dupes() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 20, ..Default::default() },
            hlock::Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 21, ..Default::default() },
        ],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

fn make_lockfile_no_dupes() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package { name: "lodash".to_string(), source_idx: 0, major: 4, minor: 17, patch: 21, ..Default::default() },
        ],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

#[test]
fn test_dedup_with_opportunities() {
    let serialized = make_lockfile_with_dupes();
    let path = write_temp_file("dedup_dupes.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("dedup")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "dedup should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lodash"), "should mention lodash, got: {}", stdout);
}

#[test]
fn test_dedup_no_opportunities() {
    let serialized = make_lockfile_no_dupes();
    let path = write_temp_file("dedup_clean.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("dedup")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "dedup should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No deduplication opportunities found"), "should say no opportunities, got: {}", stdout);
}

#[test]
fn test_dedup_json() {
    let serialized = make_lockfile_with_dupes();
    let path = write_temp_file("dedup_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("dedup")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "dedup --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["opportunities"].is_array(), "should have opportunities array");
}
