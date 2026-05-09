use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_tree_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_tree() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package {
                name: "my-app".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                dependencies: vec![
                    hlock::Dependency { name: "react".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
                    hlock::Dependency { name: "express".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
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
                ..Default::default()
            },
            hlock::Package {
                name: "express".to_string(),
                source_idx: 0,
                major: 4, minor: 21, patch: 0,
                dependencies: vec![],
                ..Default::default()
            },
            hlock::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

#[test]
fn test_tree_text() {
    let serialized = make_lockfile_with_tree();
    let path = write_temp_file("tree_text.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("tree")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "tree should succeed, stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("my-app"), "should contain my-app, got: {}", stdout);
    assert!(stdout.contains("react"), "should contain react");
    assert!(stdout.contains("lodash"), "should contain lodash");
}

#[test]
fn test_tree_json() {
    let serialized = make_lockfile_with_tree();
    let path = write_temp_file("tree_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("tree")
        .arg(&path)
        .arg("--format")
        .arg("json")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "tree --format json should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("should be valid JSON");
    assert!(parsed["roots"].is_array(), "should have roots array");
}

#[test]
fn test_tree_with_root() {
    let serialized = make_lockfile_with_tree();
    let path = write_temp_file("tree_root.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("tree")
        .arg(&path)
        .arg("--root")
        .arg("my-app")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "tree --root should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("my-app"), "should contain my-app");
}
