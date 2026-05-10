use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_dependents_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_dependents() -> String {
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
                major: 18, minor: 0, patch: 0,
                dependencies: vec![
                    hlock::Dependency { name: "lodash".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
                ],
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
fn test_dependents_direct() {
    let serialized = make_lockfile_with_dependents();
    let path = write_temp_file("dependents_direct.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("dependents")
        .arg(&path)
        .arg("lodash")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "dependents should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("react"), "should contain react, got: {}", stdout);
}

#[test]
fn test_dependents_transitive() {
    let serialized = make_lockfile_with_dependents();
    let path = write_temp_file("dependents_transitive.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("dependents")
        .arg(&path)
        .arg("lodash")
        .arg("--transitive")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "dependents --transitive should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("my-app"), "should contain my-app transitively, got: {}", stdout);
}

#[test]
fn test_dependents_not_found() {
    let serialized = make_lockfile_with_dependents();
    let path = write_temp_file("dependents_notfound.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("dependents")
        .arg(&path)
        .arg("nonexistent")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "dependents with nonexistent package should fail");
}
