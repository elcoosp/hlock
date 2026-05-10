use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_deps_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_lockfile_with_deps() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package {
                name: "my-app".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                dependencies: vec![
                    hlock::Dependency { name: "react".to_string(), dep_type: hlock::DepType::Runtime, requested_features: vec![] },
                    hlock::Dependency { name: "jest".to_string(), dep_type: hlock::DepType::Dev, requested_features: vec![] },
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
                name: "jest".to_string(),
                source_idx: 0,
                major: 29, minor: 0, patch: 0,
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
fn test_deps_direct() {
    let serialized = make_lockfile_with_deps();
    let path = write_temp_file("deps_direct.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("deps")
        .arg(&path)
        .arg("my-app")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "deps should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("react"), "should contain react");
    assert!(stdout.contains("jest"), "should contain jest");
}

#[test]
fn test_deps_transitive() {
    let serialized = make_lockfile_with_deps();
    let path = write_temp_file("deps_transitive.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("deps")
        .arg(&path)
        .arg("my-app")
        .arg("--transitive")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "deps --transitive should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("lodash"), "should contain lodash transitively");
}

#[test]
fn test_deps_not_found() {
    let serialized = make_lockfile_with_deps();
    let path = write_temp_file("deps_notfound.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color").arg("never")
        .arg("deps")
        .arg(&path)
        .arg("nonexistent")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "deps with nonexistent package should fail");
}
