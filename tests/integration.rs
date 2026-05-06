use hlock::{Package, write_lockfile, read_lockfile, serialize, deserialize, Error};
use std::path::PathBuf;

fn setup_pkg(name: &str, maj: u64, min: u64, pat: u64, deps: Vec<&str>) -> Package {
    Package {
        name: name.to_string(),
        major: maj,
        minor: min,
        patch: pat,
        hash: vec![42u8; 32], // Testing dynamic 32-byte hash
        dependencies: deps.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn test_e2e_write_and_read() {
    let temp_path = PathBuf::from("target/test_e2e_v2.hlock");
    let mut packages = vec![
        setup_pkg("alpha", 1, 0, 0, vec!["beta"]),
        setup_pkg("beta", 2, 0, 0, vec![]),
    ];

    write_lockfile(&temp_path, &mut packages).expect("Write failed");
    let read_packages = read_lockfile(&temp_path).expect("Read failed");

    assert_eq!(read_packages.len(), 2);
    assert_eq!(read_packages[0].name, "alpha");
    assert_eq!(read_packages[0].dependencies[0], "beta");
    assert_eq!(read_packages[0].hash.len(), 32); // Verify dynamic hash length

    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_nonexistent_file() {
    assert!(read_lockfile(&PathBuf::from("target/nope_v2.hlock")).is_err());
}

#[test]
fn test_e2e_deep_tree() {
    let path = PathBuf::from("target/test_deep_v2.hlock");
    let mut pkgs = vec![
        setup_pkg("a", 1, 0, 0, vec!["b"]),
        setup_pkg("b", 1, 0, 0, vec!["c"]),
        setup_pkg("c", 1, 0, 0, vec![]),
    ];
    write_lockfile(&path, &mut pkgs).unwrap();
    let res = read_lockfile(&path).unwrap();
    assert_eq!(res[0].dependencies[0], "b");
    assert_eq!(res[1].dependencies[0], "c");
    assert_eq!(res[2].dependencies.len(), 0);
    std::fs::remove_file(&path).ok();
}

#[test]
fn test_string_api_roundtrip() {
    let mut pkgs = vec![
        setup_pkg("zeta", 1, 0, 0, vec![]),
        setup_pkg("alpha", 1, 0, 0, vec!["zeta"]),
    ];
    let serialized = serialize(&mut pkgs).unwrap();

    // Tamper with CRC to trigger IntegrityCheckFailed
    let mut tampered = serialized.chars().collect::<Vec<_>>();
    if let Some(last) = tampered.last_mut() {
        if *last != 'A' { *last = 'A'; } else { *last = 'B'; }
    }
    let tampered_str: String = tampered.into_iter().collect();

    let result = deserialize(&tampered_str);
    assert!(matches!(result, Err(Error::IntegrityCheckFailed { .. })));
}
