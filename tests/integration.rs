use hlock::{Package, write_lockfile, read_lockfile};
use std::path::PathBuf;

fn setup_pkg(name: &str, maj: u64, min: u64, pat: u64, deps: Vec<&str>) -> Package {
    Package {
        name: name.to_string(),
        major: maj,
        minor: min,
        patch: pat,
        hash: [42u8; 16],
        dependencies: deps.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn test_e2e_write_and_read() {
    let temp_path = PathBuf::from("target/test_e2e.hlock");

    let packages = vec![
        setup_pkg("alpha", 1, 0, 0, vec!["beta"]),
        setup_pkg("beta", 2, 0, 0, vec![]),
    ];

    write_lockfile(&temp_path, packages.clone()).expect("Write failed");

    let read_packages = read_lockfile(&temp_path).expect("Read failed");

    assert_eq!(read_packages.len(), 2);
    assert_eq!(read_packages[0].name, "alpha");
    assert_eq!(read_packages[0].dependencies[0], "beta");
    assert_eq!(read_packages[0].hash, [42u8; 16]);

    std::fs::remove_file(&temp_path).ok();
}
