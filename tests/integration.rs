use hlock::*;
use std::path::PathBuf;

#[test]
fn test_e2e_write_and_read_v4() {
    let temp_path = PathBuf::from("target/test_e2e_v4.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://npmjs.org/".to_string())],
        overrides: vec![],
        packages: vec![
            Package {
                name: "alpha".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![42u8; 32] }],
                dependencies: vec![Dependency { name: "beta".to_string(), dep_type: DepType::Runtime }],
            },
            Package {
                name: "beta".to_string(),
                source_idx: 0,
                major: 2, minor: 0, patch: 0,
                hashes: vec![IntegrityHash { algo: HashAlgorithm::Blake3, digest: vec![42u8; 32] }],
                dependencies: vec![],
            },
        ],
    };

    write_lockfile(&temp_path, &mut lockfile).expect("Write failed");
    let read_lockfile = read_lockfile(&temp_path).expect("Read failed");

    assert_eq!(read_lockfile.packages.len(), 2);
    assert_eq!(read_lockfile.packages[0].hashes[0].algo, HashAlgorithm::Sha256);
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_workspace_roundtrip() {
    let temp_path = PathBuf::from("target/test_ws_v4.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Workspace],
        overrides: vec![],
        packages: vec![
            Package {
                name: "core".to_string(),
                source_idx: 0, major: 1, minor: 0, patch: 0,
                hashes: vec![],
                dependencies: vec![],
            },
        ],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert_eq!(res.sources[0], Source::Workspace);
    assert_eq!(res.packages[0].hashes.len(), 0);
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_string_api_crc_corruption() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        packages: vec![Package {
            name: "z".to_string(), source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], dependencies: vec![],
        }],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let mut tampered = serialized.chars().collect::<Vec<_>>();
    if tampered.len() > 2 {
        let idx = tampered.len() - 2;
        if tampered[idx] != 'A' { tampered[idx] = 'A'; } else { tampered[idx] = 'B'; }
    }
    let tampered_str: String = tampered.into_iter().collect();
    assert!(matches!(deserialize(&tampered_str), Err(Error::IntegrityCheckFailed { .. })));
}
