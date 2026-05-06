use hlock::*;
use std::collections::HashSet;
use std::path::PathBuf;

#[test]
fn test_e2e_write_and_read_v5() {
    let temp_path = PathBuf::from("target/test_e2e_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://npmjs.org/".to_string())],
        overrides: vec![],
        features: vec![],
        packages: vec![
            Package {
                name: "alpha".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                }],
                features: vec![],
                dependencies: vec![Dependency {
                    name: "beta".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec![],
                }],
            },
            Package {
                name: "beta".to_string(),
                source_idx: 0,
                major: 2,
                minor: 0,
                patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Blake3,
                    digest: vec![42u8; 32],
                }],
                features: vec![],
                dependencies: vec![],
            },
        ],
    };

    write_lockfile(&temp_path, &mut lockfile).expect("Write failed");
    let read_lockfile = read_lockfile(&temp_path).expect("Read failed");

    assert_eq!(read_lockfile.packages.len(), 2);
    assert_eq!(
        read_lockfile.packages[0].hashes[0].algo,
        HashAlgorithm::Sha256
    );
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_workspace_roundtrip() {
    let temp_path = PathBuf::from("target/test_ws_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Workspace],
        overrides: vec![],
        features: vec![],
        packages: vec![Package {
            name: "core".to_string(),
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            dependencies: vec![],
        }],
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
        features: vec![],
        packages: vec![Package {
            name: "z".to_string(),
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            dependencies: vec![],
        }],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let mut tampered = serialized.chars().collect::<Vec<_>>();
    if tampered.len() > 2 {
        let idx = tampered.len() - 2;
        if tampered[idx] != 'A' {
            tampered[idx] = 'A';
        } else {
            tampered[idx] = 'B';
        }
    }
    let tampered_str: String = tampered.into_iter().collect();
    assert!(matches!(
        deserialize(&tampered_str),
        Err(Error::IntegrityCheckFailed { .. })
    ));
}

#[test]
fn test_e2e_diff_after_adding_package() {
    let mut v1 = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        features: vec![],
        packages: vec![Package {
            name: "core".to_string(),
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![],
            features: vec![],
            dependencies: vec![],
        }],
    };
    let serialized_v1 = serialize(&mut v1).unwrap();

    let v2 = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        features: vec![],
        packages: vec![
            Package {
                name: "core".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![],
            },
            Package {
                name: "utils".to_string(),
                source_idx: 0,
                major: 2,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![],
            },
        ],
    };

    let parsed_v1 = deserialize(&serialized_v1).unwrap();
    let diff = diff_lockfiles(&parsed_v1, &v2);

    assert_eq!(diff.unchanged_count, 1);
    assert_eq!(diff.changes.len(), 1);
    assert!(matches!(&diff.changes[0], PackageChange::Added(p) if p.name == "utils"));
}

#[test]
fn test_e2e_extract_and_serialize_is_valid() {
    let mut lockfile = Lockfile {
        sources: vec![
            Source::Registry("https://r.com/".to_string()),
            Source::Workspace,
        ],
        overrides: vec![],
        features: vec![],
        packages: vec![
            Package {
                name: "app".to_string(),
                source_idx: 1,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![Dependency {
                    name: "serde".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec![],
                }],
            },
            Package {
                name: "serde".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![0; 32],
                }],
                features: vec![],
                dependencies: vec![],
            },
            Package {
                name: "unused".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![],
            },
        ],
    };

    let app_cid = fnv::calculate("app@1.0.0");
    let mut subgraph = extract_subgraph(&lockfile, &[app_cid]).unwrap();

    let serialized_sub = serialize(&mut subgraph).unwrap();
    let reparsed = deserialize(&serialized_sub).unwrap();

    assert_eq!(reparsed.sources.len(), 2);
    assert_eq!(reparsed.packages.len(), 2);
    let names: HashSet<&str> = reparsed.packages.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains("app"));
    assert!(names.contains("serde"));
    assert!(!names.contains("unused"));
}

#[test]
fn test_e2e_features_roundtrip() {
    let temp_path = PathBuf::from("target/test_feat_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        features: vec![(
            "serde".to_string(),
            vec!["derive".to_string(), "rc".to_string()],
        )],
        packages: vec![
            Package {
                name: "serde".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec!["derive".to_string(), "rc".to_string()],
                dependencies: vec![],
            },
            Package {
                name: "app".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec!["derive".to_string()],
                dependencies: vec![Dependency {
                    name: "serde".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec!["derive".to_string()],
                }],
            },
        ],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert_eq!(
        res.packages[0].dependencies[0].requested_features,
        vec!["derive"]
    );
    assert_eq!(res.packages[1].features, vec!["derive", "rc"]);
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_optional_target_roundtrip() {
    let temp_path = PathBuf::from("target/test_opt_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        features: vec![],
        packages: vec![
            Package {
                name: "esbuild".to_string(),
                source_idx: 0,
                major: 0,
                minor: 17,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![],
            },
            Package {
                name: "app".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hashes: vec![],
                features: vec![],
                dependencies: vec![Dependency {
                    name: "esbuild".to_string(),
                    dep_type: DepType::OptionalTarget(TargetOS::Linux, TargetArch::X86_64),
                    requested_features: vec![],
                }],
            },
        ],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert!(matches!(
        &res.packages[0].dependencies[0].dep_type,
        DepType::OptionalTarget(TargetOS::Linux, TargetArch::X86_64)
    ));
    std::fs::remove_file(&temp_path).ok();
}
