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
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "alpha".to_string(),
                logical_name: None,
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![42u8; 32], attestation: Attestation::None }],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![Dependency { name: "beta".to_string(), dep_type: DepType::Runtime, requested_features: vec![] }],
                ..Default::default()
            },
            Package {
                name: "beta".to_string(),
                logical_name: None,
                source_idx: 0,
                major: 2, minor: 0, patch: 0,
                hashes: vec![IntegrityHash { algo: HashAlgorithm::Blake3, digest: vec![42u8; 32], attestation: Attestation::None }],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![],
                ..Default::default()
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
    let temp_path = PathBuf::from("target/test_ws_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Workspace],
        overrides: vec![],
        features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "core".to_string(),
                logical_name: None,
                source_idx: 0, major: 1, minor: 0, patch: 0,
                hashes: vec![],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![],
                ..Default::default()
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
        features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "z".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![],
            ..Default::default()
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

#[test]
fn test_e2e_features_roundtrip() {
    let temp_path = PathBuf::from("target/test_feat_v5.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![],
        features: vec![("serde".to_string(), vec!["derive".to_string(), "rc".to_string()])],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "serde".to_string(),
                logical_name: None,
                source_idx: 0, major: 1, minor: 0, patch: 0,
                hashes: vec![],
                features: vec!["derive".to_string(), "rc".to_string()],
                resolved_peers: vec![],
                dependencies: vec![],
                ..Default::default()
            },
            Package {
                name: "app".to_string(),
                logical_name: None,
                source_idx: 0, major: 1, minor: 0, patch: 0,
                hashes: vec![],
                features: vec!["derive".to_string()],
                resolved_peers: vec![],
                dependencies: vec![Dependency {
                    name: "serde".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec!["derive".to_string()],
                }],
                ..Default::default()
            },
        ],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert_eq!(res.packages[0].dependencies[0].requested_features, vec!["derive"]);
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
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "esbuild".to_string(),
                logical_name: None,
                source_idx: 0, major: 0, minor: 17, patch: 0,
                hashes: vec![],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![],
                ..Default::default()
            },
            Package {
                name: "app".to_string(),
                logical_name: None,
                source_idx: 0, major: 1, minor: 0, patch: 0,
                hashes: vec![],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![Dependency {
                    name: "esbuild".to_string(),
                    dep_type: DepType::OptionalTarget(TargetOS::Linux, TargetArch::X86_64),
                    requested_features: vec![],
                }],
                ..Default::default()
            },
        ],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert!(matches!(&res.packages[0].dependencies[0].dep_type, DepType::OptionalTarget(TargetOS::Linux, TargetArch::X86_64)));
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_diff_after_adding_package() {
    let mut v1 = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "core".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
        ],
    };
    let serialized_v1 = serialize(&mut v1).unwrap();

    let v2 = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "core".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
            Package { name: "utils".to_string(), logical_name: None, source_idx: 0, major: 2, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
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
    let lockfile = Lockfile {
        sources: vec![
            Source::Registry("https://r.com/".to_string()),
            Source::Workspace,
        ],
        overrides: vec![],
        features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "app".to_string(), logical_name: None, source_idx: 1, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![
                Dependency { name: "serde".to_string(), dep_type: DepType::Runtime, requested_features: vec![] }
            ], ..Default::default() },
            Package { name: "serde".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![0; 32], attestation: Attestation::None }], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
            Package { name: "unused".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
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
fn test_e2e_v7_provenance_roundtrip() {
    let temp_path = PathBuf::from("target/test_e2e_v7.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "crypto-lib".to_string(),
            logical_name: None,
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![IntegrityHash {
                algo: HashAlgorithm::Sha256,
                digest: vec![42u8; 32],
                attestation: Attestation::ExternalBundleSha256([0u8; 32]),
            }],
            features: vec![], resolved_peers: vec![], dependencies: vec![],
            ..Default::default()
        }],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert_eq!(res.packages[0].hashes.len(), 1);
    assert!(matches!(&res.packages[0].hashes[0].attestation, Attestation::ExternalBundleSha256(_)));
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_graph_manipulation_ignores_provenance() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "a".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![], attestation: Attestation::InlineSlsa(SlsaPredicate { builder: "b".to_string(), source: "s".to_string() }) }],
            features: vec![], resolved_peers: vec![], dependencies: vec![],
            ..Default::default()
        }],
    };
    let cid = fnv::calculate("a@1.0.0");
    let sub = extract_subgraph(&lockfile, &[cid]).unwrap();
    match &sub.packages[0].hashes[0].attestation {
        Attestation::InlineSlsa(p) => assert_eq!(p.builder, "b"),
        _ => panic!("Failed to preserve attestation in subgraph"),
    }
}

#[test]
fn test_e2e_v8_peer_resolution_topology() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "app".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![
                PeerResolution { peer_name: "react".to_string(), satisfied_by_content_id: fnv::calculate("react@18.0.0"), is_hoisted_to_root: true }
            ], dependencies: vec![], ..Default::default() },
            Package { name: "react".to_string(), logical_name: None, source_idx: 0, major: 18, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
        ],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let res = deserialize(&serialized).unwrap();
    assert_eq!(res.packages[0].resolved_peers[0].peer_name, "react");
    assert!(res.packages[0].resolved_peers[0].is_hoisted_to_root);
}

#[test]
fn test_e2e_graph_extract_preserves_peers() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "a".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![], features: vec![],
            resolved_peers: vec![PeerResolution { peer_name: "b".to_string(), satisfied_by_content_id: fnv::calculate("b@1.0.0"), is_hoisted_to_root: false }],
            dependencies: vec![],
            ..Default::default()
        }],
    };
    let sub = extract_subgraph(&lockfile, &[fnv::calculate("a@1.0.0")]).unwrap();
    assert_eq!(sub.packages[0].resolved_peers[0].peer_name, "b");
}

#[test]
fn test_e2e_v8_alias_and_cas_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::CasHttp("https://cas.example.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "react".to_string(), logical_name: Some("react-v18".to_string()), source_idx: 0, major: 18, minor: 2, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![], ..Default::default() },
        ],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let deserialized = deserialize(&serialized).unwrap();

    assert_eq!(deserialized.sources[0], Source::CasHttp("https://cas.example.com/".to_string()));
    assert_eq!(deserialized.packages[0].logical_name, Some("react-v18".to_string()));
    assert_eq!(deserialized.packages[0].major, 18);
}

#[test]
fn test_e2e_ipfs_source_roundtrip() {
    let temp_path = PathBuf::from("target/test_ipfs.hlock");
    let mut lockfile = Lockfile {
        sources: vec![Source::Ipfs("ipfs://QmXyZ1abcDEF".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "some-pkg".to_string(),
            logical_name: None,
            source_idx: 0, major: 1, minor: 0, patch: 0,
            hashes: vec![],
            features: vec![], resolved_peers: vec![], dependencies: vec![],
            ..Default::default()
        }],
    };
    write_lockfile(&temp_path, &mut lockfile).unwrap();
    let res = read_lockfile(&temp_path).unwrap();
    assert_eq!(res.sources[0], Source::Ipfs("ipfs://QmXyZ1abcDEF".to_string()));
    assert_eq!(res.packages[0].source_idx, 0);
    std::fs::remove_file(&temp_path).ok();
}

#[test]
fn test_e2e_v9_peer_requirements_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "react-dom".to_string(),
                logical_name: None, source_idx: 0,
                major: 18, minor: 0, patch: 0,
                peer_requirements: vec![
                    PeerRequirement { peer_name: "react".to_string(), version_range: ">=17.0.0".to_string(), is_optional: false },
                    PeerRequirement { peer_name: "react-native".to_string(), version_range: "".to_string(), is_optional: true },
                ],
                resolved_peers: vec![
                    PeerResolution { peer_name: "react".to_string(), satisfied_by_content_id: fnv::calculate("react@18.0.0"), is_hoisted_to_root: true },
                ],
                dependencies: vec![],
                ..Default::default()
            },
            Package { name: "react".to_string(), logical_name: None, source_idx: 0, major: 18, minor: 0, patch: 0, ..Default::default() },
        ],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let res = deserialize(&serialized).unwrap();

    let rdom = res.packages.iter().find(|p| p.name == "react-dom").unwrap();
    assert_eq!(rdom.peer_requirements.len(), 2);
    assert_eq!(rdom.peer_requirements[0].peer_name, "react");
    assert_eq!(rdom.peer_requirements[0].version_range, ">=17.0.0");
    assert!(!rdom.peer_requirements[0].is_optional);
    assert_eq!(rdom.peer_requirements[1].peer_name, "react-native");
    assert!(rdom.peer_requirements[1].is_optional);
    assert_eq!(rdom.resolved_peers.len(), 1);
}

#[test]
fn test_e2e_v9_platform_tags_roundtrip() {
    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package {
                name: "esbuild-darwin-arm64".to_string(),
                logical_name: None, source_idx: 0,
                major: 0, minor: 17, patch: 0,
                platform_tags: vec![PlatformTag { os: TargetOS::MacOS, arch: TargetArch::Aarch64 }],
                ..Default::default()
            },
            Package {
                name: "esbuild-linux-x64".to_string(),
                logical_name: None, source_idx: 0,
                major: 0, minor: 17, patch: 0,
                platform_tags: vec![PlatformTag { os: TargetOS::Linux, arch: TargetArch::X86_64 }],
                ..Default::default()
            },
            Package {
                name: "lodash".to_string(),
                logical_name: None, source_idx: 0,
                major: 4, minor: 17, patch: 21,
                platform_tags: vec![],
                ..Default::default()
            },
        ],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let res = deserialize(&serialized).unwrap();

    assert_eq!(res.packages[0].platform_tags.len(), 1);
    assert_eq!(res.packages[0].platform_tags[0].os, TargetOS::MacOS);
    assert_eq!(res.packages[0].platform_tags[0].arch, TargetArch::Aarch64);
    assert_eq!(res.packages[1].platform_tags.len(), 1);
    assert_eq!(res.packages[1].platform_tags[0].os, TargetOS::Linux);
    assert_eq!(res.packages[2].platform_tags.len(), 0);
}

#[test]
fn test_e2e_sign_lockfile_and_verify() {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key_bytes = *signing_key.verifying_key().as_bytes();
    let mut expanded_key = [0u8; 64];
    expanded_key[..32].copy_from_slice(&seed);
    expanded_key[32..].copy_from_slice(&verifying_key_bytes);

    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![Package {
            name: "app".to_string(), logical_name: None, source_idx: 0,
            major: 1, minor: 0, patch: 0, ..Default::default()
        }],
    };
    let serialized = serialize(&mut lockfile).unwrap();

    let signed = sign_lockfile(&serialized, "ci@company.com", &expanded_key).unwrap();
    assert!(signed.contains("@signature ci@company.com "));

    let verify_result = verify_signature(&signed, &verifying_key_bytes);
    assert!(verify_result.is_ok());
}

#[test]
fn test_e2e_signed_lockfile_deserializes_correctly() {
    let seed: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let verifying_key_bytes = *signing_key.verifying_key().as_bytes();
    let mut expanded_key = [0u8; 64];
    expanded_key[..32].copy_from_slice(&seed);
    expanded_key[32..].copy_from_slice(&verifying_key_bytes);

    let mut lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "alpha".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0, ..Default::default() },
            Package { name: "beta".to_string(), logical_name: None, source_idx: 0, major: 2, minor: 0, patch: 0, ..Default::default() },
        ],
    };
    let serialized = serialize(&mut lockfile).unwrap();
    let signed = sign_lockfile(&serialized, "bot@github-actions", &expanded_key).unwrap();

    let deserialized = deserialize(&signed).unwrap();
    assert_eq!(deserialized.packages.len(), 2);
    assert_eq!(deserialized.packages[0].name, "alpha");
    assert_eq!(deserialized.packages[1].name, "beta");
}

#[test]
fn test_e2e_platform_extraction_with_real_lockfile() {
    let lockfile = Lockfile {
        sources: vec![Source::Registry("https://r.com/".to_string())],
        overrides: vec![], features: vec![],
        metadata: vec![],
        workspace_root: None,
        workspace_pkgs: vec![],
        hoist_boundaries: vec![],
        artifacts: vec![],
        patches: vec![],
        packages: vec![
            Package { name: "app".to_string(), logical_name: None, source_idx: 0, major: 1, minor: 0, patch: 0,
                dependencies: vec![
                    Dependency { name: "esbuild".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                    Dependency { name: "lodash".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                ],
                ..Default::default() },
            Package { name: "esbuild".to_string(), logical_name: None, source_idx: 0, major: 0, minor: 17, patch: 0,
                dependencies: vec![
                    Dependency { name: "esbuild-darwin-arm64".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                    Dependency { name: "esbuild-linux-x64".to_string(), dep_type: DepType::Runtime, requested_features: vec![] },
                ],
                ..Default::default() },
            Package { name: "esbuild-darwin-arm64".to_string(), logical_name: None, source_idx: 0, major: 0, minor: 17, patch: 0,
                platform_tags: vec![PlatformTag { os: TargetOS::MacOS, arch: TargetArch::Aarch64 }],
                dependencies: vec![], ..Default::default() },
            Package { name: "esbuild-linux-x64".to_string(), logical_name: None, source_idx: 0, major: 0, minor: 17, patch: 0,
                platform_tags: vec![PlatformTag { os: TargetOS::Linux, arch: TargetArch::X86_64 }],
                dependencies: vec![], ..Default::default() },
            Package { name: "lodash".to_string(), logical_name: None, source_idx: 0, major: 4, minor: 17, patch: 21,
                platform_tags: vec![],
                dependencies: vec![], ..Default::default() },
        ],
    };
    let app_cid = fnv::calculate("app@1.0.0");

    let mac_res = extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::MacOS, TargetArch::Aarch64).unwrap();
    let mac_names: HashSet<&str> = mac_res.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(mac_res.packages.len(), 4, "mac should have 4 packages: {:?}", mac_names);
    assert!(mac_names.contains("app"));
    assert!(mac_names.contains("esbuild"));
    assert!(mac_names.contains("esbuild-darwin-arm64"));
    assert!(mac_names.contains("lodash"));
    assert!(!mac_names.contains("esbuild-linux-x64"));

    let linux_res = extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Linux, TargetArch::X86_64).unwrap();
    let linux_names: HashSet<&str> = linux_res.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(linux_res.packages.len(), 4, "linux should have 4 packages: {:?}", linux_names);
    assert!(linux_names.contains("app"));
    assert!(linux_names.contains("esbuild"));
    assert!(linux_names.contains("esbuild-linux-x64"));
    assert!(linux_names.contains("lodash"));
    assert!(!linux_names.contains("esbuild-darwin-arm64"));

    let win_res = extract_subgraph_platform(&lockfile, &[app_cid], TargetOS::Windows, TargetArch::X86_64).unwrap();
    let win_names: HashSet<&str> = win_res.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(win_res.packages.len(), 3, "windows should have 3 packages (no native esbuild): {:?}", win_names);
    assert!(win_names.contains("app"));
    assert!(win_names.contains("esbuild"));
    assert!(win_names.contains("lodash"));
    assert!(!win_names.contains("esbuild-darwin-arm64"));
    assert!(!win_names.contains("esbuild-linux-x64"));
}
