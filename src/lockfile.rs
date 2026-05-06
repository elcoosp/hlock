use crate::error::Error;
use crate::payload::{PayloadData, DepPayload, pack_payload, unpack_payload};
use crate::base64url::{encode, decode};
use crate::fnv;
use std::collections::hash_map::HashMap;
use std::path::Path;
use std::fs;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Registry(String),
    Local(String),
    Git(String),
    Workspace,
    CasHttp(String),
    Ipfs(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm { Sha1, Sha256, Sha512, Blake3 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlsaPredicate {
    pub builder: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    None,
    ExternalBundleSha256([u8; 32]),
    InlineSlsa(SlsaPredicate),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityHash {
    pub algo: HashAlgorithm,
    pub digest: Vec<u8>,
    pub attestation: Attestation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOS { Any, Linux, MacOS, Windows, FreeBSD, Android, IOS, Unknown }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetArch { Any, X86_64, Aarch64, Wasm32, Arm, S390x, Ppc64le, Unknown }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepType {
    Runtime,
    Dev,
    Peer,
    Optional,
    OptionalTarget(TargetOS, TargetArch),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub dep_type: DepType,
    pub requested_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageChange {
    Added(Package),
    Removed(Package),
    Altered(Package, Package),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockfileDiff {
    pub changes: Vec<PackageChange>,
    pub unchanged_count: usize,
}

#[derive(Debug, Clone)]
pub struct Override {
    pub name: String,
    pub from_version: String,
    pub ty: DepType,
    pub to_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTag {
    pub os: TargetOS,
    pub arch: TargetArch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRequirement {
    pub peer_name: String,
    pub version_range: String,
    pub is_optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatMode {
    V8,
    V9,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerResolution {
    pub peer_name: String,
    pub satisfied_by_content_id: u64,
    pub is_hoisted_to_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    pub logical_name: Option<String>,
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<IntegrityHash>,
    pub features: Vec<String>,
    pub resolved_peers: Vec<PeerResolution>,
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone)]
pub struct Lockfile {
    pub sources: Vec<Source>,
    pub overrides: Vec<Override>,
    pub features: Vec<(String, Vec<String>)>,
    pub packages: Vec<Package>,
}

fn format_header(lockfile: &Lockfile) -> Result<String, Error> {
    let mut out = String::new();
    for (idx, source) in lockfile.sources.iter().enumerate() {
        let val = match source {
            Source::Registry(u) => u.clone(),
            Source::Local(u) => u.clone(),
            Source::Git(u) => u.clone(),
            Source::Workspace => "workspace".to_string(),
            Source::CasHttp(u) => format!("cas+{}", u),
            Source::Ipfs(u) => u.clone(),
        };
        out.push_str(&format!("@source {} {}\n", idx, val));
    }
    for ovr in &lockfile.overrides {
        out.push_str(&format!("@override {} {} -> {}\n", ovr.name, ovr.from_version, ovr.to_version));
    }
    for (name, flags) in &lockfile.features {
        let flags_str = if flags.is_empty() { "" } else { &flags.join(",") };
        out.push_str(&format!("@feature {} {}\n", name, flags_str));
    }
    out.push('\n');
    Ok(out)
}

fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let mut features = vec![];
    let lines = content.lines().enumerate();

    for (line_num, line) in lines {
        if line.is_empty() {
            let header_end = content.find("\n\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((Lockfile { sources, overrides, features, packages: vec![] }, remaining));
        }

        if let Some(rest) = line.strip_prefix("@source ") {
            let mut parts = rest.splitn(2, ' ');
            let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source index".to_string() })?;
            let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader { line_number: line_num, reason: "Invalid source index".to_string() })?;
            let val = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source value".to_string() })?;
            let source = if val == "workspace" {
                Source::Workspace
            } else if val.starts_with("file://") || val.starts_with('/') {
                Source::Local(val.to_string())
            } else if val.starts_with("git://") || (val.starts_with("https://") && val.contains(".git")) {
                Source::Git(val.to_string())
            } else if val.starts_with("cas+http://") || val.starts_with("cas+https://") {
                Source::CasHttp(val.strip_prefix("cas+").unwrap_or(val).to_string())
            } else if val.starts_with("ipfs://") {
                Source::Ipfs(val.to_string())
            } else {
                Source::Registry(val.to_string())
            };
            if idx != sources.len() {
                return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Source index {} is out of order", idx) });
            }
            sources.push(source);
        } else if let Some(rest) = line.strip_prefix("@override ") {
            let mut parts = rest.split(" -> ");
            let left = parts.next().unwrap_or("");
            let to_ver = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing '->' in override".to_string() })?;
            let mut left_parts = left.splitn(2, ' ');
            let name = left_parts.next().unwrap_or("").to_string();
            let from_ver = left_parts.next().unwrap_or("").to_string();
            overrides.push(Override { name, from_version: from_ver, ty: DepType::Runtime, to_version: to_ver.to_string() });
        } else if let Some(rest) = line.strip_prefix("@feature ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().unwrap_or("").to_string();
            let flags_str = parts.next().unwrap_or("").to_string();
            let flags = if flags_str.is_empty() { vec![] } else { flags_str.split(',').map(|s| s.trim().to_string()).collect() };
            features.push((name, flags));
        } else {
            return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}

pub fn serialize(lockfile: &mut Lockfile) -> Result<String, Error> {
    let mut out = format_header(lockfile)?;
    lockfile.packages.sort_by(|a, b| a.name.cmp(&b.name));

    for pkg in &lockfile.packages {
        if pkg.source_idx >= lockfile.sources.len() {
            return Err(Error::MissingSource { line_number: 0, index: pkg.source_idx });
        }
        if matches!(lockfile.sources[pkg.source_idx], Source::Workspace) && !pkg.hashes.is_empty() {
            return Err(Error::InvalidWorkspaceHash { line_number: 0 });
        }

        let hashes: Vec<crate::payload::HashPayload> = pkg.hashes.iter().map(|h| {
            let algo_id = match h.algo { HashAlgorithm::Sha1 => 0, HashAlgorithm::Sha256 => 1, HashAlgorithm::Sha512 => 2, HashAlgorithm::Blake3 => 3 };
            crate::payload::HashPayload { algo_id, digest: h.digest.clone(), attestation: h.attestation.clone() }
        }).collect();

        let mut deps = Vec::new();
        for dep in &pkg.dependencies {
            let dep_pkg = lockfile.packages.iter()
                .find(|p| p.name == dep.name)
                .ok_or_else(|| Error::MissingContentId {
                    package: pkg.name.clone(),
                    content_id: fnv::calculate(&format!("{}@0.0.0", dep.name)),
                })?;

            let dep_ver_str = format!("{}@{}.{}.{}", dep_pkg.name, dep_pkg.major, dep_pkg.minor, dep_pkg.patch);
            let cid = fnv::calculate(&dep_ver_str);

            let mut req_indices = Vec::new();
            for req_feat in &dep.requested_features {
                if let Some(idx) = pkg.features.iter().position(|f| f == req_feat) {
                    req_indices.push(idx);
                }
            }

            let (ty, os, arch) = match &dep.dep_type {
                DepType::Runtime => (0x00, None, None),
                DepType::Dev => (0x01, None, None),
                DepType::Peer => (0x02, None, None),
                DepType::Optional => (0x03, None, None),
                DepType::OptionalTarget(target_os, target_arch) => {
                    let os_id = match target_os {
                        TargetOS::Any => 0x00, TargetOS::Linux => 0x01, TargetOS::MacOS => 0x02,
                        TargetOS::Windows => 0x03, TargetOS::FreeBSD => 0x04, TargetOS::Android => 0x05,
                        TargetOS::IOS => 0x06, TargetOS::Unknown => 0xFF,
                    };
                    let arch_id = match target_arch {
                        TargetArch::Any => 0x00, TargetArch::X86_64 => 0x01, TargetArch::Aarch64 => 0x02,
                        TargetArch::Wasm32 => 0x03, TargetArch::Arm => 0x04, TargetArch::S390x => 0x05,
                        TargetArch::Ppc64le => 0x06, TargetArch::Unknown => 0xFF,
                    };
                    (0x04, Some(os_id), Some(arch_id))
                }
            };
            deps.push(DepPayload {
                content_id: cid,
                dep_type: ty,
                target_os: os,
                target_arch: arch,
                req_feat_indices: req_indices,
            });
        }

        let payload_data = PayloadData {
            logical_name: pkg.logical_name.clone(),
            source_idx: pkg.source_idx,
            major: pkg.major,
            minor: pkg.minor,
            patch: pkg.patch,
            hashes,
            features: pkg.features.clone(),
            resolved_peers: pkg.resolved_peers.clone(),
            deps,
        };
        let encoded = encode(&pack_payload(&payload_data));
        out.push_str(&format!("{}\t{}\n", pkg.name, encoded));
    }
    Ok(out)
}

pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    let (mut lockfile, pkg_content) = parse_header(content)?;

    let header_line_count = content.lines().count() - pkg_content.lines().count();
    let mut parsed_payloads = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let line_num = header_line_count + idx;
        let (name, encoded) = line.split_once('\t')
            .ok_or(Error::MissingDelimiter { line_number: line_num })?;
        let binary = decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidBase64 { line_number: line_num })?;
        let payload = unpack_payload(&binary, line_num)?;

        if payload.source_idx >= lockfile.sources.len() {
            return Err(Error::MissingSource { line_number: line_num, index: payload.source_idx });
        }

        parsed_payloads.push((name.to_string(), payload, line_num));
    }

    let mut id_map: HashMap<u64, (String, Vec<String>)> = HashMap::new();
    for (name, payload, _) in &parsed_payloads {
        let cid = fnv::calculate(&format!("{}@{}.{}.{}", name, payload.major, payload.minor, payload.patch));
        id_map.insert(cid, (name.clone(), payload.features.clone()));
    }

    let mut packages = Vec::new();
    for (name, payload, _line_num) in parsed_payloads {
        let hashes: Vec<IntegrityHash> = payload.hashes.iter().map(|h| {
            let algo = match h.algo_id { 0 => HashAlgorithm::Sha1, 1 => HashAlgorithm::Sha256, 2 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 };
            IntegrityHash { algo, digest: h.digest.clone(), attestation: h.attestation.clone() }
        }).collect();

        let mut dependencies = Vec::new();
        for dep in &payload.deps {
            let (dep_name, dep_features) = id_map.get(&dep.content_id)
                .ok_or_else(|| Error::MissingContentId {
                    package: name.clone(),
                    content_id: dep.content_id,
                })?;

            let req_feats: Vec<String> = dep.req_feat_indices.iter()
                .map(|i| dep_features.get(*i).cloned().unwrap_or_default())
                .collect();

            let ty = match dep.dep_type {
                0 => DepType::Runtime,
                1 => DepType::Dev,
                2 => DepType::Peer,
                3 => DepType::Optional,
                4 => {
                    let os = dep.target_os.map(|o| match o {
                        0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS,
                        0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android,
                        0x06 => TargetOS::IOS, _ => TargetOS::Unknown,
                    }).unwrap_or(TargetOS::Any);
                    let arch = dep.target_arch.map(|a| match a {
                        0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64,
                        0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x,
                        0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown,
                    }).unwrap_or(TargetArch::Any);
                    DepType::OptionalTarget(os, arch)
                }
                _ => DepType::Runtime,
            };
            dependencies.push(Dependency {
                name: dep_name.clone(),
                dep_type: ty,
                requested_features: req_feats,
            });
        }
        packages.push(Package {
            name,
            logical_name: payload.logical_name,
            source_idx: payload.source_idx,
            major: payload.major,
            minor: payload.minor,
            patch: payload.patch,
            hashes,
            features: payload.features,
            resolved_peers: payload.resolved_peers,
            dependencies,
        });
    }
    lockfile.packages = packages;
    Ok(lockfile)
}

pub fn write_lockfile(path: &Path, lockfile: &mut Lockfile) -> Result<(), Error> {
    let content = serialize(lockfile)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn read_lockfile(path: &Path) -> Result<Lockfile, Error> {
    let content = fs::read_to_string(path)?;
    deserialize(&content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{extract_subgraph, diff_lockfiles};

    fn mock_pkg(
        name: &str,
        maj: u64, min: u64, pat: u64,
        hashes: Vec<(u8, Vec<u8>)>,
        features: Vec<&str>,
        deps: Vec<(&str, DepType, Vec<&str>)>,
    ) -> Package {
        Package {
            name: name.to_string(),
            logical_name: None,
            source_idx: 0,
            major: maj, minor: min, patch: pat,
            hashes: hashes.iter().map(|(id, d)| IntegrityHash {
                algo: match *id {
                    0 => HashAlgorithm::Sha1,
                    1 => HashAlgorithm::Sha256,
                    2 => HashAlgorithm::Sha512,
                    _ => HashAlgorithm::Blake3,
                },
                digest: d.clone(),
                attestation: Attestation::None,
            }).collect(),
            features: features.iter().map(|s| s.to_string()).collect(),
            resolved_peers: vec![],
            dependencies: deps.iter().map(|(n, ty, f)| Dependency {
                name: n.to_string(),
                dep_type: ty.clone(),
                requested_features: f.iter().map(|s| s.to_string()).collect(),
            }).collect(),
        }
    }

    fn mock_pkg_with_attestation(
        name: &str, maj: u64, min: u64, pat: u64,
        hashes: Vec<(u8, Vec<u8>, Attestation)>,
        features: Vec<&str>, deps: Vec<(&str, DepType, Vec<&str>)>
    ) -> Package {
        Package {
            name: name.to_string(),
            logical_name: None,
            source_idx: 0,
            major: maj, minor: min, patch: pat,
            hashes: hashes.iter().map(|(id, d, a)| IntegrityHash {
                algo: match *id { 0 => HashAlgorithm::Sha1, 1 => HashAlgorithm::Sha256, 2 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 },
                digest: d.clone(),
                attestation: a.clone(),
            }).collect(),
            features: features.iter().map(|s| s.to_string()).collect(),
            resolved_peers: vec![],
            dependencies: deps.iter().map(|(n, ty, f)| Dependency { name: n.to_string(), dep_type: ty.clone(), requested_features: f.iter().map(|s| s.to_string()).collect() }).collect(),
        }
    }

    #[test]
    fn test_full_roundtrip_v5() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://reg.com/".to_string())],
            overrides: vec![],
            features: vec![],
            packages: vec![
                mock_pkg("serde", 1, 0, 0, vec![(0x01, vec![0; 32])], vec!["derive"], vec![]),
                mock_pkg("app", 1, 0, 0, vec![], vec![], vec![("serde", DepType::Runtime, vec!["derive"])]),
            ],
        };

        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();

        assert_eq!(deserialized.packages[0].name, "app");
        assert_eq!(deserialized.packages[0].dependencies[0].requested_features.len(), 0);
        assert_eq!(deserialized.packages[1].name, "serde");
        assert_eq!(deserialized.packages[1].features[0], "derive");
    }

    #[test]
    fn test_roundtrip_v7_with_slsa() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![
                mock_pkg_with_attestation("secure-pkg", 1, 0, 0, vec![
                    (0x01, vec![0; 32], Attestation::InlineSlsa(SlsaPredicate { builder: "gha".to_string(), source: "git".to_string() }))
                ], vec![], vec![]),
            ],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();

        assert_eq!(deserialized.packages[0].name, "secure-pkg");
        match &deserialized.packages[0].hashes[0].attestation {
            Attestation::InlineSlsa(p) => assert_eq!(p.builder, "gha"),
            _ => panic!("Expected InlineSlsa"),
        }
    }

    #[test]
    fn test_extract_missing_root() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![mock_pkg("alpha", 1, 0, 0, vec![], vec![], vec![])],
        };
        let fake_cid = 999999999;
        let res = extract_subgraph(&lockfile, &[fake_cid]);
        assert!(matches!(res, Err(Error::RootContentIdMissing { content_id: 999999999 })));
    }

    #[test]
    fn test_extract_single_root_no_deps() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![mock_pkg("alpha", 1, 0, 0, vec![], vec![], vec![])],
        };
        let cid = fnv::calculate("alpha@1.0.0");
        let res = extract_subgraph(&lockfile, &[cid]).unwrap();
        assert_eq!(res.packages.len(), 1);
        assert_eq!(res.packages[0].name, "alpha");
    }

    #[test]
    fn test_extract_transitive_deps() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![
                mock_pkg("alpha", 1, 0, 0, vec![], vec![], vec![("beta", DepType::Runtime, vec![])]),
                mock_pkg("beta", 1, 0, 0, vec![], vec![], vec![("gamma", DepType::Runtime, vec![])]),
                mock_pkg("gamma", 1, 0, 0, vec![], vec![], vec![]),
                mock_pkg("omega", 1, 0, 0, vec![], vec![], vec![]),
            ],
        };
        let cid_alpha = fnv::calculate("alpha@1.0.0");
        let res = extract_subgraph(&lockfile, &[cid_alpha]).unwrap();

        assert_eq!(res.packages.len(), 3);
        let names: Vec<&str> = res.packages.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(names.contains(&"gamma"));
        assert!(!names.contains(&"omega"));
    }

    #[test]
    fn test_extract_source_pruning() {
        let lockfile = Lockfile {
            sources: vec![
                Source::Registry("https://unused.com/".to_string()),
                Source::Registry("https://used.com/".to_string()),
            ],
            overrides: vec![],
            features: vec![],
            packages: vec![
                Package { name: "alpha".to_string(), logical_name: None, source_idx: 1, major: 1, minor: 0, patch: 0, hashes: vec![], features: vec![], resolved_peers: vec![], dependencies: vec![] },
            ],
        };
        let cid_alpha = fnv::calculate("alpha@1.0.0");
        let res = extract_subgraph(&lockfile, &[cid_alpha]).unwrap();

        assert_eq!(res.sources.len(), 1);
        assert_eq!(res.sources[0], Source::Registry("https://used.com/".to_string()));
        assert_eq!(res.packages[0].source_idx, 0);
    }

    #[test]
    fn test_extract_preserves_metadata() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("r".to_string())],
            overrides: vec![Override { name: "lodash".to_string(), from_version: "4.0.0".to_string(), ty: DepType::Runtime, to_version: "4.17.21".to_string() }],
            features: vec![("cli".to_string(), vec!["verbose".to_string()])],
            packages: vec![mock_pkg("cli", 1, 0, 0, vec![], vec![], vec![])],
        };
        let res = extract_subgraph(&lockfile, &[fnv::calculate("cli@1.0.0")]).unwrap();
        assert_eq!(res.overrides.len(), 1);
        assert_eq!(res.features.len(), 1);
    }

    #[test]
    fn test_diff_empty_lockfiles() {
        let old = Lockfile { sources: vec![], overrides: vec![], features: vec![], packages: vec![] };
        let new = Lockfile { sources: vec![], overrides: vec![], features: vec![], packages: vec![] };
        let diff = diff_lockfiles(&old, &new);
        assert_eq!(diff.unchanged_count, 0);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn test_diff_unchanged_packages() {
        let pkg = mock_pkg("serde", 1, 0, 0, vec![(0x01, vec![0; 32])], vec![], vec![]);
        let old = Lockfile { sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![], packages: vec![pkg.clone()] };
        let new = old.clone();
        let diff = diff_lockfiles(&old, &new);
        assert_eq!(diff.unchanged_count, 1);
        assert!(diff.changes.is_empty());
    }

    #[test]
    fn test_target_os_expanded_variants() {
        let os = TargetOS::FreeBSD;
        let os2 = TargetOS::Android;
        let os3 = TargetOS::IOS;
        let os4 = TargetOS::Unknown;
        assert_eq!(format!("{:?}", os), "FreeBSD");
        assert_eq!(format!("{:?}", os2), "Android");
        assert_eq!(format!("{:?}", os3), "IOS");
        assert_eq!(format!("{:?}", os4), "Unknown");
    }

    #[test]
    fn test_diff_added_removed_altered() {
        let old = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![
                mock_pkg("alpha", 1, 0, 0, vec![], vec![], vec![]),
                mock_pkg("beta", 1, 0, 0, vec![(0x01, vec![0; 32])], vec![], vec![]),
            ],
        };
        let new = Lockfile {
            sources: vec![Source::Registry("r".to_string())], overrides: vec![], features: vec![],
            packages: vec![
                mock_pkg("beta", 2, 0, 0, vec![(0x01, vec![0; 32])], vec![], vec![]),
                mock_pkg("gamma", 1, 0, 0, vec![], vec![], vec![]),
            ],
        };

        let diff = diff_lockfiles(&old, &new);

        assert!(matches!(&diff.changes[0], PackageChange::Removed(p) if p.name == "alpha"));
        assert!(matches!(&diff.changes[1], PackageChange::Altered(o, n) if o.name == "beta" && o.major == 1 && n.major == 2));
        assert!(matches!(&diff.changes[2], PackageChange::Added(p) if p.name == "gamma"));
        assert_eq!(diff.unchanged_count, 0);
    }

    #[test]
    fn test_serialize_missing_content_id() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![],
            features: vec![],
            packages: vec![Package {
                name: "app".to_string(),
                logical_name: None,
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                hashes: vec![],
                features: vec![],
                resolved_peers: vec![],
                dependencies: vec![Dependency {
                    name: "missing".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec![],
                }],
            }],
        };
        assert!(matches!(serialize(&mut lockfile), Err(Error::MissingContentId { .. })));
    }
}
