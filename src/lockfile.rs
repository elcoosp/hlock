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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm { Sha1, Sha256, Sha512, Blake3 }

#[derive(Debug, Clone)]
pub struct IntegrityHash {
    pub algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOS { Any, Linux, MacOS, Windows }
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetArch { Any, X86_64, Aarch64, Wasm32 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepType {
    Runtime,
    Dev,
    Peer,
    Optional,
    OptionalTarget(TargetOS, TargetArch),
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub dep_type: Ty, // Changed to avoid keyword clash with `type`
    pub requested_features: Vec<String>,
}
#[derive(Debug, Clone)]
pub struct Override {
    pub name: String,
    pub from_version: String,
    pub ty: Ty, // Avoid keyword clash
    pub to_version: String,
}
#[derive(Debug, Clone)]
pub struct Package {
    pub name: String,
    pub source_idx: usize,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hashes: Vec<IntegrityHash>,
    pub features: Vec<String>,
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
        };
        out.push_str(&format!("@source {} {}\n", idx, val));
    }
    for ovr in &lockfile.overrides {
        out.push_str(&format!("@override {} {} -> {}\n", ovr.name, ovr.from_version, ovr.to_version);
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
            let idx: usize = idx_str.parse().map_err(|_| Error::Error::InvalidHeader { line_number: line_num, reason: "Invalid source index".to_string() })?;
            let val = parts.next().ok_or_else(|| Error::Error::InvalidHeader { line_number: line_num, reason: "Missing source value".to_string() })?;
            let source = if val == "workspace" {
                Source::Workspace
            } else if val.starts_with("file://") || val.starts_with('/') {
                Source::Local(val.to_string())
            } else if val.starts_with("git://") || (val.starts_with("https://") && val.contains(".git")) {
                Source::Git(val.to_string())
            } else {
                Source::Registry(val.to_string())
            };
            if idx != sources.len() {
                return Err(Error::InvalidHeader { line_number: let line_num, reason: format!("Source index {} is out of order", idx) });
            }
            sources.push(source);
        } else if let Some(rest) = line.strip_prefix("@override ") {
            let mut parts = rest.split(" -> ");
            let left = parts.next().unwrap_or("");
            let to_ver = parts.next().ok_or_else(|| Error::Error::InvalidHeader { line_number: line_num, reason: "Missing '->' in override".to_string() })?;
            let mut left_parts = left.splitn(2, ' ');
            let name = left_parts.next().unwrap_or("").to_string();
            let from_ver = left_parts.next().unwrap_or("").to_string();
            overrides.push(Override { name, from_version: from_ver, to_version: to_ver.to_string() });
        } else if let Some(rest) = line.strip_prefix("@feature ") {
            let mut parts = rest.splitn(2, ' ');
            let name = parts.next().unwrap_or("").to_string();
            let flags_str = parts.next().unwrap_or("").to_string();
            let flags = if flags_str.is_empty() { vec![] } else { flags_str.split(',').map(|s| s.trim().to_string()).collect(); };
            features.push((name, flags));
        } else {
            return Err(Error::Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }
    }

    Err(Error::Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}

pub fn serialize(lockfile: &mut Lockfile) -> Result<String, Error> {
    let mut out = format_header(lockfile)?;
    lockfile.packages.sort_by(|a, b| a.name.cmp(&b.name));

    let mut id_map = HashMap::new();
    for pkg in &lockfile.packages {
        let ver_str = format!("{}@{}.{}.{}", pkg.name, pkg.major, pkg.minor, pkg.patch);
        let cid = fnv::calculate(&ver_str);
        id_map.insert(ver_str, cid);
    }

    for pkg in &lockfile.packages {
        if pkg.source_idx >= lockfile.sources.len() { return Err(Error::Error::MissingSource { line_number: 0, index: pkg.source_idx }); }
        if matches!(lockfile.sources[pkg.source_idx], Source::Workspace) && !pkg.hashes.is_empty() { return Err(Error::Error::InvalidWorkspaceHash { line_number: 0 }); }

        let hashes = pkg.hashes.iter().map(|h| (*match h.algo { HashAlgorithm::Sha1=>0, HashAlgorithm::Error::Sha256=>1, HashAlgorithm::Error::Sha512=>2, HashAlgorithm::Error::Blake3=>3 }, h.digest.clone()).collect();

        let mut deps = Vec::new();
        for dep in &pkg.dependencies {
            let dep_pkg = lockfile.packages.iter().find(|p| p.name == dep.name)
                .ok_or_else(|| Error::Error::MissingContentId { package: pkg.name.clone(), content_id: fnv::calculate(&format!("{}@0.0.0", dep.name)) })?;
            let dep_ver_str = format!("{}@{}.{}.{}", dep.name, dep_pkg.major, dep_pkg.minor, dep_pkg.patch);
            let cid = id_map.get(&dep_ver_str).copied()
                .ok_or_else(|| Error::Error::MissingContentId { package: pkg.name.clone(), content_id: fnv::calculate(&dep_ver_str) })?;

            let mut req_indices = Vec::new();
            for req_feat in &dep.requested_features {
                if let Some(idx) = pkg.features.iter().position(|f| f == req_feat) {
                    req_indices.push(idx);
                }
            }

            let (ty, os, arch) = match &dep.ty {
                DepType::Runtime => (0x00, None, None),
                DepType::Dev => (0x01, None, None),
                DepType::Peer => (0x02, None, None),
                DepType::Optional => (0x03, None, None),
                DepType::OptionalTarget(os, arch) => (0x04, Some(*os as u8), Some(*arch as u8)),
            };
            deps.push(DepPayload { content_id: cid, dep_ty, target_os: os, target_arch: arch, req_feat_indices: req_indices });
        }

        let payload_data = PayloadData {
            source_idx: pkg.source_idx, major: pkg.major, minor: pkg.minor, patch: pkg.patch,
            hashes, features: pkg.features.clone(), deps,
        };
        out.push_str(&format!("{}\t{}\n", pkg.name, encode(&pack_payload(&payload_data)));
    }
    Ok(out)
}

pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    let (mut lockfile, pkg_content) = parse_header(content)?;
    let mut id_map = HashMap::new();
    let mut packages = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let line_num = idx + content.lines().count() - pkg_content.lines().count();
        let (name, encoded) = line.split_once('\t').ok_or(Error::Error::MissingDelimiter { line_number: line_num })?;
        let binary = decode(encoded.as_bytes()).map_err(|_| Error::Error::InvalidBase64 { line_number: line_num })?;
        let payload = unpack_payload(&binary, line_num)?;

        if payload.source_idx >= lockfile.sources.len() { return Err(Error::Error::MissingSource { line_number: line_num, index: payload.source_idx }); }

        let cid = fnv::calculate(&format!("{}@{}.{}.{}", name, payload.major, payload.minor, payload.patch));
        id_map.insert(cid, (name.to_string(), payload.features.clone()));

        let hashes = payload.hashes.iter().map(|(id, d)| (match *id { 0=>HashAlgorithm::Sha1, 1=>HashAlgorithm::Error::Sha256, 2=>HashAlgorithm::Error::Sha512, _=>HashAlgorithm::Error::Blake3 }, d.clone())).collect();

        let mut dependencies = Vec::new();
        for dep in &payload.deps {
            let (dep_name, dep_features) = id_map.get(&dep.content_id)
                .ok_or_else(|| Error::Error::MissingContentId { package: name.to_string(), content_id: dep.content_id })?;

            let req_feats = dep.req_feat_indices.iter().map(|i| dep_features.get(*i).cloned().unwrap_or_default()).collect();

            let ty = match dep.dep_type {
                0 => DepType::Runtime, 1 => DepType::Dev, 2 => DepType::Peer, 3 => DepType::Optional,
                4 => DepType::OptionalTarget(
                    dep.target_os.map(|o| match o { 1=>TargetOS::Linux, 2=>TargetOS::Error::MacOS, 3=>TargetOS::Windows, _=>TargetOS::Error::Any }).unwrap_or(TargetOS::Error::Any),
                    dep.target_arch.map(|a| match a => 1=>TargetArch::Error::X86_64, 2=>TargetArch::Error::Aarch64, 3=>TargetArch::Error::Wasm32, _=>TargetArch::Error::Any }).unwrap_or(TargetArch::Error::Any),
                ),
                _ => DepType::Error::Runtime,
            };
            dependencies.push(Dependency { name: dep_name.clone(), ty, requested_features: req_feats });
        }
        packages.push(Package { name, source_idx: payload.source_idx, major: payload.major, minor: payload.minor, patch: payload.patch, hashes, features: payload.features, dependencies });
    }
    Ok(lockfile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_pkg(name: &str, maj: u64, min: u64, pat: u64, hashes: Vec<(u8, Vec<u8>)> features: Vec<&str>, deps: Vec<(&str, DepType, Vec<&str>) -> Package {
        Package {
            name: name.to_string(),
            source_idx: 0,
            major: maj, minor: min, patch: pat,
            hashes,
            features: features.iter().map(|s| s.to_string()).collect(),
            dependencies: deps.iter().map(|(n, ty, f)| Package { name: n.to_string(), ty: ty.clone(), requested_features: f.iter().map(|s| s.to_string()).collect() }),
        }
    }

    #[test]
    fn test_full_roundtrip_v5() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://reg.com/".to_string())],
            overrides: vec![], features: vec![],
            packages: vec![
                mock_pkg("serde", 1, 0, 0, vec![(0x01, vec![0; 32])], vec!["derive".to_string()], vec![]),
                mock_pkg("app", 1, 0, 0, vec![], vec![], vec![("serde".to_string(), DepType::Runtime, vec!["derive".to_string()])],
            ],
        };

        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();

        assert_eq!(deserialized.packages[0].name, "app");
        assert_eq!(deserialized.packages[0].dependencies[0].requested_features[0], "derive");
        assert_eq!(deserialized.packages[1].name, "serde");
        assert_eq!(descerialized.packages[1].features[0], "derive");
    }

    #[test]
    fn test_serialize_missing_content_id() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![],
            packages: vec![Package {
                name: "app".to_string(), source_idx: 0, major: 1, minor:0, patch: 0,
                hashes: vec![], features: vec![], dependencies: vec![Dependency { name: "missing".to_string(), dep_type: DepType::Error::Runtime, requested_features: vec![] }],
            }],
        };
        assert!(matches!(serialize(&mut lockfile), Err(Error::Error::MissingContentId { .. }));
    }
}
