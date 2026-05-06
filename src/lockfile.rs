use crate::error::Error;
use crate::payload::{PayloadData, pack_payload, unpack_payload};
use crate::base64url::{encode, decode};
use std::collections::HashMap;
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
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Blake3,
}

#[derive(Debug, Clone)]
pub struct IntegrityHash {
    pub algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DepType {
    Runtime,
    Dev,
    Peer,
    Optional,
}

#[derive(Debug, Clone)]
pub struct Dependency {
    pub name: String,
    pub dep_type: DepType,
}

#[derive(Debug, Clone)]
pub struct Override {
    pub name: String,
    pub from_version: String,
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
    pub dependencies: Vec<Dependency>,
}

#[derive(Debug, Clone)]
pub struct Lockfile {
    pub sources: Vec<Source>,
    pub overrides: Vec<Override>,
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
        out.push_str(&format!("@override {} {} -> {}\n", ovr.name, ovr.from_version, ovr.to_version));
    }
    out.push('\n');
    Ok(out)
}

fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let lines = content.lines().enumerate();

    for (line_num, line) in lines {
        if line.is_empty() {
            let header_end = content.find("\n\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((Lockfile { sources, overrides, packages: vec![] }, remaining));
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

            overrides.push(Override { name, from_version: from_ver, to_version: to_ver.to_string() });
        } else {
            return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}

pub fn serialize(lockfile: &mut Lockfile) -> Result<String, Error> {
    let mut out = format_header(lockfile)?;
    lockfile.packages.sort_by(|a, b| a.name.cmp(&b.name));

    let mut index_map = HashMap::new();
    for (i, p) in lockfile.packages.iter().enumerate() {
        index_map.insert(p.name.clone(), i as u64);
    }

    for pkg in &lockfile.packages {
        if pkg.source_idx >= lockfile.sources.len() {
            return Err(Error::MissingSource { line_number: 0, index: pkg.source_idx });
        }

        if matches!(lockfile.sources[pkg.source_idx], Source::Workspace) && !pkg.hashes.is_empty() {
            return Err(Error::InvalidWorkspaceHash { line_number: 0 });
        }

        let hashes = pkg.hashes.iter().map(|h| {
            let algo_id = match h.algo {
                HashAlgorithm::Sha1 => 0x00,
                HashAlgorithm::Sha256 => 0x01,
                HashAlgorithm::Sha512 => 0x02,
                HashAlgorithm::Blake3 => 0x03,
            };
            (algo_id, h.digest.clone())
        }).collect();

        let mut deps = Vec::with_capacity(pkg.dependencies.len());
        for dep in &pkg.dependencies {
            let idx = index_map.get(&dep.name)
                .ok_or_else(|| Error::MissingPackage { package: pkg.name.clone(), missing_dep: dep.name.clone() })?;
            let type_id = match dep.dep_type {
                DepType::Runtime => 0x00,
                DepType::Dev => 0x01,
                DepType::Peer => 0x02,
                DepType::Optional => 0x03,
            };
            deps.push((*idx, type_id));
        }

        let payload_data = PayloadData {
            source_idx: pkg.source_idx,
            major: pkg.major, minor: pkg.minor, patch: pkg.patch,
            hashes, deps,
        };

        let binary = pack_payload(&payload_data);
        let encoded = encode(&binary);
        out.push_str(&format!("{}\t{}\n", pkg.name, encoded));
    }
    Ok(out)
}

pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    let (mut lockfile, pkg_content) = parse_header(content)?;
    let mut name_index = HashMap::new();
    let mut raw_entries = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        let line_num = idx + content.lines().count() - pkg_content.lines().count();
        let (name, encoded) = line.split_once('\t')
            .ok_or(Error::MissingDelimiter { line_number: line_num })?;

        let binary = decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidBase64 { line_number: line_num })?;
        let payload = unpack_payload(&binary, line_num)?;

        if payload.source_idx >= lockfile.sources.len() {
            return Err(Error::MissingSource { line_number: line_num, index: payload.source_idx });
        }

        name_index.insert(idx as u64, name.to_string());
        raw_entries.push((name.to_string(), payload));
    }

    for (name, payload) in raw_entries {
        let hashes = payload.hashes.iter().map(|(algo_id, digest)| {
            let algo = match algo_id {
                0x00 => HashAlgorithm::Sha1,
                0x01 => HashAlgorithm::Sha256,
                0x02 => HashAlgorithm::Sha512,
                0x03 => HashAlgorithm::Blake3,
                _ => HashAlgorithm::Sha256,
            };
            IntegrityHash { algo, digest: digest.clone() }
        }).collect();

        let dependencies = payload.deps.iter().map(|(line_idx, type_id)| {
            let dep_name = name_index.get(line_idx).cloned().unwrap_or_else(|| format!("<missing_idx_{}>", line_idx));
            let dep_type = match type_id {
                0x00 => DepType::Runtime,
                0x01 => DepType::Dev,
                0x02 => DepType::Peer,
                0x03 => DepType::Optional,
                _ => DepType::Runtime,
            };
            Dependency { name: dep_name, dep_type }
        }).collect();

        lockfile.packages.push(Package {
            name, source_idx: payload.source_idx,
            major: payload.major, minor: payload.minor, patch: payload.patch,
            hashes, dependencies,
        });
    }
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

    #[test]
    fn test_format_header_workspace() {
        let lockfile = Lockfile {
            sources: vec![Source::Workspace],
            overrides: vec![],
            packages: vec![],
        };
        let res = format_header(&lockfile).unwrap();
        assert_eq!(res.trim(), "@source 0 workspace");
    }

    #[test]
    fn test_parse_header_workspace() {
        let content = "@source 0 workspace\n\nrest";
        let (lockfile, remaining) = parse_header(content).unwrap();
        assert_eq!(lockfile.sources.len(), 1);
        assert_eq!(lockfile.sources[0], Source::Workspace);
        assert_eq!(remaining, "rest");
    }

    #[test]
    fn test_serialize_workspace_rejects_hashes() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Workspace],
            overrides: vec![],
            packages: vec![
                Package {
                    name: "local-pkg".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![0; 32] }],
                    dependencies: vec![],
                },
            ],
        };
        assert!(matches!(serialize(&mut lockfile), Err(Error::InvalidWorkspaceHash { .. })));
    }

    #[test]
    fn test_full_roundtrip_v4() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://reg.com/".to_string())],
            overrides: vec![],
            packages: vec![
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hashes: vec![
                        IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![0; 32] },
                        IntegrityHash { algo: HashAlgorithm::Blake3, digest: vec![0; 32] },
                    ],
                    dependencies: vec![],
                },
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hashes: vec![],
                    dependencies: vec![Dependency { name: "beta".to_string(), dep_type: DepType::Dev }],
                },
            ],
        };

        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();

        assert_eq!(deserialized.packages[0].name, "alpha");
        assert_eq!(deserialized.packages[1].name, "beta");
        assert_eq!(deserialized.packages[1].hashes.len(), 2);
        assert_eq!(deserialized.packages[1].hashes[1].algo, HashAlgorithm::Blake3);
        assert_eq!(deserialized.packages[0].dependencies[0].dep_type, DepType::Dev);
    }
}
