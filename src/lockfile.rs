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
    pub hash: Vec<u8>,
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
        let uri = match source {
            Source::Registry(u) => u,
            Source::Local(u) => u,
            Source::Git(u) => u,
        };
        out.push_str(&format!("@source {} {}\n", idx, uri));
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
    let mut lines = content.lines().enumerate();

    while let Some((line_num, line)) = lines.next() {
        if line.is_empty() {
            let header_end = content.find("\n\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((Lockfile { sources, overrides, packages: vec![] }, remaining));
        }

        if let Some(rest) = line.strip_prefix("@source ") {
            let mut parts = rest.splitn(2, ' ');
            let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source index".to_string() })?;
            let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader { line_number: line_num, reason: "Invalid source index".to_string() })?;
            let uri = parts.next().ok_or_else(|| Error::InvalidHeader { line_number: line_num, reason: "Missing source URI".to_string() })?;

            let source = if uri.starts_with("file://") || uri.starts_with('/') {
                Source::Local(uri.to_string())
            } else if uri.starts_with("git://") || (uri.starts_with("https://") && uri.contains(".git")) {
                Source::Git(uri.to_string())
            } else {
                Source::Registry(uri.to_string())
            };

            if idx != sources.len() {
                return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Source index {} is out of order (expected {})", idx, sources.len()) });
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
    lockfile.packages.iter().enumerate().for_each(|(i, p)| {
        index_map.insert(p.name.clone(), i as u64);
    });

    for pkg in &lockfile.packages {
        if pkg.source_idx >= lockfile.sources.len() {
            return Err(Error::MissingSource { line_number: 0, index: pkg.source_idx });
        }

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
            major: pkg.major,
            minor: pkg.minor,
            patch: pkg.patch,
            hash: pkg.hash.clone(),
            deps,
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
            name,
            source_idx: payload.source_idx,
            major: payload.major,
            minor: payload.minor,
            patch: payload.patch,
            hash: payload.hash,
            dependencies,
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
    fn test_format_header() {
        let lockfile = Lockfile {
            sources: vec![Source::Registry("https://reg.com/".to_string())],
            overrides: vec![Override {
                name: "react".to_string(),
                from_version: "18.0.0".to_string(),
                to_version: "18.0.1".to_string(),
            }],
            packages: vec![],
        };
        let res = format_header(&lockfile).unwrap();
        assert!(res.contains("@source 0 https://reg.com/"));
        assert!(res.contains("@override react 18.0.0 -> 18.0.1"));
        assert!(res.ends_with("\n\n"));
    }

    #[test]
    fn test_parse_header() {
        let content = "@source 0 https://reg.com/\n@source 1 file:///local\n\nrest of file";
        let (lockfile, remaining) = parse_header(content).unwrap();
        assert_eq!(lockfile.sources.len(), 2);
        assert_eq!(lockfile.sources[1], Source::Local("file:///local".to_string()));
        assert_eq!(remaining, "rest of file");
    }

    #[test]
    fn test_parse_invalid_header() {
        let content = "@source bad_url\n\nrest";
        assert!(matches!(parse_header(content), Err(Error::InvalidHeader { .. })));
    }

    #[test]
    fn test_full_roundtrip() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://reg.com/".to_string())],
            overrides: vec![],
            packages: vec![
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hash: vec![0u8; 16],
                    dependencies: vec![],
                },
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hash: vec![0u8; 16],
                    dependencies: vec![Dependency { name: "beta".to_string(), dep_type: DepType::Dev }],
                },
            ],
        };

        let serialized = serialize(&mut lockfile).unwrap();
        assert!(serialized.starts_with("@source"));

        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.packages.len(), 2);
        assert_eq!(deserialized.packages[0].name, "alpha");
        assert_eq!(deserialized.packages[0].dependencies[0].name, "beta");
        assert_eq!(deserialized.packages[0].dependencies[0].dep_type, DepType::Dev);
    }

    #[test]
    fn test_missing_source_ref() {
        let mut lockfile = Lockfile {
            sources: vec![],
            overrides: vec![],
            packages: vec![
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    hash: vec![0u8; 16],
                    dependencies: vec![],
                },
            ],
        };
        assert!(matches!(serialize(&mut lockfile), Err(Error::MissingSource { .. })));
    }
}
