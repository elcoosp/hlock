use crate::error::Error;
use crate::payload::{PayloadData, pack_payload, unpack_payload};
use crate::base64url::{encode, decode};
use std::collections::HashMap;
use std::path::Path;
use std::fs;

#[derive(Clone)]
pub struct Package {
    pub name: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: Vec<u8>,
    pub dependencies: Vec<String>,
}

pub fn serialize(packages: &mut Vec<Package>) -> Result<String, Error> {
    packages.sort_by(|a, b| a.name.cmp(&b.name));

    let mut index_map = HashMap::new();
    packages.iter().enumerate().for_each(|(i, p)| {
        index_map.insert(p.name.clone(), i as u64);
    });

    let mut lines = Vec::with_capacity(packages.len());

    for pkg in packages {
        let mut dep_indices = Vec::with_capacity(pkg.dependencies.len());
        for dep_name in &pkg.dependencies {
            let idx = index_map.get(dep_name)
                .ok_or_else(|| Error::MissingPackage {
                    package: pkg.name.clone(),
                    missing_dep: dep_name.clone()
                })?;
            dep_indices.push(*idx);
        }

        let payload_data = PayloadData {
            major: pkg.major,
            minor: pkg.minor,
            patch: pkg.patch,
            hash: pkg.hash.clone(),
            dep_indices,
        };

        let binary = pack_payload(&payload_data);
        let encoded = encode(&binary);

        lines.push(format!("{}\t{}", pkg.name, encoded));
    }

    Ok(lines.join("\n"))
}

pub fn deserialize(content: &str) -> Result<Vec<Package>, Error> {
    let mut name_index = HashMap::new();
    let mut raw_entries = Vec::new();

    for (idx, line) in content.lines().enumerate() {
        if line.trim().is_empty() { continue; }

        let (name, encoded) = line.split_once('\t')
            .ok_or(Error::MissingDelimiter { line_number: idx })?;

        if name.is_empty() {
            return Err(Error::MissingDelimiter { line_number: idx });
        }

        let binary = decode(encoded.as_bytes())
            .map_err(|_| Error::InvalidBase64 { line_number: idx })?;

        let payload = unpack_payload(&binary, idx)?;

        name_index.insert(idx as u64, name.to_string());
        raw_entries.push((name.to_string(), payload));
    }

    let mut packages = Vec::with_capacity(raw_entries.len());
    for (name, payload) in raw_entries {
        let deps = payload.dep_indices.iter().map(|idx| {
            name_index.get(idx).cloned().unwrap_or_else(|| format!("<missing_idx_{}>", idx))
        }).collect();

        packages.push(Package {
            name,
            major: payload.major,
            minor: payload.minor,
            patch: payload.patch,
            hash: payload.hash,
            dependencies: deps,
        });
    }

    Ok(packages)
}

pub fn write_lockfile(path: &Path, packages: &mut Vec<Package>) -> Result<(), Error> {
    let content = serialize(packages)?;
    fs::write(path, content)?;
    Ok(())
}

pub fn read_lockfile(path: &Path) -> Result<Vec<Package>, Error> {
    let content = fs::read_to_string(path)?;
    deserialize(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_pkg(name: &str, maj: u64, min: u64, pat: u64, hash: Vec<u8>, deps: Vec<&str>) -> Package {
        Package {
            name: name.to_string(),
            major: maj,
            minor: min,
            patch: pat,
            hash,
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_serialize_contains_tab() {
        let mut pkgs = vec![mock_pkg("a", 1, 0, 0, vec![0u8; 16], vec![])];
        let res = serialize(&mut pkgs).unwrap();
        assert!(res.contains('a'));
        assert!(res.contains('\t'));
    }

    #[test]
    fn test_deserialize_missing_tab() {
        let content = "no_tab_here";
        assert!(matches!(deserialize(content), Err(Error::MissingDelimiter { .. })));
    }

    #[test]
    fn test_deserialize_invalid_base64() {
        let content = "name\t!!!invalidbase64";
        assert!(matches!(deserialize(content), Err(Error::InvalidBase64 { .. })));
    }

    #[test]
    fn test_roundtrip() {
        let mut pkgs = vec![
            mock_pkg("axios", 1, 6, 0, vec![0xAA; 16], vec![]),
            mock_pkg("lodash", 4, 17, 21, vec![0xBB; 16], vec![]),
            mock_pkg("react", 18, 2, 0, vec![0xCC; 16], vec!["lodash"]),
        ];
        let serialized = serialize(&mut pkgs).unwrap();
        let deserialized = deserialize(&serialized).unwrap();

        assert_eq!(deserialized.len(), 3);
        assert_eq!(deserialized[0].name, "axios");
        assert_eq!(deserialized[2].name, "react");
        assert_eq!(deserialized[2].dependencies[0], "lodash");
        assert_eq!(deserialized[0].hash.len(), 16);
    }
}
