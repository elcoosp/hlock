use std::collections::HashMap;
use crate::payload::{PayloadData, pack_payload, unpack_payload};
use crate::base64url::{encode, decode};

pub struct Package {
    pub name: String,
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub hash: [u8; 16],
    pub dependencies: Vec<String>,
}

pub fn format_line(pkg: &Package, index_map: &HashMap<String, u64>) -> String {
    let mut dep_indices = Vec::with_capacity(pkg.dependencies.len());
    for dep_name in &pkg.dependencies {
        let idx = index_map.get(dep_name)
            .unwrap_or_else(|| panic!("Missing dependency index for {}", dep_name));
        dep_indices.push(*idx);
    }

    let payload_data = PayloadData {
        major: pkg.major,
        minor: pkg.minor,
        patch: pkg.patch,
        hash: pkg.hash,
        dep_indices,
    };

    let binary = pack_payload(&payload_data);
    let encoded = encode(&binary);

    format!("{}\t{}", pkg.name, encoded)
}

pub fn parse_line(line: &str) -> Result<(String, PayloadData), &'static str> {
    let (name, encoded) = line.split_once('\t')
        .ok_or("Line missing tab delimiter")?;

    if name.is_empty() {
        return Err("Package name is empty");
    }

    let binary = decode(encoded.as_bytes())
        .map_err(|_| "Invalid Base64URL payload")?;

    let payload = unpack_payload(&binary)?;

    Ok((name.to_string(), payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mock_pkg(name: &str, maj: u64, min: u64, pat: u64, deps: Vec<&str>) -> Package {
        Package {
            name: name.to_string(),
            major: maj,
            minor: min,
            patch: pat,
            hash: [0u8; 16],
            dependencies: deps.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn test_format_line_contains_tab() {
        let pkg = mock_pkg("axios", 1, 6, 0, vec![]);
        let line = format_line(&pkg, &HashMap::new());
        assert!(line.contains('\t'));
        assert!(line.starts_with("axios\t"));
    }

    #[test]
    #[should_panic(expected="Missing dependency index for")]
    fn test_format_line_panics_on_missing_dep() {
        let pkg = mock_pkg("react", 18, 2, 0, vec!["lodash"]);
        let empty_map = HashMap::new();
        format_line(&pkg, &empty_map);
    }

    #[test]
    fn test_parse_line_success() {
        let line = "axios\tAQIDAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let pkg = parse_line(line).unwrap();
        assert_eq!(pkg.0, "axios");
        assert_eq!(pkg.1.major, 1);
        assert_eq!(pkg.1.minor, 2);
        assert_eq!(pkg.1.patch, 3);
        assert_eq!(pkg.1.dep_indices.len(), 0);
    }

    #[test]
    fn test_parse_line_missing_tab() {
        let line = "axios_no_tab";
        assert!(parse_line(line).is_err());
    }

    #[test]
    fn test_full_write_read_cycle() {
        let mut packages = vec![
            mock_pkg("axios", 1, 6, 0, vec![]),
            mock_pkg("lodash", 4, 17, 21, vec![]),
            mock_pkg("react", 18, 2, 0, vec!["lodash"]),
        ];

        packages.sort_by(|a, b| a.name.cmp(&b.name));
        let mut index_map = HashMap::new();
        packages.iter().enumerate().for_each(|(i, p)| {
            index_map.insert(p.name.clone(), i as u64);
        });

        let lines: Vec<String> = packages.iter().map(|p| format_line(p, &index_map)).collect();
        let file_content = lines.join("\n");

        let mut reconstructed = Vec::new();
        let mut name_index: HashMap<u64, String> = HashMap::new();

        for (idx, line) in file_content.lines().enumerate() {
            let (name, payload) = parse_line(line).unwrap();
            name_index.insert(idx as u64, name.clone());
            reconstructed.push((name, payload));
        }

        let final_pkg = &reconstructed[2];
        assert_eq!(final_pkg.0, "react");
        let dep_name = name_index.get(&final_pkg.1.dep_indices[0]).unwrap();
        assert_eq!(dep_name, "lodash");
    }
}
