//! Header parsing and formatting

use crate::error::Error;
use super::types::{Mirror, Source, Override, WorkspacePkg, HoistBoundary, Lockfile, DepType};

fn classify_source(val: &str) -> Source {
    if val == "workspace" {
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
    }
}

pub fn format_header(lockfile: &Lockfile) -> Result<String, Error> {
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
    for mirror in &lockfile.mirrors {
        out.push_str(&format!("@mirror {} {}\n", mirror.scope, mirror.url));
    }

    for policy in &lockfile.policies {
        let policy_type_str = match policy.policy_type {
            crate::policy::PolicyType::AllowHook => "allow-hook",
            crate::policy::PolicyType::DenyHook => "deny-hook",
            crate::policy::PolicyType::AllowScript => "allow-script",
            crate::policy::PolicyType::DenyScript => "deny-script",
            crate::policy::PolicyType::BuildEnv => "build-env",
            crate::policy::PolicyType::Engine => "engine",
        };
        out.push_str(&format!("@policy {} {} {}\n", policy_type_str, policy.package_pattern, policy.value));
    }
    for tr in &lockfile.trust_roots {
        let algo_str = match tr.algorithm {
            crate::signature::SignatureAlgorithm::Ed25519 => "00",
            crate::signature::SignatureAlgorithm::Ed448 => "01",
            crate::signature::SignatureAlgorithm::MlDsa65 => "02",
        };
        let role_str = match tr.role {
            crate::policy::TrustRole::Root => "root",
            crate::policy::TrustRole::Targets => "targets",
            crate::policy::TrustRole::Snapshot => "snapshot",
            crate::policy::TrustRole::Delegation => "delegation",
        };
        let pub_key_hex = tr.public_key.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        out.push_str(&format!("@trust-root {} {} {} {} {}\n", tr.key_id, algo_str, pub_key_hex, tr.expires_epoch, role_str));
    }
    for ovr in &lockfile.overrides {
        out.push_str(&format!("@override {} {} -> {}\n", ovr.name, ovr.from_version, ovr.to_version));
    }
    for (name, flags) in &lockfile.features {
        let flags_str = if flags.is_empty() { "" } else { &flags.join(",") };
        out.push_str(&format!("@feature {} {}\n", name, flags_str));
    }
    if let Some(root) = &lockfile.workspace_root {
        out.push_str(&format!("@workspace-root {}\n", root));
    }
    for wp in &lockfile.workspace_pkgs {
        out.push_str(&format!("@workspace-pkg {} {}\n", wp.name, wp.manifest_path));
    }
    for hb in &lockfile.hoist_boundaries {
        let deps = if hb.allowed_deps.is_empty() { String::new() } else { format!("[{}]", hb.allowed_deps.join(",")) };
        out.push_str(&format!("@hoist-boundary {} -> {}\n", hb.cosine, deps));
    }
    for (key, value) in &lockfile.metadata {
        out.push_str(&format!("@metadata {} {}\n", key, value));
    }
    out.push('\n');
    Ok(out)
}

pub fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let mut features = vec![];
    let mut metadata = vec![];
    let mut workspace_root = None;
    let mut workspace_pkgs = Vec::new();
    let mut mirrors = Vec::new();
    let mut policies: Vec<crate::policy::Policy> = Vec::new();
    let mut trust_roots: Vec<crate::policy::TrustRoot> = Vec::new();
    let mut hoist_boundaries = Vec::new();
    let lines = content.lines().enumerate();

    for (line_num, line) in lines {
        if line.is_empty() {
            let header_end = content.find("\n\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((
                Lockfile {
                    sources, overrides, features, metadata,
                    workspace_root, workspace_pkgs, hoist_boundaries,
                    packages: vec![],
                    artifacts: vec![],
                    patches: vec![],
                    provenance: vec![],
                    advisories: vec![],
                    licenses: vec![],
                    policies,
                    trust_roots,
                    mirrors,
                    compat: None,
                },
                remaining,
            ));
        }

        if let Some(rest) = line.strip_prefix("@source ") {
            let mut parts = rest.splitn(2, ' ');
            let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader {
                line_number: line_num,
                reason: "Missing source index".to_string(),
            })?;
            let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader {
                line_number: line_num,
                reason: "Invalid source index".to_string(),
            })?;
            let val = parts.next().ok_or_else(|| Error::InvalidHeader {
                line_number: line_num,
                reason: "Missing source value".to_string(),
            })?;
            let source = classify_source(val);
            if idx != sources.len() {
                return Err(Error::InvalidHeader {
                    line_number: line_num,
                    reason: format!("Source index {} is out of order", idx),
                });
            }
            sources.push(source);
        } else if let Some(rest) = line.strip_prefix("@trust-root ") {
            let mut parts = rest.splitn(5, ' ');
            let key_id = parts.next().unwrap_or("").to_string();
            let algo_str = parts.next().unwrap_or("");
            let public_key_hex = parts.next().unwrap_or("");
            let expires_str = parts.next().unwrap_or("");
            let role_str = parts.next().unwrap_or("");

            let algorithm = match algo_str {
                "00" => crate::signature::SignatureAlgorithm::Ed25519,
                "01" => crate::signature::SignatureAlgorithm::Ed448,
                "02" => crate::signature::SignatureAlgorithm::MlDsa65,
                _ => return Err(Error::InvalidHeader {
                    line_number: line_num,
                    reason: format!("Unknown algorithm: {}", algo_str),
                }),
            };

            let expires_epoch: u64 = expires_str.parse().map_err(|_| Error::InvalidHeader {
                line_number: line_num,
                reason: "Invalid expires_epoch".to_string(),
            })?;

            let role = match role_str {
                "root" => crate::policy::TrustRole::Root,
                "targets" => crate::policy::TrustRole::Targets,
                "snapshot" => crate::policy::TrustRole::Snapshot,
                "delegation" => crate::policy::TrustRole::Delegation,
                _ => return Err(Error::InvalidHeader {
                    line_number: line_num,
                    reason: format!("Unknown role: {}", role_str),
                }),
            };

            let public_key = (0..public_key_hex.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&public_key_hex[i..i+2], 16).ok())
                .collect::<Vec<u8>>();

            trust_roots.push(crate::policy::TrustRoot {
                key_id,
                algorithm,
                public_key,
                expires_epoch,
                role,
            });
        } else if let Some(rest) = line.strip_prefix("@mirror ") {
            let mut parts = rest.splitn(2, ' ');
            let scope = parts.next().unwrap_or("").to_string();
            let url = parts.next().unwrap_or("").to_string();
            mirrors.push(Mirror { scope, url });
        } else if let Some(rest) = line.strip_prefix("@override ") {
            let mut parts = rest.split(" -> ");
            let left = parts.next().unwrap_or("");
            let to_ver = parts.next().ok_or_else(|| Error::InvalidHeader {
                line_number: line_num,
                reason: "Missing '->' in override".to_string(),
            })?;
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
        } else if let Some(rest) = line.strip_prefix("@workspace-root ") {
            workspace_root = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("@workspace-pkg ") {
            let (name, manifest_path) = rest.split_once(' ').unwrap_or((rest, ""));
            workspace_pkgs.push(WorkspacePkg { name: name.to_string(), manifest_path: manifest_path.to_string() });
        } else if let Some(rest) = line.strip_prefix("@hoist-boundary ") {
            let mut parts = rest.splitn(2, "->");
            let cosine = parts.next().unwrap_or("").trim().to_string();
            let deps_str = parts.next().unwrap_or("").trim();
            let deps_str = deps_str.strip_prefix("[").unwrap_or(deps_str);
            let deps_str = deps_str.strip_suffix("]").unwrap_or(deps_str);
            let allowed_deps = if deps_str.is_empty() { vec![] } else { deps_str.split(',').map(|s| s.trim().to_string()).collect() };
            hoist_boundaries.push(HoistBoundary { cosine, allowed_deps });
        } else if let Some(rest) = line.strip_prefix("@policy ") {
            let mut parts = rest.splitn(3, ' ');
            let policy_type_str = parts.next().unwrap_or("").to_string();
            let package_pattern = parts.next().unwrap_or("").to_string();
            let value = parts.next().unwrap_or("").to_string();

            let policy_type = match policy_type_str.as_str() {
                "allow-hook" => crate::policy::PolicyType::AllowHook,
                "deny-hook" => crate::policy::PolicyType::DenyHook,
                "allow-script" => crate::policy::PolicyType::AllowScript,
                "deny-script" => crate::policy::PolicyType::DenyScript,
                "build-env" => crate::policy::PolicyType::BuildEnv,
                "engine" => crate::policy::PolicyType::Engine,
                _ => return Err(Error::InvalidHeader {
                    line_number: line_num,
                    reason: format!("Unknown policy type: {}", policy_type_str),
                }),
            };

            policies.push(crate::policy::Policy {
                policy_type,
                package_pattern,
                value,
            });
        } else if let Some(rest) = line.strip_prefix("@metadata ") {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            metadata.push((key.to_string(), value.to_string()));
        } else {
            return Err(Error::InvalidHeader {
                line_number: line_num,
                reason: format!("Unknown directive: {}", line),
            });
        }
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}
