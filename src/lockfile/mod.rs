//! Lockfile module - split into submodules

pub mod types;
pub mod diff;
pub mod digest;
pub mod header;

// Re-export all types
pub use types::*;

// Re-export diff functions
pub use diff::serialize_diff;

// Re-export digest functions
pub use digest::{whole_lockfile_digest, validate_digest};

// Re-export header functions
pub use header::{format_header, parse_header};

// Import dependencies for serialize/deserialize
use crate::error::Error;
use crate::fnv;
use crate::payload::{
    DepPayload, HookHashPayload, PayloadData, PeerReqPayload, PlatformTagPayload,
};
use crate::payload::{pack_payload, unpack_payload};
use crate::base64url::{encode, decode};
use std::collections::hash_map::HashMap;
use std::fs;
use std::path::Path;

// Serialize function
pub fn serialize(lockfile: &mut Lockfile) -> Result<String, Error> {
    let mut out = header::format_header(lockfile)?;
    lockfile.packages.sort_by(|a, b| a.name.cmp(&b.name));

    for pkg in lockfile.packages.iter() {
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
            let dep_pkg = lockfile.packages.iter().find(|p| p.name == dep.name)
                .ok_or_else(|| Error::MissingContentId { package: pkg.name.clone(), content_id: fnv::calculate(&format!("{}@0.0.0", dep.name)) })?;
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
            deps.push(DepPayload { content_id: cid, dep_type: ty, target_os: os, target_arch: arch, req_feat_indices: req_indices });
        }

        let peer_reqs: Vec<PeerReqPayload> = pkg.peer_requirements.iter().map(|r| {
            PeerReqPayload { peer_name: r.peer_name.clone(), version_range: r.version_range.clone(), is_optional: r.is_optional }
        }).collect();

        let tags: Vec<PlatformTagPayload> = pkg.platform_tags.iter().map(|t| {
            let os_id = match t.os { TargetOS::Any => 0x00, TargetOS::Linux => 0x01, TargetOS::MacOS => 0x02,
                TargetOS::Windows => 0x03, TargetOS::FreeBSD => 0x04, TargetOS::Android => 0x05,
                TargetOS::IOS => 0x06, TargetOS::Unknown => 0xFF };
            let arch_id = match t.arch { TargetArch::Any => 0x00, TargetArch::X86_64 => 0x01, TargetArch::Aarch64 => 0x02,
                TargetArch::Wasm32 => 0x03, TargetArch::Arm => 0x04, TargetArch::S390x => 0x05,
                TargetArch::Ppc64le => 0x06, TargetArch::Unknown => 0xFF };
            PlatformTagPayload { os_id, arch_id }
        }).collect();

        let exports: Vec<crate::payload::ExportPayload> = pkg.exports.iter().map(|ex| {
            let algo_id = match ex.hash_algo { HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01,
                HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03 };
            crate::payload::ExportPayload { identifier: ex.identifier.clone(), hash_algo: algo_id, digest: ex.digest.clone() }
        }).collect();

        let artifacts: Vec<crate::payload::ArtifactPayload> = pkg.artifacts.iter().map(|art| {
            let algo_id = match art.hash_algo { HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01,
                HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03 };
            crate::payload::ArtifactPayload { os_id: art.os_id, arch_id: art.arch_id, hash_algo: algo_id, digest: art.digest.clone() }
        }).collect();

        let hook_hashes: Vec<HookHashPayload> = pkg.hook_hashes.iter().map(|sh| {
            let algo_id = match sh.hash_algo { HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01,
                HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03 };
            HookHashPayload { hook_type: sh.hook_type.clone(), hash_algo: algo_id, digest: sh.digest.clone() }
        }).collect();

        let patch_hash = pkg.patch_hash.as_ref().map(|(algo, digest)| {
            let algo_id = match algo { HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01,
                HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03 };
            (algo_id, digest.clone())
        });

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
            peer_requirements: peer_reqs,
            platform_tags: tags,
            exports,
            artifacts,
            hook_hashes,
            patch_hash,
        };
        let encoded = encode(&pack_payload(&payload_data));
        out.push_str(&format!("{}\t{}\n", pkg.name, encoded));
    }

    for a in &lockfile.artifacts {
        out.push_str(&format!("@artifact {:016x} {:02x} {:02x} {}\n", a.content_id, a.os_id, a.arch_id, a.relative_path));
    }
    for p in &lockfile.patches {
        out.push_str(&format!("@patch {:016x} {:02x} {}\n", p.content_id, p.patch_type, p.relative_path));
    }
    for prov in &lockfile.provenance {
        let dep_type_id = match &prov.dep_type { DepType::Runtime => 0, DepType::Dev => 1, DepType::Peer => 2, DepType::Optional => 3, DepType::OptionalTarget(_, _) => 4 };
        let source_type_id = match &prov.source_type {
            crate::provenance::ProvenanceSourceType::Registry => 0,
            crate::provenance::ProvenanceSourceType::Local => 1,
            crate::provenance::ProvenanceSourceType::Git => 2,
            crate::provenance::ProvenanceSourceType::Workspace => 3,
            crate::provenance::ProvenanceSourceType::CasHttp => 4,
            crate::provenance::ProvenanceSourceType::Ipfs => 5,
        };
        out.push_str(&format!("@provenance {} {} {} {} {} {}\n", prov.package_name, prov.constraint, prov.constrained_by, dep_type_id, source_type_id, prov.depth));
    }
    for adv in &lockfile.advisories {
        out.push_str(&format!("@advisory {} {} {} {} {}\n", 
            adv.package, 
            adv.advisory_id, 
            adv.severity.as_str(),
            adv.url,
            adv.affected_versions
        ));
    }
    for vex in &lockfile.vex_entries {
        out.push_str(&format!("@vex {} {} {} {} {}\n",
            vex.package, vex.advisory_id, vex.status.as_str(),
            vex.justification, vex.impact_statement));
    }
    for lic in &lockfile.licenses {
        out.push_str(&format!("@license {} {}\n", lic.package, lic.expression));
    }
    let digest = blake3::hash(out.as_bytes());
    out.push_str(&format!("@digest {}\n", crate::lockfile::digest::bytes_to_hex(digest.as_bytes())));
    Ok(out)
}

// Deserialize function
pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    let (mut lockfile, pkg_content) = header::parse_header(content)?;
    let header_line_count = content.lines().count() - pkg_content.lines().count();
    let mut parsed_payloads = Vec::new();
    let mut patches = Vec::new();
    let mut artifacts = Vec::new();
    let mut provenance: Vec<crate::provenance::ResolutionProvenance> = Vec::new();
    let mut provenance_parse_errors: Vec<Error> = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if line.trim().is_empty() || line.starts_with("@signature ") || line.starts_with("@digest ") { continue; }
        if let Some(rest) = line.strip_prefix("@vex ") {
            let mut parts = rest.splitn(5, ' ');
            let package = parts.next().unwrap_or("").to_string();
            let advisory_id = parts.next().unwrap_or("").to_string();
            let status_str = parts.next().unwrap_or("");
            let justification = parts.next().unwrap_or("").to_string();
            let impact_statement = parts.next().unwrap_or("").to_string();

            let status = match crate::lockfile::VexStatus::from_str(status_str) {
                Some(s) => s,
                None => {
                    provenance_parse_errors.push(Error::InvalidVexStatus {
                        line_number: idx + 1,
                        status: status_str.to_string(),
                    });
                    continue;
                }
            };

            lockfile.vex_entries.push(crate::lockfile::VexEntry {
                package,
                advisory_id,
                status,
                justification,
                impact_statement,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("@license ") {
            let mut parts = rest.splitn(2, ' ');
            let package = parts.next().unwrap_or("").to_string();
            let expression = parts.next().unwrap_or("").to_string();
            lockfile.licenses.push(crate::policy::LicenseEntry {
                package,
                expression,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("@advisory ") {
            let mut parts = rest.splitn(5, ' ');
            let package = parts.next().unwrap_or("").to_string();
            let advisory_id = parts.next().unwrap_or("").to_string();
            let severity_str = parts.next().unwrap_or("");
            let url = parts.next().unwrap_or("").to_string();
            let affected_versions = parts.next().unwrap_or("").to_string();

            let severity = match severity_str {
                "critical" => crate::policy::AdvisorySeverity::Critical,
                "high" => crate::policy::AdvisorySeverity::High,
                "medium" => crate::policy::AdvisorySeverity::Medium,
                "low" => crate::policy::AdvisorySeverity::Low,
                "info" => crate::policy::AdvisorySeverity::Info,
                _ => {
                    provenance_parse_errors.push(Error::InvalidAdvisorySeverity {
                        line_number: idx + 1,
                        severity: severity_str.to_string(),
                    });
                    continue;
                }
            };

            lockfile.advisories.push(crate::policy::Advisory {
                package,
                advisory_id,
                severity,
                url,
                affected_versions,
            });
            continue;
        }
        if let Some(rest) = line.strip_prefix("@artifact ") {
            let mut parts = rest.splitn(4, ' ');
            let content_id = u64::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
            let os_id = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
            let arch_id = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
            let rel_path = parts.next().unwrap_or("");
            artifacts.push(ArtifactDirective { content_id, os_id, arch_id, relative_path: rel_path.to_string() });
            continue;
        }
        if let Some(rest) = line.strip_prefix("@patch ") {
            let mut parts = rest.splitn(3, ' ');
            let content_id = u64::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
            let patch_type = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
            let rel_path = parts.next().unwrap_or("");
            patches.push(PatchDirective { content_id, patch_type, relative_path: rel_path.to_string() });
            continue;
        }
        if let Some(rest) = line.strip_prefix("@provenance ") {
            let mut parts = rest.splitn(6, ' ');
            let pkg_name = parts.next().unwrap_or("").to_string();
            let constraint = parts.next().unwrap_or("").to_string();
            let constrained_by = parts.next().unwrap_or("").to_string();
            let dep_type_id: u8 = parts.next().unwrap_or("").parse().unwrap_or(255);
            let source_type_id: u8 = parts.next().unwrap_or("").parse().unwrap_or(255);
            let depth: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);

            let dep_type = match dep_type_id { 0 => DepType::Runtime, 1 => DepType::Dev, 2 => DepType::Peer, 3 => DepType::Optional, 4 => DepType::OptionalTarget(TargetOS::Any, TargetArch::Any), _ => { provenance_parse_errors.push(Error::UnknownProvenanceDepType { type_id: dep_type_id }); continue; } };
            let source_type = match source_type_id { 0 => crate::provenance::ProvenanceSourceType::Registry, 1 => crate::provenance::ProvenanceSourceType::Local, 2 => crate::provenance::ProvenanceSourceType::Git, 3 => crate::provenance::ProvenanceSourceType::Workspace, 4 => crate::provenance::ProvenanceSourceType::CasHttp, 5 => crate::provenance::ProvenanceSourceType::Ipfs, _ => { provenance_parse_errors.push(Error::UnknownProvenanceSourceType { type_id: source_type_id }); continue; } };

            let prov = crate::provenance::ResolutionProvenance { package_name: pkg_name, constraint, constrained_by, dep_type, source_type, depth };
            if let Some(existing) = provenance.iter().position(|p| p.package_name == prov.package_name) { provenance[existing] = prov; } else { provenance.push(prov); }
            continue;
        }
        let line_num = header_line_count + idx;
        let (name, encoded) = line.split_once('\t').ok_or(Error::MissingDelimiter { line_number: line_num })?;
        let binary = decode(encoded.as_bytes()).map_err(|_| Error::InvalidBase64 { line_number: line_num })?;
        let payload = unpack_payload(&binary, line_num)?;
        if payload.source_idx >= lockfile.sources.len() { return Err(Error::MissingSource { line_number: line_num, index: payload.source_idx }); }
        parsed_payloads.push((name.to_string(), payload, line_num));
    }
    if let Some(err) = provenance_parse_errors.into_iter().next() { return Err(err); }

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
            let (dep_name, dep_features) = id_map.get(&dep.content_id).ok_or_else(|| Error::MissingContentId { package: name.clone(), content_id: dep.content_id })?;
            let req_feats: Vec<String> = dep.req_feat_indices.iter().map(|i| dep_features.get(*i).cloned().unwrap_or_default()).collect();
            let ty = match dep.dep_type {
                0 => DepType::Runtime, 1 => DepType::Dev, 2 => DepType::Peer, 3 => DepType::Optional,
                4 => {
                    let os = dep.target_os.map(|o| match o { 0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS, 0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android, 0x06 => TargetOS::IOS, _ => TargetOS::Unknown }).unwrap_or(TargetOS::Any);
                    let arch = dep.target_arch.map(|a| match a { 0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64, 0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x, 0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown }).unwrap_or(TargetArch::Any);
                    DepType::OptionalTarget(os, arch)
                }
                _ => DepType::Runtime,
            };
            dependencies.push(Dependency { name: dep_name.clone(), dep_type: ty, requested_features: req_feats });
        }
        packages.push(Package { name, logical_name: payload.logical_name, source_idx: payload.source_idx, major: payload.major, minor: payload.minor, patch: payload.patch, hashes, features: payload.features, resolved_peers: payload.resolved_peers, dependencies, peer_requirements: payload.peer_requirements.iter().map(|r| PeerRequirement { peer_name: r.peer_name.clone(), version_range: r.version_range.clone(), is_optional: r.is_optional }).collect(), platform_tags: payload.platform_tags.iter().map(|t| { let os = match t.os_id { 0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS, 0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android, 0x06 => TargetOS::IOS, _ => TargetOS::Unknown }; let arch = match t.arch_id { 0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64, 0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x, 0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown }; PlatformTag { os, arch } }).collect(), exports: payload.exports.iter().map(|ex| { let algo = match ex.hash_algo { 0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256, 0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 }; Export { identifier: ex.identifier.clone(), hash_algo: algo, digest: ex.digest.clone() } }).collect(), artifacts: payload.artifacts.iter().map(|art| { let algo = match art.hash_algo { 0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256, 0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 }; Artifact { os_id: art.os_id, arch_id: art.arch_id, hash_algo: algo, digest: art.digest.clone() } }).collect(), hook_hashes: payload.hook_hashes.iter().map(|sh| { let algo = match sh.hash_algo { 0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256, 0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 }; HookHash { hook_type: sh.hook_type.clone(), hash_algo: algo, digest: sh.digest.clone() } }).collect(), patch_hash: payload.patch_hash.as_ref().map(|(algo, digest)| { let a = match algo { 0x00 => HashAlgorithm::Sha1, 0x01 => HashAlgorithm::Sha256, 0x02 => HashAlgorithm::Sha512, _ => HashAlgorithm::Blake3 }; (a, digest.clone()) }) });
    }
    lockfile.packages = packages;
    lockfile.artifacts = artifacts;
    lockfile.patches = patches;
    lockfile.provenance = provenance;
    Ok(lockfile)
}

// File I/O functions
pub fn write_lockfile(path: &Path, lockfile: &mut Lockfile) -> Result<(), Error> {
    fs::write(path, serialize(lockfile)?)?;
    Ok(())
}

pub fn read_lockfile(path: &Path) -> Result<Lockfile, Error> {
    deserialize(&fs::read_to_string(path)?)
}

// Validation functions
pub fn validate_hoist_boundary(lockfile: &Lockfile, cosine_name: &str) -> Result<(), Error> {
    let boundary = lockfile.hoist_boundaries.iter().find(|b| b.cosine == cosine_name);
    let Some(boundary) = boundary else { return Ok(()) };
    let Some(cosine_pkg) = lockfile.packages.iter().find(|p| p.name == cosine_name) else { return Ok(()) };
    for dep in &cosine_pkg.dependencies {
        if !boundary.allowed_deps.contains(&dep.name) {
            return Err(Error::PhantomDependency { consumer: cosine_name.to_string(), dep: dep.name.clone() });
        }
    }
    Ok(())
}

pub fn validate_patches(lockfile: &Lockfile, lockfile_dir: &std::path::Path) -> Result<(), Error> {
    for pd in &lockfile.patches {
        let pkg = lockfile.packages.iter().find(|p| {
            let ver_str = format!("{}@{}.{}.{}", p.name, p.major, p.minor, p.patch);
            fnv::calculate(&ver_str) == pd.content_id
        });
        let Some(pkg) = pkg else { continue };
        let Some((_algo, expected_digest)) = &pkg.patch_hash else {
            return Err(Error::OrphanPatchHash { package: pkg.name.clone() });
        };
        let patch_path = lockfile_dir.join(&pd.relative_path);
        let content = std::fs::read(&patch_path).map_err(|_| Error::PatchFileMissing {
            package: pkg.name.clone(), content_id: pd.content_id, path: pd.relative_path.clone(),
        })?;
        let actual = blake3::hash(&content).as_bytes().to_vec();
        if &actual != expected_digest {
            return Err(Error::PatchDigestMismatch {
                package: pkg.name.clone(),
                expected: format!("{:?}", expected_digest),
                actual: format!("{:?}", actual),
            });
        }
    }
    Ok(())
}

pub fn validate_scripts(lockfile: &Lockfile, lockfile_dir: &std::path::Path) -> Result<Vec<String>, Error> {
    for pkg in &lockfile.packages {
        let source_path = match &lockfile.sources.get(pkg.source_idx) {
            Some(Source::Local(p)) => std::path::Path::new(p),
            _ => continue,
        };
        let full_path = lockfile_dir.join(source_path).join("package.json");
        let Ok(manifest_content) = std::fs::read_to_string(&full_path) else { continue };
        for sh in &pkg.hook_hashes {
            let script_name = sh.hook_type.as_str();
            if script_name.is_empty() { continue; }
            let pattern = format!("\"{}\"", script_name);
            let script_text = if let Some(idx) = manifest_content.find(&pattern) {
                let rest = &manifest_content[idx + pattern.len()..];
                let end = rest.find('"').unwrap_or(rest.len());
                rest[..end].to_string()
            } else { continue };
            let actual = blake3::hash(script_text.as_bytes()).as_bytes().to_vec();
            if actual != sh.digest {
                return Err(Error::ScriptDigestMismatch { package: pkg.name.clone(), script: script_name.to_string() });
            }
        }
    }
    Ok(Vec::new())
}
