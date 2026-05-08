use crate::error::Error;
use crate::payload::{PayloadData, DepPayload, PeerReqPayload, PlatformTagPayload, HookHashPayload, pack_payload, unpack_payload};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffFormat {
    Text,
    Json,
}

fn version_string(pkg: &Package) -> String {
    format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch)
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
pub struct HookHash {
    pub hook_type: String,
    pub hash_algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    pub identifier: String,
    pub hash_algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub os_id: u8,
    pub arch_id: u8,
    pub hash_algo: HashAlgorithm,
    pub digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspacePkg {
    pub name: String,
    pub manifest_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoistBoundary {
    pub cosine: String,
    pub allowed_deps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchDirective {
    pub content_id: u64,
    pub patch_type: u8,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactDirective {
    pub content_id: u64,
    pub os_id: u8,
    pub arch_id: u8,
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerResolution {
    pub peer_name: String,
    pub satisfied_by_content_id: u64,
    pub is_hoisted_to_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRequirement {
    pub peer_name: String,
    pub version_range: String,
    pub is_optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
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
    pub peer_requirements: Vec<PeerRequirement>,
    pub platform_tags: Vec<PlatformTag>,
    pub exports: Vec<Export>,
    pub artifacts: Vec<Artifact>,
    pub hook_hashes: Vec<HookHash>,
    pub patch_hash: Option<(HashAlgorithm, Vec<u8>)>,
}

#[derive(Debug, Clone)]
pub struct Lockfile {
    pub sources: Vec<Source>,
    pub overrides: Vec<Override>,
    pub features: Vec<(String, Vec<String>)>,
    pub metadata: Vec<(String, String)>,
    pub workspace_root: Option<String>,
    pub workspace_pkgs: Vec<WorkspacePkg>,
    pub hoist_boundaries: Vec<HoistBoundary>,
    pub packages: Vec<Package>,
    pub artifacts: Vec<ArtifactDirective>,
    pub patches: Vec<PatchDirective>,
    pub provenance: Vec<crate::provenance::ResolutionProvenance>,
}

pub fn serialize_diff(diff: &LockfileDiff, format: DiffFormat) -> String {
    match format {
        DiffFormat::Text => serialize_diff_text(diff),
        DiffFormat::Json => serialize_diff_json(diff),
    }
}

fn serialize_diff_text(diff: &LockfileDiff) -> String {
    let mut out = String::new();
    out.push_str("LOCKFILE DIFF\n");
    out.push_str(&format!("  unchanged: {} packages\n", diff.unchanged_count));

    let added: Vec<&Package> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Added(p) => Some(p),
        _ => None,
    }).collect();
    let removed: Vec<&Package> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Removed(p) => Some(p),
        _ => None,
    }).collect();
    let altered: Vec<(&Package, &Package)> = diff.changes.iter().filter_map(|c| match c {
        PackageChange::Altered(old, new) => Some((old, new)),
        _ => None,
    }).collect();

    out.push_str(&format!("  added: {}\n", added.len()));
    for p in &added {
        out.push_str(&format!("    + {}@{}\n", p.name, version_string(p)));
    }
    out.push_str(&format!("  removed: {}\n", removed.len()));
    for p in &removed {
        out.push_str(&format!("    - {}@{}\n", p.name, version_string(p)));
    }
    out.push_str(&format!("  altered: {}\n", altered.len()));
    for (old, new) in &altered {
        out.push_str(&format!("    ~ {}@{} -> {}@{}\n", old.name, version_string(old), new.name, version_string(new)));
    }

    out
}

fn serialize_diff_json(diff: &LockfileDiff) -> String {
    let mut changes = Vec::new();
    for change in &diff.changes {
        match change {
            PackageChange::Added(p) => {
                changes.push(serde_json::json!({
                    "type": "added",
                    "name": p.name,
                    "version": version_string(p),
                }));
            }
            PackageChange::Removed(p) => {
                changes.push(serde_json::json!({
                    "type": "removed",
                    "name": p.name,
                    "version": version_string(p),
                }));
            }
            PackageChange::Altered(old, new) => {
                changes.push(serde_json::json!({
                    "type": "altered",
                    "name": new.name,
                    "old_version": version_string(old),
                    "new_version": version_string(new),
                }));
            }
        }
    }

    let obj = serde_json::json!({
        "unchanged_count": diff.unchanged_count,
        "changes": changes,
    });

    serde_json::to_string(&obj).unwrap()
}

fn find_digest_or_signature_boundary(content: &str) -> usize {
    let mut offset = 0;
    for line in content.lines() {
        if line.starts_with("@digest ") || line.starts_with("@signature ") {
            return offset;
        }
        offset += line.len();
        if offset < content.len() {
            offset += 1;
        }
    }
    content.len()
}

pub fn whole_lockfile_digest(content: &str) -> [u8; 32] {
    let boundary = find_digest_or_signature_boundary(content);
    let hash = blake3::hash(&content.as_bytes()[..boundary]);
    let mut result = [0u8; 32];
    result.copy_from_slice(hash.as_bytes());
    result
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 { return None; }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

pub fn validate_digest(content: &str) -> Result<(), Error> {
    let mut digest_lines = Vec::new();
    for line in content.lines() {
        if line.starts_with("@digest ") {
            digest_lines.push(line);
        }
    }

    if digest_lines.is_empty() {
        return Ok(());
    }

    if digest_lines.len() > 1 {
        return Err(Error::DuplicateDigestDirective);
    }

    let hex_str = digest_lines[0].strip_prefix("@digest ").unwrap().trim();
    let expected = hex_to_bytes(hex_str).ok_or_else(|| Error::DigestMismatch {
        expected: String::new(),
        actual: String::new(),
    })?;

    if expected.len() != 32 {
        return Err(Error::DigestMismatch {
            expected: hex_str.to_string(),
            actual: String::new(),
        });
    }

    let boundary = find_digest_or_signature_boundary(content);
    let computed = blake3::hash(&content.as_bytes()[..boundary]);

    if computed.as_bytes() != expected.as_slice() {
        return Err(Error::DigestMismatch {
            expected: hex_str.to_string(),
            actual: bytes_to_hex(computed.as_bytes()),
        });
    }

    Ok(())
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

fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut sources = Vec::new();
    let mut overrides = Vec::new();
    let mut features = vec![];
    let mut metadata = vec![];
    let mut workspace_root = None;
    let mut workspace_pkgs = Vec::new();
    let mut hoist_boundaries = Vec::new();
    let lines = content.lines().enumerate();

    for (line_num, line) in lines {
        if line.is_empty() {
            let header_end = content.find("\n\n").map(|i| i + 2).unwrap_or(content.len());
            let remaining = &content[header_end..];
            return Ok((Lockfile { sources, overrides, features, metadata, workspace_root, workspace_pkgs, hoist_boundaries, packages: vec![], artifacts: vec![], patches: vec![], provenance: vec![] }, remaining));
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
        } else if let Some(rest) = line.strip_prefix("@metadata ") {
            let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
            metadata.push((key.to_string(), value.to_string()));
        } else {
            return Err(Error::InvalidHeader { line_number: line_num, reason: format!("Unknown directive: {}", line) });
        }
    }

    Err(Error::InvalidHeader { line_number: 0, reason: "Missing empty line separator after header".to_string() })
}

pub fn serialize(lockfile: &mut Lockfile) -> Result<String, Error> {
    let mut out = format_header(lockfile)?;
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

        let peer_reqs: Vec<PeerReqPayload> = pkg.peer_requirements.iter().map(|r| {
            PeerReqPayload { peer_name: r.peer_name.clone(), version_range: r.version_range.clone(), is_optional: r.is_optional }
        }).collect();

        let tags: Vec<PlatformTagPayload> = pkg.platform_tags.iter().map(|t| {
            let os_id = match t.os {
                TargetOS::Any => 0x00, TargetOS::Linux => 0x01, TargetOS::MacOS => 0x02,
                TargetOS::Windows => 0x03, TargetOS::FreeBSD => 0x04, TargetOS::Android => 0x05,
                TargetOS::IOS => 0x06, TargetOS::Unknown => 0xFF,
            };
            let arch_id = match t.arch {
                TargetArch::Any => 0x00, TargetArch::X86_64 => 0x01, TargetArch::Aarch64 => 0x02,
                TargetArch::Wasm32 => 0x03, TargetArch::Arm => 0x04, TargetArch::S390x => 0x05,
                TargetArch::Ppc64le => 0x06, TargetArch::Unknown => 0xFF,
            };
            PlatformTagPayload { os_id, arch_id }
        }).collect();

        let exports: Vec<crate::payload::ExportPayload> = pkg.exports.iter().map(|ex| {
            let algo_id: u8 = match ex.hash_algo {
                HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01, HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03,
            };
            crate::payload::ExportPayload { identifier: ex.identifier.clone(), hash_algo: algo_id, digest: ex.digest.clone() }
        }).collect();

        let artifacts: Vec<crate::payload::ArtifactPayload> = pkg.artifacts.iter().map(|art| {
            let algo_id: u8 = match art.hash_algo {
                HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01, HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03,
            };
            crate::payload::ArtifactPayload { os_id: art.os_id, arch_id: art.arch_id, hash_algo: algo_id, digest: art.digest.clone() }
        }).collect();

        let hook_hashes: Vec<HookHashPayload> = pkg.hook_hashes.iter().map(|sh| {
            let algo_id: u8 = match sh.hash_algo {
                HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01, HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03,
            };
            HookHashPayload { hook_type: sh.hook_type.clone(), hash_algo: algo_id, digest: sh.digest.clone() }
        }).collect();

        let patch_hash: Option<(u8, Vec<u8>)> = pkg.patch_hash.as_ref().map(|(algo, digest): &(HashAlgorithm, Vec<u8>)| {
            let algo_id: u8 = match algo {
                HashAlgorithm::Sha1 => 0x00, HashAlgorithm::Sha256 => 0x01, HashAlgorithm::Sha512 => 0x02, HashAlgorithm::Blake3 => 0x03,
            };
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
        let dep_type_id = match &prov.dep_type {
            DepType::Runtime => 0,
            DepType::Dev => 1,
            DepType::Peer => 2,
            DepType::Optional => 3,
            DepType::OptionalTarget(_, _) => 4,
        };
        let source_type_id = match &prov.source_type {
            crate::provenance::ProvenanceSourceType::Registry => 0,
            crate::provenance::ProvenanceSourceType::Local => 1,
            crate::provenance::ProvenanceSourceType::Git => 2,
            crate::provenance::ProvenanceSourceType::Workspace => 3,
            crate::provenance::ProvenanceSourceType::CasHttp => 4,
            crate::provenance::ProvenanceSourceType::Ipfs => 5,
        };
        out.push_str(&format!(
            "@provenance {} {} {} {} {} {}\n",
            prov.package_name,
            prov.constraint,
            prov.constrained_by,
            dep_type_id,
            source_type_id,
            prov.depth
        ));
    }
    let digest = blake3::hash(out.as_bytes());
    out.push_str(&format!("@digest {}\n", bytes_to_hex(digest.as_bytes())));
    Ok(out)
}

pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    let (mut lockfile, pkg_content) = parse_header(content)?;

    let header_line_count = content.lines().count() - pkg_content.lines().count();
    let mut parsed_payloads = Vec::new();
    let mut patches = Vec::new();
    let mut artifacts = Vec::new();
    let mut provenance: Vec<crate::provenance::ResolutionProvenance> = Vec::new();
    let mut provenance_parse_errors: Vec<Error> = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if line.trim().is_empty() { continue; }
        if line.starts_with("@signature ") { continue; }
        if line.starts_with("@digest ") { continue; }
        if line.starts_with("@artifact ") {
            let rest = &line["@artifact ".len()..];
            let mut parts = rest.splitn(4, ' ');
            let cid_hex = parts.next().unwrap_or("");
            let os_id_str = parts.next().unwrap_or("");
            let arch_id_str = parts.next().unwrap_or("");
            let rel_path = parts.next().unwrap_or("");
            let content_id = u64::from_str_radix(cid_hex, 16).unwrap_or(0);
            let os_id = u8::from_str_radix(os_id_str, 16).unwrap_or(0);
            let arch_id = u8::from_str_radix(arch_id_str, 16).unwrap_or(0);
            artifacts.push(ArtifactDirective { content_id, os_id, arch_id, relative_path: rel_path.to_string() });
            continue;
        }
        if line.starts_with("@patch ") {
            let rest = &line["@patch ".len()..];
            let mut parts = rest.splitn(3, ' ');
            let cid_hex = parts.next().unwrap_or("");
            let patch_type_str = parts.next().unwrap_or("");
            let rel_path = parts.next().unwrap_or("");
            let content_id = u64::from_str_radix(cid_hex, 16).unwrap_or(0);
            let patch_type = u8::from_str_radix(patch_type_str, 16).unwrap_or(0);
            patches.push(PatchDirective { content_id, patch_type, relative_path: rel_path.to_string() });
            continue;
        }
        if line.starts_with("@provenance ") {
            let rest = &line["@provenance ".len()..];
            let mut parts = rest.splitn(6, ' ');
            let pkg_name = parts.next().unwrap_or("").to_string();
            let constraint = parts.next().unwrap_or("").to_string();
            let constrained_by = parts.next().unwrap_or("").to_string();
            let dep_type_str = parts.next().unwrap_or("");
            let source_type_str = parts.next().unwrap_or("");
            let depth_str = parts.next().unwrap_or("0");

            let dep_type_id: u8 = dep_type_str.parse().unwrap_or(255);
            let dep_type = match dep_type_id {
                0 => DepType::Runtime,
                1 => DepType::Dev,
                2 => DepType::Peer,
                3 => DepType::Optional,
                4 => DepType::OptionalTarget(TargetOS::Any, TargetArch::Any),
                _ => {
                    provenance_parse_errors.push(Error::UnknownProvenanceDepType { type_id: dep_type_id });
                    continue;
                }
            };

            let source_type_id: u8 = source_type_str.parse().unwrap_or(255);
            let source_type = match source_type_id {
                0 => crate::provenance::ProvenanceSourceType::Registry,
                1 => crate::provenance::ProvenanceSourceType::Local,
                2 => crate::provenance::ProvenanceSourceType::Git,
                3 => crate::provenance::ProvenanceSourceType::Workspace,
                4 => crate::provenance::ProvenanceSourceType::CasHttp,
                5 => crate::provenance::ProvenanceSourceType::Ipfs,
                _ => {
                    provenance_parse_errors.push(Error::UnknownProvenanceSourceType { type_id: source_type_id });
                    continue;
                }
            };

            let depth: u32 = depth_str.parse().unwrap_or(0);

            let prov = crate::provenance::ResolutionProvenance {
                package_name: pkg_name,
                constraint,
                constrained_by,
                dep_type,
                source_type,
                depth,
            };

            if let Some(existing) = provenance.iter().position(|p: &crate::provenance::ResolutionProvenance| p.package_name == prov.package_name) {
                provenance[existing] = prov;
            } else {
                provenance.push(prov);
            }
            continue;
        }
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
            peer_requirements: payload.peer_requirements.iter().map(|r| {
                PeerRequirement { peer_name: r.peer_name.clone(), version_range: r.version_range.clone(), is_optional: r.is_optional }
            }).collect(),
            platform_tags: payload.platform_tags.iter().map(|t| {
                let os = match t.os_id {
                    0x00 => TargetOS::Any, 0x01 => TargetOS::Linux, 0x02 => TargetOS::MacOS,
                    0x03 => TargetOS::Windows, 0x04 => TargetOS::FreeBSD, 0x05 => TargetOS::Android,
                    0x06 => TargetOS::IOS, _ => TargetOS::Unknown,
                };
                let arch = match t.arch_id {
                    0x00 => TargetArch::Any, 0x01 => TargetArch::X86_64, 0x02 => TargetArch::Aarch64,
                    0x03 => TargetArch::Wasm32, 0x04 => TargetArch::Arm, 0x05 => TargetArch::S390x,
                    0x06 => TargetArch::Ppc64le, _ => TargetArch::Unknown,
                };
                PlatformTag { os, arch }
            }).collect(),
            exports: payload.exports.iter().map(|ex| {
                let algo = match ex.hash_algo {
                    0x00 => HashAlgorithm::Sha1,
                    0x01 => HashAlgorithm::Sha256,
                    0x02 => HashAlgorithm::Sha512,
                    _ => HashAlgorithm::Blake3,
                };
                Export { identifier: ex.identifier.clone(), hash_algo: algo, digest: ex.digest.clone() }
            }).collect(),
            artifacts: payload.artifacts.iter().map(|art| {
                let algo = match art.hash_algo {
                    0x00 => HashAlgorithm::Sha1,
                    0x01 => HashAlgorithm::Sha256,
                    0x02 => HashAlgorithm::Sha512,
                    _ => HashAlgorithm::Blake3,
                };
                Artifact { os_id: art.os_id, arch_id: art.arch_id, hash_algo: algo, digest: art.digest.clone() }
            }).collect(),
            hook_hashes: payload.hook_hashes.iter().map(|sh| {
                let algo = match sh.hash_algo {
                    0x00 => HashAlgorithm::Sha1,
                    0x01 => HashAlgorithm::Sha256,
                    0x02 => HashAlgorithm::Sha512,
                    _ => HashAlgorithm::Blake3,
                };
                HookHash { hook_type: sh.hook_type.clone(), hash_algo: algo, digest: sh.digest.clone() }
            }).collect(),
            patch_hash: payload.patch_hash.as_ref().map(|(algo, digest)| {
                let a = match algo {
                    0x00 => HashAlgorithm::Sha1,
                    0x01 => HashAlgorithm::Sha256,
                    0x02 => HashAlgorithm::Sha512,
                    _ => HashAlgorithm::Blake3,
                };
                (a, digest.clone())
            }),
            ..Default::default()
        });
    }
    if let Some(err) = provenance_parse_errors.into_iter().next() {
        return Err(err);
    }
    lockfile.packages = packages;
    lockfile.artifacts = artifacts;
    lockfile.patches = patches;
    lockfile.provenance = provenance;
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

pub fn validate_hoist_boundary(lockfile: &Lockfile, cosine_name: &str) -> Result<(), Error> {
    let boundary = match lockfile.hoist_boundaries.iter().find(|b| b.cosine == cosine_name) {
        Some(b) => b,
        None => return Ok(()),
    };
    let cosine_pkg = match lockfile.packages.iter().find(|p| p.name == cosine_name) {
        Some(p) => p,
        None => return Ok(()),
    };
    for dep in &cosine_pkg.dependencies {
        if !boundary.allowed_deps.contains(&dep.name) {
            return Err(Error::PhantomDependency {
                consumer: cosine_name.to_string(),
                dep: dep.name.clone(),
            });
        }
    }
    Ok(())
}

pub fn validate_patches(lockfile: &Lockfile, lockfile_dir: &std::path::Path) -> Result<(), Error> {
    for pd in &lockfile.patches {
        let pkg = match lockfile.packages.iter().find(|p| {
            let ver_str = format!("{}@{}.{}.{}", p.name, p.major, p.minor, p.patch);
            crate::fnv::calculate(&ver_str) == pd.content_id
        }) {
            Some(p) => p,
            None => continue,
        };
        let Some((_algo, expected_digest)) = &pkg.patch_hash else {
            return Err(Error::OrphanPatchHash { package: pkg.name.clone() });
        };
        let patch_path = lockfile_dir.join(&pd.relative_path);
        let content = match std::fs::read(&patch_path) {
            Ok(c) => c,
            Err(_) => {
                return Err(Error::PatchFileMissing {
                    package: pkg.name.clone(),
                    content_id: pd.content_id,
                    path: pd.relative_path.clone(),
                });
            }
        };
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
    let warnings = Vec::new();
    for pkg in &lockfile.packages {
        let source_path = match &lockfile.sources.get(pkg.source_idx) {
            Some(Source::Local(p)) => std::path::Path::new(p),
            _ => continue,
        };
        let full_path = lockfile_dir.join(source_path).join("package.json");
        let manifest_content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };
        for sh in &pkg.hook_hashes {
            let script_name = sh.hook_type.as_str();
            if script_name.is_empty() { continue; }
            let pattern = format!("\"{}\"", script_name);
            let script_text = if let Some(idx) = manifest_content.find(&pattern) {
                let rest = &manifest_content[idx + pattern.len()..];
                let end = rest.find('"').unwrap_or(rest.len());
                rest[..end].to_string()
            } else {
                continue;
            };
            let actual = blake3::hash(script_text.as_bytes()).as_bytes().to_vec();
            if actual != sh.digest {
                return Err(Error::ScriptDigestMismatch {
                    package: pkg.name.clone(),
                    script: script_name.to_string(),
                });
            }
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_directive_roundtrip() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![],
            metadata: vec![
                ("license".to_string(), "MIT".to_string()),
                ("repository".to_string(), "https://github.com/example".to_string()),
            ],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.metadata.len(), 2);
        assert_eq!(deserialized.metadata[0].0, "license");
        assert_eq!(deserialized.metadata[0].1, "MIT");
        assert_eq!(deserialized.metadata[1].0, "repository");
    }

    #[test]
    fn test_artifact_directive_roundtrip() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![ArtifactDirective {
                content_id: 0xdeadbeef,
                os_id: 0x01,
                arch_id: 0x01,
                relative_path: "./bin/app".to_string(),
            }],
            patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.artifacts.len(), 1);
        assert_eq!(deserialized.artifacts[0].content_id, 0xdeadbeef);
        assert_eq!(deserialized.artifacts[0].os_id, 0x01);
        assert_eq!(deserialized.artifacts[0].relative_path, "./bin/app");
    }

    #[test]
    fn test_patch_directive_roundtrip() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![],
            patches: vec![PatchDirective {
                content_id: 0xcafebabe,
                patch_type: 0x01,
                relative_path: "./fix.patch".to_string(),
            }],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
                provenance: vec![],
    };
        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.patches.len(), 1);
        assert_eq!(deserialized.patches[0].content_id, 0xcafebabe);
        assert_eq!(deserialized.patches[0].patch_type, 0x01);
        assert_eq!(deserialized.patches[0].relative_path, "./fix.patch");
    }

    #[test]
    fn test_diff_format_enum_exists() {
        let _text = DiffFormat::Text;
        let _json = DiffFormat::Json;
    }

    #[test]
    fn test_serialize_diff_text_added() {
        let diff = LockfileDiff {
            changes: vec![PackageChange::Added(Package {
                name: "lodash".to_string(),
                major: 4, minor: 17, patch: 21,
                ..Default::default()
            })],
            unchanged_count: 42,
        };
        let text = serialize_diff(&diff, DiffFormat::Text);
        assert!(text.starts_with("LOCKFILE DIFF\n"));
        assert!(text.contains("  unchanged: 42 packages\n"));
        assert!(text.contains("  added: 1\n"));
        assert!(text.contains("    + lodash@4.17.21\n"));
    }

    #[test]
    fn test_serialize_diff_text_all_change_types() {
        let diff = LockfileDiff {
            changes: vec![
                PackageChange::Added(Package {
                    name: "react".to_string(),
                    major: 18, minor: 3, patch: 1,
                    ..Default::default()
                }),
                PackageChange::Removed(Package {
                    name: "axios".to_string(),
                    major: 0, minor: 21, patch: 1,
                    ..Default::default()
                }),
                PackageChange::Altered(
                    Package {
                        name: "webpack".to_string(),
                        major: 5, minor: 70, patch: 0,
                        ..Default::default()
                    },
                    Package {
                        name: "webpack".to_string(),
                        major: 5, minor: 75, patch: 0,
                        ..Default::default()
                    },
                ),
            ],
            unchanged_count: 10,
        };
        let text = serialize_diff(&diff, DiffFormat::Text);
        assert!(text.contains("  added: 1\n"));
        assert!(text.contains("    + react@18.3.1\n"));
        assert!(text.contains("  removed: 1\n"));
        assert!(text.contains("    - axios@0.21.1\n"));
        assert!(text.contains("  altered: 1\n"));
        assert!(text.contains("    ~ webpack@5.70.0 -> webpack@5.75.0\n"));
    }

    #[test]
    fn test_serialize_diff_json_added() {
        let diff = LockfileDiff {
            changes: vec![PackageChange::Added(Package {
                name: "lodash".to_string(),
                major: 4, minor: 17, patch: 21,
                ..Default::default()
            })],
            unchanged_count: 42,
        };
        let json_str = serialize_diff(&diff, DiffFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["unchanged_count"], 42);
        assert_eq!(parsed["changes"][0]["type"], "added");
        assert_eq!(parsed["changes"][0]["name"], "lodash");
        assert_eq!(parsed["changes"][0]["version"], "4.17.21");
    }

    #[test]
    fn test_serialize_diff_json_all_change_types() {
        let diff = LockfileDiff {
            changes: vec![
                PackageChange::Added(Package {
                    name: "react".to_string(),
                    major: 18, minor: 3, patch: 1,
                    ..Default::default()
                }),
                PackageChange::Removed(Package {
                    name: "axios".to_string(),
                    major: 0, minor: 21, patch: 1,
                    ..Default::default()
                }),
                PackageChange::Altered(
                    Package {
                        name: "webpack".to_string(),
                        major: 5, minor: 70, patch: 0,
                        ..Default::default()
                    },
                    Package {
                        name: "webpack".to_string(),
                        major: 5, minor: 75, patch: 0,
                        ..Default::default()
                    },
                ),
            ],
            unchanged_count: 10,
        };
        let json_str = serialize_diff(&diff, DiffFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let changes = parsed["changes"].as_array().unwrap();
        assert_eq!(changes.len(), 3);
        assert_eq!(changes[0]["type"], "added");
        assert_eq!(changes[1]["type"], "removed");
        assert_eq!(changes[1]["version"], "0.21.1");
        assert_eq!(changes[2]["type"], "altered");
        assert_eq!(changes[2]["name"], "webpack");
        assert_eq!(changes[2]["old_version"], "5.70.0");
        assert_eq!(changes[2]["new_version"], "5.75.0");
    }

    #[test]
    fn test_serialize_diff_json_empty() {
        let diff = LockfileDiff {
            changes: vec![],
            unchanged_count: 0,
        };
        let json_str = serialize_diff(&diff, DiffFormat::Json);
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["unchanged_count"], 0);
        assert_eq!(parsed["changes"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_whole_lockfile_digest_no_digest_or_signature() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let digest = whole_lockfile_digest(content);
        let expected = blake3::hash(content.as_bytes());
        assert_eq!(digest.as_slice(), expected.as_bytes());
    }

    #[test]
    fn test_whole_lockfile_digest_with_signature() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@signature key 00 0 AAAA\n";
        let digest = whole_lockfile_digest(content);
        let expected_content = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let expected = blake3::hash(expected_content.as_bytes());
        assert_eq!(digest.as_slice(), expected.as_bytes());
    }

    #[test]
    fn test_whole_lockfile_digest_with_digest() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@digest abc123\n";
        let digest = whole_lockfile_digest(content);
        let expected_content = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let expected = blake3::hash(expected_content.as_bytes());
        assert_eq!(digest.as_slice(), expected.as_bytes());
    }

    #[test]
    fn test_whole_lockfile_digest_digest_before_signature() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@digest abc123\n@signature key 00 0 AAAA\n";
        let digest = whole_lockfile_digest(content);
        let expected_content = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        let expected = blake3::hash(expected_content.as_bytes());
        assert_eq!(digest.as_slice(), expected.as_bytes());
    }

    #[test]
    fn test_validate_digest_valid() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        assert!(validate_digest(&serialized).is_ok());
    }

    #[test]
    fn test_validate_digest_mismatch() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        let without_digest: String = serialized.lines()
            .filter(|l| !l.starts_with("@digest "))
            .map(|l| format!("{}\n", l))
            .collect();
        let with_bad_digest = format!("{}@digest {}\n", without_digest, "00".repeat(32));
        assert!(matches!(validate_digest(&with_bad_digest), Err(Error::DigestMismatch { .. })));
    }

    #[test]
    fn test_validate_digest_missing_is_ok() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n";
        assert!(validate_digest(content).is_ok());
    }

    #[test]
    fn test_validate_digest_duplicate() {
        let content = "@source 0 https://r.com/\n\npkg\tAAAA\n@digest abc\n@digest def\n";
        assert!(matches!(validate_digest(content), Err(Error::DuplicateDigestDirective)));
    }

    #[test]
    fn test_serialize_includes_digest() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        assert!(serialized.contains("@digest "));
        assert!(validate_digest(&serialized).is_ok());
    }

    #[test]
    fn test_provenance_serialize_roundtrip() {
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
            provenance: vec![
                crate::provenance::ResolutionProvenance {
                    package_name: "lodash".to_string(),
                    constraint: "^4.17.0".to_string(),
                    constrained_by: "app".to_string(),
                    dep_type: DepType::Runtime,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 1,
                },
                crate::provenance::ResolutionProvenance {
                    package_name: "jest".to_string(),
                    constraint: "^29.0.0".to_string(),
                    constrained_by: String::new(),
                    dep_type: DepType::Dev,
                    source_type: crate::provenance::ProvenanceSourceType::Registry,
                    depth: 0,
                },
            ],
            packages: vec![Package {
                name: "app".to_string(),
                logical_name: None,
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        assert!(serialized.contains("@provenance lodash ^4.17.0 app 0 0 1"));
        assert!(serialized.contains("@provenance jest ^29.0.0  1 0 0"));
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.provenance.len(), 2);
        assert_eq!(deserialized.provenance[0].package_name, "lodash");
        assert_eq!(deserialized.provenance[0].constraint, "^4.17.0");
        assert_eq!(deserialized.provenance[0].constrained_by, "app");
        assert_eq!(deserialized.provenance[0].dep_type, DepType::Runtime);
        assert_eq!(deserialized.provenance[0].source_type, crate::provenance::ProvenanceSourceType::Registry);
        assert_eq!(deserialized.provenance[0].depth, 1);
        assert_eq!(deserialized.provenance[1].package_name, "jest");
        assert_eq!(deserialized.provenance[1].depth, 0);
    }

    #[test]
    fn test_provenance_unknown_dep_type() {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![],
            provenance: vec![],
            packages: vec![Package {
                name: "app".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let base = serialize(&mut lf).unwrap();
        let without_digest: String = base.lines()
            .filter(|l| !l.starts_with("@digest "))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("{}\n@provenance x ^1.0.0 app 99 0 1\n", without_digest);
        assert!(matches!(
            deserialize(&content),
            Err(Error::UnknownProvenanceDepType { type_id: 99 })
        ));
    }

    #[test]
    fn test_provenance_unknown_source_type() {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![],
            provenance: vec![],
            packages: vec![Package {
                name: "app".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let base = serialize(&mut lf).unwrap();
        let without_digest: String = base.lines()
            .filter(|l| !l.starts_with("@digest "))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("{}\n@provenance x ^1.0.0 app 0 99 1\n", without_digest);
        assert!(matches!(
            deserialize(&content),
            Err(Error::UnknownProvenanceSourceType { type_id: 99 })
        ));
    }

    #[test]
    fn test_provenance_duplicate_last_wins() {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![],
            provenance: vec![],
            packages: vec![Package {
                name: "app".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let base = serialize(&mut lf).unwrap();
        let without_digest: String = base.lines()
            .filter(|l| !l.starts_with("@digest "))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("{}\n@provenance x ^1.0.0 app 0 0 1\n@provenance x ^2.0.0 app 0 0 1\n", without_digest);
        let result = deserialize(&content).unwrap();
        assert_eq!(result.provenance.len(), 1);
        assert_eq!(result.provenance[0].constraint, "^2.0.0");
    }

    #[test]
    fn test_deserialize_skips_digest_line() {
        let mut lockfile = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![], features: vec![], metadata: vec![],
            workspace_root: None, workspace_pkgs: vec![], hoist_boundaries: vec![],
            artifacts: vec![], patches: vec![], provenance: vec![],
            packages: vec![Package {
                name: "pkg".to_string(), logical_name: None, source_idx: 0,
                major: 1, minor: 0, patch: 0, ..Default::default()
            }],
        };
        let serialized = serialize(&mut lockfile).unwrap();
        let deserialized = deserialize(&serialized).unwrap();
        assert_eq!(deserialized.packages.len(), 1);
        assert_eq!(deserialized.packages[0].name, "pkg");
    }
}
