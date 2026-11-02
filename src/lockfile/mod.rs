//! Lockfile module - split into submodules

pub mod diff;
pub mod digest;
pub mod header;
pub mod types;

// Re-export all types
use std::fmt::Write as _;
pub use types::*;

// Re-export diff functions
pub use diff::serialize_diff;

// Re-export digest functions
pub use digest::{digest_hex, validate_digest, whole_lockfile_digest};

// Re-export header functions
pub use header::{format_header, parse_header};

// Import dependencies for serialize/deserialize
use crate::base64url::{decode, encode};
use crate::cid;
use crate::error::Error;
use crate::payload::{
    DepPayload, HookHashPayload, PayloadData, PeerReqPayload, PlatformTagPayload,
};
use crate::payload::{pack_payload, unpack_payload};
use std::collections::hash_map::HashMap;
use std::fs;
use std::path::Path;

// Serialize function
///
/// # Errors
///
/// Returns `Err` if a source index is out of range ([`Error::MissingSource`]),
/// a workspace package carries integrity hashes ([`Error::InvalidWorkspaceHash`]),
/// or a dependency has no matching package ([`Error::MissingContentId`]).
pub fn serialize(lockfile: &Lockfile) -> Result<String, Error> {
    let mut out = header::format_header(lockfile)?;
    // Canonical order is name-sorted; 1.0 produces it from an index
    // permutation instead of mutating the caller's data.
    let mut order: Vec<usize> = (0..lockfile.packages.len()).collect();
    order.sort_by(|&a, &b| lockfile.packages[a].name.cmp(&lockfile.packages[b].name));
    out.reserve(lockfile.packages.len() * 64);

    let name_cid: HashMap<&str, u64> = lockfile
        .packages
        .iter()
        .map(|p| (p.name.as_str(), cid::package_cid(p)))
        .collect();
    for &idx in &order {
        serialize_package(lockfile, &name_cid, &lockfile.packages[idx], &mut out)?;
    }
    serialize_directives(lockfile, &mut out);

    let digest = blake3::hash(out.as_bytes());
    let _ = writeln!(
        out,
        "@digest {}",
        crate::lockfile::digest::bytes_to_hex(digest.as_bytes())
    );
    Ok(out)
}

/// Serializes one package line (name + base64url payload).
fn serialize_package(
    lockfile: &Lockfile,
    name_cid: &HashMap<&str, u64>,
    pkg: &Package,
    out: &mut String,
) -> Result<(), Error> {
    if pkg.source_idx >= lockfile.sources.len() {
        return Err(Error::MissingSource {
            line_number: 0,
            index: pkg.source_idx,
        });
    }
    if matches!(lockfile.sources[pkg.source_idx], Source::Workspace) && !pkg.hashes.is_empty() {
        return Err(Error::InvalidWorkspaceHash { line_number: 0 });
    }
    let payload_data = build_payload_data(name_cid, pkg)?;
    let packed = pack_payload(&payload_data)?;
    let encoded = encode(&packed);
    let _ = writeln!(out, "{}\t{}", pkg.name, encoded);
    Ok(())
}

/// Builds the binary payload for a package from its resolved dependencies.
fn build_payload_data(name_cid: &HashMap<&str, u64>, pkg: &Package) -> Result<PayloadData, Error> {
    Ok(PayloadData {
        logical_name: pkg.logical_name.clone(),
        source_idx: pkg.source_idx,
        major: pkg.major,
        minor: pkg.minor,
        patch: pkg.patch,
        hashes: build_hash_payloads(pkg),
        features: pkg.features.clone(),
        resolved_peers: pkg.resolved_peers.clone(),
        deps: build_dep_payloads(name_cid, pkg)?,
        peer_requirements: build_peer_req_payloads(pkg),
        platform_tags: build_platform_tag_payloads(pkg),
        exports: build_export_payloads(pkg),
        artifacts: build_artifact_payloads(pkg),
        hook_hashes: build_hook_hash_payloads(pkg),
        patch_hash: pkg
            .patch_hash
            .as_ref()
            .map(|(algo, digest)| (algo.id(), digest.clone())),
    })
}

/// Converts the package's integrity hashes into their wire representation.
fn build_hash_payloads(pkg: &Package) -> Vec<crate::payload::HashPayload> {
    pkg.hashes
        .iter()
        .map(|h| crate::payload::HashPayload {
            algo_id: h.algo.id(),
            digest: h.digest.clone(),
            attestation: h.attestation.clone(),
        })
        .collect()
}

/// Resolves each dependency to its content id and encodes its dep type.
///
/// A `name -> (cid, dep_package)` map is built once per lockfile (0.x did a
/// linear `find_package` scan per dependency edge).
fn build_dep_payloads(
    name_cid: &HashMap<&str, u64>,
    pkg: &Package,
) -> Result<Vec<DepPayload>, Error> {
    let mut deps = Vec::with_capacity(pkg.dependencies.len());
    for dep in &pkg.dependencies {
        let dep_cid = name_cid
            .get(dep.name.as_str())
            .ok_or_else(|| Error::MissingPackage {
                package: pkg.name.clone(),
                missing_dep: dep.name.clone(),
            })?;
        let cid = *dep_cid;
        let req_indices = dep
            .requested_features
            .iter()
            .filter_map(|req_feat| pkg.features.iter().position(|f| f == req_feat))
            .collect();
        let (ty, os, arch) = match &dep.dep_type {
            DepType::OptionalTarget(target_os, target_arch) => (
                DepType::OptionalTarget(TargetOS::Any, TargetArch::Any).id(),
                Some(target_os.id()),
                Some(target_arch.id()),
            ),
            simple => (simple.id(), None, None),
        };
        deps.push(DepPayload {
            content_id: cid,
            dep_type: ty,
            target_os: os,
            target_arch: arch,
            req_feat_indices: req_indices,
        });
    }
    Ok(deps)
}

/// Converts peer version requirements into their wire representation.
fn build_peer_req_payloads(pkg: &Package) -> Vec<PeerReqPayload> {
    pkg.peer_requirements
        .iter()
        .map(|r| PeerReqPayload {
            peer_name: r.peer_name.clone(),
            version_range: r.version_range.clone(),
            is_optional: r.is_optional,
        })
        .collect()
}

/// Converts platform tags into their wire representation.
fn build_platform_tag_payloads(pkg: &Package) -> Vec<PlatformTagPayload> {
    pkg.platform_tags
        .iter()
        .map(|t| PlatformTagPayload {
            os_id: t.os.id(),
            arch_id: t.arch.id(),
        })
        .collect()
}

/// Converts export declarations into their wire representation.
fn build_export_payloads(pkg: &Package) -> Vec<crate::payload::ExportPayload> {
    pkg.exports
        .iter()
        .map(|ex| crate::payload::ExportPayload {
            identifier: ex.identifier.clone(),
            hash_algo: ex.hash_algo.id(),
            digest: ex.digest.clone(),
        })
        .collect()
}

/// Converts artifact entries into their wire representation.
fn build_artifact_payloads(pkg: &Package) -> Vec<crate::payload::ArtifactPayload> {
    pkg.artifacts
        .iter()
        .map(|art| crate::payload::ArtifactPayload {
            os_id: art.os_id,
            arch_id: art.arch_id,
            hash_algo: art.hash_algo.id(),
            digest: art.digest.clone(),
        })
        .collect()
}

/// Converts hook integrity hashes into their wire representation.
fn build_hook_hash_payloads(pkg: &Package) -> Vec<HookHashPayload> {
    pkg.hook_hashes
        .iter()
        .map(|sh| HookHashPayload {
            hook_type: sh.hook_type.clone(),
            hash_algo: sh.hash_algo.id(),
            digest: sh.digest.clone(),
        })
        .collect()
}

/// Serializes the artifact/patch/provenance/advisory/vex/license directives.
fn serialize_directives(lockfile: &Lockfile, out: &mut String) {
    for a in &lockfile.artifacts {
        let _ = writeln!(
            out,
            "@artifact {:016x} {:02x} {:02x} {}",
            a.content_id, a.os_id, a.arch_id, a.relative_path
        );
    }
    for p in &lockfile.patches {
        let _ = writeln!(
            out,
            "@patch {:016x} {:02x} {}",
            p.content_id, p.patch_type, p.relative_path
        );
    }
    for prov in &lockfile.provenance {
        let _ = writeln!(
            out,
            "@provenance {} {} {} {} {} {}",
            prov.package_name,
            prov.constraint,
            prov.constrained_by,
            prov.dep_type.id(),
            prov.source_type.id(),
            prov.depth
        );
    }
    for adv in &lockfile.advisories {
        let _ = writeln!(
            out,
            "@advisory {} {} {} {} {}",
            adv.package,
            adv.advisory_id,
            adv.severity.as_str(),
            adv.url,
            adv.affected_versions
        );
    }
    for vex in &lockfile.vex_entries {
        let _ = writeln!(
            out,
            "@vex {} {} {} {} {}",
            vex.package,
            vex.advisory_id,
            vex.status.as_str(),
            vex.justification,
            vex.impact_statement
        );
    }
    for lic in &lockfile.licenses {
        let _ = writeln!(out, "@license {} {}", lic.package, lic.expression);
    }
}

// Deserialize function
///
/// # Errors
///
/// Returns `Err` if a VEX status string is unknown ([`Error::InvalidVexStatus`]),
/// an advisory severity is invalid ([`Error::InvalidAdvisorySeverity`]),
/// a provenance type id is unknown ([`Error::UnknownProvenanceDepType`] /
/// [`Error::UnknownProvenanceSourceType`]),
/// a package line has no tab delimiter ([`Error::MissingDelimiter`]),
/// or a payload is not valid base64url ([`Error::InvalidBase64`]).
pub fn deserialize(content: &str) -> Result<Lockfile, Error> {
    // 1.0 reports every body parse error (bounded), not just the first.
    const MAX_REPORTED_PARSE_ERRORS: usize = 10;
    let (mut lockfile, pkg_content) = header::parse_header(content)?;
    let header_line_count = content.lines().count() - pkg_content.lines().count();
    let mut parsed_payloads = Vec::new();
    let mut patches = Vec::new();
    let mut artifacts = Vec::new();
    let mut provenance: Vec<crate::provenance::ResolutionProvenance> = Vec::new();
    let mut parse_errors: Vec<Error> = Vec::new();

    for (idx, line) in pkg_content.lines().enumerate() {
        if is_skippable_body_line(line) {
            continue;
        }
        let line_num = header_line_count + idx;

        if let Some(rest) = line.strip_prefix("@vex ") {
            match parse_vex_line(rest, idx + 1) {
                Ok(vex) => lockfile.vex_entries.push(vex),
                Err(e) => parse_errors.push(e),
            }
        } else if let Some(rest) = line.strip_prefix("@license ") {
            let (package, expression) = rest.split_once(' ').unwrap_or((rest, ""));
            lockfile.licenses.push(crate::policy::LicenseEntry {
                package: package.to_string(),
                expression: expression.to_string(),
            });
        } else if let Some(rest) = line.strip_prefix("@advisory ") {
            match parse_advisory_line(rest, idx + 1) {
                Ok(adv) => lockfile.advisories.push(adv),
                Err(e) => parse_errors.push(e),
            }
        } else if let Some(rest) = line.strip_prefix("@artifact ") {
            artifacts.push(parse_artifact_line(rest));
        } else if let Some(rest) = line.strip_prefix("@patch ") {
            patches.push(parse_patch_line(rest));
        } else if let Some(rest) = line.strip_prefix("@provenance ") {
            match parse_provenance_line(
                rest,
                dep_type_id_to_dep_type,
                source_type_id_to_source_type,
            ) {
                Ok(prov) => upsert_provenance(&mut provenance, prov),
                Err(e) => parse_errors.push(e),
            }
        } else {
            match decode_package_line(line, line_num) {
                Ok((name, payload)) => {
                    if payload.source_idx >= lockfile.sources.len() {
                        parse_errors.push(Error::MissingSource {
                            line_number: line_num,
                            index: payload.source_idx,
                        });
                    } else {
                        parsed_payloads.push((name, payload, line_num));
                    }
                }
                Err(e) => parse_errors.push(e),
            }
        }
        if parse_errors.len() >= MAX_REPORTED_PARSE_ERRORS {
            break;
        }
    }
    if !parse_errors.is_empty() {
        let count = parse_errors.len();
        let first = Box::new(parse_errors.remove(0));
        return Err(Error::MultipleParseErrors { count, first });
    }

    lockfile.packages = build_packages(parsed_payloads, lockfile.sources.len())?;
    lockfile.artifacts = artifacts;
    lockfile.patches = patches;
    lockfile.provenance = provenance;
    Ok(lockfile)
}

/// True for blank lines and `@signature`/`@digest` trailers, which are not body rows.
fn is_skippable_body_line(line: &str) -> bool {
    line.trim().is_empty() || line.starts_with("@signature ") || line.starts_with("@digest ")
}

/// Parses `@artifact <content_id> <os> <arch> <path>`.
fn parse_artifact_line(rest: &str) -> ArtifactDirective {
    let mut parts = rest.splitn(4, ' ');
    let content_id = u64::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let os_id = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let arch_id = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let rel_path = parts.next().unwrap_or("");
    ArtifactDirective {
        content_id,
        os_id,
        arch_id,
        relative_path: rel_path.to_string(),
    }
}

/// Parses `@patch <content_id> <type> <path>`.
fn parse_patch_line(rest: &str) -> PatchDirective {
    let mut parts = rest.splitn(3, ' ');
    let content_id = u64::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let patch_type = u8::from_str_radix(parts.next().unwrap_or(""), 16).unwrap_or(0);
    let rel_path = parts.next().unwrap_or("");
    PatchDirective {
        content_id,
        patch_type,
        relative_path: rel_path.to_string(),
    }
}

/// Inserts a provenance record, replacing any earlier entry for the same package.
fn upsert_provenance(
    provenance: &mut Vec<crate::provenance::ResolutionProvenance>,
    prov: crate::provenance::ResolutionProvenance,
) {
    if let Some(existing) = provenance
        .iter()
        .position(|p| p.package_name == prov.package_name)
    {
        provenance[existing] = prov;
    } else {
        provenance.push(prov);
    }
}

/// Decodes one `name\t<base64url payload>` row into its name and payload.
fn decode_package_line(
    line: &str,
    line_num: usize,
) -> Result<(String, crate::payload::PayloadData), Error> {
    let (name, encoded) = line.split_once('\t').ok_or(Error::MissingDelimiter {
        line_number: line_num,
    })?;
    let binary = decode(encoded.as_bytes()).map_err(|_| Error::InvalidBase64 {
        line_number: line_num,
    })?;
    let payload = unpack_payload(&binary, line_num)?;
    Ok((name.to_string(), payload))
}

/// Parses an `@vex` directive line.
pub(crate) fn parse_vex_line(
    rest: &str,
    line_number: usize,
) -> Result<crate::lockfile::VexEntry, Error> {
    let mut parts = rest.splitn(5, ' ');
    let package = parts.next().unwrap_or("").to_string();
    let advisory_id = parts.next().unwrap_or("").to_string();
    let status_str = parts.next().unwrap_or("");
    let justification = parts.next().unwrap_or("").to_string();
    let impact_statement = parts.next().unwrap_or("").to_string();

    let status = status_str
        .parse::<crate::lockfile::VexStatus>()
        .map_err(|()| Error::InvalidVexStatus {
            line_number,
            status: status_str.to_string(),
        })?;

    Ok(crate::lockfile::VexEntry {
        package,
        advisory_id,
        status,
        justification,
        impact_statement,
    })
}

/// Parses an `@advisory` directive line.
pub(crate) fn parse_advisory_line(
    rest: &str,
    line_number: usize,
) -> Result<crate::policy::Advisory, Error> {
    let mut parts = rest.splitn(5, ' ');
    let package = parts.next().unwrap_or("").to_string();
    let advisory_id = parts.next().unwrap_or("").to_string();
    let severity_str = parts.next().unwrap_or("");
    let url = parts.next().unwrap_or("").to_string();
    let affected_versions = parts.next().unwrap_or("").to_string();

    let severity = severity_str
        .parse::<crate::policy::AdvisorySeverity>()
        .map_err(|()| Error::InvalidAdvisorySeverity {
            line_number,
            severity: severity_str.to_string(),
        })?;

    Ok(crate::policy::Advisory {
        package,
        advisory_id,
        severity,
        url,
        affected_versions,
    })
}

/// Maps a provenance dep-type id to a [`DepType`]; `Err` carries the parse error.
fn dep_type_id_to_dep_type(dep_type_id: u8) -> Result<DepType, Error> {
    match dep_type_id {
        0..=4 => Ok(DepType::from_id(dep_type_id)),
        _ => Err(Error::UnknownProvenanceDepType {
            type_id: dep_type_id,
        }),
    }
}

/// Maps a provenance source-type id to a [`ProvenanceSourceType`].
fn source_type_id_to_source_type(
    source_type_id: u8,
) -> Result<crate::provenance::ProvenanceSourceType, Error> {
    crate::provenance::ProvenanceSourceType::from_id(source_type_id).ok_or(
        Error::UnknownProvenanceSourceType {
            type_id: source_type_id,
        },
    )
}

/// Parses an `@provenance` directive line.
fn parse_provenance_line(
    rest: &str,
    dep_type_of: impl Fn(u8) -> Result<DepType, Error>,
    source_type_of: impl Fn(u8) -> Result<crate::provenance::ProvenanceSourceType, Error>,
) -> Result<crate::provenance::ResolutionProvenance, Error> {
    let mut parts = rest.splitn(6, ' ');
    let pkg_name = parts.next().unwrap_or("").to_string();
    let constraint = parts.next().unwrap_or("").to_string();
    let constrained_by = parts.next().unwrap_or("").to_string();
    let dep_type_id: u8 = parts.next().unwrap_or("").parse().unwrap_or(255);
    let source_type_id: u8 = parts.next().unwrap_or("").parse().unwrap_or(255);
    let depth: u32 = parts.next().unwrap_or("0").parse().unwrap_or(0);

    Ok(crate::provenance::ResolutionProvenance {
        package_name: pkg_name,
        constraint,
        constrained_by,
        dep_type: dep_type_of(dep_type_id)?,
        source_type: source_type_of(source_type_id)?,
        depth,
    })
}

/// Converts parsed payloads into [`Package`]s, resolving content-id references.
fn build_packages(
    parsed_payloads: Vec<(String, crate::payload::PayloadData, usize)>,
    source_count: usize,
) -> Result<Vec<Package>, Error> {
    let _ = source_count;
    let id_map = build_content_id_map(&parsed_payloads)?;
    let mut packages = Vec::with_capacity(parsed_payloads.len());
    for (name, payload, _line_num) in parsed_payloads {
        let dependencies = build_dependencies(&name, &payload, &id_map)?;
        packages.push(Package {
            name,
            logical_name: payload.logical_name,
            source_idx: payload.source_idx,
            major: payload.major,
            minor: payload.minor,
            patch: payload.patch,
            hashes: build_integrity_hashes(&payload.hashes),
            features: payload.features,
            resolved_peers: payload.resolved_peers,
            dependencies,
            peer_requirements: build_peer_requirements(&payload.peer_requirements),
            platform_tags: build_platform_tags(&payload.platform_tags),
            exports: build_exports(&payload.exports),
            artifacts: build_artifacts(&payload.artifacts),
            hook_hashes: build_hook_hashes(&payload.hook_hashes),
            patch_hash: build_patch_hash(payload.patch_hash.as_ref()),
        });
    }
    Ok(packages)
}

/// Maps every payload's content id to its name and feature list.
///
/// 1.0 content ids are domain-separated BLAKE3-64 (`cid::content_id`). A
/// 64-bit truncation collision between two distinct identities is a hard
/// parse error (`ContentIdCollision`) instead of a silent map overwrite.
pub(crate) fn build_content_id_map(
    parsed_payloads: &[(String, crate::payload::PayloadData, usize)],
) -> Result<HashMap<u64, (String, Vec<String>)>, Error> {
    let mut id_map: HashMap<u64, (String, Vec<String>)> =
        HashMap::with_capacity(parsed_payloads.len());
    let mut seen: HashMap<u64, (String, u64, u64, u64)> =
        HashMap::with_capacity(parsed_payloads.len());
    for (name, payload, _) in parsed_payloads {
        let identity = (name.clone(), payload.major, payload.minor, payload.patch);
        let cid = cid::content_id(name, payload.major, payload.minor, payload.patch);
        if let Some(first) = seen.get(&cid)
            && (first.0 != identity.0
                || first.1 != identity.1
                || first.2 != identity.2
                || first.3 != identity.3)
        {
            return Err(Error::ContentIdCollision(format!(
                "{}@{}.{}.{} and {}@{}.{}.{} share content id {cid:016x}",
                first.0, first.1, first.2, first.3, identity.0, identity.1, identity.2, identity.3
            )));
        }
        seen.insert(cid, identity);
        id_map.insert(cid, (name.clone(), payload.features.clone()));
    }
    Ok(id_map)
}

/// Rebuilds integrity hashes, defaulting unknown algorithm ids to Blake3.
pub(crate) fn build_integrity_hashes(hashes: &[crate::payload::HashPayload]) -> Vec<IntegrityHash> {
    hashes
        .iter()
        .map(|h| IntegrityHash {
            algo: HashAlgorithm::from_id(h.algo_id).unwrap_or(HashAlgorithm::Blake3),
            digest: h.digest.clone(),
            attestation: h.attestation.clone(),
        })
        .collect()
}

/// Rebuilds dependencies, resolving each content id through `id_map`.
pub(crate) fn build_dependencies(
    name: &str,
    payload: &crate::payload::PayloadData,
    id_map: &HashMap<u64, (String, Vec<String>)>,
) -> Result<Vec<Dependency>, Error> {
    let mut dependencies = Vec::with_capacity(payload.deps.len());
    for dep in &payload.deps {
        let (dep_name, dep_features) =
            id_map
                .get(&dep.content_id)
                .ok_or_else(|| Error::MissingContentId {
                    package: name.to_string(),
                    content_id: dep.content_id,
                })?;
        let req_feats: Vec<String> = dep
            .req_feat_indices
            .iter()
            .map(|i| dep_features.get(*i).cloned().unwrap_or_default())
            .collect();
        let ty = match dep.dep_type {
            4 => DepType::OptionalTarget(
                dep.target_os.map_or(TargetOS::Any, TargetOS::from_id),
                dep.target_arch.map_or(TargetArch::Any, TargetArch::from_id),
            ),
            id => DepType::from_id(id),
        };
        dependencies.push(Dependency {
            name: dep_name.clone(),
            dep_type: ty,
            requested_features: req_feats,
        });
    }
    Ok(dependencies)
}

/// Rebuilds peer version requirements from their wire representation.
pub(crate) fn build_peer_requirements(
    reqs: &[crate::payload::PeerReqPayload],
) -> Vec<PeerRequirement> {
    reqs.iter()
        .map(|r| PeerRequirement {
            peer_name: r.peer_name.clone(),
            version_range: r.version_range.clone(),
            is_optional: r.is_optional,
        })
        .collect()
}

/// Rebuilds platform tags from their wire representation.
pub(crate) fn build_platform_tags(tags: &[crate::payload::PlatformTagPayload]) -> Vec<PlatformTag> {
    tags.iter()
        .map(|t| PlatformTag {
            os: TargetOS::from_id(t.os_id),
            arch: TargetArch::from_id(t.arch_id),
        })
        .collect()
}

/// Rebuilds export declarations, defaulting unknown hash ids to Blake3.
pub(crate) fn build_exports(exports: &[crate::payload::ExportPayload]) -> Vec<Export> {
    exports
        .iter()
        .map(|ex| Export {
            identifier: ex.identifier.clone(),
            hash_algo: HashAlgorithm::from_id(ex.hash_algo).unwrap_or(HashAlgorithm::Blake3),
            digest: ex.digest.clone(),
        })
        .collect()
}

/// Rebuilds artifact entries, defaulting unknown hash ids to Blake3.
pub(crate) fn build_artifacts(artifacts: &[crate::payload::ArtifactPayload]) -> Vec<Artifact> {
    artifacts
        .iter()
        .map(|art| Artifact {
            os_id: art.os_id,
            arch_id: art.arch_id,
            hash_algo: HashAlgorithm::from_id(art.hash_algo).unwrap_or(HashAlgorithm::Blake3),
            digest: art.digest.clone(),
        })
        .collect()
}

/// Rebuilds hook integrity hashes, defaulting unknown hash ids to Blake3.
pub(crate) fn build_hook_hashes(hook_hashes: &[crate::payload::HookHashPayload]) -> Vec<HookHash> {
    hook_hashes
        .iter()
        .map(|sh| HookHash {
            hook_type: sh.hook_type.clone(),
            hash_algo: HashAlgorithm::from_id(sh.hash_algo).unwrap_or(HashAlgorithm::Blake3),
            digest: sh.digest.clone(),
        })
        .collect()
}

/// Rebuilds the optional patch hash, defaulting unknown hash ids to Blake3.
pub(crate) fn build_patch_hash(
    patch_hash: Option<&(u8, Vec<u8>)>,
) -> Option<(HashAlgorithm, Vec<u8>)> {
    patch_hash.map(|(algo, digest)| {
        (
            HashAlgorithm::from_id(*algo).unwrap_or(HashAlgorithm::Blake3),
            digest.clone(),
        )
    })
}

// File I/O functions
///
/// # Errors
///
/// Returns `Err` if input validation fails.
pub fn write_lockfile(path: &Path, lockfile: &Lockfile) -> Result<(), Error> {
    fs::write(path, serialize(lockfile)?)?;
    Ok(())
}

///
/// # Errors
///
/// Returns `Err` if input validation fails.
pub fn read_lockfile(path: &Path) -> Result<Lockfile, Error> {
    deserialize(&fs::read_to_string(path)?)
}

// Validation functions
///
/// # Errors
///
/// Returns `Err` if `PhantomDependency` occurs.
pub fn validate_hoist_boundary(lockfile: &Lockfile, cosine_name: &str) -> Result<(), Error> {
    let boundary = lockfile
        .hoist_boundaries
        .iter()
        .find(|b| b.cosine == cosine_name);
    let Some(boundary) = boundary else {
        return Ok(());
    };
    let Some(cosine_pkg) = lockfile.packages.iter().find(|p| p.name == cosine_name) else {
        return Ok(());
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

///
/// # Errors
///
/// Returns `Err` if `OrphanPatchHash` occurs; `PatchFileMissing` occurs; or if the patch digest does not match.
pub fn validate_patches(lockfile: &Lockfile, lockfile_dir: &std::path::Path) -> Result<(), Error> {
    let cid_to_idx: HashMap<u64, usize> = lockfile
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| (cid::package_cid(p), i))
        .collect();
    for pd in &lockfile.patches {
        let pkg = cid_to_idx
            .get(&pd.content_id)
            .map(|&i| &lockfile.packages[i]);
        let Some(pkg) = pkg else { continue };
        let Some((_algo, expected_digest)) = &pkg.patch_hash else {
            return Err(Error::OrphanPatchHash {
                package: pkg.name.clone(),
            });
        };
        let patch_path = lockfile_dir.join(&pd.relative_path);
        let content = std::fs::read(&patch_path).map_err(|_| Error::PatchFileMissing {
            package: pkg.name.clone(),
            content_id: pd.content_id,
            path: pd.relative_path.clone(),
        })?;
        let actual = blake3::hash(&content).as_bytes().to_vec();
        if &actual != expected_digest {
            return Err(Error::PatchDigestMismatch {
                package: pkg.name.clone(),
                expected: format!("{expected_digest:?}"),
                actual: format!("{actual:?}"),
            });
        }
    }
    Ok(())
}

///
/// # Errors
///
/// Returns `Err` if `ScriptDigestMismatch` occurs.
pub fn validate_scripts(
    lockfile: &Lockfile,
    lockfile_dir: &std::path::Path,
) -> Result<Vec<String>, Error> {
    for pkg in &lockfile.packages {
        let source_path = match &lockfile.sources.get(pkg.source_idx) {
            Some(Source::Local(p)) => std::path::Path::new(p),
            _ => continue,
        };
        let full_path = lockfile_dir.join(source_path).join("package.json");
        let Ok(manifest_content) = std::fs::read_to_string(&full_path) else {
            continue;
        };
        for sh in &pkg.hook_hashes {
            let script_name = sh.hook_type.as_str();
            if script_name.is_empty() {
                continue;
            }
            let pattern = format!("\"{script_name}\"");
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
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Advisory, AdvisorySeverity, LicenseEntry};
    use std::path::PathBuf;

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("hlock_lockfile_tests_{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn lockfile_with_packages() -> Lockfile {
        Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![
                Package {
                    name: "alpha".to_string(),
                    source_idx: 0,
                    major: 1,
                    minor: 0,
                    patch: 0,
                    ..Package::default()
                },
                Package {
                    name: "beta".to_string(),
                    source_idx: 0,
                    major: 2,
                    minor: 3,
                    patch: 4,
                    ..Package::default()
                },
            ],
            licenses: vec![LicenseEntry {
                package: "alpha".to_string(),
                expression: "MIT".to_string(),
            }],
            advisories: vec![Advisory {
                package: "beta".to_string(),
                advisory_id: "CVE-2024-1".to_string(),
                severity: AdvisorySeverity::High,
                url: "https://adv/1".to_string(),
                affected_versions: "<2.3.5".to_string(),
            }],
            ..Lockfile::default()
        }
    }

    #[test]
    fn serialize_deserialize_round_trip_with_directives() {
        let lf = lockfile_with_packages();
        let serialized = serialize(&lf).unwrap();
        assert!(serialized.contains("@digest "));
        assert!(serialized.contains("@license alpha MIT"));
        assert!(serialized.contains("@advisory beta CVE-2024-1 high https://adv/1 <2.3.5"));

        let parsed = deserialize(&serialized).unwrap();
        assert_eq!(parsed.packages.len(), 2);
        assert_eq!(parsed.packages[1].name, "beta");
        assert_eq!(
            (
                parsed.packages[1].major,
                parsed.packages[1].minor,
                parsed.packages[1].patch
            ),
            (2, 3, 4)
        );
        assert_eq!(parsed.licenses, lf.licenses);
        assert_eq!(parsed.advisories, lf.advisories);
        assert!(validate_digest(&serialized).is_ok());
    }

    #[test]
    fn serialize_rejects_source_index_out_of_range() {
        let lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![Package {
                name: "p".to_string(),
                source_idx: 5,
                ..Package::default()
            }],
            ..Lockfile::default()
        };
        match serialize(&lf) {
            Err(Error::MissingSource { index, .. }) => assert_eq!(index, 5),
            other => panic!("expected MissingSource, got {other:?}"),
        }
    }

    #[test]
    fn serialize_rejects_workspace_package_with_hashes() {
        let lf = Lockfile {
            sources: vec![Source::Workspace],
            packages: vec![Package {
                name: "ws".to_string(),
                source_idx: 0,
                hashes: vec![IntegrityHash {
                    algo: HashAlgorithm::Sha256,
                    digest: vec![1],
                    attestation: Attestation::None,
                }],
                ..Package::default()
            }],
            ..Lockfile::default()
        };
        match serialize(&lf) {
            Err(Error::InvalidWorkspaceHash { .. }) => {}
            other => panic!("expected InvalidWorkspaceHash, got {other:?}"),
        }
    }

    #[test]
    fn serialize_rejects_dependency_without_package() {
        let lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![Package {
                name: "app".to_string(),
                source_idx: 0,
                dependencies: vec![Dependency {
                    name: "ghost".to_string(),
                    dep_type: DepType::Runtime,
                    requested_features: vec![],
                }],
                ..Package::default()
            }],
            ..Lockfile::default()
        };
        match serialize(&lf) {
            Err(Error::MissingPackage {
                package,
                missing_dep,
            }) => {
                assert_eq!(package, "app");
                assert_eq!(missing_dep, "ghost");
            }
            other => panic!("expected MissingPackage, got {other:?}"),
        }
    }

    /// Deserializes `content` and returns the first aggregated parse error.
    ///
    /// v1.0 `deserialize` collects up to 10 body errors into
    /// [`Error::MultipleParseErrors`]; tests assert on the first one.
    fn first_parse_error(content: &str) -> Error {
        match deserialize(content) {
            Err(Error::MultipleParseErrors { first, .. }) => *first,
            Err(e) => e,
            Ok(_) => panic!("expected a parse error, got a valid lockfile"),
        }
    }

    #[test]
    fn deserialize_rejects_missing_tab_delimiter() {
        match first_parse_error("@source 0 https://r/\n\nbadline\n") {
            Error::MissingDelimiter { line_number } => assert!(line_number >= 1),
            other => panic!("expected MissingDelimiter, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_invalid_base64() {
        match first_parse_error("@source 0 https://r/\n\npkg\t!!!!\n") {
            Error::InvalidBase64 { .. } => {}
            other => panic!("expected InvalidBase64, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_payload_source_out_of_range() {
        let lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![Package {
                name: "p".to_string(),
                source_idx: 0,
                major: 1,
                ..Package::default()
            }],
            ..Lockfile::default()
        };
        let mut good = serialize(&lf).unwrap();
        // Swap the @source directive for a @mirror: the header still parses,
        // but the payload now points at source index 0 of an empty source list.
        good = good.replace("@source 0 https://r.com/\n", "@mirror m https://m/\n");
        match first_parse_error(&good) {
            Error::MissingSource { index, .. } => assert_eq!(index, 0),
            other => panic!("expected MissingSource, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_bad_vex_status_and_advisory_severity() {
        let lf = lockfile_with_packages();
        let mut content = serialize(&lf).unwrap();
        content = content.replace("@digest ", "@vex beta CVE-2024-1 maybe j i\n@digest ");
        match first_parse_error(&content) {
            Error::InvalidVexStatus { status, .. } => assert_eq!(status, "maybe"),
            other => panic!("expected InvalidVexStatus, got {other:?}"),
        }

        let mut content = serialize(&lf).unwrap();
        content = content.replace("@digest ", "@advisory beta CVE-2024-2 urgent u *\n@digest ");
        match first_parse_error(&content) {
            Error::InvalidAdvisorySeverity { severity, .. } => assert_eq!(severity, "urgent"),
            other => panic!("expected InvalidAdvisorySeverity, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_rejects_unknown_provenance_type_ids() {
        let lf = lockfile_with_packages();
        let mut content = serialize(&lf).unwrap();
        content = content.replace("@digest ", "@provenance beta ^2 app 9 0 1\n@digest ");
        match first_parse_error(&content) {
            Error::UnknownProvenanceDepType { type_id } => assert_eq!(type_id, 9),
            other => panic!("expected UnknownProvenanceDepType, got {other:?}"),
        }

        let mut content = serialize(&lf).unwrap();
        content = content.replace("@digest ", "@provenance beta ^2 app 0 9 1\n@digest ");
        match first_parse_error(&content) {
            Error::UnknownProvenanceSourceType { type_id } => assert_eq!(type_id, 9),
            other => panic!("expected UnknownProvenanceSourceType, got {other:?}"),
        }
    }

    #[test]
    fn deserialize_parses_artifact_patch_and_license_lines() {
        let lf = lockfile_with_packages();
        let mut content = serialize(&lf).unwrap();
        let cid = crate::cid::content_id("beta", 2, 3, 4);
        content = content.replace(
            "@digest ",
            &format!("@artifact {cid:016x} 01 02 bin/app\n@patch {cid:016x} 01 p.diff\n@digest "),
        );
        let parsed = deserialize(&content).unwrap();
        assert_eq!(parsed.artifacts.len(), 1);
        assert_eq!(parsed.artifacts[0].os_id, 1);
        assert_eq!(parsed.artifacts[0].arch_id, 2);
        assert_eq!(parsed.patches.len(), 1);
        assert_eq!(parsed.patches[0].content_id, cid);
    }

    #[test]
    fn deserialize_vex_and_provenance_round_trip() {
        let mut lf = lockfile_with_packages();
        lf.vex_entries = vec![crate::lockfile::VexEntry {
            package: "beta".to_string(),
            advisory_id: "CVE-2024-1".to_string(),
            status: crate::lockfile::VexStatus::NotAffected,
            justification: "code_not_present".to_string(),
            impact_statement: "vulnerable path unused".to_string(),
        }];
        lf.provenance = vec![crate::provenance::ResolutionProvenance {
            package_name: "beta".to_string(),
            constraint: "^2.0.0".to_string(),
            constrained_by: "app".to_string(),
            dep_type: DepType::Dev,
            source_type: crate::provenance::ProvenanceSourceType::Git,
            depth: 2,
        }];
        let content = serialize(&lf).unwrap();
        assert!(content.contains("@vex beta CVE-2024-1 not_affected"));
        assert!(content.contains("@provenance beta ^2.0.0 app 1 2 2"));
        let parsed = deserialize(&content).unwrap();
        assert_eq!(parsed.vex_entries, lf.vex_entries);
        assert_eq!(parsed.provenance, lf.provenance);
    }

    #[test]
    fn deserialize_replaces_duplicate_provenance_entries() {
        let lf = lockfile_with_packages();
        let mut content = serialize(&lf).unwrap();
        content = content.replace(
            "@digest ",
            "@provenance beta ^2 a 0 0 1\n@provenance beta ^3 b 1 0 2\n@digest ",
        );
        let parsed = deserialize(&content).unwrap();
        assert_eq!(parsed.provenance.len(), 1);
        assert_eq!(parsed.provenance[0].constraint, "^3");
    }

    #[test]
    fn write_and_read_lockfile_round_trip() {
        let dir = temp_dir("io");
        let path = dir.join("out.hlock");
        let lf = lockfile_with_packages();
        write_lockfile(&path, &lf).unwrap();
        let read_back = read_lockfile(&path).unwrap();
        assert_eq!(read_back.packages.len(), 2);
        assert_eq!(read_back.find_package("alpha").map(|p| p.major), Some(1));

        let missing = read_lockfile(&dir.join("nope.hlock"));
        assert!(matches!(missing, Err(Error::Io(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_hoist_boundary_flags_phantom_dependencies() {
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![
                Package {
                    name: "app".to_string(),
                    source_idx: 0,
                    dependencies: vec![
                        Dependency {
                            name: "allowed".to_string(),
                            dep_type: DepType::Runtime,
                            requested_features: vec![],
                        },
                        Dependency {
                            name: "phantom".to_string(),
                            dep_type: DepType::Runtime,
                            requested_features: vec![],
                        },
                    ],
                    ..Package::default()
                },
                Package {
                    name: "allowed".to_string(),
                    source_idx: 0,
                    major: 1,
                    ..Package::default()
                },
                Package {
                    name: "phantom".to_string(),
                    source_idx: 0,
                    major: 1,
                    ..Package::default()
                },
            ],
            hoist_boundaries: vec![HoistBoundary {
                cosine: "app".to_string(),
                allowed_deps: vec!["allowed".to_string()],
            }],
            ..Lockfile::default()
        };
        assert!(validate_hoist_boundary(&lf, "unknown-cosine").is_ok());
        assert!(validate_hoist_boundary(&lf, "app").is_err());
        lf.hoist_boundaries[0]
            .allowed_deps
            .push("phantom".to_string());
        assert!(validate_hoist_boundary(&lf, "app").is_ok());
    }

    #[test]
    fn validate_patches_covers_all_branches() {
        let dir = temp_dir("patches");
        let mut lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            packages: vec![Package {
                name: "p".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                ..Package::default()
            }],
            ..Lockfile::default()
        };
        let cid = crate::cid::content_id("p", 1, 0, 0);

        // A patch directive whose content id matches no package is ignored.
        lf.patches = vec![PatchDirective {
            content_id: 42,
            patch_type: 1,
            relative_path: "x.diff".to_string(),
        }];
        assert!(validate_patches(&lf, &dir).is_ok());

        // Matching package without a patch hash → orphan.
        lf.patches = vec![PatchDirective {
            content_id: cid,
            patch_type: 1,
            relative_path: "x.diff".to_string(),
        }];
        match validate_patches(&lf, &dir) {
            Err(Error::OrphanPatchHash { package }) => assert_eq!(package, "p"),
            other => panic!("expected OrphanPatchHash, got {other:?}"),
        }

        // With a patch hash but no file on disk → missing.
        lf.packages[0].patch_hash = Some((HashAlgorithm::Blake3, vec![0u8; 32]));
        match validate_patches(&lf, &dir) {
            Err(Error::PatchFileMissing { package, path, .. }) => {
                assert_eq!(package, "p");
                assert_eq!(path, "x.diff");
            }
            other => panic!("expected PatchFileMissing, got {other:?}"),
        }

        // Wrong digest → mismatch.
        std::fs::write(dir.join("x.diff"), b"actual content").unwrap();
        match validate_patches(&lf, &dir) {
            Err(Error::PatchDigestMismatch { package, .. }) => assert_eq!(package, "p"),
            other => panic!("expected PatchDigestMismatch, got {other:?}"),
        }

        // Correct digest → ok.
        let digest = blake3::hash(b"actual content").as_bytes().to_vec();
        lf.packages[0].patch_hash = Some((HashAlgorithm::Blake3, digest));
        assert!(validate_patches(&lf, &dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_scripts_checks_local_package_json() {
        let dir = temp_dir("scripts");
        let pkg_dir = dir.join("vendor");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        // Current extraction takes the text between `"postinstall"` and the next
        // double quote, i.e. `:` for compact JSON; the digest must match that.
        std::fs::write(
            pkg_dir.join("package.json"),
            r#"{"scripts":{"postinstall":"echo hi"}}"#,
        )
        .unwrap();

        let colon_digest = blake3::hash(b":").as_bytes().to_vec();
        let lf = Lockfile {
            sources: vec![
                Source::Local("vendor".to_string()),
                Source::Registry("https://r.com/".to_string()),
            ],
            packages: vec![
                Package {
                    name: "remote".to_string(),
                    source_idx: 1,
                    ..Package::default()
                },
                Package {
                    name: "local-ok".to_string(),
                    source_idx: 0,
                    hook_hashes: vec![
                        // Empty hook names are skipped before lookup.
                        HookHash {
                            hook_type: String::new(),
                            hash_algo: HashAlgorithm::Blake3,
                            digest: vec![],
                        },
                        // A hook missing from the manifest is skipped.
                        HookHash {
                            hook_type: "absent-hook".to_string(),
                            hash_algo: HashAlgorithm::Blake3,
                            digest: vec![],
                        },
                        // The postinstall hook digest matches the manifest text.
                        HookHash {
                            hook_type: "postinstall".to_string(),
                            hash_algo: HashAlgorithm::Blake3,
                            digest: colon_digest,
                        },
                    ],
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };
        assert_eq!(validate_scripts(&lf, &dir).unwrap(), Vec::<String>::new());

        // A mismatching digest is rejected.
        let mut bad = lf.clone();
        bad.packages[1].hook_hashes[2].digest = vec![1; 32];
        match validate_scripts(&bad, &dir) {
            Err(Error::ScriptDigestMismatch { package, script }) => {
                assert_eq!(package, "local-ok");
                assert_eq!(script, "postinstall");
            }
            other => panic!("expected ScriptDigestMismatch, got {other:?}"),
        }

        // A local source without a package.json is silently skipped.
        let empty_dir = temp_dir("scripts_empty");
        assert_eq!(
            validate_scripts(&lf, &empty_dir).unwrap(),
            Vec::<String>::new()
        );

        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&empty_dir);
    }
}
