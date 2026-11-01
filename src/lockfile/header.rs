//! Header parsing and formatting

use super::types::{DepType, HoistBoundary, Lockfile, Mirror, Override, Source, WorkspacePkg};
use crate::error::Error;
use std::fmt::Write as _;

fn classify_source(val: &str) -> Source {
    if val == "workspace" {
        Source::Workspace
    } else if val.starts_with("file://") || val.starts_with('/') {
        Source::Local(val.to_string())
    } else if val.starts_with("git://")
        || val.starts_with("git+")
        || (val.starts_with("https://") && val.contains(".git"))
    {
        Source::Git(val.to_string())
    } else if val.starts_with("cas+http://") || val.starts_with("cas+https://") {
        Source::CasHttp(val.strip_prefix("cas+").unwrap_or(val).to_string())
    } else if val.starts_with("ipfs://") {
        Source::Ipfs(val.to_string())
    } else {
        Source::Registry(val.to_string())
    }
}

/// Writes `@source` lines for every package source.
fn write_sources(out: &mut String, lockfile: &Lockfile) {
    for (idx, source) in lockfile.sources.iter().enumerate() {
        let val = match source {
            Source::Registry(u) | Source::Local(u) | Source::Git(u) | Source::Ipfs(u) => u.clone(),
            Source::Workspace => "workspace".to_string(),
            Source::CasHttp(u) => format!("cas+{u}"),
        };
        let _ = writeln!(out, "@source {idx} {val}");
    }
}

/// Writes `@mirror` lines.
fn write_mirrors(out: &mut String, lockfile: &Lockfile) {
    for mirror in &lockfile.mirrors {
        let _ = writeln!(out, "@mirror {} {}", mirror.scope, mirror.url);
    }
}

/// Writes `@policy` lines.
fn write_policies(out: &mut String, lockfile: &Lockfile) {
    for policy in &lockfile.policies {
        let policy_type_str = match policy.policy_type {
            crate::policy::PolicyType::AllowHook => "allow-hook",
            crate::policy::PolicyType::DenyHook => "deny-hook",
            crate::policy::PolicyType::AllowScript => "allow-script",
            crate::policy::PolicyType::DenyScript => "deny-script",
            crate::policy::PolicyType::BuildEnv => "build-env",
            crate::policy::PolicyType::Engine => "engine",
        };
        let _ = writeln!(
            out,
            "@policy {} {} {}",
            policy_type_str, policy.package_pattern, policy.value
        );
    }
}

/// Writes `@trust-root` lines with hex-encoded public keys.
fn write_trust_roots(out: &mut String, lockfile: &Lockfile) {
    for tr in &lockfile.trust_roots {
        let algo_str = match tr.algorithm {
            crate::signature::SignatureAlgorithm::Ed25519 => "00",
            crate::signature::SignatureAlgorithm::MlDsa65 => "02",
        };
        let role_str = match tr.role {
            crate::policy::TrustRole::Root => "root",
            crate::policy::TrustRole::Targets => "targets",
            crate::policy::TrustRole::Snapshot => "snapshot",
            crate::policy::TrustRole::Delegation => "delegation",
        };
        let pub_key_hex = crate::lockfile::digest::bytes_to_hex(&tr.public_key);
        let _ = writeln!(
            out,
            "@trust-root {} {} {} {} {}",
            tr.key_id, algo_str, pub_key_hex, tr.expires_epoch, role_str
        );
    }
}

/// Writes `@trust-root-rotation` lines.
fn write_root_rotations(out: &mut String, lockfile: &Lockfile) {
    for rot in &lockfile.root_rotations {
        let algo_str = match rot.new_algorithm {
            crate::signature::SignatureAlgorithm::Ed25519 => "00",
            crate::signature::SignatureAlgorithm::MlDsa65 => "02",
        };
        let role_str = match rot.new_role {
            crate::policy::TrustRole::Root => "root",
            crate::policy::TrustRole::Targets => "targets",
            crate::policy::TrustRole::Snapshot => "snapshot",
            crate::policy::TrustRole::Delegation => "delegation",
        };
        let pub_key_hex: String = crate::lockfile::digest::bytes_to_hex(&rot.new_public_key);
        let sig_hex: String = crate::lockfile::digest::bytes_to_hex(&rot.rotation_signature);
        let _ = writeln!(
            out,
            "@trust-root-rotation {} {} {} {} {} {} {} {} {}",
            rot.old_key_id,
            rot.new_key_id,
            rot.threshold,
            algo_str,
            pub_key_hex,
            rot.new_expires_epoch,
            role_str,
            rot.rotation_signature_key_id,
            sig_hex
        );
    }
}

/// Writes `@override` lines.
fn write_overrides(out: &mut String, lockfile: &Lockfile) {
    for ovr in &lockfile.overrides {
        let _ = writeln!(
            out,
            "@override {} {} -> {}",
            ovr.name, ovr.from_version, ovr.to_version
        );
    }
}

/// Writes `@feature` lines with comma-joined flags.
fn write_features(out: &mut String, lockfile: &Lockfile) {
    for (name, flags) in &lockfile.features {
        let flags_str = if flags.is_empty() {
            ""
        } else {
            &flags.join(",")
        };
        let _ = writeln!(out, "@feature {name} {flags_str}");
    }
}

/// Writes workspace root and member package lines.
fn write_workspace(out: &mut String, lockfile: &Lockfile) {
    if let Some(root) = &lockfile.workspace_root {
        let _ = writeln!(out, "@workspace-root {root}");
    }
    for wp in &lockfile.workspace_pkgs {
        let _ = writeln!(out, "@workspace-pkg {} {}", wp.name, wp.manifest_path);
    }
}

/// Writes `@hoist-boundary` lines with bracketed dependency lists.
fn write_hoist_boundaries(out: &mut String, lockfile: &Lockfile) {
    for hb in &lockfile.hoist_boundaries {
        let deps = if hb.allowed_deps.is_empty() {
            String::new()
        } else {
            format!("[{}]", hb.allowed_deps.join(","))
        };
        let _ = writeln!(out, "@hoist-boundary {} -> {}", hb.cosine, deps);
    }
}

/// Writes `@metadata` lines.
fn write_metadata(out: &mut String, lockfile: &Lockfile) {
    for (key, value) in &lockfile.metadata {
        let _ = writeln!(out, "@metadata {key} {value}");
    }
}

///
/// # Errors
///
/// Returns `Err` if input validation fails.
pub fn format_header(lockfile: &Lockfile) -> Result<String, Error> {
    let mut out = String::new();
    write_sources(&mut out, lockfile);
    write_mirrors(&mut out, lockfile);
    write_policies(&mut out, lockfile);
    write_trust_roots(&mut out, lockfile);
    write_root_rotations(&mut out, lockfile);
    write_overrides(&mut out, lockfile);
    write_features(&mut out, lockfile);
    write_workspace(&mut out, lockfile);
    write_hoist_boundaries(&mut out, lockfile);
    write_metadata(&mut out, lockfile);
    out.push('\n');
    Ok(out)
}

/// Header directives accumulated while parsing.
#[derive(Default)]
struct HeaderAcc {
    sources: Vec<Source>,
    overrides: Vec<Override>,
    features: Vec<(String, Vec<String>)>,
    metadata: Vec<(String, String)>,
    workspace_root: Option<String>,
    workspace_pkgs: Vec<WorkspacePkg>,
    mirrors: Vec<Mirror>,
    policies: Vec<crate::policy::Policy>,
    trust_roots: Vec<crate::policy::TrustRoot>,
    root_rotations: Vec<crate::lockfile::TrustRootRotation>,
    hoist_boundaries: Vec<HoistBoundary>,
}

impl HeaderAcc {
    /// Converts the accumulated directives into a header-only [`Lockfile`].
    fn into_lockfile(self) -> Lockfile {
        Lockfile {
            sources: self.sources,
            overrides: self.overrides,
            features: self.features,
            metadata: self.metadata,
            workspace_root: self.workspace_root,
            workspace_pkgs: self.workspace_pkgs,
            hoist_boundaries: self.hoist_boundaries,
            packages: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: self.policies,
            trust_roots: self.trust_roots,
            root_rotations: self.root_rotations,
            mirrors: self.mirrors,
            vex_entries: vec![],
            compat: None,
        }
    }
}

/// Decodes a hex string into bytes, dropping invalid nibble pairs.
fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

/// Parses a signature algorithm ID (`00` = Ed25519, `02` = ML-DSA-65).
fn parse_algorithm(
    algo_str: &str,
    line_number: usize,
    reason_prefix: &str,
) -> Result<crate::signature::SignatureAlgorithm, Error> {
    match algo_str {
        "00" => Ok(crate::signature::SignatureAlgorithm::Ed25519),
        "02" => Ok(crate::signature::SignatureAlgorithm::MlDsa65),
        _ => Err(Error::InvalidHeader {
            line_number,
            reason: format!("{reason_prefix}: {algo_str}"),
        }),
    }
}

/// Parses a trust role name (`root`, `targets`, `snapshot`, `delegation`).
fn parse_role(
    role_str: &str,
    line_number: usize,
    reason_prefix: &str,
) -> Result<crate::policy::TrustRole, Error> {
    match role_str {
        "root" => Ok(crate::policy::TrustRole::Root),
        "targets" => Ok(crate::policy::TrustRole::Targets),
        "snapshot" => Ok(crate::policy::TrustRole::Snapshot),
        "delegation" => Ok(crate::policy::TrustRole::Delegation),
        _ => Err(Error::InvalidHeader {
            line_number,
            reason: format!("{reason_prefix}: {role_str}"),
        }),
    }
}

/// Parses an `@source <idx> <value>` directive.
fn parse_source(acc: &mut HeaderAcc, rest: &str, line_number: usize) -> Result<(), Error> {
    let mut parts = rest.splitn(2, ' ');
    let idx_str = parts.next().ok_or_else(|| Error::InvalidHeader {
        line_number,
        reason: "Missing source index".to_string(),
    })?;
    let idx: usize = idx_str.parse().map_err(|_| Error::InvalidHeader {
        line_number,
        reason: "Invalid source index".to_string(),
    })?;
    let val = parts.next().ok_or_else(|| Error::InvalidHeader {
        line_number,
        reason: "Missing source value".to_string(),
    })?;
    let source = classify_source(val);
    if idx != acc.sources.len() {
        return Err(Error::InvalidHeader {
            line_number,
            reason: format!("Source index {idx} is out of order"),
        });
    }
    acc.sources.push(source);
    Ok(())
}

/// Parses a `@trust-root <id> <algo> <hex> <expires> <role>` directive.
fn parse_trust_root(acc: &mut HeaderAcc, rest: &str, line_number: usize) -> Result<(), Error> {
    let mut parts = rest.splitn(5, ' ');
    let key_id = parts.next().unwrap_or("").to_string();
    let algo_str = parts.next().unwrap_or("");
    let public_key_hex = parts.next().unwrap_or("");
    let expires_str = parts.next().unwrap_or("");
    let role_str = parts.next().unwrap_or("");

    let algorithm = parse_algorithm(algo_str, line_number, "Unknown algorithm")?;
    let expires_epoch: u64 = expires_str.parse().map_err(|_| Error::InvalidHeader {
        line_number,
        reason: "Invalid expires_epoch".to_string(),
    })?;
    let role = parse_role(role_str, line_number, "Unknown role")?;
    let public_key = hex_to_bytes(public_key_hex);

    acc.trust_roots.push(crate::policy::TrustRoot {
        key_id,
        algorithm,
        public_key,
        expires_epoch,
        role,
    });
    Ok(())
}

/// Parses a `@mirror <scope> <url>` directive.
fn parse_mirror(acc: &mut HeaderAcc, rest: &str) {
    let mut parts = rest.splitn(2, ' ');
    let scope = parts.next().unwrap_or("").to_string();
    let url = parts.next().unwrap_or("").to_string();
    acc.mirrors.push(Mirror { scope, url });
}

/// Parses an `@override <name> <from> -> <to>` directive.
fn parse_override(acc: &mut HeaderAcc, rest: &str, line_number: usize) -> Result<(), Error> {
    let mut parts = rest.split(" -> ");
    let left = parts.next().unwrap_or("");
    let to_ver = parts.next().ok_or_else(|| Error::InvalidHeader {
        line_number,
        reason: "Missing '->' in override".to_string(),
    })?;
    let mut left_parts = left.splitn(2, ' ');
    let name = left_parts.next().unwrap_or("").to_string();
    let from_ver = left_parts.next().unwrap_or("").to_string();
    acc.overrides.push(Override {
        name,
        from_version: from_ver,
        ty: DepType::Runtime,
        to_version: to_ver.to_string(),
    });
    Ok(())
}

/// Parses an `@feature <name> <comma,separated,flags>` directive.
fn parse_feature(acc: &mut HeaderAcc, rest: &str) {
    let mut parts = rest.splitn(2, ' ');
    let name = parts.next().unwrap_or("").to_string();
    let flags_str = parts.next().unwrap_or("").to_string();
    let flags = if flags_str.is_empty() {
        vec![]
    } else {
        flags_str.split(',').map(|s| s.trim().to_string()).collect()
    };
    acc.features.push((name, flags));
}

/// Parses a `@workspace-root <path>` directive.
fn parse_workspace_root(acc: &mut HeaderAcc, rest: &str) {
    acc.workspace_root = Some(rest.trim().to_string());
}

/// Parses a `@workspace-pkg <name> <manifest-path>` directive.
fn parse_workspace_pkg(acc: &mut HeaderAcc, rest: &str) {
    let (name, manifest_path) = rest.split_once(' ').unwrap_or((rest, ""));
    acc.workspace_pkgs.push(WorkspacePkg {
        name: name.to_string(),
        manifest_path: manifest_path.to_string(),
    });
}

/// Parses an `@hoist-boundary <consumer> -> [deps]` directive.
fn parse_hoist_boundary(acc: &mut HeaderAcc, rest: &str) {
    let mut parts = rest.splitn(2, "->");
    let cosine = parts.next().unwrap_or("").trim().to_string();
    let deps_str = parts.next().unwrap_or("").trim();
    let deps_str = deps_str.strip_prefix("[").unwrap_or(deps_str);
    let deps_str = deps_str.strip_suffix("]").unwrap_or(deps_str);
    let allowed_deps = if deps_str.is_empty() {
        vec![]
    } else {
        deps_str.split(',').map(|s| s.trim().to_string()).collect()
    };
    acc.hoist_boundaries.push(HoistBoundary {
        cosine,
        allowed_deps,
    });
}

/// Parses an `@policy <type> <pattern> <value>` directive.
fn parse_policy(acc: &mut HeaderAcc, rest: &str, line_number: usize) -> Result<(), Error> {
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
        _ => {
            return Err(Error::InvalidHeader {
                line_number,
                reason: format!("Unknown policy type: {policy_type_str}"),
            });
        }
    };

    acc.policies.push(crate::policy::Policy {
        policy_type,
        package_pattern,
        value,
    });
    Ok(())
}

/// Parses a `@trust-root-rotation` directive with its nine space-separated fields.
fn parse_trust_root_rotation(
    acc: &mut HeaderAcc,
    rest: &str,
    line_number: usize,
) -> Result<(), Error> {
    let mut parts = rest.splitn(9, ' ');
    let old_key_id = parts.next().unwrap_or("").to_string();
    let new_key_id = parts.next().unwrap_or("").to_string();
    let threshold: u8 = parts.next().unwrap_or("1").parse().unwrap_or(1);
    let algo_str = parts.next().unwrap_or("");
    let pub_key_hex = parts.next().unwrap_or("");
    let expires_str = parts.next().unwrap_or("0");
    let role_str = parts.next().unwrap_or("root");
    let sig_key_id = parts.next().unwrap_or("").to_string();
    let sig_hex = parts.next().unwrap_or("");

    let new_algorithm = parse_algorithm(algo_str, line_number, "Unknown algorithm in rotation")?;
    let new_expires_epoch: u64 = expires_str.parse().map_err(|_| Error::InvalidHeader {
        line_number,
        reason: "Invalid expires_epoch in rotation".to_string(),
    })?;
    let new_role = parse_role(role_str, line_number, "Unknown role in rotation")?;
    let new_public_key = hex_to_bytes(pub_key_hex);
    let rotation_signature = hex_to_bytes(sig_hex);

    acc.root_rotations.push(crate::lockfile::TrustRootRotation {
        old_key_id,
        new_key_id,
        threshold,
        new_algorithm,
        new_public_key,
        new_expires_epoch,
        new_role,
        rotation_signature_key_id: sig_key_id,
        rotation_signature,
    });
    Ok(())
}

/// Parses a `@metadata <key> <value>` directive.
fn parse_metadata(acc: &mut HeaderAcc, rest: &str) {
    let (key, value) = rest.split_once(' ').unwrap_or((rest, ""));
    acc.metadata.push((key.to_string(), value.to_string()));
}

/// Parses a single header line by dispatching on the directive prefix.
fn parse_directive(acc: &mut HeaderAcc, line: &str, line_number: usize) -> Result<(), Error> {
    if let Some(rest) = line.strip_prefix("@source ") {
        parse_source(acc, rest, line_number)
    } else if let Some(rest) = line.strip_prefix("@trust-root ") {
        parse_trust_root(acc, rest, line_number)
    } else if let Some(rest) = line.strip_prefix("@mirror ") {
        parse_mirror(acc, rest);
        Ok(())
    } else if let Some(rest) = line.strip_prefix("@override ") {
        parse_override(acc, rest, line_number)
    } else if let Some(rest) = line.strip_prefix("@feature ") {
        parse_feature(acc, rest);
        Ok(())
    } else if let Some(rest) = line.strip_prefix("@workspace-root ") {
        parse_workspace_root(acc, rest);
        Ok(())
    } else if let Some(rest) = line.strip_prefix("@workspace-pkg ") {
        parse_workspace_pkg(acc, rest);
        Ok(())
    } else if let Some(rest) = line.strip_prefix("@hoist-boundary ") {
        parse_hoist_boundary(acc, rest);
        Ok(())
    } else if let Some(rest) = line.strip_prefix("@policy ") {
        parse_policy(acc, rest, line_number)
    } else if let Some(rest) = line.strip_prefix("@trust-root-rotation ") {
        parse_trust_root_rotation(acc, rest, line_number)
    } else if let Some(rest) = line.strip_prefix("@metadata ") {
        parse_metadata(acc, rest);
        Ok(())
    } else {
        Err(Error::InvalidHeader {
            line_number,
            reason: format!("Unknown directive: {line}"),
        })
    }
}

///
/// # Errors
///
/// Returns `Err` if `InvalidHeader` occurs.
pub fn parse_header(content: &str) -> Result<(Lockfile, &str), Error> {
    let mut acc = HeaderAcc::default();

    for (line_num, line) in content.lines().enumerate() {
        if line.is_empty() {
            let header_end = content.find("\n\n").map_or(content.len(), |i| i + 2);
            let remaining = &content[header_end..];
            return Ok((acc.into_lockfile(), remaining));
        }
        parse_directive(&mut acc, line, line_num)?;
    }

    Err(Error::InvalidHeader {
        line_number: 0,
        reason: "Missing empty line separator after header".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{Policy, PolicyType, TrustRole, TrustRoot};
    use crate::signature::SignatureAlgorithm;

    fn parse_ok(content: &str) -> Lockfile {
        let (lf, rest) = parse_header(content).expect("header should parse");
        assert!(
            !rest.is_empty() || content.ends_with("\n\n"),
            "expected remaining payload region"
        );
        lf
    }

    fn parse_err(content: &str) -> Error {
        parse_header(content).expect_err("header should be rejected")
    }

    #[test]
    fn classify_source_covers_every_scheme() {
        assert_eq!(classify_source("workspace"), Source::Workspace);
        assert_eq!(
            classify_source("file://./vendor"),
            Source::Local("file://./vendor".to_string())
        );
        assert_eq!(
            classify_source("/abs/path"),
            Source::Local("/abs/path".to_string())
        );
        assert_eq!(
            classify_source("git://github.com/a/b"),
            Source::Git("git://github.com/a/b".to_string())
        );
        assert_eq!(
            classify_source("git+https://github.com/a/b"),
            Source::Git("git+https://github.com/a/b".to_string())
        );
        assert_eq!(
            classify_source("https://host/repo.git"),
            Source::Git("https://host/repo.git".to_string())
        );
        assert_eq!(
            classify_source("cas+https://cas.example/"),
            Source::CasHttp("https://cas.example/".to_string())
        );
        assert_eq!(
            classify_source("cas+http://cas.example/"),
            Source::CasHttp("http://cas.example/".to_string())
        );
        assert_eq!(
            classify_source("ipfs://QmHash"),
            Source::Ipfs("ipfs://QmHash".to_string())
        );
        assert_eq!(
            classify_source("https://registry.npmjs.org/"),
            Source::Registry("https://registry.npmjs.org/".to_string())
        );
    }

    #[test]
    fn parse_header_sources_mirrors_and_metadata() {
        let lf = parse_ok(
            "@source 0 https://registry.npmjs.org/\n\
             @source 1 workspace\n\
             @source 2 git+https://github.com/a/b\n\
             @mirror @internal https://npm.corp/\n\
             @metadata build ci\n\
             @metadata note hello world\n\npkg\tAAAA\n",
        );
        assert_eq!(lf.sources.len(), 3);
        assert!(matches!(lf.sources[0], Source::Registry(_)));
        assert!(matches!(lf.sources[1], Source::Workspace));
        assert!(matches!(lf.sources[2], Source::Git(_)));
        assert_eq!(lf.mirrors.len(), 1);
        assert_eq!(
            lf.metadata,
            vec![
                ("build".to_string(), "ci".to_string()),
                ("note".to_string(), "hello world".to_string())
            ]
        );
    }

    #[test]
    fn parse_header_policies_trust_roots_and_rotations() {
        let pub_hex = "aa".repeat(32);
        let content = format!(
            "@source 0 https://r/\n\
             @policy allow-hook lodash postinstall\n\
             @policy deny-hook * preinstall\n\
             @policy build-env * node20\n\
             @trust-root ci-key 00 {pub_hex} 0 root\n\
             @trust-root pq-key 02 bb 1700000000 targets\n\
             @trust-root-rotation old-key new-key 1 00 {pub_hex} 0 root sig-key deadbeef\n\n"
        );
        let lf = parse_ok(&content);
        assert_eq!(lf.policies.len(), 3);
        assert_eq!(lf.policies[0].policy_type, PolicyType::AllowHook);
        assert_eq!(lf.trust_roots.len(), 2);
        assert_eq!(lf.trust_roots[0].algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(lf.trust_roots[0].role, TrustRole::Root);
        assert_eq!(lf.trust_roots[1].algorithm, SignatureAlgorithm::MlDsa65);
        assert_eq!(lf.trust_roots[1].public_key, vec![0xbb]);
        assert_eq!(lf.root_rotations.len(), 1);
        let rot = &lf.root_rotations[0];
        assert_eq!(rot.old_key_id, "old-key");
        assert_eq!(rot.new_key_id, "new-key");
        assert_eq!(rot.threshold, 1);
        assert_eq!(rot.rotation_signature, vec![0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(rot.rotation_signature_key_id, "sig-key");
    }

    #[test]
    fn parse_header_overrides_features_workspace_and_hoist() {
        let lf = parse_ok(
            "@source 0 https://r/\n\
             @override lodash ^4.17.20 -> 4.17.21\n\
             @feature serde\n\
             @feature wasm simd,threads\n\
             @workspace-root /repo\n\
             @workspace-pkg app packages/app\n\
             @hoist-boundary app -> [lodash,react]\n\
             @hoist-boundary bare ->\n\
             @hoist-boundary none\n\n",
        );
        assert_eq!(lf.overrides.len(), 1);
        assert_eq!(lf.overrides[0].name, "lodash");
        assert_eq!(lf.overrides[0].from_version, "^4.17.20");
        assert_eq!(lf.overrides[0].to_version, "4.17.21");
        assert_eq!(
            lf.features,
            vec![
                ("serde".to_string(), vec![]),
                (
                    "wasm".to_string(),
                    vec!["simd".to_string(), "threads".to_string()]
                )
            ]
        );
        assert_eq!(lf.workspace_root.as_deref(), Some("/repo"));
        assert_eq!(lf.workspace_pkgs.len(), 1);
        assert_eq!(lf.workspace_pkgs[0].manifest_path, "packages/app");
        assert_eq!(
            lf.hoist_boundaries[0].allowed_deps,
            vec!["lodash".to_string(), "react".to_string()]
        );
        assert_eq!(lf.hoist_boundaries[1].allowed_deps.len(), 0);
        assert_eq!(lf.hoist_boundaries[2].cosine, "none");
    }

    #[test]
    fn parse_header_rejects_malformed_directives() {
        let cases: Vec<(&str, &str)> = vec![
            ("@bogus 1\n\n", "Unknown directive"),
            ("@source \n\n", "Invalid source index"),
            ("@source 0\n\n", "Missing source value"),
            ("@source 1 https://r/\n\n", "out of order"),
            ("@trust-root k 03 ab 0 root\n\n", "Unknown algorithm"),
            ("@trust-root k 00 ab xx root\n\n", "Invalid expires_epoch"),
            ("@trust-root k 00 ab 0 admin\n\n", "Unknown role"),
            ("@override pkg 1.0.0\n\n", "Missing '->'"),
            ("@policy bogus pkg val\n\n", "Unknown policy type"),
            (
                "@trust-root-rotation a b 1 03 ab 0 root sk de\n\n",
                "Unknown algorithm in rotation",
            ),
            (
                "@trust-root-rotation a b 1 00 ab xx root sk de\n\n",
                "Invalid expires_epoch in rotation",
            ),
            (
                "@trust-root-rotation a b 1 00 ab 0 admin sk de\n\n",
                "Unknown role in rotation",
            ),
        ];
        for (content, expected) in cases {
            match parse_err(content) {
                Error::InvalidHeader { reason, .. } => {
                    assert!(
                        reason.contains(expected),
                        "expected '{expected}' in '{reason}'"
                    );
                }
                other => panic!("expected InvalidHeader for {content:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_header_requires_blank_separator() {
        match parse_err("@source 0 https://r/") {
            Error::InvalidHeader { reason, .. } => {
                assert_eq!(reason, "Missing empty line separator after header");
            }
            other => panic!("expected InvalidHeader, got {other:?}"),
        }
    }

    /// Builds trust roots and rotations used by the round-trip fixture.
    fn trust_directives() -> (Vec<TrustRoot>, Vec<crate::lockfile::TrustRootRotation>) {
        let trust_roots = vec![
            TrustRoot {
                key_id: "k1".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key: vec![0xaa; 32],
                expires_epoch: 0,
                role: TrustRole::Root,
            },
            TrustRoot {
                key_id: "k2".to_string(),
                algorithm: SignatureAlgorithm::MlDsa65,
                public_key: vec![0xbb; 8],
                expires_epoch: 100,
                role: TrustRole::Snapshot,
            },
        ];
        let rotations = vec![crate::lockfile::TrustRootRotation {
            old_key_id: "k1".to_string(),
            new_key_id: "k3".to_string(),
            threshold: 2,
            new_algorithm: SignatureAlgorithm::MlDsa65,
            new_public_key: vec![0xcc; 4],
            new_expires_epoch: 500,
            new_role: TrustRole::Delegation,
            rotation_signature_key_id: "k1".to_string(),
            rotation_signature: vec![0xde, 0xad],
        }];
        (trust_roots, rotations)
    }

    /// Builds a lockfile exercising every header directive.
    fn every_directive_lockfile() -> Lockfile {
        let (trust_roots, root_rotations) = trust_directives();
        Lockfile {
            sources: vec![
                Source::Registry("https://registry.npmjs.org/".to_string()),
                Source::Local("file://./vendor".to_string()),
                Source::Git("git+https://github.com/a/b".to_string()),
                Source::Workspace,
                Source::CasHttp("https://cas.example/".to_string()),
                Source::Ipfs("ipfs://Qm".to_string()),
            ],
            mirrors: vec![Mirror {
                scope: "@scope".to_string(),
                url: "https://m.corp/".to_string(),
            }],
            policies: vec![
                Policy {
                    policy_type: PolicyType::AllowHook,
                    package_pattern: "lodash".to_string(),
                    value: "postinstall".to_string(),
                },
                Policy {
                    policy_type: PolicyType::DenyHook,
                    package_pattern: "*".to_string(),
                    value: "preinstall".to_string(),
                },
                Policy {
                    policy_type: PolicyType::AllowScript,
                    package_pattern: "*".to_string(),
                    value: "build".to_string(),
                },
                Policy {
                    policy_type: PolicyType::DenyScript,
                    package_pattern: "*".to_string(),
                    value: "test".to_string(),
                },
                Policy {
                    policy_type: PolicyType::BuildEnv,
                    package_pattern: "*".to_string(),
                    value: "node20".to_string(),
                },
                Policy {
                    policy_type: PolicyType::Engine,
                    package_pattern: "app".to_string(),
                    value: ">=22".to_string(),
                },
            ],
            trust_roots,
            root_rotations,
            overrides: vec![Override {
                name: "lodash".to_string(),
                from_version: "^4".to_string(),
                ty: DepType::Runtime,
                to_version: "4.17.21".to_string(),
            }],
            features: vec![
                ("serde".to_string(), vec![]),
                ("wasm".to_string(), vec!["simd".to_string()]),
            ],
            workspace_root: Some("/repo".to_string()),
            workspace_pkgs: vec![WorkspacePkg {
                name: "app".to_string(),
                manifest_path: "packages/app".to_string(),
            }],
            hoist_boundaries: vec![
                HoistBoundary {
                    cosine: "app".to_string(),
                    allowed_deps: vec!["lodash".to_string()],
                },
                HoistBoundary {
                    cosine: "bare".to_string(),
                    allowed_deps: vec![],
                },
            ],
            metadata: vec![("build".to_string(), "ci".to_string())],
            packages: vec![],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            vex_entries: vec![],
            compat: None,
        }
    }

    #[test]
    fn format_header_round_trips_every_directive() {
        let lockfile = every_directive_lockfile();
        let formatted = format_header(&lockfile).unwrap();
        let parsed = parse_header(&formatted).unwrap().0;

        assert_eq!(parsed.sources, lockfile.sources);
        assert_eq!(parsed.mirrors, lockfile.mirrors);
        assert_eq!(parsed.policies, lockfile.policies);
        assert_eq!(parsed.trust_roots, lockfile.trust_roots);
        assert_eq!(parsed.root_rotations, lockfile.root_rotations);
        assert_eq!(parsed.overrides, lockfile.overrides);
        assert_eq!(parsed.features, lockfile.features);
        assert_eq!(parsed.workspace_root, lockfile.workspace_root);
        assert_eq!(parsed.workspace_pkgs, lockfile.workspace_pkgs);
        assert_eq!(parsed.hoist_boundaries, lockfile.hoist_boundaries);
        assert_eq!(parsed.metadata, lockfile.metadata);
    }
}
