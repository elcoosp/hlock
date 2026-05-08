use crate::error::Error;
use crate::lockfile::{Attestation, DepType, HashAlgorithm, Lockfile, Source};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SbomFormat {
    SpdxJson,
    CycloneDxJson,
}

pub fn generate_sbom(
    lockfile: &Lockfile,
    format: SbomFormat,
    namespace: &str,
) -> Result<String, Error> {
    match format {
        SbomFormat::SpdxJson => generate_spdx(lockfile, namespace),
        SbomFormat::CycloneDxJson => generate_cyclonedx(lockfile, namespace),
    }
}

fn hash_algo_spdx(algo: &HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Sha1 => "SHA1",
        HashAlgorithm::Sha256 => "SHA256",
        HashAlgorithm::Sha512 => "SHA512",
        HashAlgorithm::Blake3 => "blake3",
    }
}

fn hash_algo_cyclonedx(algo: &HashAlgorithm) -> &'static str {
    match algo {
        HashAlgorithm::Sha1 => "SHA-1",
        HashAlgorithm::Sha256 => "SHA-256",
        HashAlgorithm::Sha512 => "SHA-512",
        HashAlgorithm::Blake3 => "BLAKE3",
    }
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{:02x}", b)).collect()
}

fn purl(name: &str, version: &str) -> String {
    let encoded_name = if name.starts_with('@') {
        name.replace('@', "%40")
    } else {
        name.to_string()
    };
    format!("pkg:npm/{}@{}", encoded_name, version)
}

fn version_string(major: u64, minor: u64, patch: u64) -> String {
    format!("{}.{}.{}", major, minor, patch)
}

fn download_location(source: &Source, name: &str, version: &str) -> String {
    match source {
        Source::Registry(url) => {
            let base = if url.ends_with('/') { url.clone() } else { format!("{}/", url) };
            format!("{}{}/-/{}-{}.tgz", base, name, name, version)
        }
        Source::Git(url) => format!("git+{}", url),
        Source::Local(path) => format!("file://{}", path),
        Source::Workspace => "NOASSERTION".to_string(),
        Source::CasHttp(url) => {
            let base = if url.ends_with('/') { url.clone() } else { format!("{}/", url) };
            format!("{}{}/{}", base, name, version)
        }
        Source::Ipfs(cid) => format!("ipfs://{}", cid),
    }
}

fn generate_spdx(lockfile: &Lockfile, namespace: &str) -> Result<String, Error> {
    let mut packages_json = Vec::new();
    let mut relationships_json = Vec::new();

    for pkg in &lockfile.packages {
        let ver = version_string(pkg.major, pkg.minor, pkg.patch);
        let spdx_id = format!("SPDXRef-Package-{}-{}", pkg.name, ver);
        let source = lockfile.sources.get(pkg.source_idx);

        let mut hashes_obj = serde_json::Map::new();
        for h in &pkg.hashes {
            hashes_obj.insert(
                hash_algo_spdx(&h.algo).to_string(),
                serde_json::Value::String(hex_digest(&h.digest)),
            );
        }

        let dl = source.map_or("NOASSERTION".to_string(), |s| download_location(s, &pkg.name, &ver));
        let purl_str = purl(&pkg.name, &ver);

        let mut pkg_obj = serde_json::json!({
            "SPDXID": spdx_id,
            "name": pkg.name,
            "versionInfo": ver,
            "downloadLocation": dl,
            "externalRefs": [{
                "referenceCategory": "PACKAGE_MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl_str,
            }],
        });

        if !hashes_obj.is_empty() {
            pkg_obj.as_object_mut().unwrap().insert("hashes".to_string(), serde_json::Value::Object(hashes_obj));
        }

        if pkg.hashes.is_empty() {
            pkg_obj.as_object_mut().unwrap().insert("filesAnalyzed".to_string(), serde_json::Value::Bool(false));
        }

        for h in &pkg.hashes {
            if let Attestation::InlineSlsa(pred) = &h.attestation {
                pkg_obj.as_object_mut().unwrap().insert(
                    "originator".to_string(),
                    serde_json::Value::String(format!("Organization: {}", pred.builder)),
                );
            }
        }

        packages_json.push(pkg_obj);

        for dep in &pkg.dependencies {
            if matches!(dep.dep_type, DepType::Runtime | DepType::Peer) {
                if let Some(dep_pkg) = lockfile.packages.iter().find(|p| p.name == dep.name) {
                    let dep_ver = version_string(dep_pkg.major, dep_pkg.minor, dep_pkg.patch);
                    let dep_spdx_id = format!("SPDXRef-Package-{}-{}", dep_pkg.name, dep_ver);
                    relationships_json.push(serde_json::json!({
                        "spdxElementId": spdx_id,
                        "relationshipType": "DEPENDS_ON",
                        "relatedSpdxElement": dep_spdx_id,
                    }));
                }
            }
        }
    }

    let doc = serde_json::json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": namespace,
        "documentNamespace": namespace,
        "creationInfo": {
            "creators": ["Tool: hlock-0.14.0"]
        },
        "packages": packages_json,
        "relationships": relationships_json,
    });

    serde_json::to_string_pretty(&doc).map_err(|e| Error::SbomGenerationFailed {
        package: String::new(),
        reason: e.to_string(),
    })
}

fn generate_cyclonedx(lockfile: &Lockfile, _namespace: &str) -> Result<String, Error> {
    let mut components = Vec::new();
    let mut dependencies = Vec::new();

    for pkg in &lockfile.packages {
        let ver = version_string(pkg.major, pkg.minor, pkg.patch);
        let purl_str = purl(&pkg.name, &ver);

        let mut hashes_arr = Vec::new();
        for h in &pkg.hashes {
            hashes_arr.push(serde_json::json!({
                "alg": hash_algo_cyclonedx(&h.algo),
                "content": hex_digest(&h.digest),
            }));
        }

        let mut comp = serde_json::json!({
            "type": "library",
            "name": pkg.name,
            "version": ver,
            "purl": purl_str,
        });

        if !hashes_arr.is_empty() {
            comp.as_object_mut().unwrap().insert("hashes".to_string(), serde_json::Value::Array(hashes_arr));
        }

        components.push(comp);

        let mut dep_refs = Vec::new();
        for dep in &pkg.dependencies {
            if matches!(dep.dep_type, DepType::Runtime | DepType::Peer) {
                if let Some(dep_pkg) = lockfile.packages.iter().find(|p| p.name == dep.name) {
                    let dep_ver = version_string(dep_pkg.major, dep_pkg.minor, dep_pkg.patch);
                    dep_refs.push(purl(&dep_pkg.name, &dep_ver));
                }
            }
        }
        if !dep_refs.is_empty() {
            dependencies.push(serde_json::json!({
                "ref": purl_str,
                "dependsOn": dep_refs,
            }));
        }
    }

    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": [{ "name": "hlock", "version": "0.14.0" }]
        },
        "components": components,
        "dependencies": dependencies,
    });

    serde_json::to_string_pretty(&doc).map_err(|e| Error::SbomGenerationFailed {
        package: String::new(),
        reason: e.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::{IntegrityHash, Package};

    fn sample_lockfile() -> Lockfile {
        Lockfile {
            sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![
                Package {
                    name: "app".to_string(),
                    source_idx: 0,
                    major: 1, minor: 0, patch: 0,
                    dependencies: vec![crate::lockfile::Dependency {
                        name: "lodash".to_string(),
                        dep_type: DepType::Runtime,
                        requested_features: vec![],
                    }],
                    ..Package::default()
                },
                Package {
                    name: "lodash".to_string(),
                    source_idx: 0,
                    major: 4, minor: 17, patch: 21,
                    hashes: vec![IntegrityHash {
                        algo: HashAlgorithm::Sha256,
                        digest: vec![42u8; 32],
                        attestation: Attestation::None,
                    }],
                    ..Package::default()
                },
            ],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            compat: None,
        }
    }

    #[test]
    fn test_sbom_spdx_basic() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["spdxVersion"], "SPDX-2.3");
        assert_eq!(parsed["name"], "test-ns");
        let pkgs = parsed["packages"].as_array().unwrap();
        assert_eq!(pkgs.len(), 2);
    }

    #[test]
    fn test_sbom_spdx_hashes() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let lodash_pkg = parsed["packages"].as_array().unwrap().iter()
            .find(|p| p["name"] == "lodash").unwrap();
        assert!(lodash_pkg["hashes"]["SHA256"].is_string());
    }

    #[test]
    fn test_sbom_spdx_relationships() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let rels = parsed["relationships"].as_array().unwrap();
        assert_eq!(rels.len(), 1);
        assert_eq!(rels[0]["relationshipType"], "DEPENDS_ON");
    }

    #[test]
    fn test_sbom_spdx_excludes_dev() {
        let mut lf = sample_lockfile();
        lf.packages.push(Package {
            name: "jest".to_string(),
            source_idx: 0,
            major: 29, minor: 0, patch: 0,
            dependencies: vec![],
            ..Package::default()
        });
        lf.packages[0].dependencies.push(crate::lockfile::Dependency {
            name: "jest".to_string(),
            dep_type: DepType::Dev,
            requested_features: vec![],
        });
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let rels = parsed["relationships"].as_array().unwrap();
        let jest_rels: Vec<_> = rels.iter()
            .filter(|r| r["relatedSpdxElement"].as_str().unwrap_or("").contains("jest"))
            .collect();
        assert!(jest_rels.is_empty());
    }

    #[test]
    fn test_sbom_cyclonedx_basic() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::CycloneDxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.5");
        let comps = parsed["components"].as_array().unwrap();
        assert_eq!(comps.len(), 2);
    }

    #[test]
    fn test_sbom_cyclonedx_hashes() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::CycloneDxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let lodash = parsed["components"].as_array().unwrap().iter()
            .find(|c| c["name"] == "lodash").unwrap();
        assert_eq!(lodash["hashes"][0]["alg"], "SHA-256");
    }

    #[test]
    fn test_sbom_workspace_no_hashes() {
        let lf = Lockfile {
            sources: vec![Source::Workspace],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![Package {
                name: "my-app".to_string(),
                source_idx: 0,
                major: 1, minor: 0, patch: 0,
                ..Package::default()
            }],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            compat: None,
        };
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let my_app = parsed["packages"].as_array().unwrap().iter()
            .find(|p| p["name"] == "my-app").unwrap();
        assert_eq!(my_app["filesAnalyzed"], false);
    }

    #[test]
    fn test_sbom_purl_scoped() {
        let lf = Lockfile {
            sources: vec![Source::Registry("https://r.com/".to_string())],
            overrides: vec![],
            features: vec![],
            metadata: vec![],
            workspace_root: None,
            workspace_pkgs: vec![],
            hoist_boundaries: vec![],
            packages: vec![Package {
                name: "@babel/core".to_string(),
                source_idx: 0,
                major: 7, minor: 0, patch: 0,
                ..Package::default()
            }],
            artifacts: vec![],
            patches: vec![],
            provenance: vec![],
            advisories: vec![],
            licenses: vec![],
            policies: vec![],
            trust_roots: vec![],
            mirrors: vec![],
            compat: None,
        };
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let pkg = &parsed["packages"][0];
        let purl_val = pkg["externalRefs"][0]["referenceLocator"].as_str().unwrap();
        assert!(purl_val.contains("%40babel"));
    }

    #[test]
    fn test_sbom_download_location() {
        let lf = sample_lockfile();
        let json_str = generate_sbom(&lf, SbomFormat::SpdxJson, "test-ns").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let lodash = parsed["packages"].as_array().unwrap().iter()
            .find(|p| p["name"] == "lodash").unwrap();
        let dl = lodash["downloadLocation"].as_str().unwrap();
        assert!(dl.starts_with("https://registry.npmjs.org/"));
        assert!(dl.contains("lodash"));
        assert!(dl.ends_with(".tgz"));
    }
}
