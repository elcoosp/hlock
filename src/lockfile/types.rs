//! Core type definitions for lockfile

use crate::policy::{Advisory, LicenseEntry, Policy, TrustRoot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    Registry(String),
    Local(String),
    Git(String),
    Workspace,
    CasHttp(String),
    Ipfs(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Blake3,
}

impl HashAlgorithm {
    /// Wire-format algorithm id used in payloads and directives.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            HashAlgorithm::Sha1 => 0,
            HashAlgorithm::Sha256 => 1,
            HashAlgorithm::Sha512 => 2,
            HashAlgorithm::Blake3 => 3,
        }
    }

    /// Inverse of [`HashAlgorithm::id`]; `None` for ids outside `0..=3`.
    #[must_use]
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(HashAlgorithm::Sha1),
            1 => Some(HashAlgorithm::Sha256),
            2 => Some(HashAlgorithm::Sha512),
            3 => Some(HashAlgorithm::Blake3),
            _ => None,
        }
    }
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetOS {
    Any,
    Linux,
    MacOS,
    Windows,
    FreeBSD,
    Android,
    IOS,
    Unknown,
}

impl TargetOS {
    /// Wire-format OS id (`0xFF` for `Unknown`).
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            TargetOS::Any => 0x00,
            TargetOS::Linux => 0x01,
            TargetOS::MacOS => 0x02,
            TargetOS::Windows => 0x03,
            TargetOS::FreeBSD => 0x04,
            TargetOS::Android => 0x05,
            TargetOS::IOS => 0x06,
            TargetOS::Unknown => 0xFF,
        }
    }

    /// Inverse of [`TargetOS::id`].
    #[must_use]
    pub fn from_id(id: u8) -> Self {
        match id {
            0x00 => TargetOS::Any,
            0x01 => TargetOS::Linux,
            0x02 => TargetOS::MacOS,
            0x03 => TargetOS::Windows,
            0x04 => TargetOS::FreeBSD,
            0x05 => TargetOS::Android,
            0x06 => TargetOS::IOS,
            _ => TargetOS::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetArch {
    Any,
    X86_64,
    Aarch64,
    Wasm32,
    Arm,
    S390x,
    Ppc64le,
    Unknown,
}

impl TargetArch {
    /// Wire-format architecture id (`0xFF` for `Unknown`).
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            TargetArch::Any => 0x00,
            TargetArch::X86_64 => 0x01,
            TargetArch::Aarch64 => 0x02,
            TargetArch::Wasm32 => 0x03,
            TargetArch::Arm => 0x04,
            TargetArch::S390x => 0x05,
            TargetArch::Ppc64le => 0x06,
            TargetArch::Unknown => 0xFF,
        }
    }

    /// Inverse of [`TargetArch::id`].
    #[must_use]
    pub fn from_id(id: u8) -> Self {
        match id {
            0x00 => TargetArch::Any,
            0x01 => TargetArch::X86_64,
            0x02 => TargetArch::Aarch64,
            0x03 => TargetArch::Wasm32,
            0x04 => TargetArch::Arm,
            0x05 => TargetArch::S390x,
            0x06 => TargetArch::Ppc64le,
            _ => TargetArch::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DepType {
    Runtime,
    Dev,
    Peer,
    Optional,
    OptionalTarget(TargetOS, TargetArch),
}

impl DepType {
    /// Wire-format dependency-type id.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            DepType::Runtime => 0x00,
            DepType::Dev => 0x01,
            DepType::Peer => 0x02,
            DepType::Optional => 0x03,
            DepType::OptionalTarget(_, _) => 0x04,
        }
    }

    /// Inverse of [`DepType::id`]; id `0x04` decodes to `OptionalTarget(Any, Any)`.
    #[must_use]
    pub fn from_id(id: u8) -> Self {
        match id {
            0x01 => DepType::Dev,
            0x02 => DepType::Peer,
            0x03 => DepType::Optional,
            0x04 => DepType::OptionalTarget(TargetOS::Any, TargetArch::Any),
            _ => DepType::Runtime,
        }
    }

    /// Human-readable name (`"runtime"`, `"dev"`, `"peer"`, `"optional"`,
    /// `"optional-target"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            DepType::Runtime => "runtime",
            DepType::Dev => "dev",
            DepType::Peer => "peer",
            DepType::Optional => "optional",
            DepType::OptionalTarget(_, _) => "optional-target",
        }
    }
}

impl std::str::FromStr for DepType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "runtime" => Ok(DepType::Runtime),
            "dev" => Ok(DepType::Dev),
            "peer" => Ok(DepType::Peer),
            "optional" => Ok(DepType::Optional),
            "optional-target" => Ok(DepType::OptionalTarget(TargetOS::Any, TargetArch::Any)),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dependency {
    pub name: String,
    pub dep_type: DepType,
    pub requested_features: Vec<String>,
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

impl Package {
    /// Renders `name@major.minor.patch`, the identity string content ids are
    /// derived from.
    #[must_use]
    pub fn version_string(&self) -> String {
        format!("{}@{}.{}.{}", self.name, self.major, self.minor, self.patch)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageChange {
    Added(Box<Package>),
    Removed(Box<Package>),
    Altered(Box<Package>, Box<Package>),
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

#[derive(Debug, Clone, Default)]
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
    pub advisories: Vec<Advisory>,
    pub licenses: Vec<LicenseEntry>,
    pub policies: Vec<Policy>,
    pub trust_roots: Vec<TrustRoot>,
    pub mirrors: Vec<Mirror>,
    pub root_rotations: Vec<TrustRootRotation>,
    pub vex_entries: Vec<VexEntry>,
    pub compat: Option<String>,
}

impl Lockfile {
    /// Finds a package by exact name.
    #[must_use]
    pub fn find_package(&self, name: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.name == name)
    }

    /// Builds a name-to-index map over [`Lockfile::packages`].
    ///
    /// Callers that need many lookups (graph walks, tree rendering) should
    /// build this once and query it instead of scanning the package list per
    /// lookup.
    #[must_use]
    pub fn package_index(&self) -> std::collections::HashMap<&str, usize> {
        self.packages
            .iter()
            .enumerate()
            .map(|(i, p)| (p.name.as_str(), i))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    pub scope: String,
    pub url: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

impl std::str::FromStr for VexStatus {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "not_affected" => Ok(VexStatus::NotAffected),
            "affected" => Ok(VexStatus::Affected),
            "fixed" => Ok(VexStatus::Fixed),
            "under_investigation" => Ok(VexStatus::UnderInvestigation),
            _ => Err(()),
        }
    }
}

impl VexStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            VexStatus::NotAffected => "not_affected",
            VexStatus::Affected => "affected",
            VexStatus::Fixed => "fixed",
            VexStatus::UnderInvestigation => "under_investigation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VexEntry {
    pub package: String,
    pub advisory_id: String,
    pub status: VexStatus,
    pub justification: String,
    pub impact_statement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRootRotation {
    pub old_key_id: String,
    pub new_key_id: String,
    pub threshold: u8,
    pub new_algorithm: crate::signature::SignatureAlgorithm,
    pub new_public_key: Vec<u8>,
    pub new_expires_epoch: u64,
    pub new_role: crate::policy::TrustRole,
    pub rotation_signature_key_id: String,
    pub rotation_signature: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AdvisorySeverity, PolicyType, TrustRole};

    #[test]
    fn hash_algorithm_ids_round_trip() {
        for (algo, id) in [
            (HashAlgorithm::Sha1, 0u8),
            (HashAlgorithm::Sha256, 1),
            (HashAlgorithm::Sha512, 2),
            (HashAlgorithm::Blake3, 3),
        ] {
            assert_eq!(algo.id(), id);
            assert_eq!(HashAlgorithm::from_id(id), Some(algo));
        }
        assert_eq!(HashAlgorithm::from_id(4), None);
        assert_eq!(HashAlgorithm::from_id(255), None);
    }

    #[test]
    fn target_os_ids_round_trip_including_unknown() {
        for (os, id) in [
            (TargetOS::Any, 0x00u8),
            (TargetOS::Linux, 0x01),
            (TargetOS::MacOS, 0x02),
            (TargetOS::Windows, 0x03),
            (TargetOS::FreeBSD, 0x04),
            (TargetOS::Android, 0x05),
            (TargetOS::IOS, 0x06),
        ] {
            assert_eq!(os.id(), id);
            assert_eq!(TargetOS::from_id(id), os);
        }
        assert_eq!(TargetOS::Unknown.id(), 0xFF);
        assert_eq!(TargetOS::from_id(0x07), TargetOS::Unknown);
        assert_eq!(TargetOS::from_id(0xFF), TargetOS::Unknown);
    }

    #[test]
    fn target_arch_ids_round_trip_including_unknown() {
        for (arch, id) in [
            (TargetArch::Any, 0x00u8),
            (TargetArch::X86_64, 0x01),
            (TargetArch::Aarch64, 0x02),
            (TargetArch::Wasm32, 0x03),
            (TargetArch::Arm, 0x04),
            (TargetArch::S390x, 0x05),
            (TargetArch::Ppc64le, 0x06),
        ] {
            assert_eq!(arch.id(), id);
            assert_eq!(TargetArch::from_id(id), arch);
        }
        assert_eq!(TargetArch::Unknown.id(), 0xFF);
        assert_eq!(TargetArch::from_id(0x99), TargetArch::Unknown);
    }

    #[test]
    fn dep_type_ids_and_names_round_trip() {
        for (ty, id, name) in [
            (DepType::Runtime, 0x00u8, "runtime"),
            (DepType::Dev, 0x01, "dev"),
            (DepType::Peer, 0x02, "peer"),
            (DepType::Optional, 0x03, "optional"),
            (
                DepType::OptionalTarget(TargetOS::Linux, TargetArch::X86_64),
                0x04,
                "optional-target",
            ),
        ] {
            assert_eq!(ty.id(), id, "{name}");
            assert_eq!(ty.as_str(), name);
            assert_eq!(
                name.parse::<DepType>().unwrap(),
                DepType::from_id(id),
                "{name}"
            );
        }
        // OptionalTarget decodes to the (Any, Any) carrier regardless of wire os/arch.
        assert_eq!(
            DepType::from_id(0x04),
            DepType::OptionalTarget(TargetOS::Any, TargetArch::Any)
        );
        // Unknown ids fall back to Runtime, both by id and by string.
        assert_eq!(DepType::from_id(0x05), DepType::Runtime);
        assert_eq!(DepType::from_id(0xFF), DepType::Runtime);
        assert!("bogus".parse::<DepType>().is_err());
    }

    #[test]
    fn package_version_string_formatting() {
        let pkg = Package {
            name: "lodash".to_string(),
            major: 4,
            minor: 17,
            patch: 21,
            ..Package::default()
        };
        assert_eq!(pkg.version_string(), "lodash@4.17.21");
        assert_eq!(Package::default().version_string(), "@0.0.0");
    }

    #[test]
    fn lockfile_find_package_and_package_index() {
        let lf = Lockfile {
            packages: vec![
                Package {
                    name: "alpha".to_string(),
                    major: 1,
                    ..Package::default()
                },
                Package {
                    name: "beta".to_string(),
                    major: 2,
                    ..Package::default()
                },
            ],
            ..Lockfile::default()
        };
        assert_eq!(lf.find_package("beta").map(|p| p.major), Some(2));
        assert!(lf.find_package("gamma").is_none());
        let index = lf.package_index();
        assert_eq!(index.get("alpha"), Some(&0));
        assert_eq!(index.get("beta"), Some(&1));
        assert!(!index.contains_key("gamma"));
    }

    #[test]
    fn vex_status_from_str_round_trip() {
        for (status, name) in [
            (VexStatus::NotAffected, "not_affected"),
            (VexStatus::Affected, "affected"),
            (VexStatus::Fixed, "fixed"),
            (VexStatus::UnderInvestigation, "under_investigation"),
        ] {
            assert_eq!(name.parse::<VexStatus>().unwrap(), status);
            assert_eq!(status.as_str(), name);
        }
        assert!("unspecified".parse::<VexStatus>().is_err());
    }

    #[test]
    fn advisory_severity_parsing_and_ordinals() {
        for (name, ordinal) in [
            ("critical", 0u8),
            ("high", 1),
            ("medium", 2),
            ("low", 3),
            ("info", 4),
        ] {
            let sev: AdvisorySeverity = name.parse().unwrap();
            assert_eq!(sev.ordinal(), ordinal);
        }
        assert!("fatal".parse::<AdvisorySeverity>().is_err());
    }

    #[test]
    fn policy_type_parsing_round_trip() {
        for name in [
            "allow-hook",
            "deny-hook",
            "allow-script",
            "deny-script",
            "build-env",
            "engine",
        ] {
            let ty: PolicyType = name.parse().unwrap();
            assert_eq!(ty.as_str(), name);
        }
        assert!("hook".parse::<PolicyType>().is_err());
    }

    #[test]
    fn trust_role_parsing_round_trip() {
        for name in ["root", "targets", "snapshot", "delegation"] {
            let role: TrustRole = name.parse().unwrap();
            assert_eq!(role.as_str(), name);
        }
        assert!("admin".parse::<TrustRole>().is_err());
    }

    #[test]
    fn struct_equality_and_clone_smoke() {
        let pkg = Package {
            name: "x".to_string(),
            major: 1,
            ..Package::default()
        };
        let clone = pkg.clone();
        assert_eq!(pkg, clone);
        let hb = HoistBoundary {
            cosine: "app".to_string(),
            allowed_deps: vec!["lib".to_string()],
        };
        assert_eq!(hb.clone().allowed_deps.len(), 1);
        let mirror = Mirror {
            scope: "*".to_string(),
            url: "https://m".to_string(),
        };
        assert_eq!(mirror.clone().scope, "*");
        assert_ne!(DiffFormat::Text, DiffFormat::Json);
        assert_ne!(
            PackageChange::Added(Box::default()),
            PackageChange::Removed(Box::default())
        );
        let patch = PatchDirective {
            content_id: 1,
            patch_type: 2,
            relative_path: "p".to_string(),
        };
        assert_eq!(patch.clone().patch_type, 2);
        let art = ArtifactDirective {
            content_id: 1,
            os_id: 2,
            arch_id: 3,
            relative_path: "a".to_string(),
        };
        assert_eq!(art.clone().arch_id, 3);
        let peer = PeerResolution {
            peer_name: "p".to_string(),
            satisfied_by_content_id: 9,
            is_hoisted_to_root: true,
        };
        assert!(peer.clone().is_hoisted_to_root);
        let ventry = VexEntry {
            package: "p".to_string(),
            advisory_id: "CVE-1".to_string(),
            status: VexStatus::Fixed,
            justification: "j".to_string(),
            impact_statement: "i".to_string(),
        };
        assert_eq!(ventry.clone().status, VexStatus::Fixed);
        let rot = TrustRootRotation {
            old_key_id: "old".to_string(),
            new_key_id: "new".to_string(),
            threshold: 1,
            new_algorithm: crate::signature::SignatureAlgorithm::Ed25519,
            new_public_key: vec![0; 32],
            new_expires_epoch: 0,
            new_role: TrustRole::Root,
            rotation_signature_key_id: "old".to_string(),
            rotation_signature: vec![1, 2],
        };
        assert_eq!(rot.clone().threshold, 1);
    }
}
