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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha512,
    Blake3,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetOS {
    Any, Linux, MacOS, Windows, FreeBSD, Android, IOS, Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetArch {
    Any, X86_64, Aarch64, Wasm32, Arm, S390x, Ppc64le, Unknown,
}

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

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
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

impl VexStatus {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "not_affected" => Some(VexStatus::NotAffected),
            "affected" => Some(VexStatus::Affected),
            "fixed" => Some(VexStatus::Fixed),
            "under_investigation" => Some(VexStatus::UnderInvestigation),
            _ => None,
        }
    }

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
