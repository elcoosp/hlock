pub mod base64url;
pub mod error;
pub mod lazy;
pub mod lint;
pub mod fnv;
pub mod graph;
pub mod lockfile;
pub mod payload;
pub mod merge;
pub mod policy;
pub mod provenance;
pub mod sbom;
pub mod signature;
pub mod varint;

pub use error::Error;
pub use lockfile::{
    serialize, deserialize, read_lockfile, write_lockfile,
    serialize_diff, validate_digest, whole_lockfile_digest,
    validate_hoist_boundary, validate_patches, validate_scripts,
};

// Re-export types from lockfile::types
pub use lockfile::types::{
    Attestation, DepType, Dependency, DiffFormat, HashAlgorithm, HoistBoundary,
    IntegrityHash, Lockfile, LockfileDiff, Override, Package, PackageChange,
    PatchDirective, PeerResolution, PeerRequirement, PlatformTag,
    Artifact, Export, HookHash, Source, SlsaPredicate, TargetArch, TargetOS, WorkspacePkg,
};

pub use graph::{
    diff_lockfiles, extract_subgraph, extract_subgraph_platform,
    topological_sort, dependents_of, transitive_deps,
    leaf_packages, detect_cycle, would_create_cycle,
    runtime_deps, dev_deps, runtime_dependents_of, dev_dependents_of,
    has_dep_path, dep_count,
};
pub use payload::{
    DepPayload, pack_payload, unpack_payload, PeerReqPayload, PlatformTagPayload,
    HookHashPayload, PayloadData,
};
pub use signature::{sign_lockfile, verify_signature, SignatureAlgorithm, SignatureDirective};
pub use merge::{MergeConflict, MergeResult, ConflictStrategy, merge_lockfiles};
pub use provenance::{ProvenanceSourceType, ResolutionProvenance};
pub use policy::{
    Advisory, AdvisorySeverity, AuditReport, DedupOpportunity, LicenseEntry,
    Mirror, Policy, PolicyDecision, PolicyReport, PolicyType, PolicyViolation,
    TrustRole, TrustRoot, TrustVerification,
};
pub use sbom::{SbomFormat, generate_sbom};
pub use lazy::{LazyLockfile, LockfileHeader};
pub use lint::{LintFinding, LintReport, LintRule, LintSeverity, lint_default};
