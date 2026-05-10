pub mod base64url;
pub mod error;
pub mod lazy;
pub mod lint;
pub mod fnv;
#[allow(clippy::collapsible_if, clippy::needless_range_loop, clippy::unused_enumerate_index)]
pub mod graph;
pub mod lockfile;
pub mod payload;
pub mod merge;
pub mod policy;
pub mod provenance;
pub mod sbom;
pub mod signature;
pub mod varint;
pub mod config;
pub mod osv;
pub mod outdated;
pub mod import;
pub mod fix;
pub mod explain;
pub mod scorecard;
pub mod sigstore;

pub use error::Error;
pub use lockfile::{
    serialize, deserialize, read_lockfile, write_lockfile,
    serialize_diff, validate_digest, whole_lockfile_digest,
    validate_hoist_boundary, validate_patches, validate_scripts,
};

// Re-export types from lockfile::types
pub use lockfile::types::{Mirror, 
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
    has_dep_path, dep_count, all_paths_to_roots,
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
    Policy, PolicyDecision, PolicyReport, PolicyType, PolicyViolation,
    TrustRole, TrustRoot, TrustVerification,
};
pub use sbom::{SbomFormat, generate_sbom};
pub use lazy::{LazyLockfile, LockfileHeader};
pub use lockfile::types::{TrustRootRotation, VexEntry, VexStatus};
pub use lint::{LintFinding, LintReport, LintRule, LintSeverity, lint_default};
pub use config::HlockConfig;
pub use osv::{OsvResponse, OsvVulnerability, query_osv, find_fixed_version, osv_severity};
pub use outdated::{OutdatedInfo, UpdateType, SourceType as OutdatedSourceType, check_outdated, compare_versions};
pub use import::{ImportFormat, ImportResult, import_yarn, import_npm};
pub use fix::{FixPlan, FixEntry, FixType, build_fix_plan, apply_fixes};
pub use explain::{Explanation, ExplanationKind, explain_rule, explain_advisory};
pub use scorecard::{ScorecardResult, ScorecardCheck, fetch_scorecard, format_scorecard};
pub use sigstore::verify_sigstore;
