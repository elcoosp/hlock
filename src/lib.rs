pub mod base64url;
pub mod cid;
pub mod config;
pub mod error;
pub mod explain;
pub mod fix;
pub mod graph;
pub mod hex;
pub mod import;
pub mod lazy;
pub mod lint;
pub mod lockfile;
pub mod merge;
pub mod osv;
pub mod outdated;
pub mod payload;
pub mod policy;
pub mod provenance;
pub mod sbom;
pub mod scorecard;
pub mod signature;
pub mod sigstore;
pub mod varint;

pub use error::Error;
pub use lockfile::{
    deserialize, read_lockfile, serialize, serialize_diff, validate_digest,
    validate_hoist_boundary, validate_patches, validate_scripts, whole_lockfile_digest,
    write_lockfile,
};

// Re-export types from lockfile::types
pub use lockfile::types::{
    Artifact, Attestation, DepType, Dependency, DiffFormat, Export, HashAlgorithm, HoistBoundary,
    HookHash, IntegrityHash, Lockfile, LockfileDiff, Mirror, Override, Package, PackageChange,
    PatchDirective, PeerRequirement, PeerResolution, PlatformTag, SlsaPredicate, Source,
    TargetArch, TargetOS, WorkspacePkg,
};

pub use config::HlockConfig;
pub use explain::{Explanation, ExplanationKind, explain_advisory, explain_rule};
pub use fix::{FixEntry, FixPlan, FixType, apply_fixes, build_fix_plan};
pub use graph::{EdgeFilter, Graph, Reachability, diff_lockfiles};
pub use import::{ImportFormat, ImportResult, import_npm, import_yarn};
pub use lazy::{LazyLockfile, LockfileHeader};
pub use lint::{
    LintFinding, LintReport, LintRule, LintSeverity, RuleCategory, RuleMetadata, lint_default,
    rule_metadata_by_name, rule_registry,
};
pub use lockfile::types::{TrustRootRotation, VexEntry, VexStatus};
pub use merge::{ConflictStrategy, MergeConflict, MergeResult, merge_lockfiles};
pub use osv::{OsvResponse, OsvVulnerability, find_fixed_version, osv_severity, query_osv};
pub use outdated::{
    OutdatedInfo, SourceType as OutdatedSourceType, UpdateType, check_outdated, compare_versions,
};
pub use payload::{
    DepPayload, HookHashPayload, PayloadData, PeerReqPayload, PlatformTagPayload, pack_payload,
    unpack_payload,
};
pub use policy::{
    Advisory, AdvisorySeverity, AuditReport, DedupOpportunity, LicenseEntry, Policy,
    PolicyDecision, PolicyReport, PolicyType, PolicyViolation, TrustRole, TrustRoot,
    TrustVerification,
};
pub use provenance::{ProvenanceSourceType, ResolutionProvenance};
pub use sbom::{SbomFormat, generate_sbom};
pub use scorecard::{ScorecardCheck, ScorecardResult, fetch_scorecard, format_scorecard};
pub use signature::{SignatureAlgorithm, SignatureDirective, sign_lockfile, verify_signature};
pub use sigstore::verify_sigstore;
