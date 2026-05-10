use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Failed to read or write lockfile: {0}")]
    Io(#[from] io::Error),

    #[error("Line {line_number}: Missing tab delimiter between name and payload")]
    MissingDelimiter { line_number: usize },

    #[error("Line {line_number}: Invalid Base64URL payload syntax")]
    InvalidBase64 { line_number: usize },

    #[error("Line {line_number}: Unsupported payload version {version}")]
    UnknownPayloadVersion { line_number: usize, version: u8 },

    #[error("Line {line_number}: BLAKE3 payload digest mismatch")]
    PayloadDigestMismatch { line_number: usize },

    #[error("Package '{package}' references invalid dependency index {index}")]
    InvalidDependencyIndex { package: String, index: u64 },

    #[error("Package '{package}' depends on '{missing_dep}', which was not found in the lockfile")]
    MissingPackage { package: String, missing_dep: String },

    #[error("Line {line_number}: Package references undefined source index {index}")]
    MissingSource { line_number: usize, index: usize },

    #[error("Invalid header syntax at line {line_number}: {reason}")]
    InvalidHeader { line_number: usize, reason: String },

    #[error("Line {line_number}: Unsupported dependency type {type_id}")]
    UnknownDepType { line_number: usize, type_id: u8 },

    #[error("Line {line_number}: Workspace package cannot have integrity hashes")]
    InvalidWorkspaceHash { line_number: usize },

    #[error("Line {line_number}: Unsupported hash algorithm {algo_id}")]
    UnknownHashAlgorithm { line_number: usize, algo_id: u8 },

    #[error("Package '{package}' depends on '{content_id:08x}', which was not found in the lockfile")]
    MissingContentId { package: String, content_id: u64 },

    #[error("Package '{package}' requests feature index {idx}, but its feature table only has {count} entries")]
    InvalidFeatureIndex { package: String, idx: usize, count: usize },

    #[error("Requested extraction root '{content_id:08x}' does not exist in the lockfile")]
    RootContentIdMissing { content_id: u64 },

    #[error("Line {line_number}: Unsupported attestation type {type_id}")]
    UnknownAttestationType { line_number: usize, type_id: u8 },

    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    #[error("Required peer '{peer_name}' for package '{package}' has version range '{range}' but resolved version '{resolved}' does not satisfy it")]
    PeerRangeMismatch { package: String, peer_name: String, range: String, resolved: String },

    #[error("Required peer '{peer_name}' for package '{package}' has no resolution")]
    PeerRequirementUnsatisfied { package: String, peer_name: String },

    #[error("No packages match the target platform ({os}, {arch})")]
    NoPackagesForPlatform { os: String, arch: String },

    #[error("Phantom dependency: '{dep}' is used by '{consumer}' but not in its hoist boundary")]
    PhantomDependency { consumer: String, dep: String },

    #[error("Patch file for '{package}' (content ID {content_id:016x}) not found at '{path}'")]
    PatchFileMissing { package: String, content_id: u64, path: String },

    #[error("Patch file for '{package}' has mismatched digest: expected {expected}, got {actual}")]
    PatchDigestMismatch { package: String, expected: String, actual: String },

    #[error("Package '{package}' has a patch hash but no @patch directive in the lockfile header")]
    OrphanPatchHash { package: String },

    #[error("Script '{script}' for package '{package}' has mismatched digest")]
    ScriptDigestMismatch { package: String, script: String },

    #[error("Unrecognized export '{identifier}' requested from package '{package}'")]
    UnknownExport { package: String, identifier: String },

    #[error("Artifact for '{package}' (os: {os}, arch: {arch}) not found at '{path}'")]
    ArtifactMissing { package: String, os: u8, arch: u8, path: String },

    #[error("Artifact for '{package}' digest mismatch: expected {expected}, got {actual}")]
    ArtifactDigestMismatch { package: String, expected: String, actual: String },

    #[error("@digest value does not match computed BLAKE3: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("Multiple @digest directives found")]
    DuplicateDigestDirective,

    #[error("Merge conflict on package '{package_name}': {description}")]
    MergeConflict {
        package_name: String,
        description: String,
    },

    #[error("Merge conflict on source index {index}: ours has '{ours_url}', theirs has '{theirs_url}'")]
    MergeSourceConflict {
        index: usize,
        ours_url: String,
        theirs_url: String,
    },

    #[error("Merge failed with {count} conflict(s)")]
    MergeFailed { count: usize },

    #[error("Package '{package}' was removed in one branch but altered in another")]
    MergeRemoveAlterConflict { package: String },

    #[error("Override conflict on '{name}': ours has '{ours}', theirs has '{theirs}'")]
    MergeOverrideConflict {
        name: String,
        ours: String,
        theirs: String,
    },

    #[error("Lazy lockfile index corrupt at line {line_number}: {reason}")]
    LazyIndexCorrupt { line_number: usize, reason: String },

    #[error("SBOM generation failed for package '{package}': {reason}")]
    SbomGenerationFailed { package: String, reason: String },

    #[error("SBOM generation requires at least one registry source")]
    SbomNoRegistrySource,

    #[error("Provenance directive references unknown dep type {type_id}")]
    UnknownProvenanceDepType { type_id: u8 },

    #[error("Provenance directive references unknown source type {type_id}")]
    UnknownProvenanceSourceType { type_id: u8 },

    #[error("Duplicate @provenance directive for package '{package}'")]
    DuplicateProvenance { package: String },

    #[error("Advisory severity '{severity}' is not one of: critical, high, medium, low, info")]
    InvalidAdvisorySeverity { line_number: usize, severity: String },

    #[error("Policy type '{type_id}' is not recognized")]
    InvalidPolicyType { line_number: usize, type_id: String },

    #[error("Trust root key '{key_id}' has expired")]
    TrustRootExpired { key_id: String, expires_epoch: u64 },

    #[error("No trust root key with role 'root' found")]
    MissingTrustRoot,

    #[error("Trust root signature verification failed for key '{key_id}'")]
    TrustRootVerificationFailed { key_id: String },

    #[error("Mirror scope '{scope}' conflicts with existing mirror")]
    DuplicateMirrorScope { scope: String },

    #[error("Import failed: {reason}")]
    ImportFailed { format: String, reason: String },

    #[error("Hook '{hook}' denied for package '{package}' by policy")]
    HookDeniedByPolicy { package: String, hook: String },

    #[error("Engine constraint '{constraint}' not satisfied for package '{package}'")]
    EngineConstraintUnsatisfied { package: String, constraint: String },

    #[error("Trust root rotation invalid: {reason}")]
    TrustRootRotationInvalid { reason: String },

    #[error("Line {line_number}: Invalid VEX status '{status}'")]
    InvalidVexStatus { line_number: usize, status: String },

    #[error("Network error: {reason}")]
    NetworkError { reason: String },

    #[error("Configuration error: {reason}")]
    ConfigError { reason: String },
}

impl Error {
    /// Return the structured error code for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            // IO: E0000-E0099
            Error::Io(_) => "E0001",
            // Parse: E0100-E0199
            Error::MissingDelimiter { .. } => "E0101",
            Error::InvalidBase64 { .. } => "E0102",
            Error::UnknownPayloadVersion { .. } => "E0103",
            Error::InvalidHeader { .. } => "E0104",
            Error::UnknownDepType { .. } => "E0105",
            Error::UnknownHashAlgorithm { .. } => "E0106",
            Error::UnknownAttestationType { .. } => "E0107",
            Error::InvalidAdvisorySeverity { .. } => "E0108",
            Error::InvalidPolicyType { .. } => "E0109",
            Error::InvalidVexStatus { .. } => "E0110",
            Error::UnknownProvenanceDepType { .. } => "E0111",
            Error::UnknownProvenanceSourceType { .. } => "E0112",
            Error::DuplicateProvenance { .. } => "E0113",
            Error::InvalidWorkspaceHash { .. } => "E0114",
            Error::LazyIndexCorrupt { .. } => "E0115",
            // Digest: E0200-E0299
            Error::PayloadDigestMismatch { .. } => "E0201",
            Error::DigestMismatch { .. } => "E0202",
            Error::DuplicateDigestDirective => "E0203",
            Error::PatchDigestMismatch { .. } => "E0204",
            Error::ArtifactDigestMismatch { .. } => "E0205",
            Error::ScriptDigestMismatch { .. } => "E0206",
            // Signature: E0300-E0399
            Error::InvalidSignature { .. } => "E0301",
            Error::TrustRootExpired { .. } => "E0302",
            Error::MissingTrustRoot => "E0303",
            Error::TrustRootVerificationFailed { .. } => "E0304",
            Error::TrustRootRotationInvalid { .. } => "E0305",
            // Lint: E0400-E0499
            Error::PhantomDependency { .. } => "E0401",
            Error::OrphanPatchHash { .. } => "E0402",
            Error::HookDeniedByPolicy { .. } => "E0403",
            Error::EngineConstraintUnsatisfied { .. } => "E0404",
            // Audit: E0500-E0599
            Error::InvalidDependencyIndex { .. } => "E0501",
            Error::MissingPackage { .. } => "E0502",
            Error::MissingContentId { .. } => "E0503",
            Error::InvalidFeatureIndex { .. } => "E0504",
            // Merge: E0600-E0699
            Error::MergeConflict { .. } => "E0601",
            Error::MergeSourceConflict { .. } => "E0602",
            Error::MergeFailed { .. } => "E0603",
            Error::MergeRemoveAlterConflict { .. } => "E0604",
            Error::MergeOverrideConflict { .. } => "E0605",
            // Network: E0700-E0799
            Error::NetworkError { .. } => "E0701",
            Error::SbomNoRegistrySource => "E0702",
            Error::PatchFileMissing { .. } => "E0703",
            Error::ArtifactMissing { .. } => "E0704",
            Error::UnknownExport { .. } => "E0705",
            Error::RootContentIdMissing { .. } => "E0706",
            Error::NoPackagesForPlatform { .. } => "E0707",
            Error::MissingSource { .. } => "E0708",
            Error::PeerRangeMismatch { .. } => "E0709",
            Error::PeerRequirementUnsatisfied { .. } => "E0710",
            // Config: E0800-E0899
            Error::ConfigError { .. } => "E0801",
            Error::DuplicateMirrorScope { .. } => "E0802",
            Error::SbomGenerationFailed { .. } => "E0803",
            Error::ImportFailed { .. } => "E0804",
        }
    }
}
