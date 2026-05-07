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

    #[error("Line {line_number}: CRC32 integrity check failed")]
    IntegrityCheckFailed { line_number: usize },

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
}
