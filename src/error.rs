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
    MissingPackage {
        package: String,
        missing_dep: String,
    },

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

    #[error(
        "Package '{package}' depends on '{content_id:08x}', which was not found in the lockfile"
    )]
    MissingContentId { package: String, content_id: u64 },

    #[error(
        "Package '{package}' requests feature index {idx}, but its feature table only has {count} entries"
    )]
    InvalidFeatureIndex {
        package: String,
        idx: usize,
        count: usize,
    },

    #[error("Requested extraction root '{content_id:08x}' does not exist in the lockfile")]
    RootContentIdMissing { content_id: u64 },

    #[error("Line {line_number}: Unsupported attestation type {type_id}")]
    UnknownAttestationType { line_number: usize, type_id: u8 },

    #[error("Invalid signature: {reason}")]
    InvalidSignature { reason: String },

    #[error(
        "Required peer '{peer_name}' for package '{package}' has version range '{range}' but resolved version '{resolved}' does not satisfy it"
    )]
    PeerRangeMismatch {
        package: String,
        peer_name: String,
        range: String,
        resolved: String,
    },

    #[error("Required peer '{peer_name}' for package '{package}' has no resolution")]
    PeerRequirementUnsatisfied { package: String, peer_name: String },

    #[error("No packages match the target platform ({os}, {arch})")]
    NoPackagesForPlatform { os: String, arch: String },

    #[error("Phantom dependency: '{dep}' is used by '{consumer}' but not in its hoist boundary")]
    PhantomDependency { consumer: String, dep: String },

    #[error("Patch file for '{package}' (content ID {content_id:016x}) not found at '{path}'")]
    PatchFileMissing {
        package: String,
        content_id: u64,
        path: String,
    },

    #[error("Patch file for '{package}' has mismatched digest: expected {expected}, got {actual}")]
    PatchDigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },

    #[error("Package '{package}' has a patch hash but no @patch directive in the lockfile header")]
    OrphanPatchHash { package: String },

    #[error("Script '{script}' for package '{package}' has mismatched digest")]
    ScriptDigestMismatch { package: String, script: String },

    #[error("Unrecognized export '{identifier}' requested from package '{package}'")]
    UnknownExport { package: String, identifier: String },

    #[error("Artifact for '{package}' (os: {os}, arch: {arch}) not found at '{path}'")]
    ArtifactMissing {
        package: String,
        os: u8,
        arch: u8,
        path: String,
    },

    #[error("Artifact for '{package}' digest mismatch: expected {expected}, got {actual}")]
    ArtifactDigestMismatch {
        package: String,
        expected: String,
        actual: String,
    },

    #[error("@digest value does not match computed BLAKE3: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },

    #[error("Multiple @digest directives found")]
    DuplicateDigestDirective,

    #[error("Merge conflict on package '{package_name}': {description}")]
    MergeConflict {
        package_name: String,
        description: String,
    },

    #[error(
        "Merge conflict on source index {index}: ours has '{ours_url}', theirs has '{theirs_url}'"
    )]
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
    InvalidAdvisorySeverity {
        line_number: usize,
        severity: String,
    },

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
    #[must_use]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<Error> {
        let mut variants = payload_variants();
        variants.extend(integrity_variants());
        variants.extend(merge_variants());
        variants.extend(policy_variants());
        variants
    }

    fn payload_variants() -> Vec<Error> {
        vec![
            Error::Io(io::Error::other("boom")),
            Error::MissingDelimiter { line_number: 1 },
            Error::InvalidBase64 { line_number: 2 },
            Error::UnknownPayloadVersion {
                line_number: 3,
                version: 9,
            },
            Error::PayloadDigestMismatch { line_number: 4 },
            Error::InvalidDependencyIndex {
                package: "p".into(),
                index: 7,
            },
            Error::MissingPackage {
                package: "p".into(),
                missing_dep: "q".into(),
            },
            Error::MissingSource {
                line_number: 5,
                index: 3,
            },
            Error::InvalidHeader {
                line_number: 6,
                reason: "bad".into(),
            },
            Error::UnknownDepType {
                line_number: 7,
                type_id: 9,
            },
            Error::InvalidWorkspaceHash { line_number: 8 },
            Error::UnknownHashAlgorithm {
                line_number: 9,
                algo_id: 42,
            },
            Error::InvalidFeatureIndex {
                package: "p".into(),
                idx: 2,
                count: 1,
            },
            Error::RootContentIdMissing { content_id: 0xcafe },
            Error::UnknownAttestationType {
                line_number: 10,
                type_id: 8,
            },
        ]
    }

    fn integrity_variants() -> Vec<Error> {
        vec![
            Error::InvalidSignature {
                reason: "bad sig".into(),
            },
            Error::PeerRangeMismatch {
                package: "p".into(),
                peer_name: "peer".into(),
                range: "^1".into(),
                resolved: "2.0".into(),
            },
            Error::PeerRequirementUnsatisfied {
                package: "p".into(),
                peer_name: "peer".into(),
            },
            Error::NoPackagesForPlatform {
                os: "linux".into(),
                arch: "x86_64".into(),
            },
            Error::PhantomDependency {
                consumer: "app".into(),
                dep: "ghost".into(),
            },
            Error::PatchFileMissing {
                package: "p".into(),
                content_id: 1,
                path: "p.diff".into(),
            },
            Error::PatchDigestMismatch {
                package: "p".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            Error::OrphanPatchHash {
                package: "p".into(),
            },
            Error::ScriptDigestMismatch {
                package: "p".into(),
                script: "postinstall".into(),
            },
            Error::UnknownExport {
                package: "p".into(),
                identifier: "nope".into(),
            },
            Error::ArtifactMissing {
                package: "p".into(),
                os: 1,
                arch: 2,
                path: "bin".into(),
            },
            Error::ArtifactDigestMismatch {
                package: "p".into(),
                expected: "a".into(),
                actual: "b".into(),
            },
            Error::DigestMismatch {
                expected: "a".into(),
                actual: "b".into(),
            },
            Error::MissingContentId {
                package: "p".into(),
                content_id: 0xdead_beef,
            },
        ]
    }

    fn merge_variants() -> Vec<Error> {
        vec![
            Error::DuplicateDigestDirective,
            Error::MergeConflict {
                package_name: "p".into(),
                description: "clash".into(),
            },
            Error::MergeSourceConflict {
                index: 0,
                ours_url: "a".into(),
                theirs_url: "b".into(),
            },
            Error::MergeFailed { count: 3 },
            Error::MergeRemoveAlterConflict {
                package: "p".into(),
            },
            Error::MergeOverrideConflict {
                name: "p".into(),
                ours: "1".into(),
                theirs: "2".into(),
            },
            Error::LazyIndexCorrupt {
                line_number: 11,
                reason: "dup".into(),
            },
            Error::SbomGenerationFailed {
                package: "p".into(),
                reason: "no source".into(),
            },
        ]
    }

    fn policy_variants() -> Vec<Error> {
        vec![
            Error::UnknownProvenanceDepType { type_id: 77 },
            Error::UnknownProvenanceSourceType { type_id: 78 },
            Error::DuplicateProvenance {
                package: "p".into(),
            },
            Error::InvalidAdvisorySeverity {
                line_number: 12,
                severity: "urgent".into(),
            },
            Error::InvalidPolicyType {
                line_number: 13,
                type_id: "bogus".into(),
            },
            Error::TrustRootExpired {
                key_id: "k".into(),
                expires_epoch: 42,
            },
            Error::MissingTrustRoot,
            Error::TrustRootVerificationFailed { key_id: "k".into() },
            Error::DuplicateMirrorScope {
                scope: "@scope".into(),
            },
            Error::ImportFailed {
                format: "yarn".into(),
                reason: "parse".into(),
            },
            Error::HookDeniedByPolicy {
                package: "p".into(),
                hook: "postinstall".into(),
            },
            Error::EngineConstraintUnsatisfied {
                package: "p".into(),
                constraint: "node>=99".into(),
            },
            Error::TrustRootRotationInvalid {
                reason: "bad rotation".into(),
            },
            Error::InvalidVexStatus {
                line_number: 14,
                status: "maybe".into(),
            },
            Error::NetworkError {
                reason: "timeout".into(),
            },
            Error::ConfigError {
                reason: "bad config".into(),
            },
        ]
    }

    #[test]
    fn every_variant_has_unique_error_code() {
        let variants = all_variants();
        let codes: Vec<&'static str> = variants.iter().map(Error::error_code).collect();
        assert_eq!(
            codes.len(),
            53,
            "expected the full variant list, got {}",
            codes.len()
        );
        for (i, code) in codes.iter().enumerate() {
            assert!(
                code.starts_with('E'),
                "code {code} for variant {i} is malformed"
            );
            assert_eq!(code.len(), 5, "code {code} for variant {i} is malformed");
        }
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            codes.len(),
            "error codes must be unique: {codes:?}"
        );
    }

    #[test]
    fn spot_check_known_codes_and_messages() {
        assert_eq!(Error::Io(io::Error::other("x")).error_code(), "E0001");
        assert_eq!(
            Error::MissingDelimiter { line_number: 0 }.error_code(),
            "E0101"
        );
        assert_eq!(
            Error::InvalidPolicyType {
                line_number: 0,
                type_id: "t".into()
            }
            .error_code(),
            "E0109"
        );
        assert_eq!(Error::MergeFailed { count: 1 }.error_code(), "E0603");
        assert_eq!(
            Error::ConfigError { reason: "r".into() }.error_code(),
            "E0801"
        );

        let missing = Error::MissingDelimiter { line_number: 17 };
        assert_eq!(
            missing.to_string(),
            "Line 17: Missing tab delimiter between name and payload"
        );

        let dup = Error::DuplicateDigestDirective.to_string();
        assert_eq!(dup, "Multiple @digest directives found");

        let content = Error::MissingContentId {
            package: "p".into(),
            content_id: 255,
        }
        .to_string();
        assert!(
            content.contains("000000ff"),
            "message should hex-format the content id: {content}"
        );

        let import = Error::ImportFailed {
            format: "yarn".into(),
            reason: "bad".into(),
        }
        .to_string();
        assert!(
            import.contains("Import failed") && import.contains("bad"),
            "got: {import}"
        );
    }

    #[test]
    fn io_error_converts_via_from() {
        let err: Error = io::Error::other("disk").into();
        assert!(matches!(err, Error::Io(_)));
        assert!(err.to_string().contains("disk"));
    }
}
