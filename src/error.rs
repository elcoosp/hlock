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
}
