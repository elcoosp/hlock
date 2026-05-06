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
}
