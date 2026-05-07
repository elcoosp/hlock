pub mod varint;
pub mod base64url;
pub mod payload;
pub mod lockfile;
pub mod error;
pub mod crc32;
pub mod fnv;
pub mod graph;
pub mod signature;

pub use error::Error;
pub use graph::{diff_lockfiles, extract_subgraph};
pub use lockfile::{
    Lockfile, Package, Source, DepType, Dependency, Override,
    HashAlgorithm, IntegrityHash, TargetOS, TargetArch,
    PackageChange, LockfileDiff, Attestation, SlsaPredicate, PeerResolution,
    PlatformTag, PeerRequirement, CompatMode,
    serialize, serialize_compat, deserialize, write_lockfile, read_lockfile,
};
pub use signature::{SignatureError, sign_lockfile, verify_signature};
