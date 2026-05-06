pub mod varint;
pub mod base64url;
pub mod payload;
pub mod lockfile;
pub mod error;
pub mod crc32;
pub mod fnv;
pub mod graph;

pub use error::Error;
pub use graph::{diff_lockfiles, extract_subgraph};
pub use lockfile::{
    Lockfile, Package, Source, DepType, Dependency, Override,
    HashAlgorithm, IntegrityHash, TargetOS, TargetArch,
    PackageChange, LockfileDiff, Attestation, SlsaPredicate,
    serialize, deserialize, write_lockfile, read_lockfile
};
