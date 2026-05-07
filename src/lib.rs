pub mod base64url;
pub mod error;
pub mod fnv;
pub mod graph;
pub mod lockfile;
pub mod payload;
pub mod signature;
pub mod varint;

pub use error::Error;
pub use lockfile::{
    Attestation, DepType, Dependency, HashAlgorithm, HoistBoundary,
    IntegrityHash, Lockfile, LockfileDiff, Override, Package, PackageChange,
    PatchDirective, PeerResolution, PeerRequirement, PlatformTag,
    Artifact, Export, HookHash, Source, SlsaPredicate, TargetArch, TargetOS, WorkspacePkg,
    deserialize, read_lockfile, serialize, validate_hoist_boundary, validate_patches,
    validate_scripts, write_lockfile,
};
pub use graph::{diff_lockfiles, extract_subgraph, extract_subgraph_platform};
pub use payload::{
    DepPayload, pack_payload, unpack_payload, PeerReqPayload, PlatformTagPayload,
    HookHashPayload, PayloadData,
};
pub use signature::{sign_lockfile, verify_signature};
