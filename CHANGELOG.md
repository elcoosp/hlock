# Changelog

All notable changes to this project will be documented in this file.

## [0.9.0] — The Platform and Provenance Release

### Added
- **Platform filter tags** — Packages can declare target OS/arch via `PlatformTag`. `extract_subgraph_platform()` produces a pruned lockfile for a specific platform.
- **Peer requirements** — `PeerRequirement` struct declares *what* a peer dependency requires (name, version range, optional flag), complementing the existing `PeerResolution` which records *how* it was satisfied.
- **Ed25519 lockfile signing** — `sign_lockfile()` appends an `@signature` directive. `verify_signature()` validates it. No hashing, no framing — raw Ed25519 over the file bytes.
- **`SignatureError` enum** — `VerificationFailed`, `MalformedDirective`, `InvalidBase64`.
- **`CompatMode` enum** — `V8` omits v0.9 sections entirely; `V9` includes them on every package. `serialize_compat()` accepts the mode.
- **`pack_payload_v8()`** — Public function to produce a v0.8-compatible binary payload.
- **New error variants** — `Error::NoPackagesForPlatform`, `Error::PeerRangeMismatch`, `Error::PeerRequirementUnsatisfied`, `Error::InvalidSignature`.
- **Expanded `TargetOS` and `TargetArch`** — Added `FreeBSD`, `Android`, `IOS`, `Wasm32`, `Arm`, `S390x`, `Ppc64le`, `Unknown`.
- **`deserialize` skips `@signature` lines** — v0.8-compatible parsers ignore the signature directive without error.

### Changed
- **`serialize()` defaults to `CompatMode::V9`** — New lockfiles include peer requirements and platform tag sections.
- **`deserialize` auto-detects v0.8 vs v0.9 payloads** — After reading the dependencies array, checks whether remaining bytes are exactly 4 (CRC32) to determine format.

### Backward Compatibility
- v0.9 deserializers read v0.8 lockfiles transparently.
- `serialize_compat(&mut lockfile, CompatMode::V8)` produces output readable by v0.8 parsers.
- Lockfiles without `@signature` are valid and verify as `Ok(())`.
- The payload version byte remains `0x06` for both formats.

## [0.8.0] — The Monorepo Topology Release

### Breaking Changes
- **Dropped v0.05 backward compatibility.** Parsers now strictly reject any payload version less than `0x06`. No fallback logic.

### Added
- **First-Class Package Aliasing** — `Package.logical_name: Option<String>` field and corresponding `LogicalNameLen`/`LogicalName` fields in the binary payload. When set, this is the name code uses to import the package (e.g., `react-v18`), while the canonical name on the text line remains the true identity for content ID computation.
- **Peer Dependency Topology Tracking** — `Package.resolved_peers: Vec<PeerResolution>` field and `PeerCount`/`Peers` array in the binary payload. Each `PeerResolution` records the peer name, the content ID of the satisfying package, and whether it is hoisted to the workspace root.
- **CAS HTTP Source** — `Source::CasHttp(String)` variant for `cas+https://` and `cas+http://` URI schemes. Enables registry-free content-addressable fetching.
- **IPFS Source** — `Source::Ipfs(String)` variant for `ipfs://` URI schemes.
- Integration tests for IPFS source roundtrip and CAS + alias roundtrip.
- Integration tests for peer resolution topology serialization and subgraph extraction with peer preservation.

### Changed
- `PeerResolution` struct now derives `Clone`, `PartialEq`, `Eq`.
- `PeerResolution` is re-exported from the library root.
- Header parser recognizes `cas+` prefix and `ipfs://` scheme for source URIs.
- Binary payload version byte remains `0x06` (unchanged from v0.7 internal schema).

## [0.7.0] — SLSA Provenance Release

### Added
- **Inline SLSA Attestation** — `Attestation::InlineSlsa(SlsaPredicate)` with builder and source fields embedded directly in the hash struct.
- **External Bundle Attestation** — `Attestation::ExternalBundleSha256([u8; 32])` for referencing detached attestation bundles.
- Attestation type byte in binary hash layout (`0x00` None, `0x01` External, `0x02` Inline SLSA).
- `UnknownAttestationType` error variant.

## [0.6.0] — Peer Resolution Skeleton

### Added
- `PeerResolution` struct with `peer_name`, `satisfied_by_content_id`, `is_hoisted_to_root`.
- `resolved_peers` field on `Package`.
- `PeerCount` and `Peers` array in binary payload layout.
- Integration tests for peer topology roundtrip and subgraph extraction with peer preservation.

## [0.5.0] — Content-ID Dependencies

### Added
- Dependencies referenced by FNV-1a 64-bit content IDs instead of positional indices.
- `MissingContentId` error variant.
- `InvalidFeatureIndex` error variant.
- Requested feature indices encoded as varint array in dependency payload.
- Optional target dependencies (`DepType::OptionalTarget`) with OS and arch bytes.

## [0.1.0] — Initial Release

### Added
- Binary payload encoding with CRC32 integrity checks.
- Base64URL transport encoding.
- `@source`, `@override`, `@feature` header directives.
- Registry, Local, Git, Workspace source types.
- SHA-1, SHA-256, SHA-512, BLAKE3 hash algorithms.
- Runtime, Dev, Peer, Optional dependency types.
- Sparse subgraph extraction with source pruning.
- Sorted merge-based lockfile diffing.
- File-based and string-based serialize/deserialize API.
