# Changelog

All notable changes to this project will be documented in this file.

## [0.12.0] — The Cryptographic Agility & Graph Intelligence Release

### Breaking Changes
- **Payload version byte `0x07` → `0x08`.** v0.11 lockfiles cannot be read by a v0.12 parser. The `UnknownPayloadVersion` error is returned for old payloads.
- **CRC32 trailer replaced by BLAKE3.** The 4-byte CRC32 is gone. Every binary payload now ends with a 32-byte BLAKE3 digest. The `IntegrityCheckFailed` error variant is removed; use `PayloadDigestMismatch` instead.
- **`sign_lockfile` API changed.** Now takes `(serialized, key_id, algorithm, private_key, expires_epoch)`. The 64-byte expanded key from v0.11 is no longer accepted; pass the 32-byte Ed25519 seed directly.
- **`verify_signature` API changed.** Now takes `(content, trusted_keys: &HashMap<String, (&[u8], SignatureAlgorithm)>)`. The bare `&[u8]` public key from v0.11 is no longer accepted. An empty trusted key map accepts only unsigned lockfiles; signed lockfiles with untrusted keys are rejected.

### Added
- **BLAKE3 payload trailer** — 32-byte BLAKE3 digest replaces CRC32. 128-bit collision resistance vs CRC32's 32-bit error detection. Faster than CRC32 on modern hardware with SIMD.
- **Pluggable signature algorithms** — `SignatureAlgorithm` enum with `Ed25519` (0x00) and `Ed448` (0x01). Adding post-quantum signatures in future releases requires only a new ID.
- **Signature expiration** — `@signature` directives now include `expires_epoch`. Verifiers reject expired signatures. Pass `0` for no expiration.
- **Multi-signature support** — Multiple `@signature` directives are allowed. The verification policy is simple: all signatures must verify.
- **Graph query API** — Six new functions in the `graph` module:
  - `topological_sort()` — Kahn's algorithm with lexicographic tiebreak for deterministic output.
  - `dependents_of()` — Reverse dependency lookup (BFS from target).
  - `transitive_deps()` — Forward transitive closure (excludes self).
  - `leaf_packages()` — Packages with no dependents (removal candidates).
  - `detect_cycle()` — DFS three-color marking, returns cycle path.
  - `would_create_cycle()` — Dry-run check before adding edges.
- **`SignatureDirective` struct** — Parsed representation of `@signature` lines with `key_id`, `algorithm`, `expires_epoch`, and `signature_bytes`.
- **New error variants** — `SignatureError::UntrustedKey`, `SignatureError::SignatureExpired`, `SignatureError::UnsupportedSignatureAlgorithm`, `SignatureError::Ed448VerificationFailed`.

### Changed
- **`@signature` directive syntax** — `@signature <key_id> <sig>` → `@signature <key_id> <algo_id> <expires_epoch> <sig>`. The v0.11 format with implicit Ed25519 and no expiration is no longer valid.
- **`sign_lockfile` private key** — Accepts the 32-byte Ed25519 seed directly (not the 64-byte expanded key). Cleaner API, avoids "which 64 bytes?" confusion.

### Removed
- **`Error::IntegrityCheckFailed`** — Replaced by `Error::PayloadDigestMismatch`.
- **CRC32 computation** — No CRC32 code remains in the codebase.

## [0.11.0] — The Interface & Artifact Transparency Release

### Breaking Changes
- **Dropped all backward-compatibility shims.** `CompatMode` enum, `serialize_compat()`, `pack_payload_v8()`, and `pack_payload_v9()` are deleted. Parsers reject any payload version byte other than `0x07` with `Error::UnknownPayloadVersion`.
- **Strict sequential binary format.** Auto-detection heuristics (checking remaining byte lengths to guess payload version) are removed. The parser reads `0x07` and expects the v0.11 field layout exactly.
- **Hook hashes are now variable-length strings.** The `HookType` field changed from a fixed enum byte to a varint-prefixed raw string, ensuring language agnosticism.

### Added
- **Export locking** — `Export` struct with `identifier`, `hash_algo`, and `digest` fields. `Package.exports: Vec<Export>` locks the public interface map of a module, enabling dependency confusion detection.
- **Artifact transparency** — `Artifact` struct with `os_id`, `arch_id`, `hash_algo`, and `digest` fields. `Package.artifacts: Vec<Artifact>` hashes dynamically fetched or compiled platform-specific binaries.
- **`ArtifactDirective`** — Header-level struct linking a content ID, OS/arch, and a relative file path via the `@artifact` directive.
- **`@artifact` header directive** — `@artifact <content_id_hex> <os_id> <arch_id> <relative_path>` declares platform-specific artifacts. Multiple directives can exist per package.
- **`@metadata` header directive** — `@metadata <key> <value>` stores arbitrary key-value pairs (e.g., SBOM fields like `license`, `author`, `repository`). Last occurrence wins if duplicated.
- **`Lockfile.metadata`** — `Vec<(String, String)>` field for parsed metadata entries.
- **`Lockfile.artifacts`** — `Vec<ArtifactDirective>` field for parsed artifact directives.
- **New error variants** — `Error::UnknownExport`, `Error::ArtifactMissing`, `Error::ArtifactDigestMismatch`.

### Changed
- **`HookHash.hook_type` is now a `String`** (was an implicit enum). Serialization uses varint-prefixed UTF-8 instead of a single byte.
- **Payload version byte is `0x07`** — All payloads are written as v0.11. Any payload with a different version byte is rejected.
- **Exports and Artifacts arrays are always present** in the binary payload, even if empty.

## [0.10.0] — The Lifecycle & Patch Release

### Added
- **Hook hash integrity** — `HookHash` struct with `hook_type`, `hash_algo`, and `digest` fields. `Package.hook_hashes` locks lifecycle script digests.
- **Patch support** — `PatchDirective` struct, `@patch` header directive, and `Package.patch_hash` for tracking source patches.
- **Script digest validation** — `validate_scripts()` verifies hook digests against `package.json` script content.
- **Patch validation** — `validate_patches()` verifies patch file existence and BLAKE3 digest.
- **Orphan patch detection** — `Error::OrphanPatchHash` when a package has a patch hash but no `@patch` directive.

## [0.9.0] — The Platform and Provenance Release

### Added
- **Platform filter tags** — Packages can declare target OS/arch via `PlatformTag`. `extract_subgraph_platform()` produces a pruned lockfile for a specific platform.
- **Peer requirements** — `PeerRequirement` struct declares *what* a peer dependency requires (name, version range, optional flag), complementing the existing `PeerResolution` which records *how* it was satisfied.
- **Ed25519 lockfile signing** — `sign_lockfile()` appends an `@signature` directive. `verify_signature()` validates it.
- **`SignatureError` enum** — `VerificationFailed`, `MalformedDirective`, `InvalidBase64`.
- **New error variants** — `Error::NoPackagesForPlatform`, `Error::PeerRangeMismatch`, `Error::PeerRequirementUnsatisfied`, `Error::InvalidSignature`.
- **Expanded `TargetOS` and `TargetArch`** — Added `FreeBSD`, `Android`, `IOS`, `Wasm32`, `Arm`, `S390x`, `Ppc64le`, `Unknown`.

## [0.8.0] — The Monorepo Topology Release

### Added
- **First-Class Package Aliasing** — `Package.logical_name: Option<String>` field.
- **Peer Dependency Topology Tracking** — `Package.resolved_peers: Vec<PeerResolution>`.
- **CAS HTTP Source** — `Source::CasHttp(String)` for `cas+https://` URIs.
- **IPFS Source** — `Source::Ipfs(String)` for `ipfs://` URIs.

## [0.7.0] — SLSA Provenance Release

### Added
- **Inline SLSA Attestation** — `Attestation::InlineSlsa(SlsaPredicate)`.
- **External Bundle Attestation** — `Attestation::ExternalBundleSha256([u8; 32])`.

## [0.6.0] — Peer Resolution Skeleton

### Added
- `PeerResolution` struct and `resolved_peers` field on `Package`.

## [0.5.0] — Content-ID Dependencies

### Added
- Dependencies referenced by FNV-1a 64-bit content IDs instead of positional indices.
- Optional target dependencies (`DepType::OptionalTarget`).

## [0.1.0] — Initial Release

### Added
- Binary payload encoding with CRC32 integrity checks.
- Base64URL transport encoding.
- Header directives, source types, hash algorithms, dependency types.
- Sparse subgraph extraction and sorted merge-based diffing.
