# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.16.0] - 2025-01-XX

### Fixed

- **CRITICAL**: BLAKE3 `@digest` now covers `@license` and `@vex` lines. Previously the digest was computed before these lines were appended, making digests invalid for any lockfile declaring licenses or VEX entries. Lockfiles with `@license` lines produced by v0.15.0 must be re-serialized.

### Added

- CLI binary (`hlock`) with 8 subcommands: `verify`, `lint`, `diff`, `audit`, `sbom`, `sign`, `graph`, `merge` (§3.2)
- `@trust-root-rotation` directive for key rotation per TUF §5.2 (§3.8)
  - New type `TrustRootRotation` with parse, serialize, and validate
  - `Lockfile::validate_root_rotation()` method
  - New error variant `Error::TrustRootRotationInvalid`
- `@vex` directive for Vulnerability Exploitability eXchange (§3.9)
  - New types `VexStatus`, `VexEntry`
  - `Lockfile::vex_for()` and `Lockfile::effective_advisories()` methods
  - New error variant `Error::InvalidVexStatus`
- Fuzz targets: `fuzz_unpack_payload` and `fuzz_deserialize` (§3.10)
- `DedupOpportunity.potential_saving_bytes` now returns non-zero estimates (§3.6)
- Re-exports: `TrustRootRotation`, `VexEntry`, `VexStatus` from `lib.rs`
- Lint rules: `NoKnownVulnerabilities`, `RequireLicense`, `DenyCopyleft`, `RequireTrustRoot`, `NoExpiredKeys`, `DenyPostinstall`

### Changed

- `Lockfile` struct gains `root_rotations: Vec<TrustRootRotation>` and `vex_entries: Vec<VexEntry>` fields
- SBOM generation now uses `env!("CARGO_PKG_VERSION")` instead of hardcoded `"0.14.0"` (§3.5)
- `LazyLockfile::scan` now delegates to `header::parse_header` instead of reimplementing directive parsing (§3.4)
- `scan_header` and `classify_source` removed from `lazy.rs` — single source of truth in `header.rs`
- Canonical serialization order updated: `@vex` and `@license` before `@digest`; `@trust-root-rotation` after `@trust-root` in header

### Removed

- `SignatureAlgorithm::Ed448` variant — algorithm ID `0x01` now returns `UnsupportedSignatureAlgorithm` (§3.7)
- `fix_parse_header.py` — obsolete post-generation patcher (§3.3)

### Migration Guide (v0.15.0 → v0.16.0)

- Re-serialize lockfiles that contain `@license` directives to generate correct digests
- Remove any hand-crafted `@signature ... 01 ...` lines (Ed448 was never implemented)
- Add `root_rotations: vec![]` and `vex_entries: vec![]` when constructing `Lockfile` manually (or use `..Default::default()`)

## [0.15.0] - 2024-12-XX

### Added

- `@provenance` directive with resolution provenance tracking
- `LazyLockfile` for on-demand package parsing
- `@mirror` directive for scoped registry mirrors
- `@policy` directive for hook/script/build-env allow/deny rules
- `@trust-root` directive with Ed25519 and ML-DSA-65 support
- `@advisory` directive and `AuditReport` type
- `@license` directive and license lookup API
- Lint framework with `lint_default` rule set
- Lockfile merge with 3-way conflict resolution
- SBOM generation (SPDX-JSON and CycloneDX-JSON)
- Graph operations: topological sort, subgraph extraction, cycle detection
- Payload version 0x08 with BLAKE3 integrity trailer
- Peer requirements and platform tags in payload
- Hook hash and export integrity in payload
- `@artifact` and `@patch` directives
- `@feature` and `@override` directives
- `@workspace-root`, `@workspace-pkg`, `@hoist-boundary` directives
- Ed25519 and ML-DSA-65 signature verification
- Diff computation and serialization (text and JSON)

## [0.14.0] - 2024-11-XX

### Added

- Initial public release
- Binary lockfile format with Base64URL-encoded payloads
- Varint (LEB128) encoding for compact version numbers
- FNV-1a content ID hashing
- Source classification (registry, git, local, workspace, cas+http, ipfs)
