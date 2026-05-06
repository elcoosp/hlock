# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2024-05-24

### Added
- **Monorepo Graph Manipulation APIs**: Introduced pure-Rust graph traversal logic in `src/graph.rs`.
- `diff_lockfiles`: Calculates exact semantic changes (Added, Removed, Altered) between two lockfiles using a fast two-pointer array merge.
- `extract_subgraph`: Extracts a fully valid, standalone lockfile containing only the transitive closure of specified root packages (Sparse Subgraph Extraction).
- `PackageChange` and `LockfileDiff` public structs.
- `RootContentIdMissing` error variant.
- Source index remapping and metadata preservation during subgraph extraction.
- `PartialEq` and `Eq` derives for `Package`, `Dependency`, and `IntegrityHash`.

## [0.5.0] - 2024-05-23

### Added
- **Merge-Safe Content-Addressable Graph**: Dependencies are now referenced by FNV-1a 64-bit hashes of `name@version` instead of array indices.
- **First-Class Feature Flags**: Local per-package feature string tables in the binary payload.
- **Platform-Targeted Dependencies**: Native support for `OptionalTarget(OS, Arch)` dependency profiles.
- **Header Directives**: `@feature <name> [flags]` directive.
- **Binary Payload v0x04**: New schema supporting Content IDs, local features, and target constraints.
- Two-pass deserialization to correctly resolve forward references in sorted package arrays.

### Changed
- **BREAKING**: HLOCK v0.5.0 parsers intentionally reject v0.4.0 and older payloads.
- Refactored module exports.
