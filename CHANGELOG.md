# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2024-05-24
### Added
- File header block for global metadata (parsed before package graph).
- `@source <idx> <uri>` directive to define package origins (Registry, Local, Git).
- `@override <name> <ver> -> <ver>` directive for dependency version substitutions.
- `Source` enum (`Registry`, `Local`, `Git`) for typed package origins.
- `DepType` enum (`Runtime`, `Dev`, `Peer`, `Optional`) for dependency profiles.
- `Dependency` struct combining target name and `DepType`.
- `Override` struct for version substitution rules.
- Unified `Lockfile` struct to encapsulate sources, overrides, and packages.
- Binary payload now includes `source_idx` mapping to the header.
- Binary payload dependencies now encode `DepType` as a trailing byte per dependency.

### Changed
- **BREAKING:** Public API completely refactored around the `Lockfile` struct. `serialize` and `deserialize` now consume/return `Lockfile` instead of `Vec<Package>`.
- **BREAKING:** `Package` struct now requires a `source_idx` field.
- **BREAKING:** `Package.dependencies` changed from `Vec<String>` to `Vec<Dependency>`.
- **BREAKING:** Payload version byte bumped to `0x02`. HLOCK v0.3.0 will intentionally reject v0.2.0 and v0.1.0 payloads.

## [0.2.0] - 2024-05-24
### Added
- HLOCK v0.2.0 binary payload spec.
- 1-byte version header to payload for future schema evolution.
- 1-byte dynamic hash length prefix (supports any hash size, e.g., SHA-256, BLAKE3).
- 4-byte CRC32 IEEE checksum trailer for payload integrity verification.
- `crc32` module for pure-Rust checksum calculation.
- `error` module with rich, context-aware error variants using `thiserror`.
- Decoupled string-based API: `serialize()` and `deserialize()`.
- File I/O is now implemented as thin wrappers (`write_lockfile`, `read_lockfile`).
- `thiserror` dependency for ergonomic error handling.

### Changed
- **BREAKING:** `Package.hash` field changed from fixed `[u8; 16]` to dynamic `Vec<u8>`.
- **BREAKING:** HLOCK v0.2.0 parsers will intentionally reject v0.1.0 payloads (due to missing version header).

## [0.1.0] - 2024-05-24
### Added
- Initial implementation of the HLOCK hybrid lockfile format.
- Zero-dependency Rust crate (Edition 2024).
- `varint` module for Unsigned LEB128 encoding/decoding.
- `base64url` module for RFC 4646 no-padding encoding/decoding.
- `payload` module for packing/unpacking binary package metadata.
- `lockfile` module providing `Package` struct, `write_lockfile`, and `read_lockfile`.
- End-to-end integration tests validating the write/read cycle.
