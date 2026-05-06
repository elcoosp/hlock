# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2024-05-24
### Added
- HLOCK v2.0 binary payload spec.
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
- **BREAKING:** HLOCK v2.0 parsers will intentionally reject v1.0 payloads (due to missing version header).

## [0.1.0] - 2024-05-24
### Added
- Initial implementation of the HLOCK hybrid lockfile format.
- Zero-dependency Rust crate (Edition 2024).
- `varint` module for Unsigned LEB128 encoding/decoding.
- `base64url` module for RFC 4648 §5 no-padding encoding/decoding.
- `payload` module for packing/unpacking binary package metadata.
- `lockfile` module providing `Package` struct, `write_lockfile`, and `read_lockfile`.
- End-to-end integration tests validating the write/read cycle.
