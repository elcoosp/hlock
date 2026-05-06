# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-05-24
### Added
- Initial implementation of the HLOCK hybrid lockfile format.
- Zero-dependency Rust crate (Edition 2024).
- `varint` module for Unsigned LEB128 encoding/decoding.
- `base64url` module for RFC 4646 no-padding encoding/decoding.
- `payload` module for packing/unpacking binary package metadata.
- `lockfile` module providing `Package` struct, `write_lockfile`, and `read_lockfile`.
- End-to-end integration tests validating the write/read cycle.
