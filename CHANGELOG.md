## [0.19.0] - 2026-11-01
### Features
- Complete v0.19.0 polish pass
### Miscellaneous tasks
- Readme
- Readme
## [0.18.0] - 2026-05-10
### Bug Fixes
- Update remaining signature test HashMaps to use Vec<u8>
- Correct test_check_json to match actual JSON output schema
- Remove invalid bool dereference in licenses command handler
- **tests:** Update check JSON test for new spec-compliant output
- **cli:** Replace serde derive with manual JSON for TreeNode, keep all Tree/Licenses/Color changes
- **tests:** Handle both single-root and multi-root JSON in tree test
- **tests:** Borrow String for sign --private-key and suppress unused variable
- **info:** Remove ANSI color codes from digest line to comply with --color never
- **check:** Add sig_expired and sig_expires_epoch to signature verification tuple
- Remove dead code, add color overrides for JSON output
- Add explicit set_override in info handler, stabilize color test
- **info:** Replace direct .bold() calls with conditional b() closure
- **cli:** Resolve clippy warnings for manual_strip and if_same_then_else
- **cli:** Replace map_or with is_some_and per clippy suggestion
- Resolve mismatched types in config.rs
- Borrow after move and unused variable in main.rs
### Documentation
- Add demo example and script for CLI testing
- Fix demo example with v2 variant for proper diff/merge testing
- Spec
- Spec
### Features
- Implement --rule filtering for lint, add completions command
- Partial chunk 3 v0.17
- Add why command to explain why a package is in the lockfile
- Add deps command to list package dependencies
- Add dependents command to list reverse dependencies
- **tree:** Make --root required per spec
- Add --quiet support to verify, diff, sbom, sign, graph, merge, completions; add verbose to verify
- Add --quiet to lint/audit, add --verbose to lint/audit/diff/info commands
- Add --quiet to lint/audit, add --verbose to lint/audit/diff/info commands
- Import
- Integrate Scorecard and Sigstore (G08/G09) into CLI
### Miscellaneous tasks
- Update demo.sh for v0.17.0 commands, fix signature.rs mut warnings
- Fix clippy warnings - allow unused_mut in tests and dead_code in output
- Update demo.sh for v0.18.0 features
### Refactoring
- Extract Cli struct and shared command helpers
### Tests
- Add more tests
## [0.16.0] - 2026-05-08
### Bug Fixes
- **policy:** Compute ver_count before move to fix borrow error
- Add root_rotations and vex_entries to all Lockfile construction sites
- **lockfile:** Compute digest after writing license and vex lines
### Documentation
- Add CHANGELOG.md and README.md for v0.16.0
### Features
- **cli:** Add hlock CLI binary with verify/lint/diff/audit/sbom/sign/graph/merge
- **policy:** Add @trust-root-rotation and @vex directives with validation and effective_advisories
### Miscellaneous tasks
- Fix all clippy warnings across workspace
### Tests
- Fuzz
- Add missing spec tests for v0.16.0 (root rotation, sbom version, lazy header, ed448 rejection, vex status, CLI)
## [0.15.0] - 2026-05-08
### Bug Fixes
- Fix mess
- Syntax errors
- Last errs
- Missing fields
### Features
- Poc v0.15
- Refactor lockfile
- **v0.15:** Implement all v0.15 specification features
- **v0.15:** Implement @trust-root directive for TUF-style trust delegation
- **v0.15:** Complete all major features including SBOM license support
### Other
- V0.15.0 - The Audit, Trust & Interop Release
## [0.14.0] - 2026-05-08
### Bug Fixes
- Triple backtick doc
- Resolve final clippy warnings (needless_range_loop, missing_safety_doc)
- Add missing provenance field to Lockfile construction in lockfile tests
- Use valid serialized lockfile content in provenance error tests
### Documentation
- Spec
- Spec
### Features
- Filter provenance in extract_subgraph and extract_subgraph_platform
- Implement merge_lockfiles with 3-way merge algorithm
- Implement LazyLockfile with scan, get_package, into_full
- Implement SBOM generation (SPDX 2.3 and CycloneDX 1.5)
- Implement SBOM generation (SPDX 2.3 and CycloneDX 1.5)
- Implement lint engine with built-in rules and lint_default
- V0.14.0 - Supply Chain & Merge Intelligence Release
### Miscellaneous tasks
- V0.13.0 release — changelog, readme, git tag
## [0.13.0] - 2026-05-08
### Bug Fixes
- Make crc_corruption test robust against @digest presence
### Documentation
- Add v0.13 spec — Post-Quantum & Diff Intelligence Release
- Mv spec
- Add v0.13 spec — Post-Quantum & Diff Intelligence Release
### Features
- **signature:** Add ML-DSA-65 algorithm ID and parse acceptance; stub sign/verify pending stable crate
- Add DiffFormat, serialize_diff (text+json), bump to v0.13.0
- Implement ML-DSA-65 signing and verification with fips204
- Add dependency-type-aware graph queries
- Add v0.13 re-exports and integration tests
### Miscellaneous tasks
- Add ML-DSA dependency to Cargo.toml
## [0.12.0] - 2026-05-07
### Bug Fixes
- **test:** Correct blake3 trailer length assertion to 48
- Readd integration
- **signature:** Correct tampered message test to use substring that exists
- **graph:** Topological sort tiebreak by package name instead of index
### Documentation
- Update README and CHANGELOG for v0.11.0
- Add v0.12.0 specification
- Mv spec
### Features
- **lockfile:** Add @metadata, @artifact, @patch header directive parsing
- Poc sig
### Miscellaneous tasks
- Bump to v0.12.0, update README and CHANGELOG
## [0.11.0] - 2026-05-07
### Bug Fixes
- **lib:** Export signature functions for integration tests
- Rename remaining script_hashes to hook_hashes
- **tests:** Add missing exports and artifacts fields to PayloadData fixtures
### Features
- Poc articat payload
### Miscellaneous tasks
- Bump to v0.11.0 and add artifact/export error variants
## [0.10.0] - 2026-05-07
### Bug Fixes
- **parse:** Assign parsed packages and correct v10 test bounds
### Miscellaneous tasks
- Bump version
## [0.9.0] - 2026-05-07
### Bug Fixes
- Try fix payload
- **test:** Use full ipfs:// URI in IPFS source roundtrip test
- **payload:** Remove duplicate platform_tags fields from test literals
- Lockfile
- **signature:** Clean up double-replaced PUBLIC_KEY references
- **graph:** Platform filter only adds matching deps to reachable set
- **tests:** Mac-native is unreachable from app, correct platform extraction expectations
### Documentation
- Add README and CHANGELOG for v0.8.0 release
- Add README and CHANGELOG for v0.9.0 release
### Features
- **lockfile:** Expand TargetOS/TargetArch variants and fix match arms
- **lockfile:** Add PlatformTag, PeerRequirement, CompatMode types
### Tests
- Impl v0.8
## [0.7.0] - 2026-05-06
### Bug Fixes
- Warn
### Documentation
- Fix readme
- Fix readme
### Features
- **types:** Add Attestation, SlsaPredicate and UnknownAttestationType
- **payload:** Implement v0.5 pack and v0.4/v0.5 unpack logic for attestations
- **lockfile:** Integrate attestation mapping in serialize/deserialize
### Tests
- **integration:** Add e2e tests for v0.7 provenance and graph compatibility
## [0.6.0] - 2026-05-06
### Bug Fixes
- **hlock:** Two-pass deserialization to handle sorted forward references
- **lockfile:** Derive PartialEq and Eq for nested structs
- **graph:** Correct transitive closure by not prematurely inserting deps into output set
### Documentation
- Update README and CHANGELOG for v0.4.0 spec
- Specs
- **spec:** Add v0.6.0 monorepo graph manipulation spec
- Mv spec
- Add README and CHANGELOG for v0.5.0 and v0.6.0
### Features
- **fnv:** Add FNV-1a 64-bit hasher for content IDs
- **payload:** Fix v0.5 pack indices and finalize tests
- **lockfile:** Implement diff_lockfiles base logic
- **graph:** Add source remapping and metadata preservation to extract_subgraph
### Miscellaneous tasks
- **deps:** Bump to v0.5.0 and add content-id errors
- Poc broken lockfile
### Refactoring
- **api:** Define v0.5 domain structs including features and targets
### Tests
- **integration:** Add e2e tests for diff and subgraph extraction
## [0.4.0] - 2026-05-06
### Documentation
- Update README and CHANGELOG for v0.3.0 spec
### Features
- **payload:** Add v0.4 pack with multi-algorithm hashes
- **payload:** Finalize v0.4 pack and unpack with multi-algorithm hash validation
- **api:** Implement v0.4 workspace and multi-hash serialize/deserialize
### Miscellaneous tasks
- **deps:** Bump to v0.4.0 and add hash/workspace errors
### Tests
- Update integration tests for v0.4 workspace and multi-hash
## [0.3.0] - 2026-05-06
### Documentation
- Update README and CHANGELOG for v0.2.0 spec
### Features
- **error:** Add header and v0.3 payload error variants
- **payload:** Finalize v0.3 pack and unpack with full tests
- **api:** Implement header parsing and formatting
- **api:** Implement full v0.3 serialize and deserialize
### Miscellaneous tasks
- **deps:** Bump to v0.3.0
- Remove unused mut from lines iterator
### Refactoring
- **api:** Define v0.3 domain structs and stubs early to fix compilation
## [0.2.0] - 2026-05-06
### Bug Fixes
- **payload:** Correct CRC corruption test to target data bytes
### Documentation
- Spec
### Features
- **error:** Add rich error enum with thiserror
- **crc32:** Add pure-rust CRC32 IEEE implementation
- **v2:** Complete v2.0 implementation with I/O wrappers and tests
### Miscellaneous tasks
- **deps:** Bump to v0.2.0 and add thiserror
### Refactoring
- **lockfile:** Update Package hash to Vec<u8> and add API stubs
## [0.1.0] - 2026-05-06
### Bug Fixes
- **base64url:** Correct assert_eq expectation to match encode output
- **lockfile:** Derive Clone for Package struct
### Documentation
- Spec
- Add README, CHANGELOG, and .gitignore; untrack Cargo.lock
- Add README, CHANGELOG, and .gitignore; untrack Cargo.lock
### Features
- Add LEB128 varint encoder/decoder
- Add binary payload pack/unpack using varints
- Add Package struct and line serializer/parser
- Add lockfile file I/O and index resolution
### Miscellaneous tasks
- Resolve clippy manual_div_ceil and useless_vec lints
### Tests
- Expand unit and integration test coverage
<!-- generated by git-cliff -->
