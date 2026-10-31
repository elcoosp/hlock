<div align="center">
  <img src="docs/logo.png" alt="hlock Logo" width="300"/>
  <p>
    <strong>Trust But Verify</strong> — supply-chain lockfile integrity for the npm ecosystem.<br/>
    A Rust library and CLI tool providing binary lockfile serialization, BLAKE3 integrity digests, Ed25519/ML-DSA-65 signature verification, policy enforcement, SBOM generation, and vulnerability auditing.
  </p>
  <p>
    <img src="https://img.shields.io/badge/Rust-1.94%20%7C%202024-000000?style=flat-square&logo=rust" alt="Rust"/>
    <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License MIT"/>
    <img src="https://img.shields.io/badge/Ecosystem-npm-CC3534?style=flat-square&logo=npm" alt="npm"/>
    <img src="https://img.shields.io/badge/Crypto-BLAKE3%20%2B%20Ed25519-FFA500?style=flat-square" alt="Cryptography"/>
    <img src="https://img.shields.io/badge/Supply%20Chain-SBOM%20%2B%20VEX-4B32C3?style=flat-square" alt="Supply Chain"/>
    <img src="https://img.shields.io/badge/Build-Passing-brightgreen?style=flat-square&logo=githubactions" alt="Build"/>
  </p>
</div>

---

> [!IMPORTANT]
> `hlock` is designed to bring deterministic, cryptographically verifiable, and policy-driven lockfile management to the npm ecosystem, actively mitigating supply-chain attacks.

## Installation

Add `hlock` to your Rust project:

```toml
[dependencies]
hlock = "0.16"
```

## CLI Usage

The `hlock` CLI provides a comprehensive suite of commands for managing and verifying lockfiles.

| Command | Description | Example |
| :--- | :--- | :--- |
| **`verify`** | Verify lockfile integrity and trust chain. | `hlock verify lockfile.hlock --trusted-key ci@example.com:ed25519:2a2a...2a` |
| **`lint`** | Lint against the default rule set. | `hlock lint lockfile.hlock --severity warning --format json` |
| **`diff`** | Diff two lockfiles. | `hlock diff old.hlock new.hlock --format text` |
| **`audit`** | Audit for vulnerabilities. | `hlock audit lockfile.hlock --format json` |
| **`sbom`** | Generate a Software Bill of Materials. | `hlock sbom lockfile.hlock --namespace my-app --format spdx-json` |
| **`sign`** | Cryptographically sign a lockfile. | `hlock sign lockfile.hlock --key-id ci@company.com --algorithm ed25519 --private-key @/path/to/key --expires 1800000000 --in-place` |
| **`graph`** | Extract a dependency subgraph. | `hlock graph lockfile.hlock --root my-app --platform linux-x86_64 --output subgraph.hlock` |
| **`merge`** | Merge lockfile branches. | `hlock merge --base base.hlock --ours ours.hlock --theirs theirs.hlock --strategy ours --output merged.hlock` |

## Lockfile Format

A `hlock` lockfile is a line-oriented text format consisting of a header section, a package section, and an integrity digest.

```text
@source 0 https://registry.npmjs.org/
@trust-root ci@company.com 00 2a2a...2a 1735689600 root
@trust-root-rotation old@key.com new@key.com 1 00 2b2b...2b 1800000000 root old@key.com a1b2...f4
@mirror @internal https://npm.company.com/
@policy deny-hook * postinstall
@policy allow-hook lodash postinstall

lodash	CAQA...
react	CAQA...
@provenance lodash ^4.17.0 app 0 0 1
@advisory lodash GHSA-jf85-cq4p-4qr8 high https://github.com/... <4.17.21
@vex lodash CVE-2024-12345 not_affected vulnerable_code_not_in_execute_path not_applicable
@license lodash MIT
@digest abc123def456...
@signature ci@company.com 00 1735689600 BASE64SIG...
```

> [!NOTE]
> **Canonical Serialization Order (v0.16.0)**  
> To ensure deterministic hashing, the lockfile is strictly ordered:
> 1. **Header section**: `@source`, `@mirror`, `@policy`, `@trust-root`, `@trust-root-rotation`, `@override`, `@feature`, `@workspace-root`, `@workspace-pkg`, `@hoist-boundary`, `@metadata`
> 2. *(Empty line)*
> 3. **Package section**: `<name>\t<base64url-payload>` (sorted alphabetically by name), followed by `@artifact`, `@patch`, `@provenance`, `@advisory`, `@vex`, `@license`, `@digest`, and `@signature` (if present).

## Library Usage

Integrate `hlock` directly into your Rust applications for programmatic lockfile handling:

```rust
use hlock::{serialize, deserialize, validate_digest, Lockfile, Source};

let mut lockfile = Lockfile {
    sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
    ..Default::default()
};

let serialized = serialize(&mut lockfile)?;
validate_digest(&serialized)?;
let parsed = deserialize(&serialized)?;
```

## Reference

### Lint Rules

| Rule | Severity | Description |
| :--- | :---: | :--- |
| `no-git-urls` | Error | Rejects git URL sources (non-reproducible) |
| `require-integrity` | Error | Requires integrity hashes for non-workspace packages |
| `no-known-vulnerabilities` | Error | Flags packages with critical/high advisories |
| `require-license` | Error | Flags packages without license declarations |
| `require-trust-root` | Error | Requires at least one root trust key |
| `no-expired-keys` | Error | Flags expired trust root keys |
| `no-sha1` | Warning | Flags deprecated SHA-1 hashes |
| `no-peer-as-runtime` | Warning | Flags peer dependencies declared as runtime |
| `max-depth` | Warning | Flags packages deeper than 5 levels |
| `deny-copyleft` | Warning | Flags copyleft licenses (GPL, AGPL, LGPL) |
| `deny-postinstall` | Warning | Flags packages with postinstall hooks |
| `require-attestation` | Info | Flags packages without supply chain attestation |

### Signature Algorithms

| Algorithm | ID | Key Length | Signature Length |
| :--- | :---: | :--- | :--- |
| **Ed25519** | `0x00` | 32 bytes | 64 bytes |
| **ML-DSA-65** | `0x02` | 1952 bytes | 3309 bytes |

> [!WARNING]
> Algorithm ID `0x01` is reserved (was Ed448, never implemented).

### VEX Statuses

Vulnerability Exploitability eXchange (VEX) statuses determine how advisories are handled during an audit.

| Status | Effect on Audit |
| :--- | :--- |
| `not_affected` | Excluded from `effective_advisories` |
| `fixed` | Excluded from `effective_advisories` |
| `affected` | Included in `effective_advisories` |
| `under_investigation` | Included in `effective_advisories` |

## Development

### Building
```sh
cargo build --release
```

### Testing
```sh
cargo nextest run --workspace
cargo clippy --workspace --tests -- -D warnings
```

### Fuzzing
```sh
cargo fuzz run fuzz_unpack_payload
cargo fuzz run fuzz_deserialize
```
