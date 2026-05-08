# hlock

**Trust But Verify** — supply-chain lockfile integrity for the npm ecosystem.

hlock is a Rust library and CLI tool that provides binary lockfile serialization, BLAKE3 integrity digests, Ed25519/ML-DSA-65 signature verification, policy enforcement, SBOM generation, and vulnerability auditing.

```toml
[dependencies]
hlock = "0.16"
```

## CLI Usage

### Verify lockfile integrity and trust chain

```sh
hlock verify lockfile.hlock --trusted-key ci@example.com:ed25519:2a2a...2a
```

### Lint against default rule set

```sh
hlock lint lockfile.hlock --severity warning --format json
```

### Diff two lockfiles

```sh
hlock diff old.hlock new.hlock --format text
```

### Audit for vulnerabilities

```sh
hlock audit lockfile.hlock --format json
```

### Generate SBOM

```sh
hlock sbom lockfile.hlock --namespace my-app --format spdx-json
```

### Sign a lockfile

```sh
hlock sign lockfile.hlock --key-id ci@company.com --algorithm ed25519 --private-key @/path/to/key --expires 1800000000 --in-place
```

### Extract dependency subgraph

```sh
hlock graph lockfile.hlock --root my-app --platform linux-x86_64 --output subgraph.hlock
```

### Merge branches

```sh
hlock merge --base base.hlock --ours ours.hlock --theirs theirs.hlock --strategy ours --output merged.hlock
```

## Lockfile Format

A hlock lockfile is a line-oriented text format with a header section, a package section, and an integrity digest.

```
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

### Canonical Serialization Order (v0.16.0)

```
Header section:
  @source
  @mirror
  @policy
  @trust-root
  @trust-root-rotation
  @override
  @feature
  @workspace-root
  @workspace-pkg
  @hoist-boundary
  @metadata
  <empty line>

Package section:
  <name>\t<base64url-payload>    (sorted by name)
  @artifact
  @patch
  @provenance
  @advisory
  @vex
  @license
  @digest
  @signature                   (if present)
```

## Library Usage

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

## Lint Rules

| Rule | Severity | Description |
|---|---|---|
| `no-git-urls` | Error | Rejects git URL sources (non-reproducible) |
| `require-integrity` | Error | Requires integrity hashes for non-workspace packages |
| `no-sha1` | Warning | Flags deprecated SHA-1 hashes |
| `no-peer-as-runtime` | Warning | Flags peer deps declared as runtime |
| `max-depth` | Warning | Flags packages deeper than 5 levels |
| `require-attestation` | Info | Flags packages without supply chain attestation |
| `no-known-vulnerabilities` | Error | Flags packages with critical/high advisories |
| `require-license` | Error | Flags packages without license declarations |
| `deny-copyleft` | Warning | Flags copyleft licenses (GPL, AGPL, LGPL) |
| `require-trust-root` | Error | Requires at least one root trust key |
| `no-expired-keys` | Error | Flags expired trust root keys |
| `deny-postinstall` | Warning | Flags packages with postinstall hooks |

## Signature Algorithms

| Algorithm | ID | Key Length | Signature Length |
|---|---|---|---|
| Ed25519 | `0x00` | 32 bytes | 64 bytes |
| ML-DSA-65 | `0x02` | 1952 bytes | 3309 bytes |

Algorithm ID `0x01` is reserved (was Ed448, never implemented).

## VEX Statuses

| Status | Effect on Audit |
|---|---|
| `not_affected` | Excluded from `effective_advisories` |
| `fixed` | Excluded from `effective_advisories` |
| `affected` | Included in `effective_advisories` |
| `under_investigation` | Included in `effective_advisories` |

## Building

```sh
cargo build --release
```

## Testing

```sh
cargo nextest run --workspace
cargo clippy --workspace --tests -- -D warnings
```

## Fuzzing

```sh
cargo fuzz run fuzz_unpack_payload
cargo fuzz run fuzz_deserialize
```

## License

MIT
