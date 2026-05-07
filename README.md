# HLOCK

A binary lockfile format for package managers. Single lockfile, many platforms, tamper-proof by default.

## Features

- **Single Lockfile, Many Platforms** — Encode all packages for all targets in one `.hlock` file. Extract platform-specific subgraphs for installation.
- **Interface Integrity** — Lock the public export map of each module, making dependency confusion attacks cryptographically detectable.
- **Artifact Transparency** — Hash dynamically fetched or compiled platform-specific binaries, closing the "trusted post-link script" loophole.
- **Full Peer Lifecycle** — Record both *what* peer dependencies require and *how* they were resolved, enabling installers to re-validate topology without re-resolving.
- **Tamper-Proof by Default** — Optional Ed25519 lockfile signing. CI pipelines verify lockfiles were produced by trusted identities before installing.
- **Language Agnostic** — No assumptions about specific ecosystems. Hook names, export identifiers, and metadata are all raw strings.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hlock = "0.11.0"
```

## File Format

```text
@source 0 https://registry.npmjs.org/
@override lodash 4.0.0 -> 4.17.21
@feature serde derive,rc
@metadata license MIT
@metadata repository https://github.com/example/project

serde\tBwcXCh8KFQ...
app\tBwcXCh8KFQ...
@artifact 00000000deadbeef 01 01 ./binaries/app-linux-x64
@artifact 00000000deadbeef 02 02 ./binaries/app-darwin-arm64
@patch 00000000cafebabe 01 ./patches/fix.patch
@signature ci@company.com FYF9Siwdqj2GB7BkK6eR8Kkx6hSp1KkvXpS1m0B1-Jdc2J6jJ5EGZjZmT1wiGlElb58K9ZmFP6jcuOhjMw_Bw
```

Each package line is a tab-separated pair of the package name and a Base64URL-encoded binary payload containing: logical name, version, source index, integrity hashes, features, peer resolutions, dependencies, peer requirements, platform tags, exports, artifacts, and hook hashes — all with CRC32 integrity protection.

## Usage

### Serialize and Deserialize

```rust
use hlock::*;

let mut lockfile = Lockfile {
    sources: vec![Source::Registry("https://registry.npmjs.org/".into())],
    overrides: vec![],
    features: vec![],
    metadata: vec![],
    workspace_root: None,
    workspace_pkgs: vec![],
    hoist_boundaries: vec![],
    packages: vec![/* ... */],
    artifacts: vec![],
    patches: vec![],
};

let serialized = serialize(&mut lockfile)?;
let parsed = deserialize(&serialized)?;
```

### Platform-Aware Subgraph Extraction

A universal lockfile contains packages for all platforms. Extract only what the current host needs:

```rust
use hlock::*;

let app_cid = fnv::calculate("app@1.0.0");
let subgraph = extract_subgraph_platform(
    &lockfile,
    &[app_cid],
    TargetOS::Linux,
    TargetArch::X86_64,
)?;
// subgraph contains only linux-x86_64 compatible packages
```

### Ed25519 Signing

Sign lockfiles in CI and verify before installation:

```rust
use hlock::*;
use ed25519_dalek::SigningKey;

let signing_key = SigningKey::from_bytes(&seed);
let vk_bytes = *signing_key.verifying_key().as_bytes();

// Build expanded key: seed (32) || public_key (32)
let mut expanded_key = [0u8; 64];
expanded_key[..32].copy_from_slice(&seed);
expanded_key[32..].copy_from_slice(&vk_bytes);

let signed = sign_lockfile(&serialized, "ci@company.com", &expanded_key)?;

// Verify before installing
verify_signature(&signed, &vk_bytes)?;
```

### Interface Locking (Exports)

Lock the public export map of a module to detect dependency confusion:

```rust
use hlock::*;

let pkg = Package {
    name: "my-lib".into(),
    exports: vec![
        Export {
            identifier: "./core".into(),
            hash_algo: HashAlgorithm::Sha256,
            digest: vec![/* hash of resolved ./core file */],
        },
        Export {
            identifier: "./utils".into(),
            hash_algo: HashAlgorithm::Sha256,
            digest: vec![/* hash of resolved ./utils file */],
        },
    ],
    // ... other fields
};
```

### Artifact Verification

Declare platform-specific binaries with integrity hashes:

```rust
use hlock::*;

// In the binary payload:
let pkg = Package {
    name: "native-tool".into(),
    artifacts: vec![
        Artifact { os_id: 0x01, arch_id: 0x01, hash_algo: HashAlgorithm::Sha256, digest: vec![/* ... */] },
        Artifact { os_id: 0x02, arch_id: 0x02, hash_algo: HashAlgorithm::Sha256, digest: vec![/* ... */] },
    ],
    // ... other fields
};

// In the header:
let directive = ArtifactDirective {
    content_id: fnv::calculate("native-tool@1.0.0"),
    os_id: 0x01,
    arch_id: 0x01,
    relative_path: "./binaries/native-tool-linux-x64".into(),
};
```

## Platform Tags

Native binaries declare their target platform. Pure packages use an empty list (platform-agnostic).

| Tag | Meaning |
|-----|---------|
| `(Linux, X86_64)` | Only linux-x86_64 |
| `(Linux, Any)` | All linux architectures |
| `(Any, Aarch64)` | aarch64 on any OS |
| `(Any, Wasm32)` | Wasm on any OS |
| `[]` | Platform-agnostic (default) |

Multiple tags are OR'd — `[(Linux, X86_64), (MacOS, Aarch64)]` matches either platform.

## Error Handling

```rust
match extract_subgraph_platform(&lockfile, &[cid], TargetOS::Windows, TargetArch::X86_64) {
    Ok(sub) => { /* install sub */ }
    Err(Error::NoPackagesForPlatform { .. }) => { /* no compatible packages */ }
    Err(Error::RootContentIdMissing { content_id }) => { /* bad root */ }
    Err(e) => { /* other error */ }
}

match verify_signature(&content, &public_key) {
    Ok(()) => { /* valid or no signature */ }
    Err(SignatureError::VerificationFailed) => { /* tampered */ }
    Err(SignatureError::MalformedDirective { .. }) => { /* bad @signature line */ }
    Err(SignatureError::InvalidBase64(_)) => { /* bad encoding */ }
}
```

## License

MIT
