# HLOCK

A binary lockfile format for package managers. Single lockfile, many platforms, tamper-proof by default.

## Features

- **Single Lockfile, Many Platforms** — Encode all packages for all targets in one `.hlock` file. Extract platform-specific subgraphs for installation.
- **Post-Quantum Ready** — ML-DSA-65 (FIPS 204) signatures alongside Ed25519. Dual-sign for graceful quantum transition.
- **Whole-Lockfile Integrity** — Optional `@digest` directive with BLAKE3 for instant change detection without parsing payloads.
- **Full Peer Lifecycle** — Record both *what* peer dependencies require and *how* they were resolved, enabling installers to re-validate topology without re-resolving.
- **Tamper-Proof by Default** — Ed25519 and ML-DSA-65 lockfile signing. CI pipelines verify lockfiles were produced by trusted identities before installing.
- **Typed Graph Queries** — Dependency-type-aware traversal: `runtime_deps()`, `dev_deps()`, `has_dep_path()`, and more. Production bundles exclude dev edges automatically.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
hlock = "0.13.0"
```

## File Format

```text
@source 0 https://registry.npmjs.org/
@override lodash 4.0.0 -> 4.17.21
@feature serde derive,rc

serde\tBwcXCh8KFQ...
app\tBwcXCh8KFQ...
@digest a3f2b7c1d4e5f6a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1
@signature ci@company.com 00 0 FYF9Siwdqj2GB7BkK6eR8Kkx6hSp1KkvXpS1m0B1-Jdc2J6jJ5EGZjZmT1wiGlElb58K9ZmFP6jcuOhjMw_Bw
```

Each package line is a tab-separated pair of the package name and a Base64URL-encoded binary payload containing: name, version, source index, integrity hashes, features, peer resolutions, peer requirements, platform tags, and dependencies — all with BLAKE3 integrity protection.

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
    artifacts: vec![],
    patches: vec![],
    packages: vec![/* ... */],
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

### Dependency-Type-Aware Queries

Separate production dependencies from development tooling:

```rust
use hlock::*;

let prod_deps = runtime_deps(&lockfile, "app");
let dev_deps = dev_deps(&lockfile, "app");

if has_dep_path(&lockfile, "app", "jest", DepType::Runtime) {
    // jest leaked into production graph — flag warning
}

let count = dep_count(&lockfile, "app", DepType::Peer);
```

### Lockfile Signing

Sign lockfiles in CI and verify before installation:

```rust
use hlock::*;
use ed25519_dalek::SigningKey;

let signing_key = SigningKey::from_bytes(&seed);
let serialized = serialize(&mut lockfile)?;

// Ed25519 signing
let signed = sign_lockfile(
    &serialized,
    "ci@company.com",
    SignatureAlgorithm::Ed25519,
    &seed,
    0,
)?;

// Verify before installing
let mut trusted: HashMap<String, (&[u8], SignatureAlgorithm)> = HashMap::new();
trusted.insert("ci@company.com".to_string(), (&public_key, SignatureAlgorithm::Ed25519));
verify_signature(&signed, &trusted)?;
```

### ML-DSA-65 Post-Quantum Signing

```rust
use hlock::*;
use fips204::traits::SerDes as FipsSerDes;

let (pk, sk) = fips204::ml_dsa_65::try_keygen().unwrap();
let sk_bytes = FipsSerDes::into_bytes(sk);
let vk_bytes = FipsSerDes::into_bytes(pk);

let signed = sign_lockfile(
    &serialized,
    "pq@company.com",
    SignatureAlgorithm::MlDsa65,
    &sk_bytes,
    0,
)?;
```

### Whole-Lockfile Digest

```rust
use hlock::*;

// validate_digest checks the @digest directive if present
validate_digest(&serialized)?;

// whole_lockfile_digest computes BLAKE3 of content before @digest/@signature
let digest = whole_lockfile_digest(&content);
```

### Diff Serialization

```rust
use hlock::*;

let diff = diff_lockfiles(&old, &new);

// Human-readable text
let text = serialize_diff(&diff, DiffFormat::Text);

// Machine-readable JSON for CI integration
let json = serialize_diff(&diff, DiffFormat::Json);
```

## Platform Tags

Native binaries declare their target platform. Pure JS/TS packages use an empty list (platform-agnostic).

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

match verify_signature(&content, &trusted_keys) {
    Ok(()) => { /* valid or no signature */ }
    Err(SignatureError::VerificationFailed) => { /* Ed25519 tampered */ }
    Err(SignatureError::MlDsaVerificationFailed) => { /* ML-DSA tampered */ }
    Err(SignatureError::MalformedDirective { .. }) => { /* bad @signature line */ }
    Err(SignatureError::UntrustedKey { .. }) => { /* key not in trusted set */ }
    Err(SignatureError::SignatureExpired { .. }) => { /* signature expired */ }
}
```

## License

MIT
