# HLOCK Specification v0.13.0

## 1. Overview

HLOCK v0.13.0 is **"The Post-Quantum & Diff Intelligence Release"**. It validates the algorithm agility design introduced in v0.12 by adding ML-DSA (Module-Lattice-Based Digital Signature Algorithm) post-quantum signatures, completes the graph module with dependency-type-aware queries, makes lockfile diffs machine-readable and CI-friendly, and adds a whole-lockfile digest for fast equality checks.

This is a non-breaking release from v0.12. The payload version byte remains `0x08`. The binary payload format is unchanged. All new functionality is additive — new graph functions, new signature algorithm IDs, new serialization for diffs, and a new optional header directive.

### Design Principles

- **Quantum Readiness** — ML-DSA-65 (FIPS 204, security level 2) is the first post-quantum signature algorithm. The v0.12 algorithm ID design makes this a one-line addition: `0x02 = ML-DSA-65`. Consumers can dual-sign with Ed25519 + ML-DSA for a graceful transition period.
- **Typed Graphs** — Not all dependency edges are equal. `devDependencies` should not appear in production bundles. `peerDependencies` are validation-only edges, not install edges. The graph module now respects `DepType`.
- **Diff as Data** — A lockfile diff is not just a debug log. It is a structured, serializable artifact suitable for machine consumption: dependabot comments, changelog generation, and audit trails.
- **One Hash to Rule Them All** — Per-payload BLAKE3 digests verify individual packages. Signatures verify authorship. The new whole-lockfile digest answers a simpler question: "Did this lockfile change?" in O(1) time.

---

## 2. File Structure

<<<text
<header directives>
<empty line>
<package lines>
<optional artifact directives>
<optional patch directives>
<optional digest directive>
<optional signature directives>
```

One structural addition: the `@digest` directive now appears after `@patch` lines and before `@signature` lines.

---

## 3. Header Directives

### 3.1 New Directive: `@digest`

<<<text
@digest <blake3_hex>
```

A single, optional directive containing the BLAKE3 hex digest (64 lowercase hex characters) of the entire lockfile content *excluding* the `@digest` line itself and all `@signature` lines.

**Rules:**
- At most one `@digest` directive is allowed. If present, it MUST appear after all package, `@artifact`, and `@patch` lines, and before any `@signature` lines.
- The digest covers bytes `[0..digest_line_start)`.
- Consumers that only need to check "did the lockfile change?" can compare this single hash without parsing any package payloads.
- If absent, consumers fall back to computing the digest themselves or doing full byte comparison.

**Why a directive and not a footer?** Directives are the established extension point. A directive can be parsed by the header parser without adding a new file section. It also makes the digest visible in `head -20 lockfile.hlock`.

### 3.2 Unchanged Directives

All v0.12 directives are unchanged: `@source`, `@override`, `@feature`, `@workspace-root`, `@workspace-pkg`, `@hoist-boundary`, `@metadata`, `@artifact`, `@patch`, `@signature`.

### 3.3 Signature Directive (Extended)

<<<text
@signature <key_id> <algo_id> <expires_epoch> <base64_sig>
```

| `algo_id` | Algorithm | Public Key Size | Signature Size | Private Key Size |
|---|---|---|---|---|
| `0x00` | Ed25519 | 32 bytes | 64 bytes | 32 bytes (seed) |
| `0x01` | Ed448 | 57 bytes | 114 bytes | 57 bytes |
| `0x02` | ML-DSA-65 | 1952 bytes | 3309 bytes | 2560 bytes |

ML-DSA-65 is FIPS 204 at security level 2 (roughly AES-128 equivalent). The key and signature sizes are large, but this is the nature of post-quantum cryptography. ML-DSA-44 (level 1) and ML-DSA-87 (level 3) are deferred to future releases — one algorithm per release validates the agility design without combinatorial complexity.

---

## 4. Content IDs

Unchanged. FNV-1a 64-bit hashes of `canonical_name@major.minor.patch`.

---

## 5. The Binary Payload (Unchanged from v0.12)

Version byte remains `0x08`. Layout, struct encoding, and BLAKE3 trailer are all unchanged. No payload format changes in v0.13.

---

## 6. Public API Specification

### 6.1 New Signature Algorithm Variant

<<<rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    Ed25519 = 0x00,
    Ed448 = 0x01,
    MlDsa65 = 0x02,  // NEW
}
```

### 6.2 Changes to `sign_lockfile`

The existing signature is extended to handle ML-DSA-65. No API change — the `algorithm` parameter already accepts `SignatureAlgorithm`.

<<<rust
pub fn sign_lockfile(
    serialized_lockfile: &str,
    key_id: &str,
    algorithm: SignatureAlgorithm,
    private_key: &[u8],
    expires_epoch: u64,
) -> Result<String, SignatureError>
```

For `MlDsa65`:
- `private_key` must be 2560 bytes (the ML-DSA-65 signing key).
- Produces a 3309-byte signature, Base64URL-encoded.
- Uses the `ml-dsa` crate with the `traits` feature for a uniform sign/verify interface.

### 6.3 Changes to `verify_signature`

No API change. The `SignatureAlgorithm::MlDsa65` variant is handled alongside Ed25519/Ed448.

### 6.4 Whole-Lockfile Digest

<<<rust
/// Computes the BLAKE3 digest of the lockfile content up to (but not including)
/// any @digest or @signature lines.
pub fn whole_lockfile_digest(content: &str) -> [u8; 32]

/// Validates the @digest directive in a lockfile, if present.
pub fn validate_digest(content: &str) -> Result<(), Error>
```

**Implementation:**

<<<rust
pub fn whole_lockfile_digest(content: &str) -> [u8; 32] {
    let boundary = find_digest_or_signature_boundary(content);
    blake3::hash(&content.as_bytes()[..boundary]).into_bytes()
}
```

Where `find_digest_or_signature_boundary` scans for the first line starting with `@digest ` or `@signature ` and returns the byte offset of that line.

### 6.5 Dependency-Type-Aware Graph Queries

Six new functions that filter edges by `DepType`. The existing v0.12 functions remain unchanged (they consider all edges).

<<<rust
pub fn runtime_deps(lockfile: &Lockfile, package_name: &str) -> HashSet<String>
pub fn dev_deps(lockfile: &Lockfile, package_name: &str) -> HashSet<String>
pub fn runtime_dependents_of(lockfile: &Lockfile, package_name: &str) -> Vec<String>
pub fn dev_dependents_of(lockfile: &Lockfile, package_name: &str) -> Vec<String>
pub fn has_dep_path(lockfile: &Lockfile, package_name: &str, target: &str, dep_type: DepType) -> bool
pub fn dep_count(lockfile: &Lockfile, package_name: &str, dep_type: DepType) -> usize
```

**Edge classification rules:**

| `DepType` | Graph behavior |
|---|---|
| `Runtime` | Standard install edge. Included in `runtime_deps`. |
| `Dev` | Build/test-only edge. Excluded from production bundles. |
| `Peer` | Validation-only edge. NOT followed in typed queries. Peer edges represent constraints, not install instructions. |
| `Optional` | Followed only if the target package is reachable via other edges (runtime or dev). |
| `OptionalTarget(os, arch)` | Same as `Optional`, plus platform filtering. |

The `Optional` and `OptionalTarget` behavior is the key subtlety: an optional dependency is only included if it is *already reachable* via non-optional edges.

<<<rust
fn is_optionally_reachable(
    lockfile: &Lockfile,
    from: usize,
    to: usize,
    non_optional_reachable: &HashSet<usize>,
) -> bool {
    // BFS from `from` following only Optional/OptionalTarget edges,
    // but only counting edges where `to` is in `non_optional_reachable`.
}
```

### 6.6 Lockfile Diff Serialization

<<<rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffFormat {
    Text,
    Json,
}

pub fn serialize_diff(diff: &LockfileDiff, format: DiffFormat) -> String
```

**Text format example:**

<<<text
LOCKFILE DIFF
  unchanged: 42 packages
  added: 3
    + lodash@4.17.21
    + react@18.3.1
    + react-dom@18.3.1
  removed: 1
    - axios@0.21.1
  altered: 2
    ~ webpack@5.70.0 -> webpack@5.75.0
    ~ typescript@4.9.0 -> typescript@5.0.0
```

**JSON format example:**

<<<json
{
  "unchanged_count": 42,
  "changes": [
    { "type": "added", "name": "lodash", "version": "4.17.21" },
    { "type": "added", "name": "react", "version": "18.3.1" },
    { "type": "removed", "name": "axios", "version": "0.21.1" },
    { "type": "altered", "name": "webpack", "old_version": "5.70.0", "new_version": "5.75.0" }
  ]
}
```

### 6.7 New Error Variants

<<<rust
// In Error:
#[error("@digest value does not match computed BLAKE3: expected {expected}, got {actual}")]
DigestMismatch { expected: String, actual: String },

#[error("Multiple @digest directives found")]
DuplicateDigestDirective,

// In SignatureError:
#[error("ML-DSA-65 verification failed")]
MlDsaVerificationFailed,
```

### 6.8 Re-exports

<<<rust
pub use graph::{
    topological_sort, dependents_of, transitive_deps,
    leaf_packages, detect_cycle, would_create_cycle,
    runtime_deps, dev_deps, runtime_dependents_of, dev_dependents_of,
    has_dep_path, dep_count,
};
pub use signature::{SignatureAlgorithm, SignatureDirective};
pub use lockfile::{whole_lockfile_digest, validate_digest, serialize_diff, DiffFormat};
```

---

## 7. Implementation Notes

### 7.1 ML-DSA-65 Integration

<<<rust
// In sign_lockfile, match arm:
SignatureAlgorithm::MlDsa65 => {
    let signing_key = ml_dsa::SigningKey::<ml_dsa::MlDsa65>::from_bytes(
        private_key.try_into().map_err(|_| SignatureError::MalformedDirective {
            reason: "ML-DSA-65 private key must be 2560 bytes".into(),
        })?,
    );
    let signature = signing_key.sign(serialized_lockfile.as_bytes());
    (0x02u8, base64url::encode(&signature.to_bytes()))
}

// In verify_signature, match arm:
SignatureAlgorithm::MlDsa65 => {
    let pk_bytes: [u8; 1952] = (*expected_pub_key).try_into().map_err(|_| ...)?;
    let sig_bytes: [u8; 3309] = directive.signature_bytes.as_slice().try_into().map_err(|_| ...)?;
    let verifying_key = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::from_bytes(&pk_bytes)?;
    let signature = ml_dsa::Signature::<ml_dsa::MlDsa65>::from_bytes(&sig_bytes)?;
    verifying_key.verify(message, &signature)
        .map_err(|_| SignatureError::MlDsaVerificationFailed)?;
}
```

### 7.2 Dependency-Type-Aware Traversal

The typed query functions share most logic with the existing untyped functions. The difference is the edge filter:

<<<rust
fn follows_edge(dep: &Dependency, query_type: DepType) -> bool {
    match query_type {
        DepType::Runtime => dep.dep_type == DepType::Runtime,
        DepType::Dev => dep.dep_type == DepType::Dev,
        _ => false,
    }
}
```

For `Optional`/`OptionalTarget`, the traversal is two-phase:
1. Compute the non-optional reachable set (Runtime + Dev edges).
2. Add optional edges where the target is in the non-optional set.

### 7.3 `@digest` Boundary Computation

<<<rust
fn find_digest_or_signature_boundary(content: &str) -> usize {
    match content.find("@digest ").or(content.find("@signature ")) {
        Some(offset) => offset,
        None => content.len(),
    }
}
```

### 7.4 Diff JSON Schema

The JSON output uses a flat schema for simplicity. Version strings are `major.minor.patch` formatted:

<<<rust
fn version_string(pkg: &Package) -> String {
    format!("{}.{}.{}", pkg.major, pkg.minor, pkg.patch)
}
```

---

## 8. Migration Guide (v0.12 -> v0.13)

### No Payload Changes

The binary payload format is identical. v0.13 can read v0.12 lockfiles and vice versa (for the payload portion).

### New Header Directive

The `@digest` directive is optional. v0.12 parsers that don't recognize it will produce an `Error::InvalidHeader` with reason "Unknown directive: @digest ...". To handle this gracefully, parsers should treat unknown `@` directives as warnings, not errors.

### Dual-Signing for Quantum Transition

<<<rust
let signed_ed25519 = sign_lockfile(&serialized, "ci@co.com", SignatureAlgorithm::Ed25519, &seed, 0)?;
let signed_both = sign_lockfile(&signed_ed25519, "pq@co.com", SignatureAlgorithm::MlDsa65, &pq_seed, 0)?;
```

This means dual-signing requires ALL verifiers to be upgraded to v0.13 and to trust both keys. The transition path is:

1. Add ML-DSA signing key to CI.
2. Dual-sign lockfiles.
3. Upgrade all verifiers to v0.13 with both keys trusted.
4. (Future) Remove Ed25519 signing once quantum threats are imminent.

### New Graph Functions

All new graph functions are additive. Existing code using v0.12 graph primitives continues to work.

<<<rust
// Before (v0.12):
let all_deps = transitive_deps(&lockfile, "app");

// After (v0.13):
let prod_deps = runtime_deps(&lockfile, "app");
```

### Diff Serialization

<<<rust
// Before (v0.12):
let diff = diff_lockfiles(&old, &new);

// After (v0.13):
let diff = diff_lockfiles(&old, &new);
let json = serialize_diff(&diff, DiffFormat::Json);
```

---

## 9. Dependencies

### New Crate Dependencies

<<<toml
[dependencies]
ml-dsa = { version = "0.1", features = ["traits"] }
serde_json = "1"
```

### Why `ml-dsa` and not `pqcrypto-ml-dsa`?

The `ml-dsa` crate is a pure-Rust implementation of FIPS 204 by the `rust-crypto` community. It has no C dependencies, supports `no_std`, and provides a `traits` feature compatible with the `signature` crate's `Signer`/`Verifier` traits. The `pqcrypto-*` crates wrap C implementations and have cross-compilation difficulties.
