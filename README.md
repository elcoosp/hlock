# HLOCK

A blazing fast, merge-safe, binary-packed lockfile format for package managers.

## Overview

HLOCK is designed to solve the fundamental issues with JSON/YAML lockfiles in large monorepos:
1. **Merge Conflicts:** Replaced by deterministic Content-Addressable IDs (FNV-1a 64-bit).
2. **Bloat:** Replaced by highly optimized binary payloads encoded in Base64URL.
3. **Monorepo CI:** Native APIs for semantic diffing and sparse subgraph extraction.

## Binary Payload

Package metadata is stored in a compact binary format (Base64URL encoded in the text file) with a CRC32 integrity checksum.

```text
package_name\tBQAAAE...base64url...\n
```

## Features (v0.5.0)

### Content-Addressable IDs
Dependencies are referenced by a 64-bit hash of `name@version`, not array indices. This means two developers adding completely different dependency trees on separate branches will experience zero textual conflicts during `git merge`.

### Platform-Targeted Dependencies
Native support for optional dependencies that only apply to specific OS/Arch combinations (e.g., fetch `esbuild` binaries only for `x86_64-linux`).

### Local Feature Tables
Packages explicitly define their feature flags locally, and dependencies request features by index, keeping payloads incredibly small.

## Monorepo Graph APIs (v0.6.0)

Because packages are sorted alphabetically and use Content IDs, HLOCK exposes lightning-fast `O(N)` graph manipulation algorithms.

### Semantic Diffing
Find out exactly what changed between two lockfiles without doing string comparisons.

```rust
use hlock::*;

let diff = diff_lockfiles(&old_lockfile, &new_lockfile);
for change in &diff.changes {
    match change {
        PackageChange::Added(p) => println!("Fetch: {}", p.name),
        PackageChange::Removed(p) => println!("Delete: {}", p.name),
        PackageChange::Altered(o, n) => println!("Update {} to {}.{}.{}", o.name, n.major, n.minor, n.patch),
    }
}
```

### Sparse Subgraph Extraction
Extract a fully valid, standalone lockfile containing *only* the transitive dependencies of a specific workspace package. Perfect for zero-dependency CI.

```rust
use hlock::*;

let root_cid = fnv::calculate("apps/web@1.0.0");
let sparse_lockfile = extract_subgraph(&full_lockfile, &[root_cid])?;

// sparse_lockfile now only contains what 'apps/web' needs.
// Write it to disk and pass it to your package fetcher.
```

## File Structure

```text
@source 0 https://registry.npmjs.org/
@source 1 workspace
@feature serde derive,rc

<empty line>

serde	BQAAAE...base64url...
app    BQAAAE...base64url...
```

## Rust Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
hlock = "0.6"
```

### Reading & Writing

```rust
use hlock::*;
use std::path::Path;

let mut lockfile = Lockfile {
    sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
    overrides: vec![],
    features: vec![],
    packages: vec![/* ... */],
};

write_lockfile(Path::new("hlock.lock"), &mut lockfile)?;
let read_lockfile = read_lockfile(Path::new("hlock.lock"))?;
```

## Performance

HLOCK is designed for zero-allocation parsing where possible. The binary payload structure avoids the massive string allocation overhead inherent to parsing large JSON lockfiles (e.g., a 50MB `package-lock.json`).

## License

MIT
