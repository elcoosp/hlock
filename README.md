# HLOCK

A blazing fast, zero-dependency Rust crate for serializing and deserializing the **HLOCK** (Hybrid Lockfile) format.

## The Problem
Traditional lockfiles (JSON, TOML, YAML) are deeply nested trees. This creates massive syntactic bloat (brackets, commas, indentation) and ruins `git diff` readability—a change deep in a dependency tree shifts all subsequent lines. Pure binary lockfiles solve the bloat but destroy `git diff` entirely and break supply chain security tooling.

## The Solution: HLOCK
HLOCK is a line-oriented, hybrid text/binary format.
- **Human & Git Friendly:** One package equals exactly one line. Adding or updating a package changes exactly one line in `git diff`.
- **Machine Optimized:** Version numbers and dependency arrays are packed into dense binary structures using Unsigned LEB128 (Varints) and Base64URL encoded directly onto the line.

### Format Example
```text
axios	AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAA
lodash	EBERAAAAAAAAAAAAAAAAAAAAAAAAAA
react	EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ
```

The left side of the tab is the plain-text package name. The right side is a dense Base64URL payload containing the Semver (3 bytes), a 128-bit integrity hash (16 bytes), and a list of dependency indices (1 byte per dependency).

## Usage

Add `hlock` to your `Cargo.toml`:

```toml
[dependencies]
hlock = "0.1.0"
```

### Writing a Lockfile
```rust
use hlock::{Package, write_lockfile};
use std::path::Path;

let packages = vec![
    Package {
        name: "lodash".to_string(),
        major: 4,
        minor: 17,
        patch: 21,
        hash: [0xAA; 16], // e.g., first 16 bytes of SHA-256
        dependencies: vec![],
    },
    Package {
        name: "react".to_string(),
        major: 18,
        minor: 2,
        patch: 0,
        hash: [0xBB; 16],
        dependencies: vec!["lodash".to_string()],
    },
];

write_lockfile(Path::new("hlock.lock"), packages).unwrap();
```

### Reading a Lockfile
```rust
use hlock::read_lockfile;

let packages = read_lockfile(Path::new("hlock.lock")).unwrap();

for pkg in packages {
    println!("{} v{}.{}.{}", pkg.name, pkg.major, pkg.minor, pkg.patch);
    for dep in pkg.dependencies {
        println!("  - depends on: {}", dep);
    }
}
```

## Under the Hood
1. **Index Mapping:** When writing, packages are sorted alphabetically and assigned a 0-based line index. Dependencies are stored as references to these indices (taking 1-2 bytes) rather than full strings.
2. **Varint Encoding:** Semver numbers are packed using LEB128, meaning `v18.2.0` takes only 3 bytes instead of 6 characters.
3. **Payload Packing:** The binary payload (Varints + Hash + Indices) is constructed, then encoded to Base64URL (RFC 4648 §5) without padding to safely append to the text line.

## License
MIT
