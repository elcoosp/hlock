# HLOCK

A blazing fast, zero-dependency (excluding `thiserror` for DX) Rust crate for serializing and deserializing the **HLOCK** (Hybrid Lockfile) format.

## The Problem
Traditional lockfiles (JSON, TOML, YAML) are deeply nested trees. This creates massive syntactic bloat (brackets, commas, indentation) and ruins `git diff` readability—a change deep in a dependency tree shifts all subsequent lines. Pure binary lockfiles solve the bloat but destroy `git diff` entirely and break supply chain security tooling.

## The Solution: HLOCK
HLOCK is a line-oriented, hybrid text/binary format.
- **Human & Git Friendly:** One package equals exactly one line. Adding or updating a package changes exactly one line in `git diff`.
- **Machine Optimized:** Version numbers, dependency profiles, and source indices are packed into dense binary structures using Unsigned LEB128 (Varints) and Base64URL encoded directly onto the line.
- **Rich Metadata:** Supports multiple registries, local paths, git sources, and dev/prod dependency profiles via a clean file header.

### Format Example

    @source 0 https://registry.npmjs.org/
    @source 1 https://packages.my-company.com/
    @override react 18.2.0 -> 18.2.1

    axios	AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAA
    lodash	EBERAAAAAAAAAAAAAAAAAAAAAAAAAA
    react	EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ

The file is split into a **Header** (sources and overrides) and a **Package Graph** (one tab-delimited package per line). The right side of the tab is a dense Base64URL payload containing a version header, a source index, the Semver, a dynamic-length integrity hash, dependency indices with profile types, and a CRC32 checksum.

## Usage

Add `hlock` to your `Cargo.toml`:

    [dependencies]
    hlock = "0.3.0"

### String API (Core)
The core logic is decoupled from the filesystem. You serialize a unified `Lockfile` struct to a string.

```rust
use hlock::{Lockfile, Package, Source, DepType, Dependency, serialize, deserialize};

let mut lockfile = Lockfile {
    sources: vec![
        Source::Registry("https://registry.npmjs.org/".to_string()),
    ],
    overrides: vec![],
    packages: vec![
        Package {
            name: "lodash".to_string(),
            source_idx: 0,
            major: 4, minor: 17, patch: 21,
            hash: vec![0xAA; 32],
            dependencies: vec![],
        },
        Package {
            name: "react".to_string(),
            source_idx: 0,
            major: 18, minor: 2, patch: 0,
            hash: vec![0xBB; 32],
            dependencies: vec![
                Dependency { name: "lodash".to_string(), dep_type: DepType::Runtime }
            ],
        },
        Package {
            name: "jest".to_string(),
            source_idx: 0,
            major: 29, minor: 0, patch: 0,
            hash: vec![0xCC; 32],
            dependencies: vec![
                Dependency { name: "react".to_string(), dep_type: DepType::Peer }
            ],
        },
    ],
};

let lockfile_string = serialize(&mut lockfile).unwrap();
let parsed_lockfile = deserialize(&lockfile_string).unwrap();
```

### File I/O (Wrappers)
Thin wrappers are provided for standard filesystem operations.

```rust
use hlock::{write_lockfile, read_lockfile};
use std::path::Path;

write_lockfile(Path::new("hlock.lock"), &mut lockfile).unwrap();
let parsed_lockfile = read_lockfile(Path::new("hlock.lock")).unwrap();
```

### Error Handling
HLOCK uses rich, context-aware errors to pinpoint exactly what went wrong in a lockfile.

```rust
use hlock::{deserialize, Error};

match deserialize("bad_base64\t!!!") {
    Err(Error::InvalidBase64 { line_number }) => {
        println!("Syntax error on line {}", line_number);
    }
    Err(Error::MissingSource { line_number, index }) => {
        println!("Line {} references undefined source {}", line_number, index);
    }
    Err(Error::UnknownDepType { line_number, type_id }) => {
        println!("Line {} has invalid dependency profile {}", line_number, type_id);
    }
    _ => {}
}
```

## Under the Hood (v0.3.0 Spec)
1. **File Headers:** The top of the file defines `@source` indices (deduplicating registry URLs) and `@override` substitution rules.
2. **Dependency Profiles:** Instead of just an array of line indices, each dependency in the binary payload is a tuple of `(LineIndex, DepType)`, allowing parsers to distinguish between `Runtime`, `Dev`, `Peer`, and `Optional` dependencies.
3. **Source Mapping:** Each package payload includes a `source_idx` pointing back to the header, allowing monorepos to fetch packages from multiple registries or local paths simultaneously.
4. **Dynamic Hashes:** The payload specifies the exact length of the hash, supporting SHA-256 (32 bytes), BLAKE3 (32 bytes), or anything else.
5. **CRC32 Checksums:** A 4-byte CRC32 IEEE checksum is appended to the end of every payload to catch corruption.

## License
MIT
