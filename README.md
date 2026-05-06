# HLOCK

A blazing fast, zero-dependency (excluding `thiserror` for DX) Rust crate for serializing and deserializing the **HLOCK** (Hybrid Lockfile) format.

## The Problem
Traditional lockfiles (JSON, TOML, YAML) are deeply nested trees. This creates massive syntactic bloat (brackets, commas, indentation) and ruins `git diff` readability—a change deep in a dependency tree shifts all subsequent lines. Pure binary lockfiles solve the bloat but destroy `git diff` entirely and break supply chain security tooling.

## The Solution: HLOCK
HLOCK is a line-oriented, hybrid text/binary format.
- **Human & Git Friendly:** One package equals exactly one line. Adding or updating a package changes exactly one line in `git diff`.
- **Machine Optimized:** Version numbers, dependency profiles, and source indices are packed into dense binary structures using Unsigned LEB128 (Varints) and Base64URL encoded directly onto the line.
- **Rich Metadata:** Supports multiple registries, local paths, git sources, workspace monorepos, and dev/prod dependency profiles via a clean file header.
- **Cryptographic Flexibility:** Supports attaching multiple integrity hashes (e.g., SHA-256 and BLAKE3) to a single package to satisfy modern supply chain standards.

### Format Example

    @source 0 https://registry.npmjs.org/
    @source 1 workspace
    @override react 18.2.0 -> 18.2.1

    local-core	AgIAAAAAAAAAAAAAAAAAAAAAAAAAAA
    axios	AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAA
    react	EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ

The file is split into a **Header** (sources, workspaces, and overrides) and a **Package Graph** (one tab-delimited package per line). The right side of the tab is a dense Base64URL payload containing a version header, a source index, the Semver, an array of typed integrity hashes, dependency indices with profile types, and a CRC32 checksum.

## Usage

Add `hlock` to your `Cargo.toml`:

    [dependencies]
    hlock = "0.4.0"

### String API (Core)
The core logic is decoupled from the filesystem. You serialize a unified `Lockfile` struct to a string.

```rust
use hlock::{Lockfile, Package, Source, DepType, Dependency, HashAlgorithm, IntegrityHash, serialize, deserialize};

let mut lockfile = Lockfile {
    sources: vec![
        Source::Registry("https://registry.npmjs.org/".to_string()),
        Source::Workspace,
    ],
    overrides: vec![],
    packages: vec![
        Package {
            name: "local-core".to_string(),
            source_idx: 1, // Points to Workspace
            major: 1, minor: 0, patch: 0,
            hashes: vec![], // Workspace packages must NOT have hashes
            dependencies: vec![],
        },
        Package {
            name: "lodash".to_string(),
            source_idx: 0, // Points to Registry
            major: 4, minor: 17, patch: 21,
            hashes: vec![
                IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![0xAA; 32] },
                IntegrityHash { algo: HashAlgorithm::Blake3, digest: vec![0xBB; 32] },
            ],
            dependencies: vec![],
        },
        Package {
            name: "react".to_string(),
            source_idx: 0,
            major: 18, minor: 2, patch: 0,
            hashes: vec![IntegrityHash { algo: HashAlgorithm::Sha256, digest: vec![0xCC; 32] }],
            dependencies: vec![
                Dependency { name: "lodash".to_string(), dep_type: DepType::Runtime }
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
    Err(Error::InvalidWorkspaceHash { line_number }) => {
        println!("Line {}: Workspace packages cannot have integrity hashes", line_number);
    }
    Err(Error::UnknownHashAlgorithm { line_number, algo_id }) => {
        println!("Line {}: Invalid hash algorithm {}", line_number, algo_id);
    }
    _ => {}
}
```

## Under the Hood (v0.4.0 Spec)
1. **File Headers:** The top of the file defines `@source` indices (deduplicating registry URLs, defining workspaces) and `@override` substitution rules.
2. **Workspace Support:** Introduces `@source <idx> workspace`. Packages pointing here bypass remote fetching and strictly enforce that they possess zero integrity hashes.
3. **Multi-Algorithm Hashes:** Instead of a single hash byte array, the payload encodes an array of structs: `(AlgoId, Len, Digest)`. This allows a package to be verified against multiple cryptographic standards simultaneously.
4. **Dependency Profiles:** Each dependency in the binary payload is a tuple of `(LineIndex, DepType)`, allowing parsers to distinguish between `Runtime`, `Dev`, `Peer`, and `Optional` dependencies.
5. **Source Mapping:** Each package payload includes a `source_idx` pointing back to the header, allowing monorepos to fetch packages from multiple registries or local paths simultaneously.
6. **CRC32 Checksums:** A 4-byte CRC32 IEEE checksum is appended to the end of every payload to catch corruption.

## License
MIT
