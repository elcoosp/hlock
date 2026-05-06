# HLOCK

A blazing fast, zero-dependency (excluding `thiserror` for DX) Rust crate for serializing and deserializing the **HLOCK** (Hybrid Lockfile) format.

## The Problem
Traditional lockfiles (JSON, TOML, YAML) are deeply nested trees. This creates massive syntactic bloat (brackets, commas, indentation) and ruins `git diff` readability—a change deep in a dependency tree shifts all subsequent lines. Pure binary lockfiles solve the bloat but destroy `git diff` entirely and break supply chain security tooling.

## The Solution: HLOCK
HLOCK is a line-oriented, hybrid text/binary format.
- **Human & Git Friendly:** One package equals exactly one line. Adding or updating a package changes exactly one line in `git diff`.
- **Machine Optimized:** Version numbers and dependency arrays are packed into dense binary structures using Unsigned LEB128 (Varints) and Base64URL encoded directly onto the line.

### Format Example

    axios	AQIDAAAAAAAAAAAAAAAAAAAAAAAAAAA
    lodash	EBERAAAAAAAAAAAAAAAAAAAAAAAAAA
    react	EgIAAAAAAAAAAAAAAAAAAAAAAAAAAQ

The left side of the tab is the plain-text package name. The right side is a dense Base64URL payload containing a version header, the Semver, a dynamic-length integrity hash, dependency indices, and a CRC32 checksum.

## Usage

Add `hlock` to your `Cargo.toml`:

    [dependencies]
    hlock = "0.2.0"

### String API (Core)
The core logic is decoupled from the filesystem. You can serialize to a string and write it anywhere.

```rust
use hlock::{Package, serialize, deserialize};

let mut packages = vec![
    Package {
        name: "lodash".to_string(),
        major: 4,
        minor: 17,
        patch: 21,
        hash: vec![0xAA; 32], // e.g., full SHA-256 hash
        dependencies: vec![],
    },
    Package {
        name: "react".to_string(),
        major: 18,
        minor: 2,
        patch: 0,
        hash: vec![0xBB; 32],
        dependencies: vec!["lodash".to_string()],
    },
];

let lockfile_string = serialize(&mut packages).unwrap();
let parsed_packages = deserialize(&lockfile_string).unwrap();
```

### File I/O (Wrappers)
Thin wrappers are provided for standard filesystem operations.

```rust
use hlock::{Package, write_lockfile, read_lockfile};
use std::path::Path;

// write_lockfile and read_lockfile work exactly like the string API,
// but handle std::fs::write and std::fs::read_to_string for you.
write_lockfile(Path::new("hlock.lock"), &mut packages).unwrap();
let packages = read_lockfile(Path::new("hlock.lock")).unwrap();
```

### Error Handling
HLOCK v2.0 uses rich, context-aware errors to pinpoint exactly what went wrong in a lockfile.

```rust
use hlock::{deserialize, Error};

match deserialize("bad_base64\t!!!") {
    Err(Error::InvalidBase64 { line_number }) => {
        println!("Syntax error on line {}", line_number);
    }
    Err(Error::IntegrityCheckFailed { line_number }) => {
        println!("CRC32 mismatch on line {}", line_number);
    }
    _ => {}
}
```

## Under the Hood (v2.0 Spec)
1. **Payload Versioning:** Every binary payload starts with a `0x01` version byte, allowing future parsers to safely reject unsupported formats.
2. **Dynamic Hashes:** Instead of hardcoding a 16-byte truncated hash, the payload specifies the exact length of the hash, supporting SHA-256 (32 bytes), BLAKE3 (32 bytes), or anything else.
3. **CRC32 Checksums:** A 4-byte CRC32 IEEE checksum is appended to the end of every payload. If a line gets partially corrupted via a bad `git merge` or disk fault, `hlock` throws a precise `IntegrityCheckFailed` error instead of panicking.
4. **Index Mapping:** Dependencies are stored as references to 0-based line indices (taking 1-2 bytes) rather than full strings.
5. **Varint Encoding:** Semver numbers are packed using LEB128, meaning `v18.2.0` takes only 3 bytes instead of 6 characters.

## License
MIT
