# HLOCK

**HLOCK** is a binary-encoded, content-addressable lockfile format designed for modern package managers. It provides cryptographically verifiable integrity, first-class peer dependency topology tracking, zero-conflict package aliasing, and content-addressable storage (CAS) source URIs.

## Version

Current release: **v0.8.0** — *The Monorepo Topology Release*

> **Breaking:** All backward compatibility with v0.05 and older payloads has been permanently dropped. Parsers MUST reject any payload version less than `0x06`.

## Features

- **Binary Payloads** — Compact, CRC32-integrity-checked binary encoding with Base64URL transport encoding
- **Content-Addressable Dependencies** — Dependencies referenced by FNV-1a 64-bit hashes of `name@version`, guaranteeing merge-safety
- **Zero-Conflict Aliasing** — Install multiple versions of the same package simultaneously via logical names (e.g., `react-v18` alongside `react@19`)
- **Peer Dependency Topology** — Explicit records of how peer dependencies are satisfied, including hoist hints
- **SLSA Provenance** — Inline or external bundle attestation on integrity hashes
- **CAS Source URIs** — `cas+https://` and `ipfs://` source schemes for registry-free fetching
- **Sparse Subgraph Extraction** — Extract only the transitive closure of a root package, with automatic source pruning
- **Lockfile Diffing** — Sorted merge-based diff producing added/removed/altered change sets

## File Structure

<<<text
<header directives>
<empty line>
<package lines>
<<<

### Header Directives

<<<text
@source <idx> <uri>
@override <name> <ver> -> <ver>
@feature <name> [flag1,flag2,...]
<<<

#### Source URI Schemes

| Scheme | Example |
|---|---|
| Registry (default) | `https://registry.npmjs.org/` |
| Local | `file:///path/to/pkg` or `/absolute/path` |
| Git | `git://...` or `https://.../*.git` |
| Workspace | `workspace` |
| CAS HTTP | `cas+https://cas.my-company.com/` |
| IPFS | `ipfs://QmXyZ1...` |

### Package Lines

Each line is `canonical_name<TAB>base64url(payload)`.

## Binary Payload Layout (v0.8)

| Field | Type | Description |
|---|---|---|
| Version | Byte | MUST be `0x06` |
| LogicalNameLen | Varint | Length of logical name; `0` means none |
| LogicalName | Bytes | Import name (e.g., `react-v18`) |
| SourceIdx | Varint | Index into `@source` table |
| Major / Minor / Patch | Varint | Canonical semver components |
| HashCount | Varint | Number of integrity hashes |
| Hashes | Array | `(AlgoId, Len, Digest, Attestation)` structs |
| FeatureCount | Varint | Number of local feature strings |
| Features | Array | `(VarintLen, UTF-8 Bytes)` pairs |
| PeerCount | Varint | Number of resolved peer dependencies |
| Peers | Array | `(NameLen, Name, ContentID[8], IsHoisted)` structs |
| DepCount | Varint | Number of direct dependencies |
| Dependencies | Array | `(ContentID[8], DepType, [OS, Arch], ReqFeatIndices)` structs |
| CRC32 | 4 bytes LE | IEEE 802.3 checksum of all preceding bytes |

### Hash Algorithms

| ID | Algorithm |
|---|---|
| 0x00 | SHA-1 |
| 0x01 | SHA-256 |
| 0x02 | SHA-512 |
| 0x03 | BLAKE3 |

### Attestation Types

| ID | Type | Layout |
|---|---|---|
| 0x00 | None | (empty) |
| 0x01 | External Bundle SHA-256 | 32 bytes |
| 0x02 | Inline SLSA | `(BuilderLen, Builder, SourceLen, Source)` |

### Dependency Types

| ID | Type | Extra Fields |
|---|---|---|
| 0x00 | Runtime | — |
| 0x01 | Dev | — |
| 0x02 | Peer | — |
| 0x03 | Optional | — |
| 0x04 | Optional Target | `target_os: u8`, `target_arch: u8` |

## Rust API

<<<rust
use hlock::*;

// Parse an existing lockfile
let lockfile = read_lockfile("hlock.lock")?;

// Build a lockfile programmatically
let mut lockfile = Lockfile {
    sources: vec![Source::Registry("https://registry.npmjs.org/".into())],
    overrides: vec![],
    features: vec![],
    packages: vec![
        Package {
            name: "react".into(),
            logical_name: Some("react-v18".into()),
            source_idx: 0,
            major: 18, minor: 2, patch: 0,
            hashes: vec![IntegrityHash {
                algo: HashAlgorithm::Sha256,
                digest: vec![0; 32],
                attestation: Attestation::InlineSlsa(SlsaPredicate {
                    builder: "github.com/actions".into(),
                    source: "git+https://github.com/facebook/react".into(),
                }),
            }],
            features: vec!["jsx".into()],
            resolved_peers: vec![PeerResolution {
                peer_name: "react-dom".into(),
                satisfied_by_content_id: fnv::calculate("react-dom@18.2.0"),
                is_hoisted_to_root: true,
            }],
            dependencies: vec![],
        },
    ],
};

// Serialize and write
write_lockfile("hlock.lock", &mut lockfile)?;

// Diff two lockfiles
let diff = diff_lockfiles(&old, &new);

// Extract a sparse subgraph by content ID
let subgraph = extract_subgraph(&lockfile, &[root_cid])?;

// Low-level string API
let serialized = serialize(&mut lockfile)?;
let parsed = deserialize(&serialized)?;
<<<

## Content IDs

Dependencies are referenced by FNV-1a 64-bit hashes of `canonical_name@major.minor.patch`. This guarantees merge-safety even when logical names are aliased.

<<<rust
use hlock::fnv;

let cid = fnv::calculate("react@18.2.0");
<<<

## Zero-Conflict Aliasing

To run React v18 and v19 simultaneously:

1. Canonical package: `react@19.0.0` (no logical name)
2. Alias package: `react@18.2.0` with `logical_name: Some("react-v18")`
3. Unmigrated dependencies point their Content ID to `react@18.2.0`
4. Installer creates `node_modules/react-v18` symlink to the v18 cache folder

## CAS Fetching

When `Source::CasHttp(endpoint)` is used, the fetcher constructs `GET {endpoint}/{sha256_of_digest}`. The integrity hash digest serves directly as the cache key, bypassing registry index lookups entirely.

## License

MIT
