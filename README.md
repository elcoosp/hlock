<div align="center">
  <img src="docs/logo.png" alt="hlock Logo" width="300"/>
  <p>
    <strong>The supply-chain gate for npm.</strong><br/>
    One fast Rust binary that verifies, lints, audits and signs lockfiles —
    fast enough to run on every merge.
  </p>
  <p>
    <img src="https://img.shields.io/badge/version-1.0.0-000000?style=flat-square" alt="v1.0.0"/>
    <img src="https://img.shields.io/badge/Rust-2024%20edition-000000?style=flat-square&logo=rust" alt="Rust"/>
    <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="License MIT"/>
    <img src="https://img.shields.io/badge/Crypto-BLAKE3%20%2B%20Ed25519%20%2B%20ML--DSA--65-FFA500?style=flat-square" alt="Cryptography"/>
    <img src="https://img.shields.io/badge/Supply%20Chain-SBOM%20%2B%20VEX%20%2B%20SLSA-4B32C3?style=flat-square" alt="Supply Chain"/>
    <img src="https://img.shields.io/badge/Clippy-pedantic--clean-brightgreen?style=flat-square&logo=rust" alt="Clippy"/>
  </p>
</div>

---

> [!WARNING]
> **v1.0 is a breaking release.** There is no compatibility with the 0.x wire
> format or library API — lockfiles produced by 0.x are rejected at parse with
> a migration error. See [`docs/specs/v1.0.0.md`](docs/specs/v1.0.0.md) for
> the full specification and [CHANGELOG.md](CHANGELOG.md) for the release notes.

## Why hlock

npm locks versions but not *provenance*: anyone who can touch your lockfile —
or the registry mirror it resolves through — can swap the artifacts you ship.
`hlock` seals the lockfile itself:

- **BLAKE3 digest** over the canonical serialization (`@digest`, verified on
  every read by `verify` / `check` / `ci`).
- **Ed25519 or ML-DSA-65 (FIPS 204) signatures** (`@signature`), verified
  against the keys you pin.
- **Trust roots + verified key rotation** (`@trust-root`,
  `@trust-root-rotation`): rotation records must be signed by the *old* root
  key or `verify`/`check`/`ci` fail with `E0306`.
- **Package content ids** derived from domain-separated BLAKE3 with explicit
  collision detection (silent FNV aliasing is gone).
- **VEX suppression, SLSA attestations, SBOM (SPDX + CycloneDX), policy
  hooks/scripts dry-runs** — the whole gate in one tool.

## 60-second tour

```bash
cargo install --path .          # build the hlock binary

# 1. Bootstrap a sealed lockfile (+ root key) from package-lock.json
hlock init package-lock.json --from npm --with-trust-root --key-id ci@acme

# 2. Sign it with the generated root key
hlock sign hlock.lock --key-id ci@acme --algorithm ed25519 \
  --private-key @hlock.key --in-place

# 3. Run the one-shot gate in CI (verify + lint + audit)
hlock ci hlock.lock --trusted-key "ci@acme:ed25519:$(hlock keygen …)" 
```

## CLI commands

| Command | Purpose |
| :--- | :--- |
| `hlock init <pkg-lock> --from npm` | Import → digest → optional `--with-trust-root`. One command from `package-lock.json` to a sealed lockfile. |
| `hlock ci <file>` | **The gate.** verify + lint + audit with `--no-verify/--no-lint/--no-audit`, `--baseline`, aggregate JSON report. |
| `hlock verify <file>` | Digest, signatures, trust chain and rotation records. |
| `hlock check <file>` | Full report: digest + signature + trust chain + lint + audit (JSON). |
| `hlock audit <file>` | Vulnerabilities; `--baseline`/`--write-baseline` for a no-new-vulnerabilities policy; `--online` for OSV batch queries. |
| `hlock lint <file>` | 12-rule registry; `--rule`, `--severity`. |
| `hlock explain --list [filter]` | The lint registry as documentation; `explain <rule>` for the full writeup with examples. |
| `hlock trust list/rotate <file>` | Inspect trust roots; generate *signed* rotation records. |
| `hlock sign <file>` | Attach `@signature` (Ed25519 / ML-DSA-65). |
| `hlock fix <file>` | Auto-remediate; `--package <name> --to <version>` for targeted bumps. |
| `hlock outdated / licenses / sbom / stats / diff / merge / graph / tree / why / deps / dependents` | Analysis suite. `stats --dedup` replaces the old `dedup` command. |
| `hlock config` | Print the resolved configuration. |
| `hlock import / completions / keygen / digest / policy-test` | Utilities. |

Every JSON output is a stable envelope: `{"schema":"hlock/v1","command":…,"ok":…,"data":…,"error":…}`.
Global flags: `--json` (force JSON everywhere), `--quiet`, `--verbose`,
`--color auto|always|never` (plus `NO_COLOR`/`FORCE_COLOR`/`CLICOLOR_FORCE`),
`--config <file>`.

**Exit codes (uniform):** `0` success · `1` findings / verification failure ·
`2` usage, unreadable input, parse or config error.

## Configuration

`.hlockrc` (TOML), walked from the working directory, or `--config <file>`.
Invalid TOML is a hard error (`E0901`), a missing explicit config is `E0902`.

```toml
[lint]
rules = ["no-sha1", "require-integrity"]
exclude_rules = ["require-attestation"]

[verify]
trusted_keys = ["ci@acme:ed25519:2a…"]

[licenses]
deny = ["GPL-3.0"]
strict = true

[outdated]
check_major = true
timeout = 60

[import]
default_registry = "https://registry.npmjs.org/"

[output]
color = "auto"
```

CLI flags always win over the config file.

## Performance

`cargo run --release --example bench` — synthetic 5 000-package / 20 000-edge
lockfile (budgets from the spec §10):

| Operation | Measured | Budget |
| :--- | ---: | ---: |
| serialize | 3.5 ms | 250 ms |
| deserialize | 8.7 ms | 250 ms |
| graph build (CSR) | 4.6 ms | 100 ms |
| extract_subgraph | 11.1 ms | 100 ms |
| reachability (stats hot path) | 1.7 ms | 250 ms |
| SBOM (SPDX JSON) | 177.8 ms | 250 ms |
| lazy get_package × 5 000 | 8.8 ms | 250 ms |

What changed vs 0.x: one CSR adjacency (forward + reverse) answers every graph
query in O(V+E) instead of rebuilding name maps per call; `extract_subgraph`
dropped from ~O(n³) to linear BFS; cycle detection is iterative (no stack
overflow on 10k+ chains); `reachability` memoizes transitive closures as
bitsets via Tarjan SCC condensation; `merge` deduplicates by hash; the lazy
reader decodes the cid map once into an `OnceLock`.

## Library quickstart

```rust
use hlock::{deserialize, serialize, Graph, Lockfile};

let text = std::fs::read_to_string("hlock.lock")?;
let lockfile: Lockfile = deserialize(&text)?;

// One cached graph answers every structural question in O(V+E).
let graph = Graph::new(&lockfile)?;
let why = graph.all_paths_to_roots("lodash", 5);
let cycle = graph.detect_cycle();

// Platform-scoped extraction is a linear BFS now.
let sub = graph.extract_subgraph(&[hlock::cid::package_cid(&lockfile.packages[0])])?;
let out = serialize(&sub)?; // no &mut: the caller's data is never reordered
```

## Competitor positioning

| Capability | npm/yarn audit | socket cli | cargo-deny | **hlock 1.0** |
| :--- | :--- | :--- | :--- | :--- |
| Signed lockfile w/ PQC option | – | – | – | ✓ Ed25519 + ML-DSA-65 |
| Verified key rotation | – | – | – | ✓ |
| Policy hooks/scripts dry-run | – | partial | – | ✓ |
| VEX suppression | – | – | – | ✓ |
| SBOM (SPDX + CycloneDX) | – | – | – | ✓ |
| Baseline (no new vulns) | – | – | ✓ | ✓ |
| One-shot CI gate | partial | partial | partial | ✓ `hlock ci` |
| Monorepo workspaces | partial | – | n/a | ✓ |

## Development

```bash
cargo test                 # 550+ tests, all green
cargo clippy --all-targets -- -W clippy::pedantic   # 0 warnings
cargo fmt --check
cargo run --release --example bench                # perf gate
```

Layout: `src/lockfile/` (canonical format + digest), `src/payload.rs` (binary
wire format v0x10), `src/graph.rs` (CSR analysis engine), `src/signature.rs`
(Ed25519 / ML-DSA-65 + rotation payloads), `src/lazy.rs` (zero-copy scanner),
`src/commands/` (CLI), `docs/specs/v1.0.0.md` (the specification).
