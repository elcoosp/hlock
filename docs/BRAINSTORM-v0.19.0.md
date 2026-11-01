# hlock v0.19.0 — Improvement Brainstorm

> Outcome of a full-codebase review (performance, modularity, DRY, KISS, and
> complementary features). Everything listed under "Adopted" was implemented in
> this release; items under "Deferred" were considered and consciously parked.

## 1. Performance

### Adopted
- **P1 — Package index for hot paths.** The CLI `tree` walker re-scanned the
  package list per dependency edge, making rendering O(n²) on large lockfiles.
  It now builds `Lockfile::package_index()` (a name→index HashMap) once and
  resolves every node in O(1). `Lockfile::find_package()` replaces ad-hoc
  linear scans in the library as well.
- **P2 — Pre-allocated serialization buffers.** `serialize` now sizes its
  `String` from the package count before writing; `bytes_to_hex` allocates
  exactly `len * 2`.
- **P3 — Hex/hot-path helpers.** `bytes_to_hex` is a single implementation with
  capacity (no intermediate `format!` per byte); `sbom`/`header` reuse it
  instead of rebuilding iterator pipelines.
- **P4 — Boxed diff variants.** `PackageChange` now stores `Box<Package>`; the
  enum shrank from ~200+ bytes to a pointer, so `Vec<PackageChange>` moves are
  cheap and `LockfileDiff` is cheaper to pass around.

### Deferred
- Parallel digest verification (lockfiles are small; threading adds complexity
  for no measurable gain — KISS).
- Streaming deserializer (lazy.rs already covers the large-lockfile use case).

## 2. Modularity

### Adopted
- **M1 — CLI split into a module tree.** `main.rs` (2 300 lines, one `match`
  with 24 command arms) became a thin dispatcher plus `src/cli/*` modules, one
  per command group. Each module owns its argument plumbing, output formatting
  and unit tests.
- **M2 — Serializer/deserializer decomposition.** `serialize` and
  `deserialize` were single 150-line functions; they are now orchestrators over
  small, individually testable section writers/parsers.
- **M3 — Header parser decomposition.** `parse_header` now delegates to one
  parser per directive kind (`@trust-root`, `@trust-root-rotation`, `@vex`,
  `@provenance`, …).
- **M4 — Tree rendering extracted.** `TreeNode`/`build_tree`/`render_tree_text`
  moved out of the command handler into `cli/tree.rs` (pure functions, unit
  tested).
- **M5 — Dependency-tree index.** `cli/tree.rs` builds the package index once
  and passes it down instead of re-scanning per recursion level (see P1).

## 3. DRY

### Adopted
- **D1 — Canonical wire-id mappings.** The `match { 0x00 => Sha1, 0x01 =>
  Sha256, … }` tables were duplicated 14+ times across `lockfile/mod.rs`,
  `payload.rs` and the CLI. Replaced by `HashAlgorithm::id()/from_id()`,
  `TargetOS::id()/from_id()`, `TargetArch::id()/from_id()`,
  `DepType::id()/from_id()` — single source of truth per enum, with
  round-trip unit tests.
- **D2 — `Package::version_string()`.** The `format!("{}.{}.{}", maj, min,
  pat)` idiom appeared ~10 times; now one method.
- **D3 — `Lockfile::find_package()`.** The `packages.iter().find(|p| p.name ==
  name)` idiom is now one method used everywhere.
- **D4 — Hex encoding.** One `bytes_to_hex` (see P3); duplicate
  implementations deleted.
- **D5 — `DepType::as_str()/from_str`.** The `"runtime" | "dev" | "peer" …`
  mapping existed twice in the CLI; now one impl.
- **D6 — `FromStr` for `VexStatus` / `AdvisorySeverity` / `PolicyType` /
  `TrustRole`.** Replaced inherent `from_str` methods that fought
  `clippy::should_implement_trait`; parsing now uses `.parse()`.

## 4. KISS

### Adopted
- **K1 — Dead code deleted.** `ColorConfig::new`, `C::g/y/r` and other
  never-called items removed instead of `#[allow(dead_code)]`-ed.
- **K2 — Zero `allow` policy.** The crate now compiles warning-free under
  `clippy::pedantic` + `clippy::all` with **no** `#[allow]`/`#[expect]`
  attributes anywhere (enforced in CI).
- **K3 — Simplified boolean logic.** e.g. the `fix` command's
  `(update_type != Major || true)` clause (always true) collapsed to the
  intended `outdated && !audit && !all`.
- **K4 — `unsafe_code = "forbid"`** at the lint level: the format never needs
  unsafe, so the compiler now guarantees it.
- **K5 — Panics removed from public paths.** Post-validation `unwrap()`s in
  `validate_digest`/`validate_root_rotation`/`verify_signature` were rewritten
  as proper errors / `let-else`, so the crate cannot panic on malicious input
  in those paths.

## 5. Complementary features (ambitious)

### Adopted
- **F1 — `hlock keygen`.** Generates Ed25519 or ML-DSA-65 keypairs and prints a
  ready-to-paste `@trust-root` directive. Closes the biggest UX gap: nothing
  in the toolchain told users *how to produce* the keys that `sign`/`verify`
  consume.
- **F2 — `hlock stats`.** One-shot metrics report (package counts by dep type,
  duplicate versions, deepest dependency chain, license histogram, advisory
  summary) in text or JSON — the natural input for CI dashboards.
- **F3 — `hlock digest`.** Prints the whole-lockfile digest (and verifies it
  with `--check`); tiny, scriptable, and the primitive every external
  auditor asks for first.
- **F4 — `hlock graph --dot`.** Exports the dependency graph as Graphviz DOT
  with dep-type styling, so humans can actually look at the graph the other
  commands reason about.
- **F5 — `hlock policy-test`.** Evaluates hypothetical installs (`--package p
  --hook postinstall`) against the lockfile's policy directives *without*
  running anything — fast feedback while authoring `@policy` rules.

### Deferred
- Automatic lint auto-fixes (`lint --fix`): touching lockfiles is the signer's
  job; auto-mutation would blur the trust model.
- Remote trust-root discovery: needs a real registry protocol; parked until an
  RFC exists.
- SBOM CVE matching against local databases: OSV online audit already covers
  the need.
