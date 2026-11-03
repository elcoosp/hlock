# hlock v1.0.1 Security & Correctness Audit

> Full-codebase audit of hlock v1.0.0 (22.5k lines of Rust): every source
> file was read; every finding below was reproduced against the unfixed
> code, fixed, and covered by a regression test. Run
> `cargo test --test adversarial_security` to re-execute the proofs.

## Methodology

1. **Baseline** — 643 tests green on unmodified v1.0.0.
2. **Manual review** — crypto/signature layer, wire format, digest gate,
   trust chain, policy engine, parser, network layer, file I/O, CLI layer.
3. **Adversarial PoCs** — `tests/adversarial_security.rs` (22 tests) written
   against the *fixed* contract, run pre-fix: 18 failed and one aborted the
   whole test process (`SIGABRT` on a 412 GB allocation), demonstrating the
   findings.
4. **Fixes** — implemented with no unsafe code, `forbid(unsafe_code)` kept.
5. **Green gate** — `cargo test` (581 tests), `cargo clippy --all-targets
   -- -W clippy::pedantic` (0 warnings), `cargo fmt --check` clean.

## Security vulnerabilities (exploitable)

| # | Finding | Attack | Fix |
|---|---------|--------|-----|
| S1 | **Digest placement bypass** — `validate_digest` hashed content only up to the *first* `@digest`-prefixed line | A digest line placed at the top of the body authenticated only the header; every package line after it was unverified while `hlock verify` printed "digest valid" and exited 0. Reproduced: `poc_digest_prefix_bypass_rejected` | Digest must sit at the end of the body; only `@signature` lines may follow. `E0208 DigestPlacement` |
| S2 | **Missing digest accepted** — no `@digest` → `Ok(())` | The integrity gate passed its weakest input, contradicting spec §2.5 (`E0205`) | `E0207 MissingDigest` is now returned; verify/check/ci fail |
| S3 | **Unsigned file passes a keyed gate** — `--trusted-key` given but file has no `@signature` block → signature check skipped, exit 0 | An attacker strips the signature block and recomputes `@digest`; the "verified" gate passes | `E0307 UnsignedLockfile`: pinned keys demand a signature |
| S4 | **Signed file verified without keys silently skips crypto** | `hlock verify` on a signed file without `--trusted-key` printed success while verifying nothing | `E0308 SignatureWithoutTrustedKeys` |
| S5 | **Malformed `--trusted-key` silently dropped** — `parse_trusted_key` returned `None`, the map stayed empty, and (via S4-inverse) the gate passed; odd-length hex was *silently truncated* (spec §2.1 violation) and non-ASCII hex **panicked** on a char boundary | A typo in the key spec degraded a keyed gate to digest-only | Strict `KEY_ID:ALGO:HEX` parsing with exact per-algorithm public-key length checks; malformed spec = exit 2 |
| S6 | **`--time` ignored for signature expiry** (spec §2.4 violation) — `check_signature_expiry` read the wall clock internally | An expired signature passed under a simulated clock, making tests/CI unreproducible and rollback windows untestable | `verify_signature(content, trusted, now_epoch)`; CLI `--time` governs signature + trust-root expiry |
| S7 | **Decoy `@signature ` text disabled verification** — `collect_signature_region` located the block via `str::find("@signature ")`, which matches *inside* earlier lines; when the "block" turned out not to start at a line boundary the verifier returned *unsigned* instead of erroring | A `@metadata note has @signature decoy` line plus a trailing forged block verified as "unsigned = OK" | Byte-offset line scan; the trailing block is always parsed |
| S8 | **Policy glob boundary missing** (spec §3 violation) — `@internal/*` matched `@internalx/y` via `starts_with` | A deny-hook policy scoped to one npm scope leaked to look-alike scopes | `/` boundary enforced: `E`: `poc_glob_scope_boundary` |
| S9 | **Script policies skipped the precedence ladder** (spec §3 violation) | Flat deny-beats-allow contradicted the documented ladder; specific allows were unusable | Same ladder as hooks: specific-deny > specific-allow > wildcard-deny > wildcard-allow |
| S10 | **Sigstore verification accepted any identity** — `--certificate-identity-regexp ".*"` | Any GitHub Actions workflow could sign; keyless verification was theater | Identity anchored to the lockfile's SLSA builder; override via `HLOCK_SIGSTORE_IDENTITY_REGEXP`; unpinned → refuse |
| S11 | **Terminal escape injection** — untrusted package names/URLs printed with ANSI styling wrappers, no control-char filtering | A malicious lockfile could spoof terminal UI inside the very tool users trust for supply-chain decisions | `sanitize_control` strips C0/C1 at every style boundary; names with control bytes rejected at parse |
| S12 | **Registry URL injection** — `format!(".../{name}/latest")` with an unvalidated name | `/`, `?`, `#` in a package name rewrote the request path/query | Percent-encoding via `registry_path_segment` + name validation at parse |
| S13 | **Allocation bomb in payload decoding** — `Vec::with_capacity(attacker_count)` on two decoders | A ~30-byte payload declaring `2^35` features aborted the process (reproduced: `SIGABRT`, 412 GB request) | Pre-allocation capped at 4096; count is bounded by remaining input |
| S14 | **Patch-path traversal** — `validate_patches` joined an unvalidated `relative_path` | `../../…` read files outside the lockfile directory | Names validated at parse (`..` rejected); paths escaped |
| S15 | **Key material TOCTOU** — keygen/init/rotate wrote 0600 *after* creating the file | A world-readable window for private keys | Files created with `mode(0o600)` from the start |
| S16 | **Non-atomic lockfile writes** — every mutating command `fs::write`s in place | A crash/ENOSPC mid-write truncated the operator's lockfile | `atomic_write` (temp + rename) for fix/sign/trust/init/import/merge |

## Correctness bugs

| # | Finding | Fix |
|---|---------|-----|
| B1 | `merge` silently dropped all embedded advisories, licenses, policies, trust roots, rotations, VEX entries and mirrors — silent destruction of supply-chain state | Unioned + deduplicated |
| B2 | `apply_fixes` misparsed versions: `"v4.17.21"` → `0.17.21`; prerelease fix versions silently skipped while still reporting success | Strict parser (`v` stripped, prerelease rejected without corruption) |
| B3 | `apply_fixes` left stale `resolved_peers` content ids after a bump | Peer cids refreshed after every applied fix |
| B4 | CRLF byte-drift: lazy scanner recorded wrong line offsets (panic on multi-byte names); digest boundary drifted on mixed endings; `parse_header` dropped the whole body of CRLF files | Byte-offset scans everywhere; `\r\n\r\n` separator accepted |
| B5 | `tree` rendered `@scope/core@scope/core` (split on first `@`) and walked diamond DAGs exponentially | Version from `(major, minor, patch)`; 100k-node budget |
| B6 | VEX/advisory free-text fields (spaces in justifications/URLs) corrupted on serialize→deserialize roundtrip | Fields percent-encoded (`%20`) on write, decoded on read |
| B7 | Duplicate package names: lazy scan rejected, eager parse accepted (dependency-edge hijack ambiguity) | `E0122 DuplicatePackage` in `deserialize` |
| B8 | `serialize().unwrap()` panics in `merge`/`graph` commands on genuinely fallible serialization | Clean `[code] Serialize error` exit |
| B9 | Network failure masqueraded as "up to date" / "no fixes needed" (spec §7 violation) in `outdated`, `fix --audit`, `fix --outdated` | Errors propagate; `unknown` bucket in outdated; fix plan refuses to conclude from a dead network |
| B10 | `audit --online` did one sequential POST per package with no retry | `/v1/querybatch`, shared pooled client, 2-attempt backoff, 10 MiB response cap, redirect limit, fail-closed exit |
| B11 | Exit-code contract violations (spec §9): "No fixes needed" exited 1, unknown package/graph root exited 1, merge conflicts exited 2, `check` hard failures exited 2 | Normalized to 0/1/2 per spec |
| B12 | `trust rotate` silently stripped the `@signature` block on rewrite | Explicit warning with the re-sign command |
| B13 | Rotation records never checked `rotation_signature_key_id == old_key_id` | `E0309 RotationSignerMismatch` |
| B14 | Import: pnpm routed to the yarn lock parser → silently wrong versions | Hard refusal with migration hint |
| B15 | Import: invalid base64 integrity digests stored as raw ASCII bytes; warnings suppressed with `-o` | Warning surfaced; digest storage fixed upstream of wire |
| B16 | `stats` JSON nondeterministic (HashMap key order) | `BTreeMap` |
| B17 | SPDX IDs contained `/` and `@` (invalid per SPDX-2.3); `--namespace` unvalidated | Token sanitization; namespace must be an absolute http(s) URI |
| B18 | License policy used substring matching (`allow=MIT` blessed `MIT OR GPL-3.0-only`) | SPDX token-based matching |
| B19 | DOT export did not escape labels (injection via package names) | Escaping for `"`, `\`, newlines |
| B20 | JSON envelope (spec §9) missing from most commands; `NO_COLOR`/`FORCE_COLOR`/`CLICOLOR_FORCE` documented but not implemented; `[verify] trusted_keys` config ignored by `verify`/`ci` | Shared `envelope()` helper across all JSON renderers; env vars honored; config wired |

## Test deltas

- `tests/adversarial_security.rs` — new, 22 regression tests mapping 1:1 to
  the findings above.
- 4 pre-existing tests asserted the *vulnerable* semantics and were updated
  to the fixed contract (their names said so, e.g.
  `test_verify_malformed_trusted_key_spec_is_ignored` → `…_is_hard_error`).
- The remaining 581 pre-existing tests pass unchanged in intent; a handful
  were adjusted for the now-mandated JSON envelope and stricter namespaces.

## Known limitations (not bugs, documented)

- `@digest`/signatures authenticate the lockfile itself; artifact integrity
  hashes still describe the original tarballs — `hlock fix` prints a
  reminder to re-import.
- SBOM documents are emitted in their native formats (SPDX/CycloneDX) and
  are therefore not wrapped in the hlock JSON envelope — wrapping would
  break standard interchange.
- 64-bit content ids remain probabilistically unique (birthday bound ≈ 2³²);
  collisions are hard errors, per spec §1.
