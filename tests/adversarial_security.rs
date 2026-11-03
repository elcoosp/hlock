//! Adversarial security regression suite.
//!
//! Every test here documents a concrete attack or abuse case against hlock
//! and asserts the *fixed* behavior. Each test maps to a finding from the
//! v1.0.1 security audit (see AUDIT.md).

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;

use hlock::lockfile::types::{VexEntry, VexStatus};
use hlock::policy::{Advisory, AdvisorySeverity, LicenseEntry, Policy, PolicyType, TrustRole};
use hlock::{
    Lockfile, Package, PolicyDecision, SignatureAlgorithm, Source, deserialize, serialize,
    sign_lockfile, verify_signature,
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// RFC 8032 test-vector 1 Ed25519 seed; its public key is `PK_HEX`.
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const PK_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn trusted_key_spec() -> String {
    format!("ci@acme:ed25519:{PK_HEX}")
}

fn trusted_map() -> HashMap<String, (Vec<u8>, SignatureAlgorithm)> {
    let mut m = HashMap::new();
    m.insert(
        "ci@acme".to_string(),
        (
            hlock::hex::decode(PK_HEX).unwrap(),
            SignatureAlgorithm::Ed25519,
        ),
    );
    m
}

fn two_pkg_lockfile() -> Lockfile {
    Lockfile {
        sources: vec![Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4,
                minor: 17,
                patch: 21,
                ..Package::default()
            },
            Package {
                name: "left-pad".to_string(),
                source_idx: 0,
                major: 1,
                minor: 3,
                patch: 0,
                ..Package::default()
            },
        ],
        ..Lockfile::default()
    }
}

/// The hardcoded public key must really match the seed, else every crypto
/// assertion below would be vacuous.
#[test]
fn sanity_keypair_vector() {
    let signed = sign_lockfile(
        "message\n",
        "ci@acme",
        SignatureAlgorithm::Ed25519,
        &SEED,
        0,
    )
    .unwrap();
    let res = verify_signature(&signed, &trusted_map(), now());
    assert!(
        res.is_ok(),
        "self-check: sign+verify with the RFC vector must work: {res:?}"
    );
}

fn tmp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_adversarial");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join(name)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

// ---------------------------------------------------------------------------
// 1. Digest gate: placement bypass, missing digest
// ---------------------------------------------------------------------------

/// A `@digest` line placed at the TOP of the body makes `validate_digest`
/// hash only the header prefix; the actual packages are never covered.
/// The gate must reject digests that do not sit at the end of the body.
#[test]
fn poc_digest_prefix_bypass_rejected() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    // Header = everything up to (and including) the blank separator line.
    let sep = serialized.find("\n\n").unwrap() + 2;
    let header = &serialized[..sep];
    let body: String = serialized[sep..]
        .lines()
        .filter(|l| !l.starts_with("@digest "))
        .fold(String::new(), |acc, l| acc + &format!("{l}\n"));
    // Attacker moves the digest line to the TOP of the body and re-seals it
    // over the (harmless) header prefix only.
    let prefix = format!("{header}\n");
    let evil = format!(
        "{prefix}@digest {}\n{body}",
        hlock::lockfile::digest::digest_hex(&prefix)
    );
    // Sanity: the body still parses into the same packages.
    assert!(
        deserialize(&evil).is_ok(),
        "evil file must remain well-formed"
    );

    let res = hlock::validate_digest(&evil);
    assert!(
        res.is_err(),
        "a digest covering only a prefix must be rejected"
    );
    let path = tmp("prefix_bypass.hlock");
    std::fs::write(&path, &evil).unwrap();
    let out = Command::new(hlock_bin())
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "verify must fail on a prefix-covering digest"
    );
}

/// A lockfile with no `@digest` at all must fail the verify gate
/// (spec §2.5, E0205), not silently pass.
#[test]
fn poc_missing_digest_fails_gate() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    let no_digest: String = serialized
        .lines()
        .filter(|l| !l.starts_with("@digest "))
        .fold(String::new(), |acc, l| acc + &format!("{l}\n"));
    let path = tmp("no_digest.hlock");
    std::fs::write(&path, &no_digest).unwrap();
    let out = Command::new(hlock_bin())
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "verify must fail without @digest"
    );
}

// ---------------------------------------------------------------------------
// 2. Signature gate: unsigned bypass, missing keys, malformed key specs
// ---------------------------------------------------------------------------

/// When the operator pins `--trusted-key`, a file with NO signature must
/// fail: otherwise any attacker strips the signature block and re-digests.
#[test]
fn poc_unsigned_file_fails_when_trusted_key_pinned() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    let path = tmp("unsigned.hlock");
    std::fs::write(&path, &serialized).unwrap();
    let out = Command::new(hlock_bin())
        .args(["verify", "--trusted-key", &trusted_key_spec()])
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "verify --trusted-key must fail on unsigned file"
    );
}

/// A file that HAS a `@signature` block but is verified without any pinned
/// key must fail instead of silently skipping signature verification.
#[test]
fn poc_signature_present_without_keys_fails() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    let signed = sign_lockfile(
        &serialized,
        "ci@acme",
        SignatureAlgorithm::Ed25519,
        &SEED,
        0,
    )
    .unwrap();
    let path = tmp("signed_no_keys.hlock");
    std::fs::write(&path, &signed).unwrap();
    let out = Command::new(hlock_bin())
        .arg("verify")
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "verify must fail when signatures exist but no keys are pinned"
    );
}

/// A malformed `--trusted-key` spec must be a hard usage error (exit 2).
/// Pre-fix: silently dropped → gate skipped; non-ASCII hex even panics.
#[test]
fn poc_malformed_trusted_key_is_hard_error() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    let path = tmp("malformed_key.hlock");
    std::fs::write(&path, &serialized).unwrap();
    for bad_spec in [
        "just-a-key-id",
        "ci@acme:ed25519:xyz",    // non-hex
        "ci@acme:ed25519:aaéb",   // multi-byte panic pre-fix
        "ci@acme:bogus-alg:aabb", // unknown algorithm
        "ci@acme:ed25519:aabb",   // wrong length for ed25519
    ] {
        let out = Command::new(hlock_bin())
            .args(["verify", "--trusted-key", bad_spec])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(2),
            "malformed trusted key {bad_spec:?} must exit 2, got {:?} (stderr: {})",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// `--time` must govern signature expiry (spec §2.4). A signature that is
/// valid now but expired at `--time T` must FAIL when T is passed.
#[test]
fn poc_time_governs_signature_expiry() {
    let serialized = serialize(&two_pkg_lockfile()).unwrap();
    // Expires one year from the wall clock…
    let future = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 86_400 * 365;
    let signed = sign_lockfile(
        &serialized,
        "ci@acme",
        SignatureAlgorithm::Ed25519,
        &SEED,
        future,
    )
    .unwrap();
    let path = tmp("time_expiry.hlock");
    std::fs::write(&path, &signed).unwrap();
    // …but verification time T = expiry + 366 days is past it.
    let t = future + 86_400 * 366;
    let out = Command::new(hlock_bin())
        .args([
            "verify",
            "--trusted-key",
            &trusted_key_spec(),
            "--time",
            &t.to_string(),
        ])
        .arg(&path)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "--time past signature expiry must fail verification"
    );
}

/// Library-level: a decoy `@signature ` occurrence *inside* an earlier line
/// must not make the verifier treat the trailing (forged) signature block
/// as nonexistent.
#[test]
fn poc_signature_region_decoy_rejected() {
    // A genuinely well-formed but *wrong-content* signature: 64 bytes,
    // produced over different bytes than this file carries.
    let wrong_content = sign_lockfile(
        "attacker content\n",
        "ci@acme",
        SignatureAlgorithm::Ed25519,
        &SEED,
        0,
    )
    .unwrap();
    let sig_line = wrong_content
        .lines()
        .find(|l| l.starts_with("@signature "))
        .unwrap()
        .to_string();
    let content = format!(
        "@source 0 https://r/\n@metadata note has @signature decoy inside\n\npkg\tAAAA\n{sig_line}\n"
    );
    let res = verify_signature(&content, &trusted_map(), now());
    assert!(
        res.is_err(),
        "decoy @signature text must not bypass verification of the trailing block: {res:?}"
    );
}

// ---------------------------------------------------------------------------
// 3. Policy engine: glob boundary, script precedence
// ---------------------------------------------------------------------------

/// `@internal/*` must require the `/` boundary (spec §3): it must NOT match
/// `@internalx/y`.
#[test]
fn poc_glob_scope_boundary() {
    let lf = Lockfile {
        sources: vec![Source::Registry("https://r/".to_string())],
        policies: vec![Policy {
            policy_type: PolicyType::DenyHook,
            package_pattern: "@internal/*".to_string(),
            value: "preinstall".to_string(),
        }],
        ..Lockfile::default()
    };
    assert_eq!(
        lf.hook_allowed("@internalx/y", "preinstall"),
        PolicyDecision::NoPolicy,
        "@internal/* must not match @internalx/y"
    );
    assert!(matches!(
        lf.hook_allowed("@internal/pkg", "preinstall"),
        PolicyDecision::Denied { .. }
    ));
}

/// Script evaluation must use the same precedence ladder as hooks
/// (spec §3): specific-allow beats wildcard-deny.
#[test]
fn poc_script_precedence_ladder() {
    let lf = Lockfile {
        sources: vec![Source::Registry("https://r/".to_string())],
        policies: vec![
            Policy {
                policy_type: PolicyType::DenyScript,
                package_pattern: "*".to_string(),
                value: "build".to_string(),
            },
            Policy {
                policy_type: PolicyType::AllowScript,
                package_pattern: "myapp".to_string(),
                value: "build".to_string(),
            },
        ],
        ..Lockfile::default()
    };
    assert_eq!(
        lf.script_allowed("myapp", "build"),
        PolicyDecision::Allowed,
        "specific allow must override wildcard deny"
    );
    assert!(matches!(
        lf.script_allowed("other", "build"),
        PolicyDecision::Denied { .. }
    ));
}

// ---------------------------------------------------------------------------
// 4. DoS: allocation bombs, CRLF panic
// ---------------------------------------------------------------------------

/// A ~30-byte payload declaring an astronomical feature count must return
/// a decode error, not attempt the allocation (pre-fix: capacity-overflow
/// abort of the whole process).
#[test]
fn poc_payload_alloc_bomb_rejected() {
    // version=0x10, logical_name=0x00, source=0, maj/min/pat=0,
    // hash_count=0, feat_count = 2^35 (5-byte varint), then EOF.
    let mut bytes = vec![0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    for b in [0x80u8, 0x80, 0x80, 0x80, 0x40] {
        bytes.push(b);
    }
    let result = std::panic::catch_unwind(|| hlock::unpack_payload(&bytes, 0));
    match result {
        Ok(Err(_)) => { /* good: bounded decode error */ }
        Ok(Ok(_)) => panic!("malformed payload must not decode"),
        Err(e) => panic!("unpack_payload must not panic/abort on huge counts: {e:?}"),
    }
}

/// CRLF body lines shift the lazy scanner's byte offsets; with multi-byte
/// UTF-8 in later lines the shifted slice must not panic (pre-fix it can
/// slice mid-character).
#[test]
fn poc_lazy_crlf_no_panic() {
    use std::fmt::Write as _;
    let mut content = String::from("@source 0 https://r/\n\n");
    for i in 0..30 {
        let _ = write!(content, "pâckage-é{i}\tAAAA\r\n");
    }
    let res = std::panic::catch_unwind(|| {
        let lazy = hlock::LazyLockfile::scan(&content).unwrap();
        let _ = lazy.into_full();
    });
    assert!(res.is_ok(), "CRLF body must not panic the lazy scanner");
}

// ---------------------------------------------------------------------------
// 5. Roundtrip fidelity + name validation
// ---------------------------------------------------------------------------

/// VEX justifications / impact statements containing spaces must survive a
/// serialize→deserialize round trip unchanged.
#[test]
fn poc_vex_roundtrip_with_spaces() {
    let mut lf = two_pkg_lockfile();
    lf.vex_entries.push(VexEntry {
        package: "lodash".to_string(),
        advisory_id: "GHSA-xxxx".to_string(),
        status: VexStatus::NotAffected,
        justification: "vulnerable function not used".to_string(),
        impact_statement: "we never call merge with arrays".to_string(),
    });
    let serialized = serialize(&lf).unwrap();
    let parsed = deserialize(&serialized).unwrap();
    assert_eq!(
        parsed.vex_entries, lf.vex_entries,
        "VEX text with spaces must roundtrip"
    );
}

/// Advisory URLs containing spaces must roundtrip too.
#[test]
fn poc_advisory_roundtrip_with_spaces() {
    let mut lf = two_pkg_lockfile();
    lf.advisories.push(Advisory {
        package: "lodash".to_string(),
        advisory_id: "GHSA-1234".to_string(),
        severity: AdvisorySeverity::High,
        url: "https://example.com/advisory with space".to_string(),
        affected_versions: "<4.17.21".to_string(),
    });
    let serialized = serialize(&lf).unwrap();
    let parsed = deserialize(&serialized).unwrap();
    assert_eq!(
        parsed.advisories, lf.advisories,
        "advisory with space in URL must roundtrip"
    );
}

/// Package names are attacker-controlled; names carrying whitespace,
/// control bytes, or URL/path metacharacters must be rejected at parse.
#[test]
fn poc_package_name_validation() {
    let mk = |name: &str| {
        let mut lf = two_pkg_lockfile();
        lf.packages[0].name = name.to_string();
        lf
    };
    for bad in [
        "evil name",          // space
        "evil\tname",         // tab
        "evil\u{1b}[31mname", // ANSI escape
        "pkg?query=1",        // URL metachar
        "pkg#frag",           // URL metachar
        "pkg/../etc",         // traversal
    ] {
        let res = deserialize(&serialize(&mk(bad)).unwrap());
        assert!(res.is_err(), "package name {bad:?} must be rejected");
    }
    for good in [
        "lodash",
        "@scope/pkg",
        "lodash.test",
        "lodash_test",
        "lodash-test",
    ] {
        let res = deserialize(&serialize(&mk(good)).unwrap());
        assert!(
            res.is_ok(),
            "legitimate name {good:?} must parse: {:?}",
            res.err()
        );
    }
}

/// Duplicate package names must be rejected by the eager parser exactly as
/// the lazy scanner already does (ambiguity = dependency-edge hijacking).
#[test]
fn poc_duplicate_names_rejected() {
    let mut lf = two_pkg_lockfile();
    lf.packages.push(Package {
        name: "lodash".to_string(),
        major: 3,
        ..Package::default()
    });
    assert!(
        deserialize(&serialize(&lf).unwrap()).is_err(),
        "duplicate package names must be a parse error"
    );
}

// ---------------------------------------------------------------------------
// 6. fix: version misparse + stale metadata
// ---------------------------------------------------------------------------

/// OSV fixed versions carrying a `v` prefix or prerelease must never be
/// misparsed into a wrong (major, minor, patch) triple.
#[test]
fn poc_apply_fixes_version_parsing() {
    let mut lf = two_pkg_lockfile();
    let plan = hlock::FixPlan {
        fixes: vec![
            hlock::FixEntry {
                package: "lodash".to_string(),
                current: "4.17.21".to_string(),
                fixed: "v4.17.22".to_string(), // 'v' prefix must be handled
                advisory_id: "X".to_string(),
                advisory_summary: String::new(),
                fix_type: hlock::FixType::Audit,
            },
            hlock::FixEntry {
                package: "left-pad".to_string(),
                current: "1.3.0".to_string(),
                fixed: "2.0.0-beta.1".to_string(), // prerelease: not representable
                advisory_id: "Y".to_string(),
                advisory_summary: String::new(),
                fix_type: hlock::FixType::Audit,
            },
        ],
        total_vulnerabilities: 2,
        warnings: Vec::new(),
    };
    let selected = vec![true, true];
    let applied = hlock::apply_fixes(&mut lf, &plan, &selected);
    assert_eq!(applied, 1, "only the clean version bump applies");
    assert_eq!(
        (
            lf.packages[0].major,
            lf.packages[0].minor,
            lf.packages[0].patch
        ),
        (4, 17, 22)
    );
    assert_eq!(
        (
            lf.packages[1].major,
            lf.packages[1].minor,
            lf.packages[1].patch
        ),
        (1, 3, 0),
        "prerelease fix must not mangle the current version"
    );
}

/// Bumping a package must refresh every `resolved_peers` content id that
/// pointed at the old version (stale cids = silent integrity break).
#[test]
fn poc_apply_fixes_updates_peer_cids() {
    use hlock::PeerResolution;
    let mut lf = two_pkg_lockfile();
    let old_cid = hlock::cid::package_cid(&lf.packages[0]);
    lf.packages[1].resolved_peers.push(PeerResolution {
        peer_name: "lodash".to_string(),
        satisfied_by_content_id: old_cid,
        is_hoisted_to_root: false,
    });
    let plan = hlock::FixPlan {
        fixes: vec![hlock::FixEntry {
            package: "lodash".to_string(),
            current: "4.17.21".to_string(),
            fixed: "4.17.22".to_string(),
            advisory_id: "X".to_string(),
            advisory_summary: String::new(),
            fix_type: hlock::FixType::Audit,
        }],
        total_vulnerabilities: 1,
        warnings: Vec::new(),
    };
    hlock::apply_fixes(&mut lf, &plan, &[true]);
    let new_cid = hlock::cid::package_cid(&lf.packages[0]);
    assert_ne!(old_cid, new_cid);
    assert_eq!(
        lf.packages[1].resolved_peers[0].satisfied_by_content_id, new_cid,
        "peer content id must track the version bump"
    );
}

// ---------------------------------------------------------------------------
// 7. merge must not silently drop security directives
// ---------------------------------------------------------------------------

#[test]
fn poc_merge_preserves_security_directives() {
    let mut base = two_pkg_lockfile();
    base.advisories.push(Advisory {
        package: "lodash".to_string(),
        advisory_id: "GHSA-1".to_string(),
        severity: AdvisorySeverity::High,
        url: "https://g.dev/1".to_string(),
        affected_versions: "<4".to_string(),
    });
    base.licenses.push(LicenseEntry {
        package: "lodash".to_string(),
        expression: "MIT".to_string(),
    });
    base.trust_roots.push(hlock::policy::TrustRoot {
        key_id: "k".to_string(),
        algorithm: SignatureAlgorithm::Ed25519,
        public_key: vec![0xaa; 32],
        expires_epoch: 0,
        role: TrustRole::Root,
    });
    base.policies.push(Policy {
        policy_type: PolicyType::DenyHook,
        package_pattern: "*".to_string(),
        value: "preinstall".to_string(),
    });

    let ours = base.clone();
    let theirs = base.clone();
    let merged = hlock::merge_lockfiles(&base, &ours, &theirs, hlock::ConflictStrategy::Ours)
        .expect("merge should succeed");
    assert_eq!(
        merged.lockfile.advisories.len(),
        1,
        "advisories must survive merge"
    );
    assert_eq!(
        merged.lockfile.licenses.len(),
        1,
        "licenses must survive merge"
    );
    assert_eq!(
        merged.lockfile.trust_roots.len(),
        1,
        "trust roots must survive merge"
    );
    assert_eq!(
        merged.lockfile.policies.len(),
        1,
        "policies must survive merge"
    );
}

// ---------------------------------------------------------------------------
// 8. tree: scoped names must render real versions
// ---------------------------------------------------------------------------

#[test]
fn poc_tree_scoped_package_version() {
    let lf = Lockfile {
        sources: vec![Source::Registry("https://r/".to_string())],
        packages: vec![Package {
            name: "@scope/core".to_string(),
            source_idx: 0,
            major: 7,
            minor: 24,
            patch: 0,
            ..Package::default()
        }],
        ..Lockfile::default()
    };
    let path = tmp("scoped.hlock");
    std::fs::write(&path, serialize(&lf).unwrap()).unwrap();
    let out = Command::new(hlock_bin())
        .args(["tree", "--root", "@scope/core", "--format", "json"])
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\"7.24.0\""),
        "tree must render the numeric version for scoped names, got: {stdout}"
    );
    assert!(
        !stdout.contains("@scope/core@scope"),
        "version must not be cut on the scope separator: {stdout}"
    );
}

// ---------------------------------------------------------------------------
// 9. Output hardening: terminal escapes from untrusted data
// ---------------------------------------------------------------------------

#[test]
fn poc_terminal_escape_neutralized() {
    let mut lf = two_pkg_lockfile();
    lf.packages[0].name = "evil\u{1b}[31mname".to_string();
    let path = tmp("escape.hlock");
    std::fs::write(&path, serialize(&lf).unwrap()).unwrap();
    let out = Command::new(hlock_bin())
        .args(["--color", "never", "stats"])
        .arg(&path)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains('\u{1b}'),
        "no ANSI escapes may reach stdout with --color never"
    );
}

// ---------------------------------------------------------------------------
// 10. init: output/key path collision
// ---------------------------------------------------------------------------

#[test]
fn poc_init_key_path_collision_rejected() {
    let dir = std::env::temp_dir().join("hlock_adversarial_init");
    std::fs::create_dir_all(&dir).unwrap();
    let lock_path = dir.join("out.key");
    let _ = std::fs::remove_file(&lock_path);
    let npm_lock = dir.join("package-lock.json");
    std::fs::write(
        &npm_lock,
        r#"{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="}}}"#,
    )
    .unwrap();
    let out = Command::new(hlock_bin())
        .args(["init", "--from", "npm", "--with-trust-root", "--output"])
        .arg(&lock_path)
        .arg(&npm_lock)
        .output()
        .unwrap();
    assert_ne!(
        out.status.code(),
        Some(0),
        "init must refuse an output path whose key-collision would clobber it"
    );
}
