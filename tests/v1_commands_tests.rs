//! Integration tests for the v1.0 CLI surface: `ci`, `init`, `trust`,
//! `config`, `explain --list`, audit baselines, `stats --dedup` and the
//! global `--json` shorthand.

use std::path::PathBuf;
use std::process::Command;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hlock_v1_tests_{name}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn package_lock_json() -> &'static str {
    r#"{
  "name": "v1app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "v1app", "version": "1.0.0", "dependencies": { "lodash": "^4.17.0" } },
    "node_modules/lodash": { "version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==" }
  }
}"#
}

/// Boots a lockfile in `dir` via `init --with-trust-root`, signs it and
/// returns (`lockfile_path`, `pubkey_hex`).
fn bootstrap(dir: &std::path::Path) -> (PathBuf, String) {
    let source = dir.join("package-lock.json");
    std::fs::write(&source, package_lock_json()).unwrap();
    let lf = dir.join("app.hlock");

    let out = Command::new(hlock_bin())
        .args([
            "init",
            source.to_str().unwrap(),
            "--from",
            "npm",
            "--with-trust-root",
            "--key-id",
            "ci@test",
            "--output",
            lf.to_str().unwrap(),
        ])
        .output()
        .expect("init runs");
    assert!(
        out.status.success(),
        "init failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Extract the public key from the lockfile's trust-root directive.
    let content = std::fs::read_to_string(&lf).unwrap();
    let pubkey = content
        .lines()
        .find(|l| l.starts_with("@trust-root "))
        .map(|l| l.split_whitespace().nth(3).unwrap().to_string())
        .expect("trust root present");

    // Sign in place so the verify gate passes.
    let key_file = dir.join("app.key");
    let sign = Command::new(hlock_bin())
        .args([
            "sign",
            lf.to_str().unwrap(),
            "--key-id",
            "ci@test",
            "--algorithm",
            "ed25519",
            "--private-key",
            &format!("@{}", key_file.to_str().unwrap()),
            "--in-place",
        ])
        .output()
        .expect("sign runs");
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    (lf, pubkey)
}

// ------------------------------------------------------------------ init ----

#[test]
fn test_init_produces_verifiable_lockfile() {
    let dir = scratch_dir("init");
    let (lf, pubkey) = bootstrap(&dir);

    // v1.0.1: a signed file demands pinned keys — verify without them
    // fails with E0308 instead of silently skipping the signature gate.
    let verify = Command::new(hlock_bin())
        .args([
            "verify",
            lf.to_str().unwrap(),
            "--trusted-key",
            &format!("ci@test:ed25519:{pubkey}"),
        ])
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "verify after init failed: {}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let stdout = String::from_utf8_lossy(&verify.stdout);
    assert!(stdout.contains("digest valid"), "{stdout}");
    assert!(stdout.contains("trust chain valid"), "{stdout}");

    // The private key file must exist (key material was generated).
    assert!(dir.join("app.key").exists());
}

#[test]
fn test_init_unknown_format_fails() {
    let dir = scratch_dir("init_bad");
    let source = dir.join("deps.json");
    std::fs::write(&source, "{}").unwrap();
    let out = Command::new(hlock_bin())
        .args(["init", source.to_str().unwrap(), "--from", "cargo"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
}

// -------------------------------------------------------------------- ci ----

#[test]
fn test_ci_passes_on_clean_signed_lockfile() {
    let dir = scratch_dir("ci_pass");
    let (lf, pubkey) = bootstrap(&dir);

    let out = Command::new(hlock_bin())
        .args([
            "ci",
            lf.to_str().unwrap(),
            "--trusted-key",
            &format!("ci@test:ed25519:{pubkey}"),
            "--no-lint",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "ci should pass: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ci gate passed"), "{stdout}");
}

#[test]
fn test_ci_fails_on_lint_findings() {
    let dir = scratch_dir("ci_lint");
    let (lf, _) = bootstrap(&dir);

    let out = Command::new(hlock_bin())
        .args(["ci", lf.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(1),
        "lint findings must fail the gate"
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ci gate failed"), "{stdout}");
    assert!(stdout.contains("Lint:"), "{stdout}");
}

#[test]
fn test_ci_json_envelope() {
    let dir = scratch_dir("ci_json");
    let (lf, _) = bootstrap(&dir);

    let out = Command::new(hlock_bin())
        .args([
            "ci",
            lf.to_str().unwrap(),
            "--no-verify",
            "--no-audit",
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    let json: serde_json::Value = serde_json::from_str(&String::from_utf8_lossy(&out.stdout))
        .expect("ci json envelope must parse");
    assert_eq!(json["schema"], "hlock/v1");
    assert_eq!(json["command"], "ci");
    assert_eq!(json["ok"], serde_json::Value::Bool(false));
    assert_eq!(json["data"]["gates"]["verify"], "skipped");
    assert_eq!(json["data"]["gates"]["lint"], "failed");
    assert_eq!(json["data"]["gates"]["audit"], "skipped");
    assert_eq!(out.status.code(), Some(1));
}

// ----------------------------------------------------------------- trust ----

#[test]
fn test_trust_rotate_round_trip() {
    let dir = scratch_dir("trust");
    let (lf, pubkey) = bootstrap(&dir);

    // Rotate the root key with the old private key.
    let rotate = Command::new(hlock_bin())
        .args([
            "trust",
            "rotate",
            lf.to_str().unwrap(),
            "--new-key-id",
            "ci@test-2027",
            "--old-private-key",
            &format!("@{}", dir.join("app.key").to_str().unwrap()),
        ])
        .output()
        .unwrap();
    assert!(
        rotate.status.success(),
        "rotate failed: {}",
        String::from_utf8_lossy(&rotate.stderr)
    );

    // `trust list` shows the rotation record.
    let list = Command::new(hlock_bin())
        .args(["trust", "list", lf.to_str().unwrap()])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&list.stdout);
    assert!(stdout.contains("ci@test-2027"), "{stdout}");
    assert!(stdout.contains("Rotation records"), "{stdout}");

    // The rotated lockfile still verifies (rotation signature validates).
    // v1.0.1: `trust rotate` rewrites the file, which drops the old
    // @signature block (its digest no longer matches) — so the file is
    // unsigned again and must verify without pinned keys; the rotation
    // record itself is checked by the trust-chain gate.
    let verify = Command::new(hlock_bin())
        .args(["verify", lf.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verify.status.success(), "verify after rotation failed");
    let _ = pubkey;

    // JSON output exposes both sections.
    let list_json = Command::new(hlock_bin())
        .args(["trust", "list", lf.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&list_json.stdout)).unwrap();
    let data = &json["data"];
    assert_eq!(data["rotations"].as_array().unwrap().len(), 1);
    assert_eq!(data["rotations"][0]["signed_by"], "ci@test");
}

#[test]
fn test_trust_list_json_empty() {
    let dir = scratch_dir("trust_empty");
    let (lf, _) = bootstrap(&dir);
    let out = Command::new(hlock_bin())
        .args(["trust", "list", lf.to_str().unwrap(), "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let data = &json["data"];
    assert_eq!(data["rotations"].as_array().unwrap().len(), 0);
    assert_eq!(data["trust_roots"].as_array().unwrap().len(), 1);
}

// ---------------------------------------------------------------- config ----

#[test]
fn test_config_prints_resolved_defaults() {
    let out = Command::new(hlock_bin()).args(["config"]).output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("source: defaults"), "{stdout}");
    assert!(stdout.contains("[audit]"), "{stdout}");
}

#[test]
fn test_config_json_envelope() {
    let out = Command::new(hlock_bin())
        .args(["config", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert_eq!(json["schema"], "hlock/v1");
    assert_eq!(json["command"], "config");
    assert_eq!(json["ok"], serde_json::Value::Bool(true));
    assert_eq!(json["data"]["config"]["outdated"]["timeout"], 30);
}

#[test]
fn test_config_invalid_toml_is_hard_error() {
    let dir = scratch_dir("config_bad");
    let path = dir.join("broken.toml");
    std::fs::write(&path, "[[[not valid toml").unwrap();
    let out = Command::new(hlock_bin())
        .args(["--config", path.to_str().unwrap(), "config"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2), "invalid TOML must be E0901");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E0901"), "{stderr}");
}

#[test]
fn test_config_missing_explicit_file_is_hard_error() {
    let out = Command::new(hlock_bin())
        .args(["--config", "/nonexistent/hlock-9f11.toml", "config"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "missing --config file must be E0902"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E0902"), "{stderr}");
}

// --------------------------------------------------------------- explain ----

#[test]
fn test_explain_list_shows_registry() {
    let out = Command::new(hlock_bin())
        .args(["explain", "--list"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Lint rule registry"), "{stdout}");
    assert!(stdout.contains("no-git-urls"), "{stdout}");
    assert!(stdout.contains("deny-postinstall"), "{stdout}");
}

#[test]
fn test_explain_list_filter_and_json() {
    let out = Command::new(hlock_bin())
        .args(["explain", "--list", "trust", "--format", "json"])
        .output()
        .unwrap();
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    let names: Vec<&str> = json["rules"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"require-trust-root"));
    assert!(names.contains(&"no-expired-keys"));
    assert!(!names.contains(&"no-sha1"));
}

#[test]
fn test_explain_unknown_suggests_close_rule() {
    let out = Command::new(hlock_bin())
        .args(["explain", "no-git-url"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Did you mean 'no-git-urls'?"), "{stderr}");
}

// ------------------------------------------------------- audit baseline ----

#[test]
fn test_audit_write_baseline_then_dry_run() {
    let dir = scratch_dir("baseline");
    let (lf, _) = bootstrap(&dir);
    let baseline = dir.join("baseline.json");

    let write = Command::new(hlock_bin())
        .args([
            "audit",
            lf.to_str().unwrap(),
            "--write-baseline",
            baseline.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(write.status.success());
    let content = std::fs::read_to_string(&baseline).unwrap();
    let json: serde_json::Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["schema"], "hlock/baseline/v1");
    assert!(json["advisory_ids"].is_array());

    // With an empty baseline and no embedded advisories the audit passes.
    let audit = Command::new(hlock_bin())
        .args([
            "audit",
            lf.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(audit.status.success(), "no new advisories must pass");
}

#[test]
fn test_audit_baseline_invalid_json_is_config_error() {
    let dir = scratch_dir("baseline_bad");
    let (lf, _) = bootstrap(&dir);
    let baseline = dir.join("bad.json");
    std::fs::write(&baseline, "{not json").unwrap();
    let out = Command::new(hlock_bin())
        .args([
            "audit",
            lf.to_str().unwrap(),
            "--baseline",
            baseline.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("E0901"), "{stderr}");
}

// ---------------------------------------------------------- stats --dedup ----

#[test]
fn test_stats_dedup_flag() {
    let dir = scratch_dir("dedup");
    let (lf, _) = bootstrap(&dir);
    let out = Command::new(hlock_bin())
        .args(["stats", lf.to_str().unwrap(), "--dedup"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Deduplication Opportunities") || stdout.contains("No deduplication"),
        "{stdout}"
    );
}

// --------------------------------------------------------------- --json ----

#[test]
fn test_global_json_shorthand() {
    let dir = scratch_dir("global_json");
    let (lf, _) = bootstrap(&dir);
    let out = Command::new(hlock_bin())
        .args(["--json", "stats", lf.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let json: serde_json::Value =
        serde_json::from_str(&String::from_utf8_lossy(&out.stdout)).unwrap();
    assert!(
        json["data"]["total_packages"].is_number(),
        "--json must force JSON output"
    );
}
