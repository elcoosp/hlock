//! Cross-cutting CLI coverage for the newer commands: keygen, stats, digest,
//! policy-test, sign, graph --dot, completions, info, why, deps, explain,
//! import, outdated, fix and check.
//!
//! These tests spawn the compiled `hlock` binary the same way `cli_tests.rs`
//! does, and never touch the network.

use std::path::PathBuf;
use std::process::Command;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_coverage_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn run_cli(args: &[&std::ffi::OsStr]) -> (String, String, Option<i32>) {
    let output = Command::new(hlock_bin())
        .args(args)
        .output()
        .expect("failed to run hlock");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code(),
    )
}

/// RFC 8032 test-vector seed; its Ed25519 public key is well known.
const TEST_SEED_HEX: &str = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const TEST_PUB_HEX: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}

fn simple_lockfile() -> String {
    let lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry(
            "https://registry.npmjs.org/".to_string(),
        )],
        packages: vec![
            hlock::Package {
                name: "alpha".to_string(),
                source_idx: 0,
                major: 1,
                minor: 2,
                patch: 3,
                ..Default::default()
            },
            hlock::Package {
                name: "app".to_string(),
                source_idx: 0,
                major: 4,
                minor: 0,
                patch: 0,
                dependencies: vec![hlock::Dependency {
                    name: "alpha".to_string(),
                    dep_type: hlock::DepType::Runtime,
                    requested_features: vec![],
                }],
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    hlock::serialize(&lf.clone()).unwrap()
}

fn lockfile_with_directives() -> String {
    let lf = hlock::Lockfile {
        sources: vec![
            hlock::Source::Registry("https://registry.npmjs.org/".to_string()),
            hlock::Source::Git("git+https://github.com/acme/pkg.git".to_string()),
        ],
        packages: vec![
            hlock::Package {
                name: "hooked".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                hook_hashes: vec![hlock::HookHash {
                    hook_type: "postinstall".to_string(),
                    hash_algo: hlock::HashAlgorithm::Blake3,
                    digest: vec![0u8; 32],
                }],
                ..Default::default()
            },
            hlock::Package {
                name: "gitdep".to_string(),
                source_idx: 1,
                major: 2,
                minor: 0,
                patch: 0,
                ..Default::default()
            },
        ],
        licenses: vec![hlock::LicenseEntry {
            package: "hooked".to_string(),
            expression: "MIT".to_string(),
        }],
        advisories: vec![
            hlock::Advisory {
                package: "hooked".to_string(),
                advisory_id: "GHSA-test-0001".to_string(),
                severity: hlock::AdvisorySeverity::High,
                url: "https://osv.dev/vulnerability/GHSA-test-0001".to_string(),
                affected_versions: "<1.1.0".to_string(),
            },
            hlock::Advisory {
                package: "hooked".to_string(),
                advisory_id: "GHSA-test-0002".to_string(),
                severity: hlock::AdvisorySeverity::Critical,
                url: String::new(),
                affected_versions: "<1.0.0".to_string(),
            },
        ],
        vex_entries: vec![hlock::VexEntry {
            package: "hooked".to_string(),
            advisory_id: "GHSA-test-0001".to_string(),
            status: hlock::VexStatus::NotAffected,
            justification: "code_not_present".to_string(),
            impact_statement: "unused".to_string(),
        }],
        policies: vec![
            hlock::Policy {
                policy_type: hlock::PolicyType::DenyHook,
                package_pattern: "*".to_string(),
                value: "postinstall".to_string(),
            },
            hlock::Policy {
                policy_type: hlock::PolicyType::BuildEnv,
                package_pattern: "*".to_string(),
                value: "node20".to_string(),
            },
        ],
        ..Default::default()
    };
    hlock::serialize(&lf.clone()).unwrap()
}

/// A lockfile whose packages all resolve from non-registry sources, so the
/// outdated/fix code paths short-circuit without any network access.
fn non_registry_lockfile() -> String {
    let lf = hlock::Lockfile {
        sources: vec![
            hlock::Source::Git("git+https://github.com/acme/pkg.git".to_string()),
            hlock::Source::Workspace,
        ],
        packages: vec![
            hlock::Package {
                name: "gitdep".to_string(),
                source_idx: 0,
                major: 1,
                minor: 0,
                patch: 0,
                ..Default::default()
            },
            hlock::Package {
                name: "wsdep".to_string(),
                source_idx: 1,
                major: 2,
                minor: 0,
                patch: 0,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    hlock::serialize(&lf.clone()).unwrap()
}

/// A lockfile that passes every error-severity lint rule, for clean `check`.
fn clean_lockfile() -> String {
    let lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry(
            "https://registry.npmjs.org/".to_string(),
        )],
        packages: vec![hlock::Package {
            name: "ok".to_string(),
            source_idx: 0,
            major: 1,
            minor: 0,
            patch: 0,
            hashes: vec![hlock::IntegrityHash {
                algo: hlock::HashAlgorithm::Sha256,
                digest: vec![7u8; 32],
                attestation: hlock::Attestation::None,
            }],
            ..Default::default()
        }],
        licenses: vec![hlock::LicenseEntry {
            package: "ok".to_string(),
            expression: "MIT".to_string(),
        }],
        trust_roots: vec![hlock::TrustRoot {
            key_id: "ci-key".to_string(),
            algorithm: hlock::SignatureAlgorithm::Ed25519,
            public_key: hex_to_bytes(TEST_PUB_HEX),
            expires_epoch: 0,
            role: hlock::TrustRole::Root,
        }],
        ..Default::default()
    };
    hlock::serialize(&lf.clone()).unwrap()
}

fn signed_with_test_key(content: &str) -> String {
    hlock::sign_lockfile(
        content,
        "ci@test.example",
        hlock::SignatureAlgorithm::Ed25519,
        &hex_to_bytes(TEST_SEED_HEX),
        0,
    )
    .unwrap()
}

// ---------------------------------------------------------------- keygen ----

#[test]
fn test_keygen_ed25519_prints_keypair() {
    let (stdout, stderr, code) = run_cli(&["keygen".as_ref(), "--key-id".as_ref(), "k@x".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Generated a new ed25519 keypair."));
    assert!(stdout.contains("Private key (hex, KEEP SECRET)"));
    assert!(stdout.contains("Public key (hex)"));
    assert!(stdout.contains("@trust-root k@x 00 "));
    assert!(stdout.contains(" root\n") || stdout.contains(" root\r"));
    assert!(stdout.contains("--algorithm ed25519"));
}

#[test]
fn test_keygen_ml_dsa65_prints_keypair() {
    let (stdout, stderr, code) = run_cli(&[
        "keygen".as_ref(),
        "--algorithm".as_ref(),
        "ml-dsa-65".as_ref(),
        "--key-id".as_ref(),
        "pq@x".as_ref(),
        "--expires".as_ref(),
        "12345".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Generated a new mldsa65 keypair."));
    assert!(stdout.contains("@trust-root pq@x 02 "));
    assert!(stdout.contains("12345"));
    // ML-DSA-65 public keys are large hex blobs.
    assert!(
        stdout.lines().any(|l| l.len() > 1000),
        "public key line too short: {stdout}"
    );
}

#[test]
fn test_keygen_unknown_algorithm_fails() {
    let (_, stderr, code) = run_cli(&["keygen".as_ref(), "--algorithm".as_ref(), "rsa".as_ref()]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("unknown algorithm 'rsa'"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_keygen_output_writes_private_key_file() {
    let path = std::env::temp_dir()
        .join("hlock_coverage_tests")
        .join("keygen_private.key");
    let (stdout, stderr, code) =
        run_cli(&["keygen".as_ref(), "--output".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains(&format!("Private key written to {}", path.display())));
    let written = std::fs::read_to_string(&path).unwrap();
    assert_eq!(
        written.len(),
        65,
        "64 hex chars + newline, got: {written:?}"
    );
    assert!(written.trim_end().chars().all(|c| c.is_ascii_hexdigit()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "private key must be user-only");
    }
    std::fs::remove_file(&path).ok();
}

// ------------------------------------------------------------------ sign ----

#[test]
fn test_sign_stdout_round_trip_through_verify() {
    let content = simple_lockfile();
    let path = write_temp_file("sign_src.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "sign".as_ref(),
        path.as_os_str(),
        "--key-id".as_ref(),
        "ci@test.example".as_ref(),
        "--private-key".as_ref(),
        TEST_SEED_HEX.as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let signed = stdout;
    assert!(signed.contains("@signature ci@test.example 00 0 "));
    let signed_path = write_temp_file("sign_out.hlock", &signed);

    let (vout, verr, vcode) = run_cli(&[
        "verify".as_ref(),
        signed_path.as_os_str(),
        "--trusted-key".as_ref(),
        format!("ci@test.example:ed25519:{TEST_PUB_HEX}").as_ref(),
    ]);
    assert_eq!(vcode, Some(0), "stderr: {verr}");
    assert!(vout.contains("signature valid"), "stdout: {vout}");
}

#[test]
fn test_sign_in_place_rewrites_file() {
    let content = simple_lockfile();
    let path = write_temp_file("sign_inplace.hlock", &content);
    let (_, stderr, code) = run_cli(&[
        "sign".as_ref(),
        path.as_os_str(),
        "--key-id".as_ref(),
        "ci@test.example".as_ref(),
        "--private-key".as_ref(),
        TEST_SEED_HEX.as_ref(),
        "--in-place".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let rewritten = std::fs::read_to_string(&path).unwrap();
    assert!(rewritten.contains("@signature ci@test.example"));
}

#[test]
fn test_sign_in_place_with_stdin_is_rejected() {
    let (_, stderr, code) = run_cli(&[
        "sign".as_ref(),
        "-".as_ref(),
        "--in-place".as_ref(),
        "--key-id".as_ref(),
        "k".as_ref(),
        "--private-key".as_ref(),
        TEST_SEED_HEX.as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("--in-place cannot be used with stdin"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_sign_missing_key_file_fails() {
    let content = simple_lockfile();
    let path = write_temp_file("sign_keyfile_src.hlock", &content);
    let (_, stderr, code) = run_cli(&[
        "sign".as_ref(),
        path.as_os_str(),
        "--key-id".as_ref(),
        "k".as_ref(),
        "--private-key".as_ref(),
        "@/nonexistent/hlock_key_9f11".as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("Error reading key file"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_sign_mldsa65_uses_key_from_file() {
    let key_path = std::env::temp_dir()
        .join("hlock_coverage_tests")
        .join("mldsa_sk.hex");
    let (kout, kerr, kcode) = run_cli(&[
        "keygen".as_ref(),
        "--algorithm".as_ref(),
        "ml-dsa-65".as_ref(),
        "--output".as_ref(),
        key_path.as_os_str(),
        "--quiet".as_ref(),
    ]);
    assert_eq!(kcode, Some(0), "stderr: {kerr}");
    assert!(kout.is_empty(), "quiet keygen must not print: {kout}");

    let content = simple_lockfile();
    let path = write_temp_file("sign_mldsa.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "sign".as_ref(),
        path.as_os_str(),
        "--key-id".as_ref(),
        "pq@x".as_ref(),
        "--algorithm".as_ref(),
        "mldsa65".as_ref(),
        "--private-key".as_ref(),
        format!("@{}", key_path.display()).as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("@signature pq@x 02 0 "));
    std::fs::remove_file(&key_path).ok();
}

#[test]
fn test_sign_malformed_input_fails() {
    let content = simple_lockfile().replace('\t', " ");
    let path = write_temp_file("sign_malformed.hlock", &content);
    let (_, stderr, code) = run_cli(&[
        "sign".as_ref(),
        path.as_os_str(),
        "--key-id".as_ref(),
        "k".as_ref(),
        "--private-key".as_ref(),
        TEST_SEED_HEX.as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("Parse error"), "stderr: {stderr}");
}

// ----------------------------------------------------------------- stats ----

#[test]
fn test_stats_text_output() {
    let content = lockfile_with_directives();
    let path = write_temp_file("stats_directives.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["stats".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Lockfile statistics"));
    assert!(stdout.contains("Packages:           2"));
    assert!(stdout.contains("Duplicate names:    none"));
    assert!(stdout.contains("Advisories:         2 embedded"));
    assert!(stdout.contains("high"));
    assert!(stdout.contains("Directives:"));
}

#[test]
fn test_stats_json_output() {
    let content = lockfile_with_directives();
    let path = write_temp_file("stats_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "stats".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["total_packages"], 2);
    assert_eq!(json["by_kind"]["runtime"], 2);
    assert!(json["by_kind"]["dev"].as_u64().is_some());
    assert_eq!(json["workspace_sources"], 0);
    assert_eq!(json["advisories_by_severity"]["high"], 1);
    assert_eq!(json["advisories_by_severity"]["critical"], 1);
    assert_eq!(json["sources"], 2);
    assert_eq!(json["policies"], 2);
    assert_eq!(json["vex_entries"], 1);
    assert_eq!(json["license_histogram"][0]["license"], "MIT");
}

#[test]
fn test_stats_quiet_prints_nothing() {
    let content = simple_lockfile();
    let path = write_temp_file("stats_quiet.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["stats".as_ref(), path.as_os_str(), "--quiet".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stdout, "", "quiet stdout should be empty: {stdout}");
    assert_eq!(stderr, "");
}

#[test]
fn test_stats_missing_file_fails() {
    let (_, stderr, code) = run_cli(&["stats".as_ref(), "/nonexistent/stats.hlock".as_ref()]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("Error reading"), "stderr: {stderr}");
}

// ---------------------------------------------------------------- digest ----

#[test]
fn test_digest_prints_computed_digest() {
    let content = simple_lockfile();
    let path = write_temp_file("digest_print.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["digest".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let digest = stdout.trim();
    assert_eq!(digest.len(), 64, "blake3 hex length: {digest}");
    let expected: String = hlock::whole_lockfile_digest(&content).iter().fold(
        String::with_capacity(128),
        |mut acc, b| {
            use std::fmt::Write as _;
            let _ = write!(acc, "{b:02x}");
            acc
        },
    );
    assert_eq!(digest, expected);
}

#[test]
fn test_digest_check_ok() {
    let content = simple_lockfile();
    let path = write_temp_file("digest_ok.hlock", &content);
    let (stdout, stderr, code) =
        run_cli(&["digest".as_ref(), path.as_os_str(), "--check".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("digest OK"), "stdout: {stdout}");
}

#[test]
fn test_digest_check_mismatch_fails() {
    let content = simple_lockfile();
    let tampered = content.replace("alpha", "gamma");
    let path = write_temp_file("digest_bad.hlock", &tampered);
    let (_, stderr, code) = run_cli(&["digest".as_ref(), path.as_os_str(), "--check".as_ref()]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("digest MISMATCH"), "stderr: {stderr}");
}

#[test]
fn test_digest_quiet_prints_nothing() {
    let content = simple_lockfile();
    let path = write_temp_file("digest_quiet.hlock", &content);
    let (stdout, _, code) = run_cli(&["digest".as_ref(), path.as_os_str(), "--quiet".as_ref()]);
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "");
}

// ----------------------------------------------------------- policy-test ----

#[test]
fn test_policy_test_text_reports_decisions() {
    let content = lockfile_with_directives();
    let path = write_temp_file("policy_text.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "policy-test".as_ref(),
        path.as_os_str(),
        "--package".as_ref(),
        "hooked".as_ref(),
        "--hook".as_ref(),
        "postinstall".as_ref(),
        "--script".as_ref(),
        "build".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Policy evaluation for `hooked`"));
    assert!(stdout.contains("hook   postinstall"));
    assert!(stdout.contains("→ denied"));
    assert!(stdout.contains("→ no policy"));
    assert!(stdout.contains("build-env → node20"));
    assert!(stdout.contains("engine    → (none)"));
    assert!(stdout.contains("full evaluation: 1 violation(s)"));
    assert!(stdout.contains("deny-hook"));
}

#[test]
fn test_policy_test_json_reports_decisions() {
    let content = lockfile_with_directives();
    let path = write_temp_file("policy_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "policy-test".as_ref(),
        path.as_os_str(),
        "--package".as_ref(),
        "hooked".as_ref(),
        "--hook".as_ref(),
        "postinstall".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["package"], "hooked");
    assert_eq!(json["hook"]["decision"], "denied");
    assert!(
        json["hook"]["reason"]
            .as_str()
            .unwrap()
            .contains("postinstall")
    );
    assert_eq!(json["script"], serde_json::Value::Null);
    assert_eq!(json["full_report"]["build_env"], "node20");
    assert_eq!(
        json["full_report"]["violations"][0]["policy_type"],
        "deny-hook"
    );
}

#[test]
fn test_policy_test_without_policies_prints_note() {
    let content = simple_lockfile();
    let path = write_temp_file("policy_nop.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "policy-test".as_ref(),
        path.as_os_str(),
        "--package".as_ref(),
        "alpha".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("no @policy directives"), "stderr: {stderr}");
    assert!(stdout.contains("hook   (not tested"));
    assert!(stdout.contains("script (not tested"));
    assert!(stdout.contains("full evaluation: no violations"));
}

#[test]
fn test_policy_test_quiet_prints_nothing() {
    let content = lockfile_with_directives();
    let path = write_temp_file("policy_quiet.hlock", &content);
    let (stdout, _, code) = run_cli(&[
        "policy-test".as_ref(),
        path.as_os_str(),
        "--package".as_ref(),
        "hooked".as_ref(),
        "--hook".as_ref(),
        "postinstall".as_ref(),
        "--quiet".as_ref(),
    ]);
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "");
}

// ----------------------------------------------------------------- graph ----

#[test]
fn test_graph_dot_stdout() {
    let content = simple_lockfile();
    let path = write_temp_file("graph_dot.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "graph".as_ref(),
        path.as_os_str(),
        "--root".as_ref(),
        "app".as_ref(),
        "--dot".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.starts_with("digraph dependencies"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("alpha@1.2.3"));
}

#[test]
fn test_graph_dot_writes_output_file() {
    let content = simple_lockfile();
    let path = write_temp_file("graph_dot_file.hlock", &content);
    let out_path = std::env::temp_dir()
        .join("hlock_coverage_tests")
        .join("graph_out.dot");
    let (_, stderr, code) = run_cli(&[
        "graph".as_ref(),
        path.as_os_str(),
        "--root".as_ref(),
        "app".as_ref(),
        "--dot".as_ref(),
        "--output".as_ref(),
        out_path.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let dot = std::fs::read_to_string(&out_path).unwrap();
    assert!(dot.contains("digraph"));
    std::fs::remove_file(&out_path).ok();
}

#[test]
fn test_graph_platform_extraction() {
    let content = simple_lockfile();
    let path = write_temp_file("graph_platform.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "graph".as_ref(),
        path.as_os_str(),
        "--root".as_ref(),
        "app".as_ref(),
        "--platform".as_ref(),
        "linux-x86_64".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("@source"),
        "expected a lockfile on stdout: {stdout}"
    );
}

#[test]
fn test_graph_bad_platform_fails() {
    let content = simple_lockfile();
    let path = write_temp_file("graph_badplatform.hlock", &content);
    let (_, stderr, code) = run_cli(&[
        "graph".as_ref(),
        path.as_os_str(),
        "--root".as_ref(),
        "app".as_ref(),
        "--platform".as_ref(),
        "bogus-platform".as_ref(),
    ]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("Invalid platform format"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_graph_missing_root_fails() {
    let content = simple_lockfile();
    let path = write_temp_file("graph_missing_root.hlock", &content);
    let (_, stderr, code) = run_cli(&[
        "graph".as_ref(),
        path.as_os_str(),
        "--root".as_ref(),
        "ghost".as_ref(),
    ]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("Some root packages not found"),
        "stderr: {stderr}"
    );
}

// ------------------------------------------------------------ completions ----

#[test]
fn test_completions_bash() {
    let (stdout, stderr, code) = run_cli(&["completions".as_ref(), "bash".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("hlock"),
        "bash completion should mention hlock"
    );
}

#[test]
fn test_completions_all_shells() {
    for shell in ["zsh", "fish", "elvish", "powershell"] {
        let (stdout, stderr, code) = run_cli(&["completions".as_ref(), shell.as_ref()]);
        assert_eq!(code, Some(0), "shell {shell} stderr: {stderr}");
        assert!(!stdout.is_empty(), "shell {shell} produced no output");
    }
}

#[test]
fn test_completions_unknown_shell_fails() {
    let (_, stderr, code) = run_cli(&["completions".as_ref(), "tcsh".as_ref()]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("unknown shell 'tcsh'"), "stderr: {stderr}");
}

#[test]
fn test_completions_quiet_prints_nothing() {
    let (stdout, _, code) = run_cli(&["completions".as_ref(), "bash".as_ref(), "--quiet".as_ref()]);
    assert_eq!(code, Some(0));
    assert_eq!(stdout, "");
}

// ---------------------------------------------------------- stats --dedup ----

#[test]
fn test_stats_dedup_reports_opportunities() {
    let content = lockfile_with_directives();
    let path = write_temp_file("stats_dedup.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["stats".as_ref(), "--dedup".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    // The section header must always render; opportunities depend on content.
    assert!(
        stdout.contains("Deduplication Opportunities")
            || stdout.contains("No deduplication opportunities"),
        "unexpected dedup output: {stdout}"
    );
}

#[test]
fn test_stats_dedup_json_is_valid() {
    let content = lockfile_with_directives();
    let path = write_temp_file("stats_dedup_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "stats".as_ref(),
        "--dedup".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        json["opportunities"].is_array(),
        "opportunities must be an array"
    );
}

// ------------------------------------------------------------------- why ----

#[test]
fn test_why_text_prints_chains() {
    let content = simple_lockfile();
    let path = write_temp_file("why_text.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["why".as_ref(), path.as_os_str(), "alpha".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("alpha@1.2.3"));
    assert!(
        stdout.contains("app"),
        "chain should include the root: {stdout}"
    );
}

#[test]
fn test_why_json_prints_chains() {
    let content = simple_lockfile();
    let path = write_temp_file("why_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "why".as_ref(),
        path.as_os_str(),
        "alpha".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["package"], "alpha");
    assert_eq!(json["version"], "1.2.3");
    let chains = json["chains"].as_array().unwrap();
    assert!(
        chains
            .iter()
            .any(|c| c.as_array().unwrap().contains(&serde_json::json!("app")))
    );
}

#[test]
fn test_why_missing_package_fails() {
    let content = simple_lockfile();
    let path = write_temp_file("why_missing.hlock", &content);
    let (_, stderr, code) = run_cli(&["why".as_ref(), path.as_os_str(), "ghost".as_ref()]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("package 'ghost' not found"),
        "stderr: {stderr}"
    );
}

// ------------------------------------------------------------------ deps ----

#[test]
fn test_deps_text_lists_direct_and_transitive() {
    let content = simple_lockfile();
    let path = write_temp_file("deps_text.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "deps".as_ref(),
        path.as_os_str(),
        "app".as_ref(),
        "--transitive".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Direct dependencies of app:"));
    assert!(stdout.contains("alpha@1.2.3 (runtime)"));
}

#[test]
fn test_deps_json_and_dep_type_filter() {
    let content = simple_lockfile();
    let path = write_temp_file("deps_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "deps".as_ref(),
        path.as_os_str(),
        "app".as_ref(),
        "--dep-type".as_ref(),
        "runtime".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["direct"][0]["dep_type"], "runtime");
}

#[test]
fn test_deps_missing_package_fails() {
    let content = simple_lockfile();
    let path = write_temp_file("deps_missing.hlock", &content);
    let (_, stderr, code) = run_cli(&["deps".as_ref(), path.as_os_str(), "ghost".as_ref()]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("not found"), "stderr: {stderr}");
}

// --------------------------------------------------------------- explain ----

#[test]
fn test_explain_rule_text() {
    let (stdout, stderr, code) = run_cli(&["explain".as_ref(), "no-git-urls".as_ref()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Rule: no-git-urls"));
    assert!(stdout.contains("Severity: error"));
    assert!(stdout.contains("Category: supply-chain"));
    assert!(stdout.contains("Why it matters:"));
    assert!(stdout.contains("How to fix:"));
    assert!(stdout.contains("Related rules: require-integrity"));
    assert!(stdout.contains("References:"));
}

#[test]
fn test_explain_rule_json() {
    let (stdout, stderr, code) = run_cli(&[
        "explain".as_ref(),
        "require-license".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["name"], "require-license");
    assert_eq!(json["kind"], "rule");
    assert_eq!(json["severity"], "error");
    assert_ne!(json["why_it_matters"].as_array().unwrap().len(), 0);
}

#[test]
fn test_explain_advisory_via_file() {
    let content = lockfile_with_directives();
    let path = write_temp_file("explain_adv.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "explain".as_ref(),
        "GHSA-test-0001".as_ref(),
        "--file".as_ref(),
        path.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Advisory: GHSA-test-0001"));
    assert!(stdout.contains("Severity: high"));
    assert!(stdout.contains("hooked@1.0.0"));
    assert!(stdout.contains("osv.dev"));
}

#[test]
fn test_explain_advisory_json() {
    let content = lockfile_with_directives();
    let path = write_temp_file("explain_adv_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "explain".as_ref(),
        "GHSA-test-0001".as_ref(),
        "--file".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["kind"], "advisory");
    assert_eq!(json["category"], "vulnerability");
    assert_eq!(
        json["references"][0],
        "https://osv.dev/vulnerability/GHSA-test-0001"
    );
}

#[test]
fn test_explain_unknown_fails_with_hint() {
    let (_, stderr, code) = run_cli(&["explain".as_ref(), "not-a-thing".as_ref()]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("not found as a rule or advisory"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("explain --list"), "stderr: {stderr}");
}

// ---------------------------------------------------------------- import ----

#[test]
fn test_import_yarn_to_stdout() {
    let yarn = "lodash@^4.17.0:\n  version \"4.17.21\"\n  resolved \"https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz\"\n  integrity sha512-abc==\n";
    let path = write_temp_file("import_yarn.lock", yarn);
    let (stdout, stderr, code) = run_cli(&[
        "import".as_ref(),
        path.as_os_str(),
        "--from".as_ref(),
        "yarn".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("@source 0 https://registry.npmjs.org/"));
    assert!(stdout.contains("@digest "));
    assert!(
        stderr.contains("Imported 1 packages from"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("yarn-v1"), "stderr: {stderr}");
}

#[test]
fn test_import_npm_to_output_file() {
    let npm = r#"{"packages": {"node_modules/react": {"version": "18.3.1", "integrity": "sha512-aaa=="}}}"#;
    let path = write_temp_file("package-lock.json", npm);
    let out_path = std::env::temp_dir()
        .join("hlock_coverage_tests")
        .join("imported.hlock");
    let (_, stderr, code) = run_cli(&[
        "import".as_ref(),
        path.as_os_str(),
        "--from".as_ref(),
        "npm".as_ref(),
        "--output".as_ref(),
        out_path.as_os_str(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stderr.contains("Imported 1 packages to"),
        "stderr: {stderr}"
    );
    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("react"));
    std::fs::remove_file(&out_path).ok();
}

#[test]
fn test_import_pnpm_uses_yarn_parser() {
    let pnpm_like = "chalk@^5.0.0:\n  version \"5.3.0\"\n";
    let path = write_temp_file("pnpm-lock.yaml", pnpm_like);
    let (_, stderr, code) = run_cli(&[
        "import".as_ref(),
        path.as_os_str(),
        "--from".as_ref(),
        "pnpm".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stderr.contains("Imported 1 packages"), "stderr: {stderr}");
}

#[test]
fn test_import_unknown_format_fails() {
    let path = write_temp_file("import_src.txt", "whatever");
    let (_, stderr, code) = run_cli(&[
        "import".as_ref(),
        path.as_os_str(),
        "--from".as_ref(),
        "cargo".as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("unknown format 'cargo'"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_import_invalid_npm_json_fails() {
    let path = write_temp_file("bad_package_lock.json", "{oops");
    let (_, stderr, code) = run_cli(&[
        "import".as_ref(),
        path.as_os_str(),
        "--from".as_ref(),
        "npm".as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("Import failed"), "stderr: {stderr}");
}

// ---------------------------------------------------------- verify extras ----

#[test]
fn test_verify_missing_file_fails() {
    let (_, stderr, code) = run_cli(&["verify".as_ref(), "/nonexistent/verify.hlock".as_ref()]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("Error reading"), "stderr: {stderr}");
}

#[test]
fn test_verify_trust_chain_valid() {
    let content = simple_lockfile();
    // Add the trust root at the model level so the re-serialized digest matches.
    let mut parsed = hlock::deserialize(&content).unwrap();
    parsed.trust_roots.push(hlock::policy::TrustRoot {
        key_id: "ci-key".to_string(),
        algorithm: hlock::signature::SignatureAlgorithm::Ed25519,
        public_key: hex_to_bytes(TEST_PUB_HEX),
        expires_epoch: 0,
        role: hlock::policy::TrustRole::Root,
    });
    let content = hlock::serialize(&parsed).unwrap();
    let path = write_temp_file("verify_trust_ok.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["verify".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("trust chain valid"), "stdout: {stdout}");
}

#[test]
fn test_verify_expired_trust_root_fails() {
    let content = simple_lockfile();
    let mut parsed = hlock::deserialize(&content).unwrap();
    parsed.trust_roots.push(hlock::policy::TrustRoot {
        key_id: "ci-key".to_string(),
        algorithm: hlock::signature::SignatureAlgorithm::Ed25519,
        public_key: hex_to_bytes(TEST_PUB_HEX),
        expires_epoch: 1000,
        role: hlock::policy::TrustRole::Root,
    });
    let content = hlock::serialize(&parsed).unwrap();
    let path = write_temp_file("verify_trust_expired.hlock", &content);
    let (_, stderr, code) = run_cli(&["verify".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("expired"), "stderr: {stderr}");
}

#[test]
fn test_verify_malformed_trusted_key_spec_is_ignored() {
    let content = simple_lockfile();
    let path = write_temp_file("verify_badkey.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "verify".as_ref(),
        path.as_os_str(),
        "--trusted-key".as_ref(),
        "not-a-valid-spec".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("digest valid"), "stdout: {stdout}");
}

#[test]
fn test_verify_untrusted_signature_fails() {
    let content = signed_with_test_key(&simple_lockfile());
    let path = write_temp_file("verify_untrusted.hlock", &content);
    // No --trusted-key passed: signature check is skipped entirely.
    let (_, stderr, code) = run_cli(&["verify".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");

    let (_, stderr, code) = run_cli(&[
        "verify".as_ref(),
        path.as_os_str(),
        "--trusted-key".as_ref(),
        format!("someone-else:ed25519:{TEST_PUB_HEX}").as_ref(),
    ]);
    assert_eq!(code, Some(1));
    assert!(
        stderr.contains("not in the trusted key set"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_verify_tampered_signature_fails() {
    let content = signed_with_test_key(&simple_lockfile());
    let tampered = content.replace("alpha", "delta");
    // Tampering breaks the digest before the signature is even checked.
    let path = write_temp_file("verify_tampered_sig.hlock", &tampered);
    let (_, stderr, code) = run_cli(&[
        "verify".as_ref(),
        path.as_os_str(),
        "--verbose".as_ref(),
        "--trusted-key".as_ref(),
        format!("ci@test.example:ed25519:{TEST_PUB_HEX}").as_ref(),
    ]);
    assert_eq!(code, Some(1));
    assert!(stderr.contains("digest"), "stderr: {stderr}");
}

// ------------------------------------------------------ outdated and fix ----

#[test]
fn test_outdated_skips_non_registry_packages_without_network() {
    let content = non_registry_lockfile();
    let path = write_temp_file("outdated_skip.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["outdated".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(
        stdout.contains("No outdated packages found."),
        "stdout: {stdout}"
    );

    let (stdout, _, code) = run_cli(&[
        "outdated".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0));
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["summary"]["total"], 2);
    assert_eq!(json["summary"]["skipped"], 2);
    let reasons: Vec<&str> = json["skipped"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["reason"].as_str().unwrap())
        .collect();
    assert!(reasons.contains(&"git"));
    assert!(reasons.contains(&"workspace"));
}

#[test]
fn test_fix_outdated_without_fixes_reports_and_exits_one() {
    let content = non_registry_lockfile();
    let path = write_temp_file("fix_nofixes.hlock", &content);
    let (stdout, _, code) = run_cli(&["fix".as_ref(), path.as_os_str(), "--outdated".as_ref()]);
    assert_eq!(code, Some(1));
    assert!(stdout.contains("No fixes needed."), "stdout: {stdout}");
}

#[test]
fn test_fix_dry_run_without_fixes_exits_one() {
    let content = non_registry_lockfile();
    let path = write_temp_file("fix_dryrun.hlock", &content);
    let (_, _, code) = run_cli(&[
        "fix".as_ref(),
        path.as_os_str(),
        "--outdated".as_ref(),
        "--dry-run".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(1));
}

#[test]
fn test_fix_stdin_rejected() {
    let (_, stderr, code) = run_cli(&["fix".as_ref(), "-".as_ref(), "--outdated".as_ref()]);
    assert_eq!(code, Some(2));
    assert!(
        stderr.contains("requires a real file path"),
        "stderr: {stderr}"
    );
}

#[test]
fn test_fix_missing_file_fails() {
    let (_, stderr, code) = run_cli(&[
        "fix".as_ref(),
        "/nonexistent/fix.hlock".as_ref(),
        "--outdated".as_ref(),
    ]);
    assert_eq!(code, Some(2));
    assert!(stderr.contains("Error reading"), "stderr: {stderr}");
}

// ----------------------------------------------------------------- check ----

#[test]
fn test_check_clean_lockfile_passes() {
    let content = clean_lockfile();
    let path = write_temp_file("check_clean.hlock", &content);
    let (stdout, stderr, code) = run_cli(&["check".as_ref(), path.as_os_str()]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert!(stdout.contains("Digest valid"));
    assert!(stdout.contains("No signature found"));
    assert!(stdout.contains("Trust chain valid"));
    assert!(stdout.contains("Lint: 0 errors, 0 warnings, 0 info"));
    assert!(stdout.contains("Audit: 0 vulnerabilities"));
}

#[test]
fn test_check_json_clean_report() {
    let content = clean_lockfile();
    let path = write_temp_file("check_clean_json.hlock", &content);
    let (stdout, stderr, code) = run_cli(&[
        "check".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["digest_valid"], true);
    assert_eq!(json["signature"]["present"], false);
    assert_eq!(json["trust_chain_valid"], true);
    assert_eq!(json["passed"], true);
}

#[test]
fn test_check_text_reports_vex_suppression() {
    let content = lockfile_with_directives();
    let path = write_temp_file("check_vex.hlock", &content);
    let (stdout, _, code) = run_cli(&["check".as_ref(), path.as_os_str()]);
    // One critical advisory remains effective; the high one is VEX-suppressed.
    assert_eq!(code, Some(1));
    assert!(stdout.contains("Audit: 1 critical"), "stdout: {stdout}");
    assert!(stdout.contains("VEX-suppressed"), "stdout: {stdout}");
    assert!(stdout.contains("suppressed by VEX"), "stdout: {stdout}");
    assert!(stdout.contains("not_affected"), "stdout: {stdout}");
    assert!(stdout.contains("GHSA-test-0001"), "stdout: {stdout}");
}

#[test]
fn test_check_json_reports_vex_suppression() {
    let content = lockfile_with_directives();
    let path = write_temp_file("check_vex_json.hlock", &content);
    let (stdout, _, code) = run_cli(&[
        "check".as_ref(),
        path.as_os_str(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(1));
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["passed"], false);
    assert_eq!(json["audit"]["critical"].as_array().unwrap().len(), 1);
    assert_eq!(json["audit"]["high"].as_array().unwrap().len(), 0);
    let suppressed = json["audit"]["vex_suppressed"].as_array().unwrap();
    assert_eq!(suppressed.len(), 1);
    assert_eq!(suppressed[0]["status"], "not_affected");
}

#[test]
fn test_check_vex_flag_disables_suppression() {
    let content = lockfile_with_directives();
    let path = write_temp_file("check_vex_flag.hlock", &content);
    let (stdout, _, code) = run_cli(&["check".as_ref(), path.as_os_str(), "--vex".as_ref()]);
    // With --vex the raw audit (both advisories) is reported.
    assert_eq!(code, Some(1));
    assert!(
        stdout.contains("Audit: 1 critical, 1 high"),
        "stdout: {stdout}"
    );
    let (stdout, _, code) = run_cli(&[
        "check".as_ref(),
        path.as_os_str(),
        "--vex".as_ref(),
        "--format".as_ref(),
        "json".as_ref(),
    ]);
    assert_eq!(code, Some(1));
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(json["audit"]["high"].as_array().unwrap().len(), 1);
    assert_eq!(json["audit"]["vex_suppressed"].as_array().unwrap().len(), 0);
}
