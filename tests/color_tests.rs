use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

fn write_temp_file(name: &str, content: &str) -> PathBuf {
    let dir = std::env::temp_dir().join("hlock_color_tests");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path
}

fn make_simple_lockfile() -> String {
    let mut lf = hlock::Lockfile {
        sources: vec![hlock::Source::Registry("https://registry.npmjs.org/".to_string())],
        packages: vec![
            hlock::Package {
                name: "lodash".to_string(),
                source_idx: 0,
                major: 4, minor: 17, patch: 21,
                hashes: vec![hlock::IntegrityHash {
                    algo: hlock::HashAlgorithm::Sha256,
                    digest: vec![42u8; 32],
                    attestation: hlock::Attestation::None,
                }],
                ..Default::default()
            },
        ],
        licenses: vec![hlock::policy::LicenseEntry { package: "lodash".to_string(), expression: "MIT".to_string() }],
        trust_roots: vec![hlock::policy::TrustRoot {
            key_id: "ci@key".to_string(),
            algorithm: hlock::signature::SignatureAlgorithm::Ed25519,
            public_key: vec![0u8; 32],
            expires_epoch: 0,
            role: hlock::policy::TrustRole::Root,
        }],
        ..Default::default()
    };
    hlock::serialize(&mut lf).unwrap()
}

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

#[test]
fn test_color_never_no_ansi() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("color_never.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color=never")
        .arg("info")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\x1b["), "should have no ANSI escapes with --color never, got: {:?}", stdout.chars().take(200).collect::<String>());
}

#[test]
fn test_color_always_has_ansi() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("color_always.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color=always")
        .arg("info")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\x1b["), "should have ANSI escapes with --color always, got: {:?}", stdout.chars().take(200).collect::<String>());
}

#[test]
fn test_json_no_ansi_even_with_color_always() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("color_json.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color=always")
        .arg("info")
        .arg(&path)
        .arg("--format=json")
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\x1b["), "JSON output should never have ANSI escapes, got: {:?}", stdout.chars().take(200).collect::<String>());
}

#[test]
fn test_verify_color_never() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("verify_color.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color=never")
        .arg("verify")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("\x1b["), "verify with --color never should have no ANSI, got: {:?}", stdout.chars().take(200).collect::<String>());
}

#[test]
fn test_info_never_still_has_content() {
    let serialized = make_simple_lockfile();
    let path = write_temp_file("info_content.hlock", &serialized);
    let output = Command::new(hlock_bin())
        .arg("--color=never")
        .arg("info")
        .arg(&path)
        .output()
        .expect("failed to run hlock");
    let stdout = strip_ansi(&String::from_utf8_lossy(&output.stdout));
    assert!(stdout.contains("Packages:"), "should contain Packages header even without color, got: {}", stdout);
    assert!(stdout.contains("Sources:"), "should contain Sources header, got: {}", stdout);
}
