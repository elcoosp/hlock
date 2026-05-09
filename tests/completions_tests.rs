use std::process::Command;
use std::path::PathBuf;

fn hlock_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hlock"))
}

#[test]
fn test_completions_bash() {
    let output = Command::new(hlock_bin())
        .arg("completions")
        .arg("bash")
        .output()
        .expect("failed to run hlock");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "completions bash should succeed");
    assert!(stdout.contains("hlock"), "bash completions should mention hlock");
}

#[test]
fn test_completions_zsh() {
    let output = Command::new(hlock_bin())
        .arg("completions")
        .arg("zsh")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "completions zsh should succeed");
}

#[test]
fn test_completions_fish() {
    let output = Command::new(hlock_bin())
        .arg("completions")
        .arg("fish")
        .output()
        .expect("failed to run hlock");
    assert!(output.status.success(), "completions fish should succeed");
}

#[test]
fn test_completions_invalid_shell() {
    let output = Command::new(hlock_bin())
        .arg("completions")
        .arg("csh")
        .output()
        .expect("failed to run hlock");
    assert!(!output.status.success(), "completions with invalid shell should fail");
}
