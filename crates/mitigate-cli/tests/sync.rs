//! Actual CLI input failures must not create consent, touch credentials or echo paths.
use std::process::{Command, Stdio};

#[test]
fn sync_help_explains_explicit_delivery_and_local_controls() {
    for (action, required) in [
        ("enable", "without starting a sender"),
        ("pause", "wait for active delivery"),
        ("send", "at most one"),
        ("run", "until paused or interrupted"),
        ("purge", "--confirm"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mitigate"))
            .args(["sync", action, "--help"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout).unwrap().contains(required));
    }
}

#[test]
fn live_capture_requires_explicit_enforcement_and_does_not_echo_invalid_input() {
    let output = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args(["mcp", "serve", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("--sync-profile")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args([
            "mcp",
            "serve",
            "--launch-config",
            "private-canary",
            "--allow-exec",
            "--inventory-only",
            "--sync-profile",
            "private-canary",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("private-canary")
    );
}

#[test]
fn invalid_sync_requests_never_echo_input_or_create_partial_state() {
    let missing = std::env::temp_dir()
        .join(format!("mitigate-sync-absent-{}", std::process::id()))
        .join("private-canary");
    let path = missing.to_str().unwrap();
    for (arguments, code) in [
        (
            vec![
                "sync",
                "enable",
                "--profile",
                path,
                "--enrollment",
                path,
                "--outbox",
                path,
                "--platform",
                "http://private-canary.invalid",
                "--json",
            ],
            "enrollment_origin",
        ),
        (
            vec!["sync", "status", "--profile", path, "--json"],
            "sync_profile",
        ),
        (
            vec!["sync", "pause", "--profile", path, "--json"],
            "sync_profile",
        ),
        (
            vec!["sync", "resume", "--profile", path, "--json"],
            "sync_profile",
        ),
        (
            vec!["sync", "send", "--profile", path, "--json"],
            "sync_profile",
        ),
        (
            vec!["sync", "run", "--profile", path, "--json"],
            "sync_profile",
        ),
        (
            vec!["sync", "purge", "--profile", path, "--json"],
            "cli_invalid_arguments",
        ),
        (
            vec!["sync", "purge", "--profile", path, "--confirm", "--json"],
            "sync_profile",
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_mitigate"))
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], code);
        let message = String::from_utf8(output.stderr).unwrap();
        assert!(!message.contains("private-canary"));
        assert!(!message.contains(path));
        assert!(!missing.exists());
    }
}

#[test]
fn inventory_capture_requires_an_explicit_sync_profile() {
    let output = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args([
            "mcp",
            "serve",
            "--sync-inventory",
            "--inventory-only",
            "--allow-exec",
            "--launch-config",
            "inventory-private-canary",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(
        !String::from_utf8(output.stderr)
            .unwrap()
            .contains("inventory-private-canary")
    );
}
