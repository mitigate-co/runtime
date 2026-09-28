//! Actual-binary validation and secret-safe enrollment diagnostics.
use std::{
    io::Write,
    process::{Command, Stdio},
};

fn run(arguments: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}
#[test]
fn enrollment_help_explains_network_native_state_and_code_input() {
    let output = run(&["enroll", "start", "--help"], b"");
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    for required in ["HTTPS", "--platform", "--state", "--stdin", "argument"] {
        assert!(help.contains(required));
    }
}
#[test]
fn invalid_enrollment_requests_never_echo_input_or_reach_native_storage() {
    let missing = std::env::temp_dir()
        .join(format!("mitigate-enrollment-absent-{}", std::process::id()))
        .join("state");
    let path = missing.to_str().unwrap();
    let code =
        "mcp1:00000000-0000-4000-8000-000000000001:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (arguments, input, expected) in [
        (
            vec![
                "enroll",
                "start",
                "--platform",
                "https://mitigate.example",
                "--state",
                path,
                "--json",
            ],
            code.as_bytes(),
            "enrollment_code",
        ),
        (
            vec![
                "enroll",
                "start",
                "--platform",
                "http://secret-canary.invalid",
                "--state",
                path,
                "--stdin",
                "--json",
            ],
            code.as_bytes(),
            "enrollment_origin",
        ),
        (
            vec![
                "enroll",
                "start",
                "--platform",
                "https://mitigate.example",
                "--state",
                path,
                "--stdin",
                "--json",
            ],
            b"secret-canary".as_slice(),
            "enrollment_code",
        ),
        (
            vec![
                "enroll",
                "start",
                "--platform",
                "https://mitigate.example",
                "--state",
                path,
                "--code",
                "secret-canary",
                "--json",
            ],
            b"".as_slice(),
            "cli_invalid_arguments",
        ),
        (
            vec![
                "enroll",
                "forget",
                "--platform",
                "https://mitigate.example",
                "--state",
                path,
                "--json",
            ],
            b"".as_slice(),
            "cli_invalid_arguments",
        ),
    ] {
        let output = run(&arguments, input);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], expected);
        let text = String::from_utf8(output.stderr).unwrap();
        assert!(!text.contains("secret-canary"));
        assert!(!text.contains(code));
        assert!(!text.contains(path));
        assert!(!missing.exists());
    }
    let output = run(
        &[
            "enroll",
            "start",
            "--platform",
            "https://mitigate.example",
            "--state",
            path,
        ],
        b"secret-canary",
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(message.contains("Hidden input is unavailable"));
    assert!(!message.contains("secret-canary"));
    assert!(!missing.exists());
}
