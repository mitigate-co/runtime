//! Subprocess contract and content-leak regression tests for the shipped CLI.

use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn file(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("runtime.json");
        fs::write(&path, bytes).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mitigate"))
        .args(args)
        // Runtime commands must not require home directories or Platform auth.
        .env_remove("HOME")
        .env_remove("USERPROFILE")
        .env_remove("MITIGATE_TOKEN")
        .env_remove("MITIGATE_ORGANIZATION")
        .output()
        .unwrap()
}

#[test]
fn version_and_configuration_work_without_account_or_home() {
    let version = cli(&["version", "--json"]);
    assert!(version.status.success());
    assert!(version.stderr.is_empty());
    let report: Value = serde_json::from_slice(&version.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::json!({"schema_version":1,"product":"Mitigate Runtime","version":env!("CARGO_PKG_VERSION"),"config_schema_version":1})
    );
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/runtime.json");
    let valid = cli(&[
        "config",
        "check",
        "--config",
        config.to_str().unwrap(),
        "--json",
    ]);
    assert!(valid.status.success());
    assert!(valid.stderr.is_empty());
    let valid: Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(valid["valid"], true);
    assert_eq!(valid["config"]["scan"]["max_servers"], 128);
}

#[test]
fn config_errors_are_stable_and_do_not_echo_content_or_paths() {
    let fixture = Fixture::new();
    for (content, code) in [
        (
            br#"{"schema_version":1,"credential":"private-canary-value"}"#.as_slice(),
            "config_invalid_document",
        ),
        (
            br#"{"schema_version":"private-canary-value"}"#.as_slice(),
            "config_invalid_document",
        ),
        (
            br#"{"schema_version":99}"#.as_slice(),
            "config_unsupported_version",
        ),
        (
            br#"{"schema_version":1,"scan":{"max_servers":0}}"#.as_slice(),
            "config_invalid_limits",
        ),
    ] {
        let path = fixture.file(content);
        for json in [true, false] {
            let mut args = vec!["config", "check", "--config", path.to_str().unwrap()];
            if json {
                args.push("--json");
            }
            let output = cli(&args);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(!error.contains("private-canary-value"));
            assert!(!error.contains(path.to_str().unwrap()));
            if json {
                assert_eq!(
                    serde_json::from_str::<Value>(&error).unwrap()["error"],
                    code
                );
            }
        }
    }
}

#[test]
fn rejects_missing_directory_and_oversized_configuration() {
    let fixture = Fixture::new();
    for (path, code) in [
        (fixture.0.join("absent.json"), "config_unavailable"),
        (fixture.0.clone(), "config_not_regular_file"),
        (fixture.file(&vec![b' '; 65_537]), "config_too_large"),
    ] {
        let output = cli(&[
            "config",
            "check",
            "--config",
            path.to_str().unwrap(),
            "--json",
        ]);
        assert_eq!(output.status.code(), Some(2));
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["error"], code);
    }
}

#[cfg(unix)]
#[test]
fn refuses_symlink_configuration() {
    let fixture = Fixture::new();
    let target = fixture.file(br#"{"schema_version":1}"#);
    let link = fixture.0.join("link.json");
    std::os::unix::fs::symlink(target, &link).unwrap();
    let output = cli(&[
        "config",
        "check",
        "--config",
        link.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stderr).unwrap()["error"],
        "config_not_regular_file"
    );
}
