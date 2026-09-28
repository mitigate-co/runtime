//! Subprocess contract and content-leak regression tests for the shipped CLI.

use serde_json::Value;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[test]
fn approval_confirmation_guidance_is_specific_and_content_free() {
    for decision in ["approve", "deny"] {
        let result = cli(&[
            "--json",
            "mcp",
            "approvals",
            decision,
            "--db",
            "private-path-canary",
            "--reference",
            &"a".repeat(64),
            "--operator-ref",
            &"b".repeat(64),
        ]);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(error.contains("--confirm"));
        assert!(!error.contains("--allow-exec"));
        assert!(!error.contains("private-path-canary"));
    }
}

#[test]
fn audit_commands_validate_bounds_preserve_files_and_require_prune_intent() {
    let fixture = Fixture::new();
    let path = fixture.0.join("audit.sqlite");
    let db = path.to_str().unwrap();
    let invalid = cli(&[
        "mcp",
        "audit",
        "init",
        "--db",
        db,
        "--max-records",
        "0",
        "--json",
    ]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(!path.exists());
    let created = cli(&[
        "mcp",
        "audit",
        "init",
        "--db",
        db,
        "--max-records",
        "12",
        "--json",
    ]);
    assert!(created.status.success());
    let report: Value = serde_json::from_slice(&created.stdout).unwrap();
    assert_eq!(report["retention"]["max_records"], 12);
    let before = fs::read(&path).unwrap();
    assert_eq!(
        cli(&["mcp", "audit", "init", "--db", db, "--json"])
            .status
            .code(),
        Some(2)
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let listed = cli(&["mcp", "audit", "list", "--db", db]);
    assert!(listed.status.success());
    assert!(
        String::from_utf8(listed.stdout)
            .unwrap()
            .contains("No retained events.")
    );
    assert_eq!(
        cli(&[
            "mcp", "audit", "list", "--db", db, "--limit", "251", "--json"
        ])
        .status
        .code(),
        Some(2)
    );
    assert_eq!(
        cli(&["mcp", "audit", "prune", "--db", db, "--json"])
            .status
            .code(),
        Some(2)
    );
    assert!(
        cli(&["mcp", "audit", "prune", "--db", db, "--confirm", "--json"])
            .status
            .success()
    );
    assert!(
        cli(&["mcp", "audit", "verify", "--db", db, "--json"])
            .status
            .success()
    );
    fs::write(&path, b"sensitive-audit-error-canary").unwrap();
    let failed = cli(&["mcp", "audit", "verify", "--db", db, "--json"]);
    assert_eq!(failed.status.code(), Some(2));
    assert!(failed.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("canary"));
    assert!(!String::from_utf8_lossy(&failed.stderr).contains(db));
}

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
fn secret_commands_reject_invalid_intent_and_references_without_value_echo() {
    for args in [
        vec!["secrets", "import", "--json"],
        vec![
            "secrets",
            "import",
            "--stdin",
            "--value",
            "secret-command-canary",
            "--json",
        ],
        vec![
            "secrets",
            "check",
            "--reference",
            "secret-command-canary",
            "--json",
        ],
        vec![
            "secrets",
            "delete",
            "--reference",
            "sec_0123456789abcdef0123456789abcdef",
            "--json",
        ],
        vec![
            "secrets",
            "replace",
            "--reference",
            "secret-command-canary",
            "--stdin",
            "--json",
        ],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let error: Value = serde_json::from_slice(&output.stderr).unwrap();
        assert_eq!(error["schema_version"], 1);
        assert!(!String::from_utf8_lossy(&output.stderr).contains("secret-command-canary"));
    }
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

#[test]
fn scanner_reports_scope_and_fixture_without_an_account() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/scanner-project");
    for json in [false, true] {
        let mut args = vec!["mcp", "scan", "--root", root.to_str().unwrap()];
        if json {
            args.push("--json");
        }
        let result = cli(&args);
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        let output = String::from_utf8(result.stdout).unwrap();
        assert!(!output.contains("EXAMPLE_TOKEN"));
        assert!(!output.contains("this-command-is-never-executed"));
        assert!(!output.contains("/customer/workspace"));
        if json {
            let report: Value = serde_json::from_str(&output).unwrap();
            assert_eq!(report["schema_version"], 2);
            assert_eq!(report["sources"].as_array().unwrap().len(), 2);
            assert_eq!(report["servers"].as_array().unwrap().len(), 3);
        } else {
            assert!(output.contains("No servers started or contacted"));
        }
    }
    let empty = Fixture::new();
    let result = cli(&["mcp", "scan", "--root", empty.0.to_str().unwrap(), "--json"]);
    assert!(result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["servers"], serde_json::json!([]));
    assert!(
        report["sources"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["present"] == false)
    );
}

#[test]
fn scanner_errors_and_custom_limits_have_stable_exit_contracts() {
    let fixture = Fixture::new();
    let config = fixture.file(br#"{"schema_version":1,"scan":{"max_servers":1}}"#);
    fs::write(
        fixture.0.join(".mcp.json"),
        br#"{"mcpServers":{"one":{"command":"npx"},"two":{"command":"npx"}}}"#,
    )
    .unwrap();
    let result = cli(&[
        "mcp",
        "scan",
        "--root",
        fixture.0.to_str().unwrap(),
        "--runtime-config",
        config.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&result.stderr).unwrap()["error"],
        "scan_server_limit"
    );
    fs::write(
        fixture.0.join(".mcp.json"),
        br#"{"mcpServers":{"private-canary-value":{"command":42}}}"#,
    )
    .unwrap();
    for json in [false, true] {
        let mut args = vec!["mcp", "scan", "--root", fixture.0.to_str().unwrap()];
        if json {
            args.push("--json");
        }
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let error = String::from_utf8(result.stderr).unwrap();
        assert!(!error.contains("private-canary-value"));
        assert!(!error.contains(fixture.0.to_str().unwrap()));
        assert!(error.contains("scan_invalid_server"));
    }
}

#[test]
fn inspect_requires_execution_intent_and_does_not_echo_invalid_config() {
    let fixture = Fixture::new();
    let path = fixture.file(br#"{"schema_version":1,"executable_path":"secret-canary","working_directory":"unused","env":{"TOKEN":"secret-canary"}}"#);
    let unapproved = cli(&[
        "mcp",
        "inspect",
        "--launch-config",
        path.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(unapproved.status.code(), Some(2));
    assert!(unapproved.stdout.is_empty());
    assert!(
        String::from_utf8(unapproved.stderr)
            .unwrap()
            .contains("--allow-exec")
    );
    let approved = cli(&[
        "mcp",
        "inspect",
        "--launch-config",
        path.to_str().unwrap(),
        "--allow-exec",
        "--json",
    ]);
    assert_eq!(approved.status.code(), Some(2));
    assert!(approved.stdout.is_empty());
    let error = String::from_utf8(approved.stderr).unwrap();
    assert!(!error.contains("secret-canary"));
    assert!(!error.contains(path.to_str().unwrap()));
    assert_eq!(
        serde_json::from_str::<Value>(&error).unwrap()["error"],
        "mcp_configuration_invalid"
    );
}

#[test]
fn diff_runs_offline_and_rejects_invalid_snapshots_without_source_content() {
    let fixture = Fixture::new();
    let before = fixture.0.join("before.json");
    let after = fixture.0.join("after.json");
    let inventory = mitigate_mcp::Inventory {
        protocol_version: "2025-11-25".into(),
        server_name: "fixture".into(),
        server_version: "1.0.0".into(),
        tools_supported: true,
        tools: vec![],
    };
    let snapshot = mitigate_mcp::Snapshot::from_inventory(&inventory).unwrap();
    snapshot.write_new(&before).unwrap();
    snapshot.write_new(&after).unwrap();
    for json in [false, true] {
        let mut args = vec![
            "mcp",
            "diff",
            "--before",
            before.to_str().unwrap(),
            "--after",
            after.to_str().unwrap(),
        ];
        if json {
            args.push("--json");
        }
        let result = cli(&args);
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        if json {
            let report: Value = serde_json::from_slice(&result.stdout).unwrap();
            assert_eq!(report["tools"], serde_json::json!([]));
            assert_eq!(report["server_facts_changed"], false);
        } else {
            assert_eq!(
                String::from_utf8(result.stdout).unwrap().trim(),
                "No changes."
            );
        }
    }
    fs::write(&after, br#"{"secret":"snapshot-canary"}"#).unwrap();
    let result = cli(&[
        "mcp",
        "diff",
        "--before",
        before.to_str().unwrap(),
        "--after",
        after.to_str().unwrap(),
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let error = String::from_utf8(result.stderr).unwrap();
    assert!(!error.contains("canary"));
    assert!(!error.contains(after.to_str().unwrap()));
    assert_eq!(
        serde_json::from_str::<Value>(&error).unwrap()["error"],
        "mcp_snapshot_invalid"
    );
}

#[test]
fn invalid_classification_is_rejected_before_attempting_a_launch() {
    let fixture = Fixture::new();
    let policy = fixture.file(br#"{"secret":"override-canary"}"#);
    let result = cli(&[
        "mcp",
        "inspect",
        "--launch-config",
        "absent-launch.json",
        "--classification-overrides",
        policy.to_str().unwrap(),
        "--allow-exec",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let text = String::from_utf8(result.stderr).unwrap();
    assert!(!text.contains("override-canary"));
    assert!(!text.contains(policy.to_str().unwrap()));
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap()["error"],
        "mcp_classification_invalid"
    );
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

#[test]
fn parser_errors_are_content_free_json_and_help_stays_usable() {
    for args in [
        vec!["version", "--accidental-secret=argument-canary", "--json"],
        vec!["--json", "mcp", "argument-canary"],
        vec!["mcp", "scan", "--details", "--json"],
        vec![
            "mcp",
            "inspect",
            "--launch-config",
            "argument-canary",
            "--json",
        ],
    ] {
        let result = cli(&args);
        assert_eq!(result.status.code(), Some(2));
        assert!(result.stdout.is_empty());
        let text = String::from_utf8(result.stderr).unwrap();
        assert!(!text.contains("argument-canary"));
        let error: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(error["schema_version"], 1);
        assert_eq!(error["error"], "cli_invalid_arguments");
        assert_eq!(error.as_object().unwrap().len(), 3);
    }
    for args in [
        vec!["--help"],
        vec!["mcp", "inspect", "--help"],
        vec!["--json", "mcp", "scan", "--help"],
        vec!["--version"],
    ] {
        let result = cli(&args);
        assert!(result.status.success());
        assert!(result.stderr.is_empty());
        assert!(!result.stdout.is_empty());
    }
    let human = cli(&["version", "--accidental-secret=argument-canary"]);
    assert_eq!(human.status.code(), Some(2));
    assert!(
        !String::from_utf8(human.stderr)
            .unwrap()
            .contains("argument-canary")
    );
}

#[test]
fn serve_requires_explicit_mode_and_refuses_invalid_profile_before_launch() {
    for args in [
        vec!["mcp", "serve", "--launch-config", "unused", "--allow-exec"],
        vec![
            "mcp",
            "serve",
            "--launch-config",
            "unused",
            "--inventory-only",
        ],
        vec![
            "mcp",
            "serve",
            "--launch-config",
            "unused",
            "--allow-exec",
            "--inventory-only",
            "--json",
        ],
    ] {
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let fixture = Fixture::new();
    let profile = fixture.0.join("profile.json");
    fs::write(
        &profile,
        br#"{"schema_version":1,"client_ref":"client","secret":"profile-canary"}"#,
    )
    .unwrap();
    let output = cli(&[
        "mcp",
        "serve",
        "--launch-config",
        "no-such-launch-file",
        "--allow-exec",
        "--inventory-only",
        "--profile",
        profile.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("gateway_profile_invalid"));
    assert!(!stderr.contains("canary"));
}

#[test]
fn governed_mode_requires_review_and_cannot_mix_audit_or_inventory_configuration() {
    for extra in [
        vec![],
        vec!["--launch-review", "unused", "--inventory-only"],
        vec!["--launch-review", "unused", "--audit-db", "unused"],
        vec!["--launch-review", "unused", "--json"],
    ] {
        let mut args = vec![
            "mcp",
            "serve",
            "--allow-exec",
            "--launch-config",
            "unused",
            "--enforce",
            "unused",
        ];
        args.extend(extra);
        let output = cli(&args);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("cli_invalid_arguments")
        );
    }
}

#[test]
fn context_requires_explicit_execution_and_rejects_invalid_profiles_before_launch() {
    let mut args = vec![
        "mcp",
        "context",
        "--launch-config",
        "unused",
        "--launch-review",
        "unused",
        "--tool-snapshot",
        "unused",
        "--json",
    ];
    let no_intent = cli(&args);
    assert_eq!(no_intent.status.code(), Some(2));
    assert!(no_intent.stdout.is_empty());
    let error: Value = serde_json::from_slice(&no_intent.stderr).unwrap();
    assert_eq!(error["error"], "cli_invalid_arguments");
    let fixture = Fixture::new();
    let profile = fixture.file(br#"{"schema_version":1,"client_ref":"raw canary"}"#);
    args.extend(["--allow-exec", "--profile", profile.to_str().unwrap()]);
    let invalid = cli(&args);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("canary"));
    let error: Value = serde_json::from_slice(&invalid.stderr).unwrap();
    assert_eq!(error["error"], "gateway_profile_invalid");
}

#[test]
fn scan_findings_exit_is_opt_in_and_keeps_complete_json() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/scanner-project");
    let result = cli(&[
        "mcp",
        "scan",
        "--root",
        root.to_str().unwrap(),
        "--fail-on-risk",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(3));
    assert!(result.stderr.is_empty());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["servers"].as_array().unwrap().len(), 3);
    let empty = Fixture::new();
    let result = cli(&[
        "mcp",
        "scan",
        "--root",
        empty.0.to_str().unwrap(),
        "--fail-on-risk",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(0));
    let result = cli(&["mcp", "scan", "--root", root.to_str().unwrap(), "--details"]);
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Review the shell wrapper before execution."));
    assert!(!text.contains("this-command-is-never-executed"));
    assert!(!text.contains("EXAMPLE_TOKEN"));
}

#[test]
fn snapshot_change_exit_is_opt_in_and_invalid_input_wins_over_findings() {
    let fixture = Fixture::new();
    let before = fixture.0.join("before.json");
    let after = fixture.0.join("after.json");
    let mut inventory = mitigate_mcp::Inventory {
        protocol_version: "2025-11-25".into(),
        server_name: "fixture".into(),
        server_version: "1.0.0".into(),
        tools_supported: true,
        tools: vec![],
    };
    mitigate_mcp::Snapshot::from_inventory(&inventory)
        .unwrap()
        .write_new(&before)
        .unwrap();
    inventory.server_version = "2.0.0".into();
    mitigate_mcp::Snapshot::from_inventory(&inventory)
        .unwrap()
        .write_new(&after)
        .unwrap();
    for (after_path, expected) in [(&after, 3), (&before, 0)] {
        let result = cli(&[
            "mcp",
            "diff",
            "--before",
            before.to_str().unwrap(),
            "--after",
            after_path.to_str().unwrap(),
            "--fail-on-change",
            "--json",
        ]);
        assert_eq!(result.status.code(), Some(expected));
        assert!(result.stderr.is_empty());
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["server_facts_changed"], expected == 3);
    }
    fs::write(&after, br#"{"secret":"diff-canary"}"#).unwrap();
    let result = cli(&[
        "mcp",
        "diff",
        "--before",
        before.to_str().unwrap(),
        "--after",
        after.to_str().unwrap(),
        "--fail-on-change",
        "--json",
    ]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
}
