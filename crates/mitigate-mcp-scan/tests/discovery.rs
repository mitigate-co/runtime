//! Read-only discovery, hostile configuration, and non-disclosure regressions.

use mitigate_config::ScanLimits;
use mitigate_mcp_scan::{
    ConfigRisk, CredentialReferenceType, ScanErrorCode, SourceKind, TransportKind, scan_project,
};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-discovery-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn write(&self, source: SourceKind, bytes: &[u8]) {
        let path = self.0.join(source.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }
    fn json(&self, source: SourceKind, value: serde_json::Value) {
        self.write(source, &serde_json::to_vec(&value).unwrap());
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn empty_project_is_explicit_and_known_sources_are_deterministic() {
    let project = Project::new();
    let empty = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert!(empty.servers.is_empty());
    assert_eq!(empty.sources.len(), 2);
    assert!(empty.sources.iter().all(|s| !s.present));
    project.json(
        SourceKind::ClaudeProject,
        json!({"mcpServers":{"z-last":{"command":"node"},"a-first":{"command":"python"}}}),
    );
    project.json(
        SourceKind::CursorProject,
        json!({"mcpServers":{"remote":{"url":"https://example.test/private-path"}}}),
    );
    let report = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert!(report.sources.iter().all(|s| s.present));
    assert_eq!(
        report
            .servers
            .iter()
            .map(|s| s.server_name.as_str())
            .collect::<Vec<_>>(),
        ["a-first", "z-last", "remote"]
    );
    assert_eq!(report.servers[2].transport, TransportKind::Unknown);
    assert_eq!(
        report.servers[2].command_or_url.as_deref(),
        Some("https://example.test")
    );
    assert!(
        report.servers[2]
            .risks
            .contains(&ConfigRisk::TransportUnresolved)
    );
    assert_eq!(
        report,
        scan_project(&project.0, &ScanLimits::default()).unwrap()
    );
}

#[test]
fn secrets_paths_and_argument_values_never_enter_normalized_output() {
    let project = Project::new();
    project.json(SourceKind::ClaudeProject, json!({"mcpServers":{
        "local":{"command":"/local-private-directory/node","args":["argument-canary"],"env":{"PRIVATE_NAME":"environment-canary","REF":"${DO_NOT_READ}"},"envFile":"missing-env-canary"},
        "remote":{"type":"http","url":"https://user-canary:password-canary@example.test/path-canary?key=query-canary#fragment-canary","headers":{"Authorization":"header-canary"},"auth":{"CLIENT_SECRET":"oauth-canary"},"headersHelper":"helper-canary"}
    }}));
    let report = scan_project(&project.0, &ScanLimits::default()).unwrap();
    let encoded = serde_json::to_string(&report).unwrap();
    let debug = format!("{report:?}");
    for canary in [
        "local-private-directory",
        "argument-canary",
        "PRIVATE_NAME",
        "environment-canary",
        "DO_NOT_READ",
        "missing-env-canary",
        "user-canary",
        "password-canary",
        "path-canary",
        "query-canary",
        "fragment-canary",
        "header-canary",
        "oauth-canary",
        "helper-canary",
    ] {
        assert!(!encoded.contains(canary), "JSON leaked {canary}");
        assert!(!debug.contains(canary), "Debug leaked {canary}");
    }
    assert_eq!(report.servers[0].argument_count, 1);
    assert!(
        report.servers[0]
            .credential_reference_types
            .contains(&CredentialReferenceType::EnvironmentReference)
    );
    assert!(
        report.servers[1]
            .risks
            .contains(&ConfigRisk::UrlCredentials)
    );
    assert!(report.servers[1].risks.contains(&ConfigRisk::HeaderHelper));
}

#[test]
fn hostile_shell_and_environment_file_are_reported_without_execution_or_reading() {
    let project = Project::new();
    let marker = project.0.join("must-not-exist");
    let command = format!("echo leaked > {}", marker.display());
    project.json(SourceKind::ClaudeProject, json!({"mcpServers":{"hostile":{"command":"cmd.exe","args":["/c",command],"envFile":"../../missing-secret-file","cwd":"${HOSTILE_VARIABLE}"}}}));
    let report = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert!(!marker.exists());
    assert!(report.servers[0].risks.contains(&ConfigRisk::ShellWrapper));
    assert!(
        report.servers[0]
            .risks
            .contains(&ConfigRisk::EnvironmentFile)
    );
    assert!(
        report.servers[0]
            .risks
            .contains(&ConfigRisk::VariableExpansion)
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("HOSTILE_VARIABLE")
    );
}

#[test]
fn malformed_or_ambiguous_present_source_never_returns_partial_success() {
    let project = Project::new();
    project.json(
        SourceKind::ClaudeProject,
        json!({"mcpServers":{"good":{"command":"node"}}}),
    );
    for content in [
        r#"{"mcpServers":{"duplicate":{"command":"node"},"duplicate":{"command":"sh"}}}"#,
        r#"{"mcpServers":{"a":{"command":"node","command":"sh"}}}"#,
        r#"{"mcpServers":{"a":{"command":"node","env":{"TOKEN":"first-canary","TOKEN":"second-canary"}}}}"#,
        r#"{"mcpServers":{}} trailing-canary"#,
        r#"{"mcpServers":{"a":{"command":"node","url":"https://example.test"}}}"#,
        r#"{"mcpServers":{"a":{"command":"node","args":"secret-canary"}}}"#,
        r#"{"mcpServers":{"a":{"command":"node","env":{"TOKEN":123}}}}"#,
        r#"{"mcpServers":{"a":{"url":"file:///secret-canary"}}}"#,
        r#"{"mcpServers":{"\u001b[31m":{"command":"node"}}}"#,
        r#"{"mcpServers":{"spoof\u202e":{"command":"node"}}}"#,
    ] {
        project.write(SourceKind::CursorProject, content.as_bytes());
        let error = scan_project(&project.0, &ScanLimits::default()).unwrap_err();
        assert_eq!(error.source, Some(SourceKind::CursorProject));
        assert!(matches!(
            error.code,
            ScanErrorCode::InvalidDocument | ScanErrorCode::InvalidServer
        ));
        assert!(!error.to_string().contains("canary"));
    }
}

#[test]
fn bounds_files_servers_arguments_and_nesting() {
    let project = Project::new();
    let limits = ScanLimits {
        max_file_bytes: 1024,
        max_servers: 1,
    };
    project.write(SourceKind::ClaudeProject, &[b' '; 1025]);
    assert_eq!(
        scan_project(&project.0, &limits).unwrap_err().code,
        ScanErrorCode::SourceTooLarge
    );
    project.json(
        SourceKind::ClaudeProject,
        json!({"mcpServers":{"one":{"command":"node"},"two":{"command":"node"}}}),
    );
    assert_eq!(
        scan_project(&project.0, &limits).unwrap_err().code,
        ScanErrorCode::ServerLimit
    );
    project.json(
        SourceKind::ClaudeProject,
        json!({"mcpServers":{"one":{"command":"node","args":vec!["arg";65]}}}),
    );
    assert_eq!(
        scan_project(&project.0, &ScanLimits::default())
            .unwrap_err()
            .code,
        ScanErrorCode::InvalidServer
    );
    let nested = format!(
        "{{\"mcpServers\":{{}},\"unknown\":{}0{}}}",
        "[".repeat(40),
        "]".repeat(40)
    );
    project.write(SourceKind::ClaudeProject, nested.as_bytes());
    assert_eq!(
        scan_project(&project.0, &ScanLimits::default())
            .unwrap_err()
            .code,
        ScanErrorCode::InvalidDocument
    );
    let invalid = ScanLimits {
        max_file_bytes: usize::MAX,
        max_servers: 1,
    };
    assert_eq!(
        scan_project(&project.0, &invalid).unwrap_err().code,
        ScanErrorCode::InvalidLimits
    );
}

#[test]
fn package_versions_are_declarations_not_resolved_tags() {
    let project = Project::new();
    for (declaration, name, version) in [
        (
            "@example/server@1.2.3",
            Some("@example/server"),
            Some("1.2.3"),
        ),
        ("@example/server@latest", Some("@example/server"), None),
        ("example-mcp", Some("example-mcp"), None),
        ("--token=secret-canary", None, None),
        ("../../private-canary", None, None),
    ] {
        project.json(
            SourceKind::ClaudeProject,
            json!({"mcpServers":{"package":{"command":"npx","args":["-y",declaration]}}}),
        );
        let report = scan_project(&project.0, &ScanLimits::default()).unwrap();
        assert_eq!(report.servers[0].package_name.as_deref(), name);
        assert_eq!(report.servers[0].package_version.as_deref(), version);
    }
}

#[test]
fn configuration_summary_fingerprint_excludes_secrets_and_tracks_visible_facts() {
    let project = Project::new();
    let mut config =
        json!({"mcpServers":{"tool":{"command":"npx","env":{"KEY":"first-secret-canary"}}}});
    project.json(SourceKind::ClaudeProject, config.clone());
    let before = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert_eq!(before.schema_version, 2);
    config["mcpServers"]["tool"]["env"]["KEY"] = json!("rotated-secret-canary");
    project.json(SourceKind::ClaudeProject, config.clone());
    let rotated = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert_eq!(
        before.servers[0].config_fingerprint,
        rotated.servers[0].config_fingerprint
    );
    config["mcpServers"]["tool"]["command"] = json!("cmd.exe");
    project.json(SourceKind::ClaudeProject, config);
    let changed = scan_project(&project.0, &ScanLimits::default()).unwrap();
    assert_ne!(
        before.servers[0].config_fingerprint,
        changed.servers[0].config_fingerprint
    );
}

#[cfg(unix)]
#[test]
fn source_and_parent_symlinks_are_refused_without_following_them() {
    use std::os::unix::fs::symlink;
    let project = Project::new();
    let outside = Project::new();
    outside.json(
        SourceKind::ClaudeProject,
        json!({"mcpServers":{"outside":{"command":"node"}}}),
    );
    symlink(outside.0.join(".mcp.json"), project.0.join(".mcp.json")).unwrap();
    assert_eq!(
        scan_project(&project.0, &ScanLimits::default())
            .unwrap_err()
            .code,
        ScanErrorCode::UnsafeSource
    );
    fs::remove_file(project.0.join(".mcp.json")).unwrap();
    symlink(&outside.0, project.0.join(".cursor")).unwrap();
    assert_eq!(
        scan_project(&project.0, &ScanLimits::default())
            .unwrap_err()
            .code,
        ScanErrorCode::UnsafeSource
    );
}
