//! Actual support CLI boundary: explicit reads, checked export, no authority changes.
use mitigate_egress::SyncRef;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-diagnostics-cli-{}",
            SyncRef::fresh().unwrap().as_str()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mitigate"))
            .args(["diagnostics", "--json"])
            .args(args)
            .current_dir(&self.0)
            .env("HOME", &self.0)
            .env("USERPROFILE", &self.0)
            .env("MITIGATE_TOKEN", "private-environment-canary")
            .env("MITIGATE_CONFIG", self.0.join("runtime.json"))
            .output()
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn report(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 4096);
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-"));
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn defaults_ignore_ambient_configuration_and_workload_files() {
    let fixture = Fixture::new();
    for file in [
        "runtime.json",
        "secrets.json",
        "audit.sqlite",
        ".mcp.json",
        "runtime.log",
    ] {
        fs::write(fixture.0.join(file), b"private-workload-canary").unwrap();
    }
    let value = report(&fixture.run(&[]));
    let mut keys: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "architecture",
            "configuration",
            "configuration_schema",
            "kind",
            "operating_system",
            "runtime_version",
            "schema_version",
            "storage_check"
        ]
    );
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["kind"], "mitigate_diagnostics");
    assert_eq!(value["runtime_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(value["configuration"], json!({"status":"not_read"}));
    assert_eq!(value["storage_check"], json!({"status":"not_run"}));
    for entry in fs::read_dir(&fixture.0).unwrap() {
        assert_eq!(
            fs::read(entry.unwrap().path()).unwrap(),
            b"private-workload-canary"
        );
    }
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 5);
}

#[test]
fn selected_configuration_exports_only_limits_or_closed_failure() {
    let fixture = Fixture::new();
    let path = fixture.0.join("private-config-canary.json");
    fs::write(
        &path,
        br#"{"schema_version":1,"scan":{"max_file_bytes":2048,"max_servers":8}}"#,
    )
    .unwrap();
    let value = report(&fixture.run(&["--config", path.to_str().unwrap()]));
    assert_eq!(
        value["configuration"],
        json!({"status":"valid","max_file_bytes":2048,"max_servers":8})
    );
    let hostile = br#"{"schema_version":1,"token":"private-token-canary"}"#;
    fs::write(&path, hostile).unwrap();
    let value = report(&fixture.run(&["--config", path.to_str().unwrap()]));
    assert_eq!(
        value["configuration"],
        json!({"status":"unavailable","error":"config_invalid_document"})
    );
    assert_eq!(fs::read(&path).unwrap(), hostile);
    let value = report(&fixture.run(&["--config", "private-missing-canary"]));
    assert_eq!(
        value["configuration"],
        json!({"status":"unavailable","error":"config_unavailable"})
    );
}

#[test]
fn synthetic_storage_probe_has_no_network_or_neighbor_changes() {
    let fixture = Fixture::new();
    let marker = fixture.0.join("private-neighbor");
    fs::write(&marker, b"private-neighbor-canary").unwrap();
    let value =
        report(&fixture.run(&["--check-storage", "--work-dir", fixture.0.to_str().unwrap()]));
    assert_eq!(
        value["storage_check"],
        json!({"status":"complete","passed":true,
        "attempted":260,"rejected":260,"positive_control":true,"queue_isolation":true,
        "persisted_canaries_absent":true,"network_requests":0})
    );
    assert_eq!(fs::read(&marker).unwrap(), b"private-neighbor-canary");
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    let value = report(&fixture.run(&[
        "--check-storage",
        "--work-dir",
        "private-missing-parent-canary",
    ]));
    assert_eq!(
        value["storage_check"],
        json!({"status":"unavailable","error":"workspace"})
    );
    let invalid = fixture.run(&["--work-dir", "private-missing-parent-canary"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(invalid.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("private-"));
}

#[test]
fn new_export_matches_checked_stdout_and_never_replaces_a_file() {
    let fixture = Fixture::new();
    let path = fixture.0.join("support.json");
    let result = fixture.run(&["--output", path.to_str().unwrap()]);
    report(&result);
    assert_eq!(fs::read(&path).unwrap(), result.stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let result = fixture.run(&["--output", path.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    let error: Value = serde_json::from_slice(&result.stderr).unwrap();
    assert_eq!(error["error"], "diagnostics_output_unavailable");
    assert!(!String::from_utf8_lossy(&result.stderr).contains(path.to_str().unwrap()));
    let value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(value["kind"], "mitigate_diagnostics");
    for name in [
        "private-missing-parent-canary/report.json",
        "NUL.json",
        "COM1",
        "LPT9.txt",
        "report:stream",
        "report.",
        "report ",
    ] {
        let result = fixture.run(&["--output", name]);
        assert_eq!(result.status.code(), Some(2), "{name}");
        assert!(result.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&result.stderr).contains("private-"));
    }
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn export_refuses_an_existing_symlink_and_preserves_its_target() {
    let fixture = Fixture::new();
    let target = fixture.0.join("private-target");
    let link = fixture.0.join("report.json");
    fs::write(&target, b"private-target-canary").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let result = fixture.run(&["--output", link.to_str().unwrap()]);
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());
    assert_eq!(fs::read(&target).unwrap(), b"private-target-canary");
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}
