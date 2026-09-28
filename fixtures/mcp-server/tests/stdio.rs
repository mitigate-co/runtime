//! Actual subprocess protocol, resource and lifecycle tests on all supported OSes.
use mitigate_mcp::{Error, LaunchConfig, enumerate};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-enumerate-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, args: &[&str], timeout: u64) -> LaunchConfig {
        LaunchConfig::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),"working_directory":self.0,"argv":args,"timeout_ms":timeout})).unwrap()).unwrap()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn initializes_paginates_normalizes_and_omits_content() {
    let project = Project::new();
    for mode in [
        "ok",
        "paged",
        "ping",
        "old-version",
        "empty",
        "no-tools",
        "arguments",
    ] {
        let args = if mode == "arguments" {
            vec![
                mode,
                "space separated",
                "$(unexpanded)",
                ";not-a-command",
                "\"quoted\"",
            ]
        } else {
            vec![mode]
        };
        let inventory = enumerate(&project.config(&args, 5000)).await.unwrap();
        let output = serde_json::to_string(&inventory.report()).unwrap();
        assert!(!output.contains("canary"));
        assert!(!output.contains("policies"));
        assert_eq!(inventory.tools_supported, mode != "no-tools");
        if mode == "paged" {
            assert_eq!(
                inventory
                    .tools
                    .iter()
                    .map(|t| t.name.as_str())
                    .collect::<Vec<_>>(),
                ["a_first", "z_last"]
            );
        } else if mode == "empty" || mode == "no-tools" {
            assert!(inventory.tools.is_empty());
        } else {
            assert_eq!(inventory.tools.len(), 1);
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_hostile_protocol_and_resource_exhaustion_without_echoing_errors() {
    let project = Project::new();
    for (mode, expected) in [
        ("duplicate", Error::Protocol),
        ("oversized", Error::Limit),
        ("malformed", Error::Protocol),
        ("error", Error::Upstream),
        ("wrong-id", Error::Protocol),
        ("ambiguous", Error::Protocol),
        ("flood", Error::Limit),
        ("version", Error::Version),
        ("changed", Error::Changed),
        ("duplicate-tool", Error::Protocol),
        ("cursor-cycle", Error::Limit),
        ("count", Error::Limit),
        ("bad-schema", Error::Protocol),
        ("bad-name", Error::Protocol),
        ("crash", Error::Disconnected),
        ("timeout", Error::Timeout),
    ] {
        let result =
            enumerate(&project.config(&[mode], if mode == "timeout" { 200 } else { 5000 })).await;
        let error = result
            .err()
            .unwrap_or_else(|| panic!("{mode} unexpectedly succeeded"));
        assert_eq!(error, expected, "{mode}");
        assert!(!error.to_string().contains("canary"));
        assert!(!format!("{error:?}").contains("canary"));
    }
}

#[tokio::test(flavor = "current_thread")]
async fn timeout_terminates_descendants_that_retain_pipes() {
    let project = Project::new();
    let marker = project.0.join("child-address");
    let config = project.config(&["tree", marker.to_str().unwrap()], 2500);
    assert_eq!(enumerate(&config).await.err(), Some(Error::Timeout));
    let address: std::net::SocketAddr = fs::read_to_string(&marker)
        .expect("child must have started")
        .parse()
        .unwrap();
    assert!(
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err(),
        "descendant survived cleanup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_enumeration_kills_the_process_group() {
    let project = Project::new();
    let marker = project.0.join("cancel-child-address");
    let config = project.config(&["tree", marker.to_str().unwrap()], 30_000);
    let mut running = Box::pin(enumerate(&config));
    let ready = async {
        loop {
            if fs::read_to_string(&marker)
                .ok()
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::select! {
        _ = &mut running => panic!("enumeration ended before cancellation"),
        result = tokio::time::timeout(Duration::from_secs(5),ready) => result.unwrap(),
    }
    drop(running);
    let address = fs::read_to_string(marker).unwrap().parse().unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while std::net::TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cancelled server tree survived");
}

#[test]
fn only_explicit_environment_references_reach_the_child() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_mitigate-test-mcp"))
        .arg("environment-harness")
        .env("AMBIENT_CANARY", "ambient-secret-canary")
        .env("ALLOWED_CANARY", "environment-secret-canary")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8(output.stdout).unwrap().contains("canary"));
}

#[tokio::test(flavor = "current_thread")]
async fn explicit_shutdown_confirms_descendant_cleanup() {
    let project = Project::new();
    let marker = project.0.join("shutdown-child-address");
    let config = project.config(&["tree", marker.to_str().unwrap()], 30_000);
    let shutdown = async {
        loop {
            if fs::read_to_string(&marker)
                .ok()
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let result = tokio::time::timeout(
        Duration::from_secs(7),
        mitigate_mcp::enumerate_with_shutdown(&config, shutdown),
    )
    .await
    .unwrap();
    assert_eq!(result.err(), Some(Error::Cancelled));
    let address = fs::read_to_string(marker).unwrap().parse().unwrap();
    assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
}

#[tokio::test(flavor = "current_thread")]
async fn validates_launch_again_at_execution_and_never_searches_path() {
    let project = Project::new();
    for command in ["mitigate-test-mcp", "../mitigate-test-mcp", "${EXECUTABLE}"] {
        let config: LaunchConfig = serde_json::from_value(
            json!({"schema_version":1,"executable_path":command,"working_directory":project.0}),
        )
        .unwrap();
        assert_eq!(enumerate(&config).await.err(), Some(Error::Executable));
    }
    let config: LaunchConfig = serde_json::from_value(json!({"schema_version":42,"executable_path":"unused","working_directory":project.0,"timeout_ms":0})).unwrap();
    assert_eq!(enumerate(&config).await.err(), Some(Error::Configuration));
    #[cfg(windows)]
    {
        let script = project.0.join("unsafe.cmd");
        fs::write(&script, "exit 0").unwrap();
        let config: LaunchConfig = serde_json::from_value(
            json!({"schema_version":1,"executable_path":script,"working_directory":project.0}),
        )
        .unwrap();
        assert_eq!(enumerate(&config).await.err(), Some(Error::Executable));
    }
}
