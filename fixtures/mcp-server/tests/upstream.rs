//! Managed real-process relay failures and cancellation, using synthetic payloads.
use mitigate_mcp::{Error, LaunchConfig, LaunchReview, Progress, StdioServer};
use serde_json::json;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

#[tokio::test]
async fn input_contract_blocks_invocation_and_valid_input_can_still_run() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-schema", 5000))
        .await
        .unwrap();
    for args in [
        json!({}),
        json!({"value":"1"}),
        json!({"value":0}),
        json!({"value":1,"extra":true}),
    ] {
        assert_eq!(
            server.call("read_status", args, None).await.err(),
            Some(Error::SchemaMismatch)
        );
        assert!(!project.0.join("call-marker").exists());
    }
    let result = server
        .call("read_status", json!({"value":1}), None)
        .await
        .unwrap();
    assert_eq!(result["structuredContent"]["ok"], true);
    server.close().await.unwrap();
}

#[tokio::test]
async fn unsupported_output_schema_is_refused_before_any_invocation() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-schema-unsupported", 5000))
        .await
        .unwrap();
    assert_eq!(
        server
            .call("read_status", json!({"value":1}), None)
            .await
            .err(),
        Some(Error::Schema)
    );
    assert!(!project.0.join("call-marker").exists());
    server.check_inventory().await.unwrap();
    server.close().await.unwrap();
}

#[tokio::test]
async fn invalid_or_missing_structured_output_is_withheld_and_poisons_connection() {
    for mode in [
        "relay-schema-wrong",
        "relay-schema-missing",
        "relay-schema-error-invalid",
    ] {
        let project = Project::new();
        let mut server = StdioServer::connect(&project.config(mode, 5000))
            .await
            .unwrap();
        let error = server
            .call("read_status", json!({"value":1}), None)
            .await
            .err()
            .unwrap();
        assert_eq!(error, Error::SchemaMismatch);
        assert!(!error.to_string().contains("canary"));
        assert!(project.0.join("call-marker").exists());
        assert_eq!(
            server.check_inventory().await.err(),
            Some(Error::Disconnected)
        );
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn tool_error_can_omit_success_output_without_fabricating_data() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-schema-error", 5000))
        .await
        .unwrap();
    let result = server
        .call("read_status", json!({"value":1}), None)
        .await
        .unwrap();
    assert_eq!(result["isError"], true);
    assert!(result.get("structuredContent").is_none());
    server.close().await.unwrap();
}

struct Project(PathBuf);
impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-upstream-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self, mode: &str, timeout: u64) -> LaunchConfig {
        LaunchConfig::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),"working_directory":self.0,"argv":[mode,self.0.join("child-address"),self.0.join("call-marker")],"timeout_ms":timeout})).unwrap()).unwrap()
    }
}
impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn reuses_initialized_connection_checks_inventory_and_relays_local_result() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay", 5000))
        .await
        .unwrap();
    assert_eq!(server.inventory().tools.len(), 1);
    for _ in 0..3 {
        server.check_inventory().await.unwrap();
        let result = server
            .call("read_status", json!({"value":"argument-canary"}), None)
            .await
            .unwrap();
        assert_eq!(result["content"][0]["text"], "synthetic-result-canary");
        assert_eq!(result["structuredContent"]["ok"], true);
    }
    server.close().await.unwrap();
    server.close().await.unwrap();
    assert_eq!(
        server.call("read_status", json!({}), None).await.err(),
        Some(Error::Disconnected)
    );
}

#[tokio::test]
async fn changed_definition_is_refused_before_any_tool_call() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-drift", 5000))
        .await
        .unwrap();
    assert_eq!(
        server.call("read_status", json!({}), None).await.err(),
        Some(Error::Changed)
    );
    assert!(!project.0.join("call-marker").exists());
    assert_eq!(
        server.check_inventory().await.err(),
        Some(Error::Disconnected)
    );
    server.close().await.unwrap();
}

#[tokio::test]
async fn reviewed_launch_rechecks_code_before_calls_and_poisoned_session_cannot_resume() {
    let project = Project::new();
    let artifact = project.0.join("code-artifact.js");
    fs::write(&artifact, b"synthetic reviewed code").unwrap();
    let value = json!({"schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),"working_directory":project.0,
        "argv":["relay",project.0.join("child-address"),project.0.join("call-marker")],"artifact_paths":[artifact],"timeout_ms":30000});
    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    let review = LaunchReview::create(&config).await.unwrap();
    let mut server = StdioServer::connect_reviewed(&config, &review)
        .await
        .unwrap();
    assert_eq!(
        server.launch_receipt().unwrap().launch_ref,
        review.receipt().launch_ref
    );
    assert_eq!(
        server.call("read_status", json!({}), None).await.unwrap()["structuredContent"]["ok"],
        true
    );
    fs::remove_file(project.0.join("call-marker")).unwrap();
    fs::write(&artifact, b"changed code").unwrap();
    assert_eq!(
        server.call("read_status", json!({}), None).await.err(),
        Some(Error::LaunchChanged)
    );
    assert!(!project.0.join("call-marker").exists());
    fs::write(&artifact, b"synthetic reviewed code").unwrap();
    assert_eq!(
        server.check_inventory().await.err(),
        Some(Error::Disconnected)
    );
    server.close().await.unwrap();
    let mut changed = value;
    changed["argv"][0] = json!("relay-error");
    let changed = LaunchConfig::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
    assert_eq!(
        StdioServer::connect_reviewed(&changed, &review)
            .await
            .err()
            .map(|e| e.code()),
        Some("mcp_launch_changed")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn retargeted_code_symlink_is_refused_before_upstream_call() {
    use std::os::unix::fs::symlink;
    let project = Project::new();
    let original = project.0.join("original.js");
    let replacement = project.0.join("replacement.js");
    let alias = project.0.join("entry.js");
    fs::write(&original, b"same bytes").unwrap();
    fs::write(&replacement, b"same bytes").unwrap();
    symlink(&original, &alias).unwrap();
    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),"working_directory":project.0,
        "argv":["relay",project.0.join("child-address"),project.0.join("call-marker")],"artifact_paths":[alias],"timeout_ms":30000})).unwrap()).unwrap();
    let review = LaunchReview::create(&config).await.unwrap();
    let mut server = StdioServer::connect_reviewed(&config, &review)
        .await
        .unwrap();
    fs::remove_file(&alias).unwrap();
    symlink(&replacement, &alias).unwrap();
    assert_eq!(
        server.call("read_status", json!({}), None).await.err(),
        Some(Error::LaunchChanged)
    );
    assert!(!project.0.join("call-marker").exists());
    server.close().await.unwrap();
}

#[tokio::test]
async fn code_change_during_refresh_is_checked_before_invocation() {
    let project = Project::new();
    let artifact = project.0.join("entry.js");
    fs::write(&artifact, b"reviewed code").unwrap();
    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({"schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),"working_directory":project.0,
        "argv":["relay-code-drift",project.0.join("child-address"),project.0.join("call-marker"),artifact],"artifact_paths":[artifact],"timeout_ms":30000})).unwrap()).unwrap();
    let review = LaunchReview::create(&config).await.unwrap();
    let mut server = StdioServer::connect_reviewed(&config, &review)
        .await
        .unwrap();
    assert_eq!(
        server.call("read_status", json!({}), None).await.err(),
        Some(Error::LaunchChanged)
    );
    assert!(!project.0.join("call-marker").exists());
    server.close().await.unwrap();
}

#[tokio::test]
async fn failures_poison_connection_without_returning_upstream_error_content() {
    for (mode, expected) in [
        ("relay-error", Error::Upstream),
        ("relay-crash", Error::Disconnected),
        ("relay-timeout", Error::Timeout),
        ("relay-invalid", Error::Protocol),
        ("relay-bad-progress", Error::Protocol),
        ("relay-progress-regress", Error::Protocol),
        ("relay-progress-total", Error::Protocol),
        ("relay-wrong-id", Error::Protocol),
    ] {
        let project = Project::new();
        let mut server = StdioServer::connect(
            &project.config(mode, if mode == "relay-timeout" { 1000 } else { 5000 }),
        )
        .await
        .unwrap();
        let error = match server
            .call("read_status", json!({}), Some(&mut |_| {}))
            .await
        {
            Err(error) => error,
            Ok(_) => panic!("upstream failure fixture unexpectedly succeeded"),
        };
        assert_eq!(error, expected);
        assert!(!error.to_string().contains("canary"));
        assert_eq!(
            server.check_inventory().await.err(),
            Some(Error::Disconnected)
        );
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn progress_is_correlated_monotonic_counters_without_message_content() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-progress", 5000))
        .await
        .unwrap();
    let mut events = Vec::new();
    server
        .call(
            "read_status",
            json!({}),
            Some(&mut |event| events.push(event)),
        )
        .await
        .unwrap();
    assert_eq!(
        events,
        [
            Progress {
                completed: 1.0,
                total: Some(2.0)
            },
            Progress {
                completed: 2.0,
                total: Some(2.0)
            }
        ]
    );
    server.close().await.unwrap();
}

#[tokio::test]
async fn invalid_invocations_never_reach_the_upstream() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay", 5000))
        .await
        .unwrap();
    for (name, args, expected) in [
        ("missing", json!({}), Error::Protocol),
        ("read_status", json!([]), Error::Protocol),
        (
            "read_status",
            json!({"huge":"x".repeat(60_001)}),
            Error::Limit,
        ),
    ] {
        assert_eq!(server.call(name, args, None).await.err(), Some(expected));
    }
    assert!(!project.0.join("call-marker").exists());
    server.check_inventory().await.unwrap();
    server.close().await.unwrap();
}

#[tokio::test]
async fn dropping_call_kills_descendants_and_forbids_reusing_the_session() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-tree", 30_000))
        .await
        .unwrap();
    let marker = project.0.join("call-marker");
    let mut call = Box::pin(server.call("read_status", json!({}), None));
    let ready = async {
        loop {
            if marker.exists() && project.0.join("child-address").exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    tokio::select! {
        result = &mut call => panic!("call ended before cancellation: {}", result.is_ok()),
        ready = tokio::time::timeout(Duration::from_secs(5), ready) => ready.unwrap(),
    }
    drop(call);
    assert_eq!(
        server.check_inventory().await.err(),
        Some(Error::Disconnected)
    );
    server.close().await.unwrap();
    let address = fs::read_to_string(project.0.join("child-address"))
        .unwrap()
        .parse()
        .unwrap();
    if let Ok(mut socket) =
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200))
    {
        use std::io::Read;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut banner = [0; b"mitigate-fixture-alive\n".len()];
        assert!(
            socket.read_exact(&mut banner).is_err(),
            "descendant responded after cleanup"
        );
    }
}

#[tokio::test]
async fn startup_shutdown_confirms_cleanup_before_returning() {
    let project = Project::new();
    let marker = project.0.join("child-address");
    let config = project.config("tree", 30_000);
    let shutdown = async {
        loop {
            if fs::read_to_string(&marker)
                .ok()
                .and_then(|s| s.parse::<std::net::SocketAddr>().ok())
                .is_some()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let result = tokio::time::timeout(
        Duration::from_secs(7),
        StdioServer::connect_with_shutdown(&config, shutdown),
    )
    .await
    .unwrap();
    assert_eq!(result.err(), Some(Error::Cancelled));
    let address = fs::read_to_string(marker).unwrap().parse().unwrap();
    if let Ok(mut socket) =
        std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200))
    {
        use std::io::Read;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let mut banner = [0; b"mitigate-fixture-alive\n".len()];
        assert!(
            socket.read_exact(&mut banner).is_err(),
            "descendant responded after startup cancellation"
        );
    }
}
