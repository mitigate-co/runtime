use super::*;
use std::cell::Cell;

#[tokio::test]
async fn gate_observes_changes_during_refresh_and_rejection_preserves_connection() {
    let project = Project::new();
    let changed = project.0.join("control-marker");
    let config = LaunchConfig::from_bytes(&serde_json::to_vec(&json!({
        "schema_version":1,"executable_path":env!("CARGO_BIN_EXE_mitigate-test-mcp"),
        "working_directory":project.0,
        "argv":["relay-gate",project.0.join("child-address"),project.0.join("call-marker"),changed],
        "timeout_ms":5000
    })).unwrap()).unwrap();
    let mut server = StdioServer::connect(&config).await.unwrap();
    assert!(!changed.exists());
    let visited = Cell::new(0);
    let outcome = server
        .call_with_gate("read_status", json!({}), None, || async {
            visited.set(visited.get() + 1);
            assert!(changed.exists());
            assert!(!project.0.join("call-marker").exists());
            Err("disabled")
        })
        .await;
    assert_eq!(outcome, Err(CallFailure::Rejected("disabled")));
    assert_eq!(visited.get(), 1);
    assert!(!project.0.join("call-marker").exists());
    server.check_inventory().await.unwrap();
    server
        .call_with_gate("read_status", json!({}), None, || async {
            visited.set(visited.get() + 1);
            Ok::<(), ()>(())
        })
        .await
        .unwrap();
    assert_eq!(visited.get(), 2);
    assert!(project.0.join("call-marker").exists());
    server.close().await.unwrap();
}

#[tokio::test]
async fn invalid_arguments_contracts_and_drift_do_not_consume_the_gate() {
    for (mode, args, error) in [
        ("relay-schema", json!({"value":0}), Error::SchemaMismatch),
        (
            "relay-schema-unsupported",
            json!({"value":1}),
            Error::Schema,
        ),
        ("relay-drift", json!({}), Error::Changed),
    ] {
        let project = Project::new();
        let mut server = StdioServer::connect(&project.config(mode, 5000))
            .await
            .unwrap();
        let visited = Cell::new(false);
        let outcome = server
            .call_with_gate("read_status", args, None, || async {
                visited.set(true);
                Ok::<(), ()>(())
            })
            .await;
        assert_eq!(outcome, Err(CallFailure::Upstream(error)));
        assert!(!visited.get());
        assert!(!project.0.join("call-marker").exists());
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn cancellation_while_gate_waits_never_dispatches_or_reuses_the_connection() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay", 5000))
        .await
        .unwrap();
    let (entered, received) = tokio::sync::oneshot::channel();
    let (release, completed) = tokio::sync::oneshot::channel();
    {
        let pending = server.call_with_gate("read_status", json!({}), None, || async {
            entered.send(()).unwrap();
            completed.await.unwrap();
            Ok::<(), ()>(())
        });
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("unexpected completion: {result:?}"),
            result = received => result.unwrap(),
        }
    }
    // Completion arriving after the owning future was dropped cannot dispatch.
    assert!(release.send(()).is_err());
    assert!(!project.0.join("call-marker").exists());
    assert_eq!(server.check_inventory().await, Err(Error::Disconnected));
    server.close().await.unwrap();
}

#[tokio::test]
async fn expired_gate_cannot_dispatch_even_if_it_returns_ready_without_yielding() {
    for blocking in [false, true] {
        let project = Project::new();
        let mut server = StdioServer::connect(&project.config("relay", 1000))
            .await
            .unwrap();
        let outcome = server
            .call_with_gate("read_status", json!({}), None, || async {
                if blocking {
                    // Deliberately exceed the configured deadline in one poll.
                    std::thread::sleep(Duration::from_millis(1200));
                } else {
                    std::future::pending::<()>().await;
                }
                Ok::<(), ()>(())
            })
            .await;
        assert_eq!(outcome, Err(CallFailure::Upstream(Error::Timeout)));
        assert!(!project.0.join("call-marker").exists());
        assert_eq!(server.check_inventory().await, Err(Error::Disconnected));
        server.close().await.unwrap();
    }
}

#[tokio::test]
async fn gate_success_does_not_hide_post_dispatch_failure_or_retry() {
    let project = Project::new();
    let mut server = StdioServer::connect(&project.config("relay-schema-wrong", 5000))
        .await
        .unwrap();
    let visited = Cell::new(0);
    let outcome = server
        .call_with_gate("read_status", json!({"value":1}), None, || async {
            visited.set(visited.get() + 1);
            Ok::<(), ()>(())
        })
        .await;
    assert_eq!(outcome, Err(CallFailure::Upstream(Error::SchemaMismatch)));
    assert_eq!(visited.get(), 1);
    assert!(project.0.join("call-marker").exists());
    let retry = server
        .call_with_gate("read_status", json!({"value":1}), None, || async {
            visited.set(visited.get() + 1);
            Ok::<(), ()>(())
        })
        .await;
    assert_eq!(retry, Err(CallFailure::Upstream(Error::Disconnected)));
    assert_eq!(visited.get(), 1);
    server.close().await.unwrap();
}
