use super::*;

pub(super) async fn run(binary: &Path, root: &Path) {
    for (label, mode, expected) in [
        ("revoke-during-refresh", "relay-governance-revoke", -32001),
        ("stop-during-refresh", "relay-governance-stop", -32009),
    ] {
        let project = Project::new(root, label, mode, "require_approval", 60_000).await;
        let mut client = Client::start(binary, &project, true);
        client.initialize().await;
        client.call(2, json!({"value":"argument-canary"})).await;
        let pending = project.pending().await;
        project.decide(&pending, Choice::Approve);
        assert_eq!(client.result(2).await.0["error"]["code"], expected);
        client.finish(0).await;
        assert!(!project.path("call-marker").exists());
        let events = project.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[1]["call"]["phase"], "decision");
        assert_eq!(events[1]["detail"]["result_class"], "not_invoked");
        if expected == -32001 {
            assert_eq!(
                events[1]["call"]["approval_actor"]["operator_ref"],
                "4".repeat(64)
            );
            assert_eq!(events[1]["call"]["approval_actor"]["choice"], "deny");
        }
        project.private();
    }

    let project = Project::new(root, "startup", "relay-governance-start", "allow", 60_000).await;
    fs::remove_file(project.path("child-address")).unwrap();
    fs::write(
        project.path("grants.json"),
        br#"{"unknown":"startup-canary"}"#,
    )
    .unwrap();
    let mut client = Client::start(binary, &project, true);
    client.finish(2).await;
    assert!(
        !project.path("child-address").exists(),
        "invalid authority must fail before execution"
    );
    assert!(project.events().is_empty());
    project.grants(true);

    // A valid snapshot with stale server facts can only be detected after the
    // selected process answers enumeration. No listener or tool call may start.
    let mut snapshot: Value =
        serde_json::from_slice(&fs::read(project.path("snapshot.json")).unwrap()).unwrap();
    snapshot["server_facts"] = json!("0".repeat(64));
    write(&project.path("snapshot.json"), snapshot);
    let mut client = Client::start(binary, &project, true);
    client.finish(2).await;
    assert!(project.path("child-address").exists());
    assert!(!project.path("call-marker").exists());
    assert!(project.events().is_empty());
    project.private();
}
