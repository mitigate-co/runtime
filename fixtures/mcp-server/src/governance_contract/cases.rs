use super::*;
use mitigate_policy::controls::{Rate, Target};

pub(super) async fn run(binary: &Path, root: &Path) {
    let project = Project::new(root, "allow", "relay-progress", "allow", 60_000).await;
    let context = context::verify(binary, &project).await;
    let mut client = Client::start(binary, &project, true);
    client.initialize().await;
    client.call(2, json!({"value":"argument-canary"})).await;
    let (reply, progress) = client.result(2).await;
    assert_eq!(reply["result"]["structuredContent"]["ok"], true);
    assert!(progress > 0);
    let events = project.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["call"]["phase"], "dispatch");
    assert_eq!(events[1]["call"]["phase"], "completion");
    assert_eq!(events[0]["call"]["call_ref"], events[1]["call"]["call_ref"]);
    assert_eq!(events[1]["detail"]["result_class"], "success");
    for field in ["client_ref", "principal_ref", "agent_ref", "server_ref"] {
        assert_eq!(events[0]["detail"][field], context[field]);
    }
    for field in ["tool_ref", "schema_fingerprint", "capability_classes"] {
        assert_eq!(events[0]["detail"][field], context["tools"][0][field]);
    }
    assert_eq!(
        events[0]["call"]["definition_fingerprint"],
        context["tools"][0]["definition_fingerprint"]
    );
    fs::remove_file(project.path("call-marker")).unwrap();

    project.control(Change::Stop {});
    client.call(3, json!({})).await;
    assert_eq!(client.result(3).await.0["error"]["code"], -32009);
    project.control(Change::Resume {});
    project.grants(false);
    client.call(4, json!({})).await;
    assert_eq!(client.result(4).await.0["error"]["code"], -32001);
    project.grants(true);
    project.policy(2, "deny");
    client.call(5, json!({})).await;
    assert_eq!(client.result(5).await.0["error"]["code"], -32001);
    assert!(!project.path("call-marker").exists());
    project.policy(3, "allow");
    project.control(Change::SetLimit {
        target: Target::Global {},
        rate: Rate {
            capacity: 1,
            refill_tokens: 1,
            period_ms: 86_400_000,
        },
    });
    client.call(6, json!({})).await;
    assert_eq!(
        client.result(6).await.0["result"]["structuredContent"]["ok"],
        true
    );
    fs::remove_file(project.path("call-marker")).unwrap();
    client.call(7, json!({})).await;
    assert_eq!(client.result(7).await.0["error"]["code"], -32010);
    assert!(!project.path("call-marker").exists());
    client.finish(0).await;
    project.private();

    // A fresh process with no declared caller must never infer one from clientInfo.
    let mut unknown = Client::start(binary, &project, false);
    unknown.initialize().await;
    unknown.call(2, json!({})).await;
    assert_eq!(unknown.result(2).await.0["error"]["code"], -32001);
    unknown.finish(0).await;
    assert!(project.events().last().unwrap()["detail"]["client_ref"].is_null());

    approvals(binary, root).await;
    for (label, mode, expected, outcome) in [
        ("schema-drift", "relay-drift", -32004, "not_invoked"),
        ("bad-output", "relay-schema-wrong", -32003, "uncertain"),
    ] {
        let project = Project::new(root, label, mode, "require_approval", 60_000).await;
        let mut client = Client::start(binary, &project, true);
        client.initialize().await;
        let arguments = if mode == "relay-drift" {
            json!({"value":"argument-canary"})
        } else {
            json!({"value":1})
        };
        client.call(2, arguments).await;
        let pending = project.pending().await;
        project.decide(&pending, Choice::Approve);
        assert_eq!(client.result(2).await.0["error"]["code"], expected);
        client.finish(0).await;
        assert_eq!(
            project.events().last().unwrap()["detail"]["result_class"],
            outcome
        );
        assert_eq!(
            project.path("call-marker").exists(),
            mode == "relay-schema-wrong"
        );
        project.private();
    }
    audit_failure(binary, root).await;
    cancellation(binary, root).await;
    changes::run(binary, root).await;
}

async fn approvals(binary: &Path, root: &Path) {
    let project = Project::new(
        root,
        "approvals",
        "relay-schema",
        "require_approval",
        60_000,
    )
    .await;
    let mut client = Client::start(binary, &project, true);
    client.initialize().await;
    client.call(2, json!({"value":0})).await;
    assert_eq!(client.result(2).await.0["error"]["code"], -32602);
    assert!(
        ApprovalStore::open(&project.path("approvals.sqlite"))
            .unwrap()
            .list(SystemClock)
            .unwrap()
            .is_empty()
    );
    client.call(3, json!({"value":1})).await;
    let pending = project.pending().await;
    assert!(!project.path("call-marker").exists());
    client
        .send(json!({"jsonrpc":"2.0","id":4,"method":"ping"}))
        .await;
    assert_eq!(client.read().await["result"], json!({}));
    project.decide(&pending, Choice::Approve);
    assert_eq!(
        client.result(3).await.0["result"]["structuredContent"]["ok"],
        true
    );
    assert_eq!(
        ApprovalStore::open(&project.path("approvals.sqlite"))
            .unwrap()
            .get(&pending.approval_ref, SystemClock)
            .unwrap()
            .state,
        State::Consumed
    );
    let events = project.events();
    let last = events.last().unwrap();
    assert_eq!(last["call"]["approval_actor"]["source"], "declared_local");
    assert_eq!(
        last["call"]["approval_actor"]["operator_ref"],
        "3".repeat(64)
    );
    fs::remove_file(project.path("call-marker")).unwrap();
    client.call(5, json!({"value":1})).await;
    let pending = project.pending().await;
    project.decide(&pending, Choice::Deny);
    assert_eq!(client.result(5).await.0["error"]["code"], -32001);
    assert!(!project.path("call-marker").exists());
    client.call(6, json!({"value":1})).await;
    let pending = project.pending().await;
    project.policy(2, "require_approval");
    assert_eq!(client.result(6).await.0["error"]["code"], -32001);
    assert_eq!(
        ApprovalStore::open(&project.path("approvals.sqlite"))
            .unwrap()
            .get(&pending.approval_ref, SystemClock)
            .unwrap()
            .cancellation,
        Some(mitigate_policy::approvals::Cancellation::ContextChanged)
    );
    client.call(7, json!({"value":1})).await;
    let pending = project.pending().await;
    client.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7,"reason":"cancel-canary"}})).await;
    client.finish(2).await;
    assert_eq!(
        ApprovalStore::open(&project.path("approvals.sqlite"))
            .unwrap()
            .get(&pending.approval_ref, SystemClock)
            .unwrap()
            .state,
        State::Cancelled
    );
    assert!(!project.path("call-marker").exists());
    project.private();

    let expired = Project::new(root, "expiry", "relay-schema", "require_approval", 100).await;
    let mut client = Client::start(binary, &expired, true);
    client.initialize().await;
    client.call(2, json!({"value":1})).await;
    assert_eq!(client.result(2).await.0["error"]["code"], -32001);
    client.finish(0).await;
    assert!(!expired.path("call-marker").exists());
    expired.private();
}

async fn audit_failure(binary: &Path, root: &Path) {
    let project = Project::new(root, "audit-busy", "relay", "allow", 60_000).await;
    let mut client = Client::start(binary, &project, true);
    client.initialize().await;
    let lock = rusqlite::Connection::open(project.path("audit.sqlite")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    client
        .call(2, json!({"value":"audit-busy-argument-canary"}))
        .await;
    assert_eq!(client.result(2).await.0["error"]["code"], -32007);
    assert!(!project.path("call-marker").exists());
    lock.execute_batch("ROLLBACK").unwrap();
    client.finish(0).await;
    assert_eq!(
        project.events().last().unwrap()["detail"]["result_class"],
        "uncertain"
    );
    project.private();
}

async fn cancellation(binary: &Path, root: &Path) {
    let project = Project::new(root, "cancel-dispatch", "relay-tree", "allow", 60_000).await;
    let mut client = Client::start(binary, &project, true);
    client.initialize().await;
    client.call(2, json!({})).await;
    timeout(Duration::from_secs(40), async {
        while !project.path("call-marker").exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("synthetic call must reach upstream");
    client
        .send(json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}))
        .await;
    client.finish(2).await;
    let events = project.events();
    assert_eq!(events[0]["call"]["phase"], "dispatch");
    assert_eq!(events[1]["detail"]["result_class"], "uncertain");
    project.private();
}
