//! Native lifecycle fixture supplies an already-consented synthetic profile.
//! This exercises the shipped CLI producer; no Platform endpoint is contacted.
use super::*;
use mitigate_egress::{
    CheckedEvent,
    outbox::{Outbox, Partition},
};
use mitigate_enrollment::storage::sync::SyncProfile;

async fn diagnostic(client: &mut Client, expected: &str) {
    timeout(Duration::from_secs(30), async {
        for _ in 0..20 {
            let mut line = String::new();
            let bytes = client.diagnostics.read_line(&mut line).await.unwrap();
            assert!(bytes > 0 && bytes < 1024);
            assert!(!line.contains("canary"));
            for category in [
                "assertion",
                "workspace",
                "setup",
                "cleanup",
                "storage_clock",
                "storage_budget",
                "storage",
            ] {
                if line.trim() == format!("Mitigate: sync privacy check category: {category}.") {
                    eprintln!("Synthetic capture privacy category: {category}.");
                }
            }
            assert!(
                !line.contains("privacy self-test did not pass"),
                "installed privacy probe must pass before capture"
            );
            if line.contains(expected) {
                return;
            }
        }
        panic!("expected bounded sync diagnostic");
    })
    .await
    .expect("bounded capture readiness");
}
async fn pending(queue: &Path, partition: &Partition, count: usize) {
    timeout(Duration::from_secs(15), async {
        loop {
            match Outbox::inspect_file(queue, partition.clone()) {
                Ok(report) if report.pending == count => return,
                Ok(report) => assert!(report.pending < count),
                Err(mitigate_egress::outbox::Error::Busy) => (),
                Err(_) => panic!("synthetic queue must remain readable"),
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("bounded durable capture");
}
fn events(queue: &Path) -> Vec<Value> {
    let db =
        rusqlite::Connection::open_with_flags(queue, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .unwrap();
    let mut statement = db.prepare("SELECT record FROM events").unwrap();
    statement
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .unwrap()
        .map(|row| {
            let record: Value = serde_json::from_slice(&row.unwrap()).unwrap();
            let body = record["event"].as_str().unwrap();
            assert!(!body.contains("canary"));
            assert!(CheckedEvent::from_bytes(body.as_bytes()).is_ok());
            serde_json::from_str(body).unwrap()
        })
        .collect()
}
pub(crate) fn verify_capture(binary: &Path, profile_path: &Path) {
    eprintln!("Synthetic capture stage: prepare.");
    let root = Project(
        std::env::temp_dir().join(format!("mitigate-capture-contract-{}", std::process::id())),
    );
    fs::create_dir(&root.0).unwrap();
    let profile = SyncProfile::open(profile_path).unwrap();
    let config: Value = serde_json::from_slice(&fs::read(profile_path).unwrap()).unwrap();
    let queue = PathBuf::from(config["outbox_file"].as_str().unwrap());
    let partition = profile.inspect().unwrap().partition;
    assert_eq!(profile.inspect().unwrap().pending, 0);
    assert!(!profile.inspect().unwrap().paused);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let project = Project::new(&root.0, "capture", "relay-progress", "allow", 60_000).await;
            eprintln!("Synthetic capture stage: first_start.");
            let mut client = Client::start_sync(binary, &project, true, Some(profile_path));
            client.initialize().await;
            eprintln!("Synthetic capture stage: first_ready.");
            diagnostic(&mut client, "sync capture ready").await;
            eprintln!("Synthetic capture stage: first_call.");
            client.call(2, json!({"value":"argument-canary"})).await;
            assert_eq!(
                client.result(2).await.0["result"]["structuredContent"]["ok"],
                true
            );
            eprintln!("Synthetic capture stage: first_commit.");
            pending(&queue, &partition, 2).await;
            let first = events(&queue);
            assert_eq!(first[0]["facts"]["call_ref"], first[1]["facts"]["call_ref"]);
            assert_ne!(first[0]["event_id"], first[1]["event_id"]);
            assert!(first.iter().any(|e| e["facts"]["phase"] == "dispatch"));
            assert!(first.iter().any(|e| e["facts"]["outcome"] == "success"));
            for local in project.events() {
                for field in [
                    "client_ref",
                    "principal_ref",
                    "server_ref",
                    "tool_ref",
                    "schema_fingerprint",
                    "policy_ref",
                ] {
                    if let Some(digest) = local["detail"][field].as_str() {
                        assert!(!serde_json::to_string(&first).unwrap().contains(digest));
                    }
                }
            }
            client.finish(0).await;

            eprintln!("Synthetic capture stage: restart.");
            let mut client =
                Client::start_capture(binary, &project, true, Some(profile_path), true);
            client.initialize().await;
            eprintln!("Synthetic capture stage: second_ready.");
            diagnostic(&mut client, "sync capture ready").await;
            eprintln!("Synthetic capture stage: second_call.");
            client.call(2, json!({})).await;
            assert_eq!(
                client.result(2).await.0["result"]["structuredContent"]["ok"],
                true
            );
            pending(&queue, &partition, 4).await;
            for event in events(&queue) {
                for field in [
                    "client_ref",
                    "principal_ref",
                    "server_ref",
                    "tool_ref",
                    "schema_ref",
                    "policy_ref",
                ] {
                    assert_eq!(event["facts"][field], first[0]["facts"][field]);
                }
            }
            eprintln!("Synthetic capture stage: policy_denial.");
            project.policy(2, "deny");
            client.call(3, json!({})).await;
            assert_eq!(client.result(3).await.0["error"]["code"], -32001);
            pending(&queue, &partition, 5).await;
            assert!(events(&queue).iter().any(
                |e| e["facts"]["decision"] == "deny" && e["facts"]["outcome"] == "not_invoked"
            ));
            eprintln!("Synthetic capture stage: inventory.");
            inventory(&mut client, &project, &profile, &queue, &partition).await;
            eprintln!("Synthetic capture stage: pause.");
            assert!(profile.pause().unwrap().paused);
            diagnostic(&mut client, "sync capture is paused").await;
            client
                .send(json!({"jsonrpc":"2.0","id":15,"method":"tools/list"}))
                .await;
            assert!(client.read().await["result"].is_object());
            assert_eq!(profile.inspect().unwrap().pending, 8);
            client.call(4, json!({})).await;
            assert_eq!(client.result(4).await.0["error"]["code"], -32001);
            assert_eq!(profile.inspect().unwrap().pending, 8);
            eprintln!("Synthetic capture stage: purge.");
            assert_eq!(profile.purge().unwrap().pending, 0);
            client.finish(0).await;

            eprintln!("Synthetic capture stage: unavailable_profile.");
            project.policy(3, "allow");
            let mut client = Client::start_sync(
                binary,
                &project,
                true,
                Some(&project.path("missing-private-canary")),
            );
            client.initialize().await;
            diagnostic(&mut client, "sync capture unavailable").await;
            client.call(2, json!({})).await;
            assert_eq!(
                client.result(2).await.0["result"]["structuredContent"]["ok"],
                true
            );
            client.finish(0).await;
            project.private();
            eprintln!("Synthetic capture stage: complete.");
        });
    println!(
        "Live capture verified: audited calls and inventory, random references, restart, pause/purge and unavailable-worker isolation. No Platform requests."
    );
}

async fn inventory(
    client: &mut Client,
    project: &Project,
    profile: &SyncProfile,
    queue: &Path,
    partition: &Partition,
) {
    // The parent native fixture owns credential resume (including macOS ACLs).
    // This child uses already-consented local metadata state only.
    assert!(!profile.inspect().unwrap().paused);
    assert_eq!(profile.inspect().unwrap().pending, 5);
    let list = |id| json!({"jsonrpc":"2.0","id":id,"method":"tools/list"});
    let lock = rusqlite::Connection::open(project.path("audit.sqlite")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    client.send(list(10)).await;
    assert_eq!(client.read().await["error"]["code"], -32007);
    lock.execute_batch("ROLLBACK").unwrap();
    assert_eq!(profile.inspect().unwrap().pending, 5);

    client.send(list(11)).await;
    assert_eq!(
        client.read().await["result"]["tools"][0]["name"],
        "read_status"
    );
    pending(queue, partition, 6).await;
    let first = events(queue)
        .into_iter()
        .find(|e| e["event_type"] == "mcp_inventory_snapshot")
        .unwrap();
    assert_eq!(first["event_type"], "mcp_inventory_snapshot");
    assert_eq!(first["facts"]["tool_count"], 1);
    assert_eq!(first["facts"]["tools_supported"], true);
    assert_eq!(
        first["facts"]["tools"][0]["capabilities"],
        json!(["read_data"])
    );
    assert_eq!(
        first["facts"]["tools"][0]["classification_sources"],
        json!(["deterministic"])
    );
    assert!(!first.to_string().contains("read_status"));
    assert!(!first.to_string().contains("canary"));
    assert!(
        mitigate_egress::inventory::CheckedSnapshot::from_parts(&[
            mitigate_egress::inventory::CheckedPart::from_bytes(
                &serde_json::to_vec(&first).unwrap()
            )
            .unwrap()
        ])
        .is_ok()
    );

    client
        .send(json!({"jsonrpc":"2.0","id":12,"method":"tools/list","params":{"cursor":"m1:0"}}))
        .await;
    assert!(client.read().await["result"].is_object());
    assert_eq!(profile.inspect().unwrap().pending, 6);

    client
        .call(13, json!({"value":"inventory-argument-canary"}))
        .await;
    assert_eq!(client.result(13).await.0["error"]["code"], -32001);
    pending(queue, partition, 7).await;
    let decisions: Vec<_> = events(queue)
        .into_iter()
        .filter(|e| e["event_type"] == "mcp_tool_decision")
        .collect();
    assert_eq!(decisions.len(), 6);
    for event in decisions {
        assert_eq!(event["facts"]["server_ref"], first["facts"]["server_ref"]);
        assert_eq!(
            event["facts"]["tool_ref"],
            first["facts"]["tools"][0]["tool_ref"]
        );
        // Inventory tracks the full definition; v1 decisions retain input-schema identity.
        assert_ne!(
            event["facts"]["schema_ref"],
            first["facts"]["tools"][0]["schema_ref"]
        );
    }
    client.send(list(14)).await;
    assert!(client.read().await["result"].is_object());
    pending(queue, partition, 8).await;
    let observations: Vec<_> = events(queue)
        .into_iter()
        .filter(|e| e["event_type"] == "mcp_inventory_snapshot")
        .collect();
    assert_eq!(observations.len(), 2);
    assert_ne!(
        observations[0]["facts"]["snapshot_ref"],
        observations[1]["facts"]["snapshot_ref"]
    );
    assert_eq!(
        observations[0]["facts"]["tools"],
        observations[1]["facts"]["tools"]
    );
}
