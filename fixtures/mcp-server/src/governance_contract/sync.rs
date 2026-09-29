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
            let mut client = Client::start_sync(binary, &project, true, Some(profile_path));
            client.initialize().await;
            diagnostic(&mut client, "sync capture ready").await;
            client.call(2, json!({"value":"argument-canary"})).await;
            assert_eq!(
                client.result(2).await.0["result"]["structuredContent"]["ok"],
                true
            );
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

            let mut client = Client::start_sync(binary, &project, true, Some(profile_path));
            client.initialize().await;
            diagnostic(&mut client, "sync capture ready").await;
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
            project.policy(2, "deny");
            client.call(3, json!({})).await;
            assert_eq!(client.result(3).await.0["error"]["code"], -32001);
            pending(&queue, &partition, 5).await;
            assert!(events(&queue).iter().any(
                |e| e["facts"]["decision"] == "deny" && e["facts"]["outcome"] == "not_invoked"
            ));
            assert!(profile.pause().unwrap().paused);
            diagnostic(&mut client, "sync capture is paused").await;
            client.call(4, json!({})).await;
            assert_eq!(client.result(4).await.0["error"]["code"], -32001);
            assert_eq!(profile.inspect().unwrap().pending, 5);
            assert_eq!(profile.purge().unwrap().pending, 0);
            client.finish(0).await;

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
        });
    println!(
        "Live capture verified: actual audited CLI calls, random references, restart, pause/purge and unavailable-worker isolation. No Platform requests."
    );
}
