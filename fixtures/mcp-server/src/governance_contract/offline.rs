//! Real-process outage cases. Fault injection touches only synthetic fixture stores.
use super::*;

fn bundle(version: u64, decision: &str, seed: &[u8; 32]) -> SignedBundle {
    SignedBundle::sign(
        reference('a'),
        version,
        format!(
            "package mitigate.mcp\ndefault decision := \"deny\"\ndecision := \"{decision}\" if {{\ninput.grant == \"explicit\"\ninput.offline == true\n}}"
        ),
        seed,
    )
    .unwrap()
}

// Simulate unavailable/untrusted refresh without replacing a live database inode.
// The production activation API deliberately refuses these candidates.
fn replace(project: &Project, version: u64, bytes: &[u8]) {
    let conn = rusqlite::Connection::open(project.path("policy.sqlite")).unwrap();
    conn.busy_timeout(Duration::from_secs(2)).unwrap();
    conn.execute_batch("PRAGMA secure_delete=ON").unwrap();
    assert_eq!(
        conn.execute(
            "UPDATE policy SET version=?1,bundle=?2 WHERE id=1",
            rusqlite::params![i64::try_from(version).unwrap(), bytes],
        )
        .unwrap(),
        1
    );
}

async fn expect_call(client: &mut Client, id: u32, allow: bool) {
    client
        .call(id, json!({"value":"offline-argument-canary"}))
        .await;
    let reply = client.result(id).await.0;
    if allow {
        assert_eq!(reply["result"]["structuredContent"]["ok"], true);
    } else {
        assert_eq!(reply["error"]["code"], -32001);
    }
}

pub(super) async fn run(binary: &Path, root: &Path) {
    for allow in [false, true] {
        let decision = if allow { "allow" } else { "deny" };
        let opposite = if allow { "deny" } else { "allow" };
        let project =
            Project::new(root, decision, "relay-governance-start", decision, 60_000).await;
        let cached = bundle(2, decision, &[7; 32]);
        PolicyStore::open(&project.path("policy.sqlite"), project.authority())
            .unwrap()
            .activate(&cached)
            .unwrap();
        let mut client = Client::start(binary, &project, true);
        client.initialize().await;

        for (id, version, bytes) in [
            (2, 3, bundle(3, opposite, &[8; 32]).to_bytes().unwrap()),
            (3, 1, bundle(1, opposite, &[7; 32]).to_bytes().unwrap()),
            (4, 2, bundle(2, opposite, &[7; 32]).to_bytes().unwrap()),
            (5, 3, b"untrusted-policy-canary".to_vec()),
        ] {
            replace(&project, version, &bytes);
            expect_call(&mut client, id, allow).await;
            assert_eq!(project.path("call-marker").exists(), allow);
            assert!(
                project
                    .events()
                    .iter()
                    .all(|e| e["detail"]["policy_version"] == 2)
            );
        }
        // A fresh process has no in-memory cache and must refuse the corrupt store.
        fs::remove_file(project.path("child-address")).unwrap();
        let mut fresh = Client::start(binary, &project, true);
        fresh.finish(2).await;
        assert!(!project.path("child-address").exists());

        // Restore the exact fixture backup, then activate a newer verified policy
        // through the supported API. Recovery must change the live decision.
        replace(&project, 2, &cached.to_bytes().unwrap());
        PolicyStore::open(&project.path("policy.sqlite"), project.authority())
            .unwrap()
            .activate(&bundle(3, opposite, &[7; 32]))
            .unwrap();
        expect_call(&mut client, 6, !allow).await;
        assert_eq!(
            project.events().last().unwrap()["detail"]["policy_version"],
            3
        );
        client.finish(0).await;
        let mut restarted = Client::start(binary, &project, true);
        restarted.initialize().await;
        expect_call(&mut restarted, 2, !allow).await;
        restarted.finish(0).await;
        project.private();
    }

    let project = Project::new(
        root,
        "approval-unavailable",
        "relay-governance-start",
        "require_approval",
        60_000,
    )
    .await;
    let mut client = Client::start(binary, &project, true);
    client.initialize().await;
    let conn = rusqlite::Connection::open(project.path("approvals.sqlite")).unwrap();
    conn.execute_batch("PRAGMA user_version=99").unwrap();
    client
        .call(2, json!({"value":"offline-argument-canary"}))
        .await;
    assert_eq!(client.result(2).await.0["error"]["code"], -32008);
    assert!(!project.path("call-marker").exists());
    assert_eq!(project.events()[0]["detail"]["result_class"], "not_invoked");
    conn.execute_batch("PRAGMA user_version=1").unwrap();
    drop(conn);
    client
        .call(3, json!({"value":"offline-argument-canary"}))
        .await;
    let pending = project.pending().await;
    project.decide(&pending, Choice::Approve);
    assert_eq!(
        client.result(3).await.0["result"]["structuredContent"]["ok"],
        true
    );
    client.finish(0).await;
    assert_eq!(
        ApprovalStore::open(&project.path("approvals.sqlite"))
            .unwrap()
            .get(&pending.approval_ref, SystemClock)
            .unwrap()
            .state,
        State::Consumed
    );
    project.private();
}
