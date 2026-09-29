use super::{
    tests::{Fixture, event, partition},
    *,
};
use serde_json::{Value, json};
use std::fs;

fn inventory() -> Vec<u8> {
    let mut value: Value = serde_json::from_slice(include_bytes!(
        "../../../../examples/egress/inventory-part.json"
    ))
    .unwrap();
    value["event_id"] = json!("ref_33333333333333333333333333333333");
    serde_json::to_vec(&value).unwrap()
}
fn counts(report: &Report) -> Value {
    serde_json::to_value(&report.pending_contracts).unwrap()
}

#[test]
fn mixed_queue_retains_exact_types_through_retry_receipt_and_reopen() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let bytes = inventory();
    let expected = CheckedEvent::from_bytes(&bytes).unwrap();
    assert_eq!(store.admit(&event('1')), Ok(Admission::Queued));
    assert_eq!(store.admit(&bytes), Ok(Admission::Queued));
    assert_eq!(store.admit(&bytes), Ok(Admission::Duplicate));
    let report = store.inspect().unwrap();
    assert_eq!(report.schema_version, 2);
    assert_eq!(
        counts(&report),
        json!([
            {"event_type":"mcp_tool_decision", "schema_version":1,"events":1,"bytes":CheckedEvent::from_bytes(&event('1')).unwrap().as_bytes().len()},
            {"event_type":"mcp_inventory_snapshot", "schema_version":2,"events":1,"bytes":expected.as_bytes().len()}
        ])
    );
    let decision = store.claim().unwrap().unwrap();
    assert_eq!(decision.event().kind(), EventKind::McpToolDecision);
    store.complete(decision, DeliveryOutcome::Accepted).unwrap();
    let lease = store.claim().unwrap().unwrap();
    assert_eq!(lease.event().as_bytes(), expected.as_bytes());
    store.complete(lease, DeliveryOutcome::Transient).unwrap();
    assert!(store.claim().unwrap().is_none());
    drop(store);
    let before = fs::read(fixture.db()).unwrap();
    let report = Outbox::inspect_file(&fixture.db(), partition()).unwrap();
    assert_eq!(report.pending_contracts.len(), 1);
    assert_eq!(
        report.pending_contracts[0].event_type,
        EventKind::McpInventorySnapshot
    );
    assert_eq!(fs::read(fixture.db()).unwrap(), before);
    let mut store = Outbox::open(&fixture.db(), partition()).unwrap();
    store.test_time = Some(2000);
    let lease = store.claim().unwrap().unwrap();
    assert_eq!(lease.event().as_bytes(), expected.as_bytes());
    store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(store.admit(&bytes), Ok(Admission::Duplicate));
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.receipts), (0, 2));
    assert!(report.pending_contracts.is_empty());
    assert!(
        report
            .counters
            .iter()
            .any(|c| c.action == Action::Queued && c.totals.events == 2)
    );
    // Same ID cannot change event kind after a completed receipt either.
    assert_eq!(store.admit(&event('3')), Ok(Admission::IdConflict));
}

#[test]
fn inventory_uses_the_original_capture_consent_and_shared_capacity() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits {
        max_events: 1,
        max_age_ms: 1000,
    });
    let checked = CheckedEvent::from_bytes(&inventory()).unwrap();
    let original = store.capture_permit().unwrap().unwrap();
    store.set_paused(true).unwrap();
    assert_eq!(store.admit(checked.as_bytes()), Ok(Admission::Paused));
    store.set_paused(false).unwrap();
    assert_eq!(
        store.admit_captured(&checked, &original),
        Ok(Admission::ConsentChanged)
    );
    let current = store.capture_permit().unwrap().unwrap();
    assert_eq!(
        store.admit_captured(&checked, &current),
        Ok(Admission::Queued)
    );
    assert_eq!(store.admit(&event('1')), Ok(Admission::Full));
    assert_eq!(store.admit(&event('3')), Ok(Admission::IdConflict));
    store.test_time = Some(2000);
    assert!(store.claim().unwrap().is_none());
    assert!(store.inspect().unwrap().pending_contracts.is_empty());
    store.purge().unwrap();
    store.set_paused(false).unwrap();
    assert_eq!(
        store.admit_captured(&checked, &current),
        Ok(Admission::ConsentChanged)
    );
    let mut wrong: Value = serde_json::from_slice(&inventory()).unwrap();
    wrong["runtime_ref"] = json!("ref_99999999999999999999999999999999");
    assert_eq!(
        store.admit(&serde_json::to_vec(&wrong).unwrap()),
        Ok(Admission::WrongRuntime)
    );
}

#[test]
fn inventory_commit_failure_and_corrupted_content_never_yield_a_lease() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert!(store.admit(&inventory()).is_err());
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    assert_eq!(store.inspect().unwrap().pending, 0);
    assert_eq!(store.admit(&inventory()), Ok(Admission::Queued));
    let mut wire: Value = serde_json::from_slice(&inventory()).unwrap();
    wire["facts"]["tools"][0]["metadata"] = json!({"content":"synthetic-private-canary"});
    assert!(matches!(
        store.admit(&serde_json::to_vec(&wire).unwrap()),
        Ok(Admission::Rejected(_))
    ));
    assert!(!String::from_utf8_lossy(&fs::read(fixture.db()).unwrap()).contains("canary"));
    let mut record: Value = serde_json::from_slice(
        &store
            .connection()
            .query_row::<Vec<u8>, _, _>("SELECT record FROM events", [], |r| r.get(0))
            .unwrap(),
    )
    .unwrap();
    record["event"] = json!(serde_json::to_string(&wire).unwrap());
    store
        .connection()
        .execute(
            "UPDATE events SET record=?1",
            [serde_json::to_vec(&record).unwrap()],
        )
        .unwrap();
    assert!(matches!(store.claim(), Err(Error::Integrity)));
    assert!(matches!(
        Outbox::inspect_file(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
}

#[test]
fn a_full_inventory_queue_remains_bounded_inspectable_and_purgeable() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let mut value: Value = serde_json::from_slice(&inventory()).unwrap();
    value["facts"]["tool_count"] = json!(4);
    let mut tool = value["facts"]["tools"][0].clone();
    tool["capabilities"] = json!([
        "read_data",
        "write_data",
        "delete_data",
        "execute_code",
        "credential_access",
        "external_communication",
        "browser_action",
        "identity_admin",
        "financial_action",
        "infrastructure_change",
        "unknown"
    ]);
    tool["risk_flags"] = json!([
        "destructive",
        "credential_access",
        "arbitrary_code_execution",
        "external_communication",
        "identity_admin",
        "infrastructure_change",
        "unknown_high_impact"
    ]);
    tool["classification_sources"] = json!(["deterministic", "admin"]);
    tool["confidence"] = json!("high");
    value["facts"]["tools"] = json!(
        (0..4)
            .map(|index| {
                let mut tool = tool.clone();
                tool["tool_ref"] = json!(format!("ref_{index:032x}"));
                tool
            })
            .collect::<Vec<_>>()
    );
    assert_eq!(
        store.admit(&serde_json::to_vec(&value).unwrap()),
        Ok(Admission::Queued)
    );
    drop(store);
    // Arrange only this synthetic store in one transaction; production admission
    // still journals each event. Avoid 1,000 fsyncs just to fill a boundary fixture.
    let mut conn = rusqlite::Connection::open(fixture.db()).unwrap();
    let template: Vec<u8> = conn
        .query_row("SELECT record FROM events", [], |r| r.get(0))
        .unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("DELETE FROM events", []).unwrap();
    for index in 0..1000 {
        let id = format!("ref_{index:032x}");
        value["event_id"] = json!(id);
        let checked = CheckedEvent::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
        let mut row: Value = serde_json::from_slice(&template).unwrap();
        row["event"] = json!(std::str::from_utf8(checked.as_bytes()).unwrap());
        tx.execute(
            "INSERT INTO events VALUES(?1,?2)",
            rusqlite::params![id, serde_json::to_vec(&row).unwrap()],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(conn);
    let mut store = Outbox::open(&fixture.db(), partition()).unwrap();
    store.test_time = Some(1000);
    let report = store.inspect().unwrap();
    assert_eq!(report.pending, 1000);
    assert_eq!(report.pending_contracts.len(), 1);
    assert_eq!(report.pending_contracts[0].events, 1000);
    assert_eq!(report.pending_contracts[0].bytes, report.payload_bytes);
    assert!(report.payload_bytes <= 1000 * crate::MAX_EVENT_BYTES);
    assert_eq!(store.admit(&inventory()), Ok(Admission::Full));
    assert!(store.claim().unwrap().is_some());
    store.purge().unwrap();
    assert!(store.inspect().unwrap().pending_contracts.is_empty());
}
