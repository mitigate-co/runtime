use super::{
    tests::{Fixture, event, partition},
    *,
};
use rusqlite::Connection;
use serde_json::{Value, json};

fn checked(ch: char) -> CheckedEvent {
    CheckedEvent::from_bytes(&event(ch)).unwrap()
}
fn reopen(fixture: &Fixture) -> Outbox {
    let mut store = Outbox::open(&fixture.db(), partition()).unwrap();
    store.test_time = Some(1000);
    store
}
fn version(conn: &Connection) -> i64 {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0))
        .unwrap()
}
fn read_state(conn: &Connection) -> Value {
    let bytes: Vec<u8> = conn
        .query_row("SELECT record FROM state", [], |r| r.get(0))
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn write_state(conn: &Connection, state: &Value) {
    conn.execute(
        "UPDATE state SET record=?1",
        [serde_json::to_vec(state).unwrap()],
    )
    .unwrap();
}

#[test]
fn consent_cannot_cross_pause_resume_purge_or_queue_boundaries() {
    let fixture = Fixture::new();
    let mut producer = fixture.store(Limits::default());
    let before_pause = producer.capture_permit().unwrap().unwrap();
    let mut controller = reopen(&fixture);
    controller.set_paused(true).unwrap();
    assert!(producer.capture_permit().unwrap().is_none());
    assert_eq!(
        producer.admit_captured(&checked('1'), &before_pause),
        Ok(Admission::ConsentChanged)
    );
    controller.set_paused(false).unwrap();
    drop(producer);
    let mut producer = reopen(&fixture);
    assert_eq!(
        producer.admit_captured(&checked('1'), &before_pause),
        Ok(Admission::ConsentChanged)
    );
    let current = producer.capture_permit().unwrap().unwrap();
    assert_eq!(
        producer.admit_captured(&checked('2'), &current),
        Ok(Admission::Queued)
    );
    assert_eq!(
        producer.admit_captured(&checked('2'), &current),
        Ok(Admission::Duplicate)
    );
    // Repeating resume is idempotent, rather than discarding active captures.
    controller.set_paused(false).unwrap();
    assert_eq!(
        producer.admit_captured(&checked('3'), &current),
        Ok(Admission::Queued)
    );
    controller.purge().unwrap();
    controller.set_paused(false).unwrap();
    assert_eq!(
        producer.admit_captured(&checked('4'), &current),
        Ok(Admission::ConsentChanged)
    );
    assert_eq!(producer.inspect().unwrap().pending, 0);

    let other = Fixture::new();
    let mut other_queue = other.store(Limits::default());
    let current = producer.capture_permit().unwrap().unwrap();
    assert_eq!(
        other_queue.admit_captured(&checked('5'), &current),
        Ok(Admission::ConsentChanged)
    );
    assert_eq!(other_queue.inspect().unwrap().pending, 0);
}

#[test]
fn authentication_pause_invalidates_buffers_even_after_journal_rollover() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let captured = store.capture_permit().unwrap().unwrap();
    store.admit_captured(&checked('1'), &captured).unwrap();
    let lease = store.claim().unwrap().unwrap();
    store
        .complete(lease, DeliveryOutcome::Unauthorized)
        .unwrap();
    assert!(store.capture_permit().unwrap().is_none());
    store.set_paused(false).unwrap();
    // Consent survives eviction of all control entries from the bounded journal.
    for _ in 0..JOURNAL_LIMIT {
        assert_eq!(store.admit(&event('1')), Ok(Admission::Duplicate));
    }
    drop(store);
    let mut store = reopen(&fixture);
    assert_eq!(
        store.admit_captured(&checked('2'), &captured),
        Ok(Admission::ConsentChanged)
    );
    let report = store.inspect().unwrap();
    assert_eq!(report.pending, 1);
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(!encoded.contains("queue_ref"));
    assert!(!encoded.contains("generation"));
}

#[test]
fn legacy_control_and_delivery_do_not_upgrade_until_explicit_resume() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    store.admit(&event('2')).unwrap();
    let mut state = read_state(store.connection());
    state.as_object_mut().unwrap().remove("capture");
    write_state(store.connection(), &state);
    store
        .connection()
        .execute_batch("PRAGMA user_version=1")
        .unwrap();
    drop(store);

    let mut store = reopen(&fixture);
    assert!(store.capture_permit().unwrap().is_none());
    assert!(
        !Outbox::inspect_file(&fixture.db(), partition())
            .unwrap()
            .paused
    );
    let lease = store.claim().unwrap().unwrap();
    store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    store.set_paused(true).unwrap();
    assert_eq!(version(store.connection()), 1);
    assert!(read_state(store.connection()).get("capture").is_none());
    // A failed commit must leave both the old storage version and consent intact.
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert_eq!(store.set_paused(false), Err(Error::Storage));
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    assert_eq!(version(store.connection()), 1);
    assert!(store.inspect().unwrap().paused);
    assert!(store.capture_permit().unwrap().is_none());
    store.set_paused(false).unwrap();
    assert_eq!(version(store.connection()), 2);
    assert!(store.capture_permit().unwrap().is_some());
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.receipts), (1, 1));
    assert_eq!(store.admit(&event('1')), Ok(Admission::Duplicate));
    assert_eq!(store.admit(&event('2')), Ok(Admission::Duplicate));
    drop(store);
    assert!(reopen(&fixture).capture_permit().unwrap().is_some());
}

#[test]
fn capture_storage_is_closed_and_versioned_without_silent_repair() {
    let fixture = Fixture::new();
    let store = fixture.store(Limits::default());
    let original = read_state(store.connection());
    for bad in [
        Value::Null,
        json!({}),
        json!({"queue_ref": "sensitive-canary", "generation": 0}),
        json!({"queue_ref": original["capture"]["queue_ref"], "generation": 1}),
        json!({"queue_ref": original["capture"]["queue_ref"], "generation": 0, "extra": true}),
    ] {
        let mut changed = original.clone();
        changed["capture"] = bad;
        write_state(store.connection(), &changed);
        assert!(matches!(
            Outbox::open(&fixture.db(), partition()),
            Err(Error::Integrity)
        ));
        assert_eq!(read_state(store.connection()), changed);
    }
    let mut missing = original.clone();
    missing.as_object_mut().unwrap().remove("capture");
    write_state(store.connection(), &missing);
    assert!(matches!(
        Outbox::open(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
    write_state(store.connection(), &original);
    store
        .connection()
        .execute_batch("PRAGMA user_version=1")
        .unwrap();
    assert!(matches!(
        Outbox::open(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
}

#[test]
fn competing_capture_and_purge_cannot_repopulate_with_old_consent() {
    use std::sync::{Arc, Barrier};
    let fixture = Fixture::new();
    let mut producer = fixture.store(Limits::default());
    let mut controller = reopen(&fixture);
    let captured = producer.capture_permit().unwrap().unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let ready = barrier.clone();
    let producer = std::thread::spawn(move || {
        ready.wait();
        producer.admit_captured(&checked('1'), &captured)
    });
    barrier.wait();
    controller.purge().unwrap();
    controller.set_paused(false).unwrap();
    assert!(matches!(
        producer.join().unwrap(),
        Ok(Admission::Queued | Admission::ConsentChanged) | Err(Error::Busy)
    ));
    assert_eq!(controller.inspect().unwrap().pending, 0);
}
