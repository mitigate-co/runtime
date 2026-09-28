use super::*;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-outbox-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("outbox.sqlite")
    }
    fn store(&self, limits: Limits) -> Outbox {
        let mut store = Outbox::create(&self.db(), partition(), limits).unwrap();
        store.test_time = Some(1000);
        store
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn reference(ch: char) -> SyncRef {
    serde_json::from_value(json!(format!("ref_{}", ch.to_string().repeat(32)))).unwrap()
}
fn partition() -> Partition {
    Partition {
        runtime_ref: reference('2'),
        enrollment_ref: reference('e'),
    }
}
fn event(ch: char) -> Vec<u8> {
    let mut value: Value =
        serde_json::from_slice(include_bytes!("../../../../examples/egress/decision.json"))
            .unwrap();
    value["event_id"] = json!(reference(ch));
    value["facts"]["call_ref"] = json!(reference(ch));
    serde_json::to_vec(&value).unwrap()
}
fn count(report: &Report, action: Action) -> u64 {
    report
        .counters
        .iter()
        .find(|c| c.action == action)
        .unwrap()
        .totals
        .events
}

#[test]
fn durable_admission_and_receipts_preserve_idempotent_exact_bytes() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let input = event('1');
    assert_eq!(store.admit(&input), Ok(Admission::Queued));
    assert_eq!(store.admit(&input), Ok(Admission::Duplicate));
    let mut changed: Value = serde_json::from_slice(&input).unwrap();
    changed["facts"]["duration_ms"] = json!(10);
    let changed = serde_json::to_vec(&changed).unwrap();
    assert_eq!(store.admit(&changed), Ok(Admission::IdConflict));
    drop(store);
    let mut reopened = Outbox::open(&fixture.db(), partition()).unwrap();
    reopened.test_time = Some(1000);
    let lease = reopened.claim().unwrap().unwrap();
    assert_eq!(
        lease.event().as_bytes(),
        CheckedEvent::from_bytes(&input).unwrap().as_bytes()
    );
    assert!(reopened.claim().unwrap().is_none());
    reopened.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(reopened.admit(&input), Ok(Admission::Duplicate));
    assert_eq!(reopened.admit(&changed), Ok(Admission::IdConflict));
    let report = reopened.inspect().unwrap();
    assert_eq!((report.pending, report.receipts), (0, 1));
    assert_eq!(count(&report, Action::Delivered), 1);
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(!encoded.contains("call_ref"));
    assert!(!encoded.contains(reference('1').as_str()));
}

#[test]
fn privacy_refusals_never_store_source_identifiers_or_body_digests() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let bad = br#"{"event_id":"untrusted-identity-canary","arguments":"private-document-canary"}"#;
    assert_eq!(
        store.admit(bad),
        Ok(Admission::Rejected(Rejection::ProhibitedField))
    );
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.receipts), (0, 0));
    assert_eq!(count(&report, Action::PrivacyRejected), 1);
    assert_eq!(report.recent[0].rejection, Some(Rejection::ProhibitedField));
    assert!(!String::from_utf8_lossy(&fs::read(fixture.db()).unwrap()).contains("canary"));
    let mut other: Value = serde_json::from_slice(&event('1')).unwrap();
    other["runtime_ref"] = json!(reference('9'));
    assert_eq!(
        store.admit(&serde_json::to_vec(&other).unwrap()),
        Ok(Admission::WrongRuntime)
    );
    assert!(store.claim().unwrap().is_none());
}

#[test]
fn leases_expire_with_backoff_and_stale_acknowledgements_cannot_delete_new_attempts() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let first = store.claim().unwrap().unwrap();
    store.test_time = Some(31_000);
    assert!(store.claim().unwrap().is_none());
    store.test_time = Some(32_000);
    let second = store.claim().unwrap().unwrap();
    assert_eq!(first.event().as_bytes(), second.event().as_bytes());
    assert_eq!(
        store.complete(first, DeliveryOutcome::Accepted),
        Err(Error::StaleLease)
    );
    assert_eq!(store.inspect().unwrap().leased, 1);
    store.complete(second, DeliveryOutcome::Transient).unwrap();
    store.test_time = Some(33_999);
    assert!(store.claim().unwrap().is_none());
    store.test_time = Some(34_000);
    let third = store.claim().unwrap().unwrap();
    store.complete(third, DeliveryOutcome::Rejected).unwrap();
    store.test_time = Some(100_000);
    assert!(store.claim().unwrap().is_none());
    assert_eq!(store.admit(&event('1')), Ok(Admission::Duplicate));
    let report = store.inspect().unwrap();
    assert_eq!(count(&report, Action::LeaseExpired), 1);
    assert_eq!(count(&report, Action::TransportRetry), 1);
    assert_eq!(count(&report, Action::DeliveryRejected), 1);
}

#[test]
fn opt_out_purge_pauses_and_invalidates_leases_without_retaining_bodies() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('a')).unwrap();
    let lease = store.claim().unwrap().unwrap();
    store.purge().unwrap();
    assert_eq!(
        store.complete(lease, DeliveryOutcome::Accepted),
        Err(Error::StaleLease)
    );
    assert_eq!(store.admit(&event('b')), Ok(Admission::Paused));
    assert!(store.claim().unwrap().is_none());
    let report = store.inspect().unwrap();
    assert!(report.paused);
    assert_eq!(report.pending, 0);
    assert!(
        !String::from_utf8_lossy(&fs::read(fixture.db()).unwrap())
            .contains(reference('a').as_str())
    );
    store.set_paused(false).unwrap();
    assert_eq!(store.admit(&event('b')), Ok(Admission::Queued));
    let lease = store.claim().unwrap().unwrap();
    store
        .complete(lease, DeliveryOutcome::Unauthorized)
        .unwrap();
    assert!(store.inspect().unwrap().paused);
    store.test_time = Some(3000);
    assert!(store.claim().unwrap().is_none());
    store.set_paused(false).unwrap();
    assert!(store.claim().unwrap().is_some());
}

#[test]
fn capacity_preserves_pending_data_and_retention_uses_admission_time() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits {
        max_events: 1,
        max_age_ms: 1000,
    });
    assert_eq!(store.admit(&event('a')), Ok(Admission::Queued));
    assert_eq!(store.admit(&event('b')), Ok(Admission::Full));
    store.test_time = Some(1999);
    assert_eq!(store.inspect().unwrap().pending, 1);
    store.test_time = Some(2000);
    assert_eq!(store.admit(&event('b')), Ok(Admission::Queued));
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.receipts), (1, 1));
    assert_eq!(count(&report, Action::Expired), 1);
    assert_eq!(store.admit(&event('a')), Ok(Admission::Duplicate));
    let lease = store.claim().unwrap().unwrap();
    assert_eq!(lease.event().event_id().as_str(), reference('b').as_str());
}

#[test]
fn clock_rollback_cannot_revive_an_observed_expired_lease() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let lease = store.claim().unwrap().unwrap();
    store.test_time = Some(31_000);
    assert_eq!(
        store.complete(lease, DeliveryOutcome::Accepted),
        Err(Error::StaleLease)
    );
    store.test_time = Some(30_999);
    assert!(matches!(store.claim(), Err(Error::Clock)));
    assert_eq!(store.admit(&event('2')), Err(Error::Clock));
    assert_eq!(store.inspect().unwrap().pending, 1);
}

#[test]
fn write_and_commit_failures_return_no_admission_or_delivery_lease() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert_eq!(store.admit(&event('1')), Err(Error::Storage));
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    let report = store.inspect().unwrap();
    assert_eq!(report.pending, 0);
    assert!(report.recent.is_empty());
    store.admit(&event('1')).unwrap();
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert!(matches!(store.claim(), Err(Error::Storage)));
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    assert_eq!(store.inspect().unwrap().leased, 0);
    let blocker = rusqlite::Connection::open(fixture.db()).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(store.admit(&event('2')), Err(Error::Storage));
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(store.inspect().unwrap().pending, 1);
}

#[test]
fn corrupt_persisted_events_and_unknown_store_schema_fail_before_delivery() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(fixture.db()).unwrap();
    let bytes: Vec<u8> = conn
        .query_row("SELECT record FROM events", [], |r| r.get(0))
        .unwrap();
    let mut record: Value = serde_json::from_slice(&bytes).unwrap();
    record["event"] = json!("{\"arguments\":\"database-content-canary\"}");
    conn.execute(
        "UPDATE events SET record=?1",
        [serde_json::to_vec(&record).unwrap()],
    )
    .unwrap();
    assert!(matches!(
        Outbox::open(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
    conn.execute("UPDATE events SET record=?1", [bytes])
        .unwrap();
    conn.execute_batch("PRAGMA user_version=99").unwrap();
    assert!(matches!(
        Outbox::open(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
}

#[test]
fn explicit_partition_and_private_regular_files_are_required() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let mut wrong = partition();
    wrong.enrollment_ref = reference('9');
    assert!(matches!(
        Outbox::open(&fixture.db(), wrong),
        Err(Error::Partition)
    ));
    assert!(matches!(
        Outbox::create(&fixture.db(), partition(), Limits::default()),
        Err(Error::Path)
    ));
    assert!(matches!(
        Outbox::open(&fixture.0.join("missing"), partition()),
        Err(Error::Path)
    ));
    assert!(matches!(
        Outbox::open(&fixture.0, partition()),
        Err(Error::Path)
    ));
    store.admit(&event('1')).unwrap();
    drop(store);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let link = fixture.0.join("linked");
        symlink(fixture.db(), &link).unwrap();
        assert!(matches!(Outbox::open(&link, partition()), Err(Error::Path)));
        fs::set_permissions(fixture.db(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            Outbox::open(&fixture.db(), partition()),
            Err(Error::Path)
        ));
    }
}

#[test]
fn journal_stays_bounded_and_receipts_do_not_grow_without_limit() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits {
        max_events: 1,
        ..Limits::default()
    });
    for _ in 0..160 {
        assert!(matches!(
            store.admit(b"{\"content\":\"canary\"}"),
            Ok(Admission::Rejected(_))
        ));
    }
    let report = store.inspect().unwrap();
    assert_eq!(report.recent.len(), 128);
    assert_eq!(report.recent[0].sequence, 33);
    assert_eq!(count(&report, Action::PrivacyRejected), 160);
    for id in ['a', 'b', 'c'] {
        store.admit(&event(id)).unwrap();
        let lease = store.claim().unwrap().unwrap();
        store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    }
    assert_eq!(store.inspect().unwrap().receipts, 1);
}

#[test]
fn concurrent_workers_cannot_claim_the_same_pending_event() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.test_time = None;
    store.admit(&event('1')).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let threads: Vec<_> = (0..2)
        .map(|_| {
            let path = fixture.db();
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                let mut worker = Outbox::open(&path, partition()).unwrap();
                barrier.wait();
                worker.claim().unwrap().is_some()
            })
        })
        .collect();
    let claimed = threads
        .into_iter()
        .map(|t| usize::from(t.join().unwrap()))
        .sum::<usize>();
    assert_eq!(claimed, 1);
    assert_eq!(store.inspect().unwrap().leased, 1);
}

#[test]
fn failed_completion_keeps_the_event_for_recovery_without_a_success_receipt() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let lease = store.claim().unwrap().unwrap();
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert_eq!(
        store.complete(lease, DeliveryOutcome::Accepted),
        Err(Error::Storage)
    );
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    drop(store);
    let mut store = Outbox::open(&fixture.db(), partition()).unwrap();
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.leased, report.receipts), (1, 1, 0));
    assert_eq!(count(&report, Action::Delivered), 0);
    store.test_time = Some(31_000);
    assert!(store.claim().unwrap().is_none());
    store.test_time = Some(32_000);
    let lease = store.claim().unwrap().unwrap();
    store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(store.inspect().unwrap().pending, 0);
}

#[test]
fn disk_full_preserves_previously_committed_events_and_journal() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store
        .connection()
        .execute_batch("PRAGMA max_page_count=5")
        .unwrap();
    let mut committed = 0;
    let mut refused = false;
    for id in ['1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c'] {
        match store.admit(&event(id)) {
            Ok(Admission::Queued) => committed += 1,
            Err(Error::Storage) => {
                refused = true;
                break;
            }
            result => panic!("unexpected admission: {result:?}"),
        }
    }
    assert!(refused);
    drop(store);
    let mut reopened = Outbox::open(&fixture.db(), partition()).unwrap();
    let report = reopened.inspect().unwrap();
    assert_eq!(report.pending, committed);
    assert_eq!(count(&report, Action::Queued), committed as u64);
}

#[test]
fn transient_backoff_is_bounded_and_does_not_change_event_bytes() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let input = event('1');
    let canonical = CheckedEvent::from_bytes(&input).unwrap();
    store.admit(&input).unwrap();
    let mut now = 1000;
    for attempt in 1..=20 {
        store.test_time = Some(now);
        let lease = store.claim().unwrap().unwrap();
        assert_eq!(lease.event().as_bytes(), canonical.as_bytes());
        store.complete(lease, DeliveryOutcome::Transient).unwrap();
        let delay = (1000u64 << (attempt - 1).min(15)).min(MAX_BACKOFF_MS);
        now += delay;
        store.test_time = Some(now - 1);
        assert!(store.claim().unwrap().is_none());
    }
    store.test_time = Some(now);
    let lease = store.claim().unwrap().unwrap();
    store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(store.inspect().unwrap().pending, 0);
}

#[test]
fn impossible_persisted_retry_and_lease_bounds_are_refused() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(fixture.db()).unwrap();
    let original: Vec<u8> = conn
        .query_row("SELECT record FROM events", [], |r| r.get(0))
        .unwrap();
    for mutation in [
        json!({"next_ms":MAX_TIME}),
        json!({"attempts":17}),
        json!({"next_ms":1001}),
        json!({"attempts":1,"lease":{"token":reference('f'),"until_ms":1001}}),
    ] {
        let mut record: Value = serde_json::from_slice(&original).unwrap();
        for (field, value) in mutation.as_object().unwrap() {
            record[field] = value.clone();
        }
        conn.execute(
            "UPDATE events SET record=?1",
            [serde_json::to_vec(&record).unwrap()],
        )
        .unwrap();
        assert!(matches!(
            Outbox::open(&fixture.db(), partition()),
            Err(Error::Integrity)
        ));
    }
    conn.execute("UPDATE events SET record=?1", [original])
        .unwrap();
    conn.execute_batch("CREATE VIEW unexpected AS SELECT record FROM events")
        .unwrap();
    assert!(matches!(
        Outbox::open(&fixture.db(), partition()),
        Err(Error::Integrity)
    ));
}

#[test]
fn maximum_capacity_can_be_verified_claimed_and_purged_within_work_limits() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    drop(store);
    // Populate only our synthetic store in one transaction, avoiding 1,000
    // fsyncs merely to arrange the fully occupied boundary fixture.
    let mut conn = rusqlite::Connection::open(fixture.db()).unwrap();
    let template: Vec<u8> = conn
        .query_row("SELECT record FROM events", [], |r| r.get(0))
        .unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute("DELETE FROM events", []).unwrap();
    for number in 0..1000 {
        let id = format!("ref_{number:032x}");
        let mut row: Value = serde_json::from_slice(&template).unwrap();
        let mut candidate: Value = serde_json::from_str(row["event"].as_str().unwrap()).unwrap();
        candidate["event_id"] = json!(id);
        let event = CheckedEvent::from_bytes(&serde_json::to_vec(&candidate).unwrap()).unwrap();
        row["event"] = json!(std::str::from_utf8(event.as_bytes()).unwrap());
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
    assert_eq!(store.inspect().unwrap().pending, 1000);
    assert_eq!(store.admit(&event('f')), Ok(Admission::Full));
    assert!(store.claim().unwrap().is_some());
    store.purge().unwrap();
    assert_eq!(store.inspect().unwrap().pending, 0);
}

#[test]
fn inspection_is_read_only_and_never_repairs_or_prunes_retained_state() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits {
        max_events: 1,
        max_age_ms: 1000,
    });
    store.admit(&event('1')).unwrap();
    drop(store);
    let before = fs::read(fixture.db()).unwrap();
    let report = Outbox::inspect_file(&fixture.db(), partition()).unwrap();
    assert_eq!(report.pending, 1); // The historical fixture time is expired today.
    assert_eq!(fs::read(fixture.db()).unwrap(), before);
    assert_eq!(fs::read_dir(&fixture.0).unwrap().count(), 1);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(fixture.db(), fs::Permissions::from_mode(0o400)).unwrap();
        assert_eq!(
            Outbox::inspect_file(&fixture.db(), partition())
                .unwrap()
                .pending,
            1
        );
        fs::set_permissions(fixture.db(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let missing = fixture.0.join("missing");
    assert!(matches!(
        Outbox::inspect_file(&missing, partition()),
        Err(Error::Path)
    ));
    assert!(!missing.exists());
}
