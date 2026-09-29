use super::{tests::*, *};
use std::fs;

#[test]
fn waiting_and_ready_polls_do_not_write_claim_or_shorten_backoff() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    let empty = fs::read(fixture.db()).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    assert_eq!(fs::read(fixture.db()).unwrap(), empty);
    store.admit(&event('1')).unwrap();
    let admitted = fs::read(fixture.db()).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Ready));
    assert_eq!(store.inspect().unwrap().leased, 0);
    assert_eq!(fs::read(fixture.db()).unwrap(), admitted);
    let lease = store.claim_for_delivery(25_000).unwrap().unwrap();
    let leased = fs::read(fixture.db()).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    assert_eq!(fs::read(fixture.db()).unwrap(), leased);
    store.complete(lease, DeliveryOutcome::Transient).unwrap();
    let delayed = fs::read(fixture.db()).unwrap();
    store.test_time = Some(1999);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    store.test_time = Some(2000);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Ready));
    assert_eq!(fs::read(fixture.db()).unwrap(), delayed);
    let retry = store.claim_for_delivery(25_000).unwrap().unwrap();
    assert_eq!(
        retry.event().as_bytes(),
        CheckedEvent::from_bytes(&event('1')).unwrap().as_bytes()
    );
}

#[test]
fn abandoned_leases_schedule_one_delayed_retry_without_native_work() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let abandoned = store.claim_for_delivery(25_000).unwrap().unwrap();
    store.test_time = Some(31_000);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    let delayed = fs::read(fixture.db()).unwrap();
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.leased), (1, 0));
    assert_eq!(
        report
            .recent
            .iter()
            .filter(|entry| entry.action == Action::LeaseExpired)
            .count(),
        1
    );
    store.test_time = Some(31_999);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    assert_eq!(fs::read(fixture.db()).unwrap(), delayed);
    store.test_time = Some(32_000);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Ready));
    let retry = store.claim_for_delivery(25_000).unwrap().unwrap();
    assert_eq!(retry.event().as_bytes(), abandoned.event().as_bytes());
    assert_eq!(
        store.complete(abandoned, DeliveryOutcome::Accepted),
        Err(Error::StaleLease)
    );
    store.complete(retry, DeliveryOutcome::Accepted).unwrap();
}

#[test]
fn insufficient_retention_cannot_block_a_later_deliverable_event() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits {
        max_events: 2,
        max_age_ms: 30_000,
    });
    store.admit(&event('1')).unwrap();
    store.test_time = Some(5000);
    store.admit(&event('2')).unwrap();
    store.test_time = Some(6000);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Ready));
    let lease = store.claim_for_delivery(25_000).unwrap().unwrap();
    assert_eq!(
        lease.event().as_bytes(),
        CheckedEvent::from_bytes(&event('2')).unwrap().as_bytes()
    );
    store.complete(lease, DeliveryOutcome::Accepted).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    assert!(store.claim_for_delivery(25_000).unwrap().is_none());
    assert_eq!(store.inspect().unwrap().pending, 1);
    store.test_time = Some(31_000);
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Waiting));
    let report = store.inspect().unwrap();
    assert_eq!(report.pending, 0);
    assert_eq!(
        report
            .recent
            .iter()
            .filter(|entry| entry.action == Action::Expired)
            .count(),
        1
    );
    store.test_time = Some(30_999);
    assert_eq!(store.prepare_delivery(25_000), Err(Error::Clock));
}

#[test]
fn readiness_never_grants_authority_after_another_connection_pauses() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Ready));
    let mut control = Outbox::open(&fixture.db(), partition()).unwrap();
    control.test_time = Some(1000);
    control.set_paused(true).unwrap();
    let paused = fs::read(fixture.db()).unwrap();
    assert_eq!(store.prepare_delivery(25_000), Ok(Readiness::Paused));
    assert_eq!(fs::read(fixture.db()).unwrap(), paused);
    assert!(store.claim_for_delivery(25_000).unwrap().is_none());
    assert_eq!(store.inspect().unwrap().pending, 1);
}

#[test]
fn preparation_rejects_bad_budgets_clock_scope_and_failed_maintenance_commit() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    for budget in [0, 30_001, u64::MAX] {
        assert_eq!(store.prepare_delivery(budget), Err(Error::Input));
        assert_eq!(store.claim_for_delivery(budget).err(), Some(Error::Input));
    }
    store.test_time = Some(999);
    assert_eq!(store.prepare_delivery(25_000), Err(Error::Clock));
    store.test_time = Some(1000);
    let _abandoned = store.claim().unwrap().unwrap();
    let before = fs::read(fixture.db()).unwrap();
    store.test_time = Some(31_000);
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert!(store.prepare_delivery(25_000).is_err());
    store
        .connection()
        .commit_hook(None::<fn() -> bool>)
        .unwrap();
    assert_eq!(fs::read(fixture.db()).unwrap(), before);
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.leased), (1, 1));
    let wrong = Partition {
        runtime_ref: partition().enrollment_ref,
        enrollment_ref: partition().runtime_ref,
    };
    assert!(matches!(
        Outbox::open(&fixture.db(), wrong),
        Err(Error::Partition)
    ));
}

#[test]
fn file_preparation_opens_writes_only_for_due_maintenance_and_rejects_corruption() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    drop(store);
    // This synthetic admission time is expired today. Read-only inspection
    // retains it; active preparation must commit ordinary expiry without a key.
    assert_eq!(
        Outbox::inspect_file(&fixture.db(), partition())
            .unwrap()
            .pending,
        1
    );
    assert_eq!(
        Outbox::prepare_delivery_file(&fixture.db(), partition(), 500),
        Ok(Readiness::Waiting)
    );
    assert_eq!(
        Outbox::inspect_file(&fixture.db(), partition())
            .unwrap()
            .pending,
        0
    );
    let before = fs::read(fixture.db()).unwrap();
    assert_eq!(
        Outbox::prepare_delivery_file(&fixture.db(), partition(), 500),
        Ok(Readiness::Waiting)
    );
    assert!(
        fs::read(fixture.db()).unwrap() == before,
        "idle file preparation rewrote storage"
    );
    let conn = rusqlite::Connection::open(fixture.db()).unwrap();
    conn.execute(
        "UPDATE state SET record=?1",
        [b"{\"metadata\":\"private-canary\"}".as_slice()],
    )
    .unwrap();
    drop(conn);
    assert_eq!(
        Outbox::prepare_delivery_file(&fixture.db(), partition(), 500),
        Err(Error::Integrity)
    );
}
