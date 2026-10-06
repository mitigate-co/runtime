use super::{tests::*, *};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

#[test]
fn final_delivery_clock_observation_follows_successful_commit() {
    // The private clock seam models elapsed time inside SQLite's commit, not a
    // delay before preflight. No host-clock changes or timing sleeps are used.
    for (age, after, elapsed_ms, expected) in [
        (60_000, 6_000, 0, Ok(false)),
        (60_000, 5_999, 0, Ok(true)),
        (60_000, 31_000, 0, Ok(false)),
        (26_000, 1_999, 0, Ok(true)),
        (26_000, 2_000, 0, Ok(false)),
        (60_000, 999, 0, Err(Error::Clock)),
        (60_000, u64::MAX, 0, Err(Error::Clock)),
        // A stalled wall clock cannot hide a slow commit either.
        (60_000, 1000, 4_999, Ok(true)),
        (60_000, 1000, 5_000, Ok(false)),
        (60_000, 1000, 30_000, Ok(false)),
        (26_000, 1000, 1_000, Ok(false)),
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.store(Limits {
            max_events: 2,
            max_age_ms: age,
        });
        store.admit(&event('1')).unwrap();
        let lease = store.claim_for_delivery(25_000).unwrap().unwrap();
        let committed = Arc::new(AtomicBool::new(false));
        let marker = Arc::clone(&committed);
        store
            .connection()
            .commit_hook(Some(move || {
                marker.store(true, Ordering::SeqCst);
                false
            }))
            .unwrap();
        let sampled = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&sampled);
        let result = store.delivery_ready_with_clock(&lease, 25_000, || {
            assert!(committed.load(Ordering::SeqCst));
            // A fresh reader sees the committed state; the write lock is gone.
            assert_eq!(
                Outbox::inspect_file(&fixture.db(), partition())
                    .unwrap()
                    .leased,
                1
            );
            observed.store(true, Ordering::SeqCst);
            Ok((after, Duration::from_millis(elapsed_ms)))
        });
        assert_eq!(result, expected, "retention={age} after_commit={after}");
        assert!(
            sampled.load(Ordering::SeqCst),
            "preflight never sampled time after commit"
        );
        let report = store.inspect().unwrap();
        assert_eq!((report.pending, report.leased, report.receipts), (1, 1, 0));
        assert!(!report.paused);
    }
}

#[test]
fn final_clock_failure_preserves_the_claim_without_delivery_permission() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let lease = store.claim_for_delivery(25_000).unwrap().unwrap();
    assert_eq!(
        store.delivery_ready_with_clock(&lease, 25_000, || Err(Error::Clock)),
        Err(Error::Clock)
    );
    let report = store.inspect().unwrap();
    assert_eq!((report.pending, report.leased, report.receipts), (1, 1, 0));
}

#[test]
fn failed_preflight_commit_never_reaches_final_clock_or_releases_readiness() {
    let fixture = Fixture::new();
    let mut store = fixture.store(Limits::default());
    store.admit(&event('1')).unwrap();
    let lease = store.claim_for_delivery(25_000).unwrap().unwrap();
    let before = std::fs::read(fixture.db()).unwrap();
    store.connection().commit_hook(Some(|| true)).unwrap();
    assert!(
        store
            .delivery_ready_with_clock(&lease, 25_000, || {
                panic!("failed commit must not reach the final observation")
            })
            .is_err()
    );
    assert_eq!(std::fs::read(fixture.db()).unwrap(), before);
}
