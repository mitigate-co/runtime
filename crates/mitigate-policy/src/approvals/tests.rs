use super::*;
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

fn binding_value() -> Value {
    json!({"schema_version":1,"client":"1".repeat(64),"principal":null,"agent":null,
        "session_ref":"2".repeat(64),"call_ref":"3".repeat(64),"server":"4".repeat(64),
        "tool":"5".repeat(64),"schema_fingerprint":"6".repeat(64),"definition_fingerprint":"7".repeat(64),
        "policy_ref":"8".repeat(64),"policy_version":1,"policy_bundle_hash":"9".repeat(64),
        "capabilities":["delete_data"],"environment":"development"})
}
fn binding() -> Binding {
    Binding::from_bytes(&serde_json::to_vec(&binding_value()).unwrap()).unwrap()
}
fn operator() -> Fingerprint {
    serde_json::from_value(json!("f".repeat(64))).unwrap()
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mitigate-approvals-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        self.0.join("approvals.db")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn pending(store: &mut ApprovalStore) -> Record {
    store.request(binding(), 1000, 1000).unwrap()
}

#[test]
fn time_is_sampled_under_the_store_lock_and_clock_failure_preserves_state() {
    use crate::clock::LockedClock;
    let dir = Directory::new();
    let db = dir.db();
    let mut store = ApprovalStore::create(&db).unwrap();
    let record = store
        .request(binding(), LockedClock(&db, Some(1000)), 1000)
        .unwrap();
    assert_eq!(record.created_at_ms, 1000);
    assert_eq!(record.expires_at_ms, 2000);
    assert!(matches!(
        store.decide(
            &record.approval_ref,
            Choice::Approve,
            operator(),
            LockedClock(&db, None)
        ),
        Err(Error::Clock)
    ));
    assert_eq!(
        store
            .get(&record.approval_ref, LockedClock(&db, Some(1000)))
            .unwrap()
            .state,
        State::Requested
    );
    store
        .decide(
            &record.approval_ref,
            Choice::Approve,
            operator(),
            LockedClock(&db, Some(1100)),
        )
        .unwrap();
    assert!(matches!(
        store.consume(
            &record.approval_ref,
            &binding(),
            LockedClock(&db, Some(1099))
        ),
        Err(Error::Clock)
    ));
    assert!(matches!(
        store
            .consume(
                &record.approval_ref,
                &binding(),
                LockedClock(&db, Some(2000))
            )
            .unwrap(),
        Consumption::Unavailable(State::Expired)
    ));
}

#[test]
fn approval_survives_restart_but_consumption_never_replays() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let r = pending(&mut store);
    assert!(matches!(
        store.consume(&r.approval_ref, &binding(), 1000).unwrap(),
        Consumption::Pending
    ));
    let approved = store
        .decide(&r.approval_ref, Choice::Approve, operator(), 1100)
        .unwrap();
    assert_eq!(approved.state, State::Approved);
    assert!(matches!(
        store.decide(&r.approval_ref, Choice::Approve, operator(), 1100),
        Err(Error::State)
    ));
    drop(store);
    let mut store = ApprovalStore::open(&dir.db()).unwrap();
    let Consumption::Ready(permit) = store.consume(&r.approval_ref, &binding(), 1200).unwrap()
    else {
        panic!("no permit")
    };
    assert_eq!(permit.reference(), &r.approval_ref);
    assert_eq!(permit.operator(), &operator());
    drop(permit);
    drop(store);
    let mut store = ApprovalStore::open(&dir.db()).unwrap();
    assert!(matches!(
        store.consume(&r.approval_ref, &binding(), 1200).unwrap(),
        Consumption::Unavailable(State::Consumed)
    ));
    let consumed = store.get(&r.approval_ref, 1200).unwrap();
    assert_eq!(consumed.decisions[0].source, OperatorSource::DeclaredLocal);
    assert_eq!(consumed.binding.policy_version, 1);
    assert!(matches!(
        store.decide(&r.approval_ref, Choice::Deny, operator(), 1200),
        Err(Error::State)
    ));
}

#[test]
fn denial_and_cancellation_are_terminal_and_revocation_retains_history() {
    for approved_first in [false, true] {
        let dir = Directory::new();
        let mut store = ApprovalStore::create(&dir.db()).unwrap();
        let r = pending(&mut store);
        if approved_first {
            store
                .decide(&r.approval_ref, Choice::Approve, operator(), 1000)
                .unwrap();
        }
        let other = fresh_reference().unwrap();
        let denied = store
            .decide(&r.approval_ref, Choice::Deny, other.clone(), 1001)
            .unwrap();
        assert_eq!(denied.state, State::Denied);
        assert_eq!(denied.decisions.len(), if approved_first { 2 } else { 1 });
        assert_eq!(denied.decisions.last().unwrap().operator_ref, other);
        if approved_first {
            assert_eq!(denied.decisions[0].operator_ref, operator());
        }
        assert!(matches!(
            store.consume(&r.approval_ref, &binding(), 1001).unwrap(),
            Consumption::Unavailable(State::Denied)
        ));
        assert!(matches!(
            store.decide(&r.approval_ref, Choice::Approve, operator(), 1001),
            Err(Error::State)
        ));
    }
    for reason in [Cancellation::CallerCancelled, Cancellation::SessionEnded] {
        let dir = Directory::new();
        let mut store = ApprovalStore::create(&dir.db()).unwrap();
        let r = pending(&mut store);
        store
            .decide(&r.approval_ref, Choice::Approve, operator(), 1000)
            .unwrap();
        let cancelled = store.cancel(&r.approval_ref, reason, 1001).unwrap();
        assert_eq!(cancelled.cancellation, Some(reason));
        assert!(matches!(
            store.consume(&r.approval_ref, &binding(), 1001).unwrap(),
            Consumption::Unavailable(State::Cancelled)
        ));
    }
}

#[test]
fn every_binding_dimension_invalidates_pending_and_approved_calls() {
    for approved in [false, true] {
        for field in [
            "client",
            "principal",
            "agent",
            "session_ref",
            "call_ref",
            "server",
            "tool",
            "schema_fingerprint",
            "definition_fingerprint",
            "policy_ref",
            "policy_version",
            "policy_bundle_hash",
            "capabilities",
            "environment",
        ] {
            let dir = Directory::new();
            let mut store = ApprovalStore::create(&dir.db()).unwrap();
            let r = pending(&mut store);
            if approved {
                store
                    .decide(&r.approval_ref, Choice::Approve, operator(), 1000)
                    .unwrap();
            }
            let mut changed = binding_value();
            changed[field] = match field {
                "policy_version" => json!(2),
                "capabilities" => json!(["delete_data", "write_data"]),
                "environment" => json!("production"),
                _ => json!("e".repeat(64)),
            };
            let changed = Binding::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                matches!(
                    store.consume(&r.approval_ref, &changed, 1000).unwrap(),
                    Consumption::Unavailable(State::Cancelled)
                ),
                "missed {field}"
            );
            assert_eq!(
                store.get(&r.approval_ref, 1000).unwrap().cancellation,
                Some(Cancellation::ContextChanged)
            );
            assert!(matches!(
                store.consume(&r.approval_ref, &binding(), 1000).unwrap(),
                Consumption::Unavailable(State::Cancelled)
            ));
        }
    }
}

#[test]
fn expiry_is_exclusive_persisted_and_not_reversed_by_clock_rollback() {
    for approved in [false, true] {
        let dir = Directory::new();
        let mut store = ApprovalStore::create(&dir.db()).unwrap();
        let r = pending(&mut store);
        if approved {
            store
                .decide(&r.approval_ref, Choice::Approve, operator(), 1999)
                .unwrap();
        }
        assert!(matches!(
            store.decide(&r.approval_ref, Choice::Approve, operator(), 2000),
            Err(Error::State)
        ));
        drop(store);
        let mut store = ApprovalStore::open(&dir.db()).unwrap();
        assert_eq!(
            store.get(&r.approval_ref, 2000).unwrap().state,
            State::Expired
        );
        assert!(matches!(
            store.consume(&r.approval_ref, &binding(), 1999),
            Err(Error::Clock)
        ));
        assert!(matches!(
            store.consume(&r.approval_ref, &binding(), 2000).unwrap(),
            Consumption::Unavailable(State::Expired)
        ));
    }
}

#[test]
fn simultaneous_consumers_receive_exactly_one_permit() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let r = pending(&mut store);
    store
        .decide(&r.approval_ref, Choice::Approve, operator(), 1100)
        .unwrap();
    let first = ApprovalStore::open(&dir.db()).unwrap();
    let second = ApprovalStore::open(&dir.db()).unwrap();
    let barrier = Arc::new(Barrier::new(2));
    let handles: Vec<_> = [first, second]
        .into_iter()
        .map(|mut conn| {
            let barrier = barrier.clone();
            let reference = r.approval_ref.clone();
            std::thread::spawn(move || {
                barrier.wait();
                matches!(
                    conn.consume(&reference, &binding(), 1200),
                    Ok(Consumption::Ready(_))
                )
            })
        })
        .collect();
    let successes = handles
        .into_iter()
        .filter_map(|h| h.join().unwrap().then_some(()))
        .count();
    assert_eq!(successes, 1);
    assert_eq!(
        store.get(&r.approval_ref, 1200).unwrap().state,
        State::Consumed
    );
}

#[test]
fn busy_corrupt_or_missing_storage_never_returns_a_permit() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let r = pending(&mut store);
    store
        .decide(&r.approval_ref, Choice::Approve, operator(), 1000)
        .unwrap();
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert!(matches!(
        store.consume(&r.approval_ref, &binding(), 1001),
        Err(Error::Storage)
    ));
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        store.get(&r.approval_ref, 1001).unwrap().state,
        State::Approved
    );
    conn.execute(
        "UPDATE approvals SET record=?1",
        [b"{\"metadata\":\"private-canary\"}".as_slice()],
    )
    .unwrap();
    assert!(matches!(
        store.consume(&r.approval_ref, &binding(), 1001),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ApprovalStore::open(&dir.db()),
        Err(Error::Storage)
    ));
    assert!(matches!(
        ApprovalStore::open(&dir.0.join("missing")),
        Err(Error::Path)
    ));
    drop(conn);
    drop(store);
}

#[test]
fn bound_inputs_duplicate_calls_and_storage_schema_are_rejected() {
    for field in ["principal", "agent", "environment"] {
        let mut value = binding_value();
        value.as_object_mut().unwrap().remove(field);
        assert!(Binding::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    for (field, value) in [
        ("client", Value::Null),
        ("policy_version", json!(0)),
        ("capabilities", json!([])),
        ("capabilities", json!(["delete_data", "delete_data"])),
        ("environment", json!("private\ncanary")),
        ("arguments", json!({"private":"canary"})),
    ] {
        let mut input = binding_value();
        input[field] = value;
        assert!(Binding::from_bytes(&serde_json::to_vec(&input).unwrap()).is_err());
    }
    assert!(Binding::from_bytes(&vec![b' '; 4097]).is_err());
    assert!(Binding::from_bytes(br#"{"schema_version":1,"schema_version":1}"#).is_err());
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    assert!(ApprovalStore::create(&dir.db()).is_err());
    for ttl in [0, 99, 300_001, u64::MAX] {
        assert!(matches!(
            store.request(binding(), 1000, ttl),
            Err(Error::Input)
        ));
    }
    pending(&mut store);
    assert!(matches!(
        store.request(binding(), 1000, 1000),
        Err(Error::Input)
    ));
    assert!(matches!(
        store.get(&fresh_reference().unwrap(), 1000),
        Err(Error::Missing)
    ));
    assert!(matches!(store.list(MAX_TIME + 1), Err(Error::Clock)));
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute_batch(
        "CREATE TRIGGER forged AFTER INSERT ON approvals BEGIN DELETE FROM approvals; END",
    )
    .unwrap();
    assert!(matches!(store.list(1000), Err(Error::Storage)));
    drop(conn);
    drop(store);
}

#[test]
fn capacity_retains_pending_requests_and_evicts_only_terminal_records() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let mut first = None;
    for _ in 0..256 {
        let mut b = binding();
        b.call_ref = fresh_reference().unwrap();
        let r = store.request(b, 1000, 1000).unwrap();
        if first.is_none() {
            first = Some(r.approval_ref);
        }
    }
    let mut b = binding();
    b.call_ref = fresh_reference().unwrap();
    assert!(matches!(
        store.request(b.clone(), 1000, 1000),
        Err(Error::Capacity)
    ));
    let reference = first.unwrap();
    store
        .decide(&reference, Choice::Deny, operator(), 1001)
        .unwrap();
    store.request(b, 1001, 1000).unwrap();
    assert!(matches!(store.get(&reference, 1001), Err(Error::Missing)));
    assert_eq!(store.list(1001).unwrap().len(), 256);
    assert_eq!(store.list(2001).unwrap().len(), 256);
    assert!(store.list(2001 + 86_400_000).unwrap().is_empty());
    assert!(matches!(store.list(2000), Err(Error::Clock)));
}

#[cfg(unix)]
#[test]
fn store_requires_private_regular_files() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = Directory::new();
    drop(ApprovalStore::create(&dir.db()).unwrap());
    assert_eq!(
        std::fs::metadata(dir.db()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let link = dir.0.join("alias.db");
    symlink(dir.db(), &link).unwrap();
    assert!(matches!(ApprovalStore::open(&link), Err(Error::Path)));
    std::fs::set_permissions(dir.db(), std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(matches!(ApprovalStore::open(&dir.db()), Err(Error::Path)));
}

#[test]
fn duplicate_stored_invocations_cannot_create_two_authorities() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let mut original = pending(&mut store);
    original.approval_ref = fresh_reference().unwrap();
    let conn = rusqlite::Connection::open(dir.db()).unwrap();
    conn.execute(
        "INSERT INTO approvals VALUES(?1,?2)",
        rusqlite::params![
            original.approval_ref.as_str(),
            serde_json::to_vec(&original).unwrap()
        ],
    )
    .unwrap();
    assert!(matches!(store.list(1000), Err(Error::Storage)));
    assert!(matches!(
        ApprovalStore::open(&dir.db()),
        Err(Error::Storage)
    ));
    drop(conn);
    drop(store);
}

#[test]
fn class_order_is_not_a_context_change_and_last_valid_instant_is_consumable() {
    let dir = Directory::new();
    let mut store = ApprovalStore::create(&dir.db()).unwrap();
    let mut b = binding();
    b.capabilities = vec![CapabilityClass::DeleteData, CapabilityClass::WriteData];
    let request = store.request(b.clone(), 1000, 1000).unwrap();
    store
        .decide(&request.approval_ref, Choice::Approve, operator(), 1000)
        .unwrap();
    b.capabilities.reverse();
    assert!(matches!(
        store.consume(&request.approval_ref, &b, 1999).unwrap(),
        Consumption::Ready(_)
    ));
}
