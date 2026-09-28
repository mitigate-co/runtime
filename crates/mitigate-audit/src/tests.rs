use super::*;
mod calls;
use mitigate_fingerprint::{Domain, fingerprint};
use mitigate_gateway::CallerIdentity;
use rusqlite::Connection;
use serde_json::json;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

struct Fixture {
    root: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "mitigate-audit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        Self {
            path: root.join("audit.sqlite"),
            root,
        }
    }
    fn create(&self, retention: Retention) -> AuditStore {
        AuditStore::create(&self.path, retention).unwrap()
    }
    fn edit(&self, sql: &str) {
        Connection::open(&self.path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for name in ["audit.sqlite", "audit.sqlite-journal", "linked.sqlite"] {
            let _ = std::fs::remove_file(self.root.join(name));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}
fn detail() -> EventDetails {
    let mut value = EventDetails::new(
        &CallerIdentity::default(),
        fingerprint(Domain::ServerIdentity, &json!("synthetic-server")).unwrap(),
        Operation::ToolCall,
    );
    value.decision = Decision::Deny;
    value.result_class = ResultClass::NotInvoked;
    value
}

#[test]
fn durable_ordered_roundtrip_and_bounded_pages() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    assert_eq!(store.prune_at(999).unwrap(), 0);
    assert_eq!(store.verify().unwrap().records, 0);
    let first = store.append_at(detail(), 1000).unwrap();
    for _ in 0..3 {
        store.append_at(detail(), 1001).unwrap();
    }
    assert_ne!(
        first.event.event_id,
        store.page(1, 1).unwrap().records[0].event.event_id
    );
    drop(store);
    let mut store = AuditStore::open(&fixture.path).unwrap();
    let verified = store.verify().unwrap();
    assert_eq!(
        (
            verified.records,
            verified.head_sequence,
            verified.anchor_sequence
        ),
        (4, 4, 0)
    );
    let first_page = store.page(0, 2).unwrap();
    assert_eq!(first_page.next_after, Some(2));
    let second = store.page(first_page.next_after.unwrap(), 2).unwrap();
    assert_eq!(second.records[0].sequence, 3);
    assert_eq!(second.records[0].previous_hash, first_page.records[1].hash);
    assert_eq!(second.next_after, None);
    assert!(store.page(0, 251).is_err());
    assert!(store.page(u64::MAX, 1).is_err());
    assert!(store.page(0, 0).is_err());
    assert!(!fixture.root.join("audit.sqlite-wal").exists());
}
#[test]
fn count_rotation_preserves_anchor_and_never_reuses_sequence() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention {
        max_records: 2,
        ..Retention::default()
    });
    let first = store.append_at(detail(), 1000).unwrap();
    store.append_at(detail(), 1000).unwrap();
    store.append_at(detail(), 1000).unwrap();
    let page = store.page(0, 250).unwrap();
    assert_eq!(page.anchor_sequence, 1);
    assert_eq!(page.anchor_hash, first.hash);
    assert_eq!(page.records[0].sequence, 2);
    drop(store);
    assert_eq!(
        AuditStore::open(&fixture.path)
            .unwrap()
            .verify()
            .unwrap()
            .records,
        2
    );
}
#[test]
fn byte_and_age_rotation_handle_clock_rollback_and_empty_history() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention {
        max_age_seconds: 1,
        max_payload_bytes: 4096,
        ..Retention::default()
    });
    for _ in 0..30 {
        store.append_at(detail(), 2000).unwrap();
    }
    let verified = store.verify().unwrap();
    assert!(verified.records < 30 && verified.records > 0);
    assert!(verified.payload_bytes <= 4096);
    assert_eq!(store.append_at(detail(), 1500).unwrap().event.time_ms, 2000);
    let retained = store.verify().unwrap().records;
    assert_eq!(store.prune_at(3001).unwrap(), retained);
    let empty = store.verify().unwrap();
    assert_eq!(empty.records, 0);
    assert_eq!(empty.anchor_sequence, 31);
    assert_eq!(empty.anchor_hash, empty.head_hash);
    assert_eq!(store.append_at(detail(), 1000).unwrap().sequence, 32);
    assert_eq!(store.page(0, 1).unwrap().records[0].event.time_ms, 3001);
}
#[test]
fn closed_fields_and_caller_attribution_exclude_content() {
    let profile = CallerIdentity::from_profile(
        br#"{"schema_version":1,"client_ref":"caller-canary","principal_ref":"principal-canary"}"#,
    )
    .unwrap();
    let event = EventDetails::new(&profile, detail().server_ref, Operation::Inventory);
    let encoded = serde_json::to_string(&event).unwrap();
    assert!(!encoded.contains("caller-canary") && !encoded.contains("principal-canary"));
    assert!(event.agent_ref.is_none());
    assert!(detail().client_ref.is_none());
    for field in [
        "arguments",
        "result",
        "metadata",
        "credential",
        "description",
        "error_message",
    ] {
        let mut hostile = serde_json::to_value(detail()).unwrap();
        hostile[field] = json!("raw-payload-canary");
        assert!(serde_json::from_value::<EventDetails>(hostile).is_err());
    }
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    store.append(event).unwrap();
    let bytes = std::fs::read(&fixture.path).unwrap();
    assert!(
        !bytes
            .windows(b"caller-canary".len())
            .any(|w| w == b"caller-canary")
    );
}
#[test]
fn invalid_events_and_retention_do_not_mutate_storage() {
    let fixture = Fixture::new();
    assert!(
        AuditStore::create(
            &fixture.path,
            Retention {
                max_records: 0,
                ..Retention::default()
            }
        )
        .is_err()
    );
    assert!(!fixture.path.exists());
    let mut store = fixture.create(Retention::default());
    let mut invalid = detail();
    invalid.duration_ms = u64::MAX;
    assert_eq!(store.append(invalid).err(), Some(Error::InvalidInput));
    let mut invalid = detail();
    invalid.principal_ref = Some(invalid.server_ref.clone());
    assert_eq!(store.append(invalid).err(), Some(Error::InvalidInput));
    let mut invalid = detail();
    invalid.policy_version = Some(1);
    assert_eq!(store.append(invalid).err(), Some(Error::InvalidInput));
    let mut invalid = detail();
    invalid.capability_classes = vec![mitigate_mcp::classification::CapabilityClass::Unknown; 2];
    assert_eq!(store.append(invalid).err(), Some(Error::InvalidInput));
    assert_eq!(store.verify().unwrap().records, 0);
}
#[test]
fn corruption_missing_tail_and_modified_checkpoints_are_rejected() {
    for sql in [
        "UPDATE records SET payload=replace(payload,'not_invoked','success') WHERE sequence=1",
        "DELETE FROM records WHERE sequence=1",
        "DELETE FROM records WHERE sequence=2",
        "UPDATE state SET head_sequence=3",
        "UPDATE state SET payload_bytes=0",
        "UPDATE state SET anchor_sequence=1",
        "UPDATE records SET hash=printf('%064d',1) WHERE sequence=2",
        "UPDATE records SET bytes=-1 WHERE sequence=1",
        "UPDATE records SET time_ms=-1 WHERE sequence=1",
        "PRAGMA user_version=2",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create(Retention::default());
        store.append(detail()).unwrap();
        store.append(detail()).unwrap();
        drop(store);
        fixture.edit(sql);
        let before = std::fs::read(&fixture.path).unwrap();
        assert_eq!(
            AuditStore::open(&fixture.path).err(),
            Some(Error::Integrity)
        );
        assert_eq!(std::fs::read(&fixture.path).unwrap(), before);
    }
}
#[test]
fn schema_injection_and_external_edits_fail_before_append() {
    for sql in [
        "CREATE TRIGGER injected AFTER INSERT ON records BEGIN DELETE FROM records; END",
        "UPDATE records SET payload='{}' WHERE sequence=1",
    ] {
        let fixture = Fixture::new();
        let mut store = fixture.create(Retention::default());
        store.append(detail()).unwrap();
        fixture.edit(sql);
        assert_eq!(store.append(detail()).err(), Some(Error::Integrity));
        let count: i64 = Connection::open(&fixture.path)
            .unwrap()
            .query_row("SELECT count(*) FROM records", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
#[test]
fn competing_writer_and_busy_failure_preserve_atomicity() {
    let fixture = Fixture::new();
    let mut first = fixture.create(Retention::default());
    let mut second = AuditStore::open(&fixture.path).unwrap();
    first.append(detail()).unwrap();
    assert_eq!(second.append(detail()).unwrap().sequence, 2);
    assert_eq!(first.append(detail()).unwrap().sequence, 3);
    let blocker = Connection::open(&fixture.path).unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(first.append(detail()).err(), Some(Error::Unavailable));
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(first.verify().unwrap().records, 3);
    assert_eq!(first.append(detail()).unwrap().sequence, 4);
    assert_eq!(second.verify().unwrap().records, 4);
    blocker.execute_batch("BEGIN EXCLUSIVE").unwrap();
    assert_eq!(first.verify().err(), Some(Error::Unavailable));
    blocker.execute_batch("ROLLBACK").unwrap();
    assert_eq!(first.verify().unwrap().records, 4);
}

#[test]
fn repeated_rotation_reclaims_pages_and_remains_verifiable() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention {
        max_records: 100,
        ..Retention::default()
    });
    for _ in 0..100 {
        store.append_at(detail(), 1000).unwrap();
    }
    let first_size = std::fs::metadata(&fixture.path).unwrap().len();
    for _ in 0..1000 {
        store.append_at(detail(), 1000).unwrap();
    }
    let verified = store.verify().unwrap();
    assert_eq!(
        (
            verified.records,
            verified.head_sequence,
            verified.anchor_sequence
        ),
        (100, 1100, 1000)
    );
    let final_size = std::fs::metadata(&fixture.path).unwrap().len();
    assert!(
        final_size <= first_size + 4 * 4096,
        "rotation must reclaim rather than grow indefinitely"
    );
    drop(store);
    assert_eq!(
        AuditStore::open(&fixture.path)
            .unwrap()
            .verify()
            .unwrap()
            .records,
        100
    );
}
#[test]
fn unsafe_paths_and_oversize_files_are_rejected() {
    let fixture = Fixture::new();
    assert_eq!(AuditStore::open(&fixture.path).err(), Some(Error::Path));
    let mut store = fixture.create(Retention::default());
    store.append(detail()).unwrap();
    assert_eq!(
        AuditStore::create(&fixture.path, Retention::default()).err(),
        Some(Error::Path)
    );
    assert_eq!(AuditStore::open(&fixture.root).err(), Some(Error::Path));
    drop(store);
    std::fs::OpenOptions::new()
        .write(true)
        .open(&fixture.path)
        .unwrap()
        .set_len(128 * 1024 * 1024 + 1)
        .unwrap();
    assert_eq!(AuditStore::open(&fixture.path).err(), Some(Error::Path));
}
#[cfg(unix)]
#[test]
fn unix_permissions_and_symlinks_are_enforced() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let fixture = Fixture::new();
    drop(fixture.create(Retention::default()));
    assert_eq!(
        std::fs::metadata(&fixture.path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let linked = fixture.root.join("linked.sqlite");
    symlink(&fixture.path, &linked).unwrap();
    assert_eq!(AuditStore::open(&linked).err(), Some(Error::Path));
    std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(AuditStore::open(&fixture.path).err(), Some(Error::Path));
}
