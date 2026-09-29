use super::*;
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    thread,
    time::{Duration, Instant},
};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-references-{}",
            SyncRef::fresh().unwrap().as_str()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("references.sqlite")
    }
    fn create(&self) -> ReferenceMap {
        ReferenceMap::create(&self.path(), partition()).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn reference(number: usize) -> SyncRef {
    serde_json::from_value(serde_json::json!(format!("ref_{number:032x}"))).unwrap()
}
fn partition() -> Partition {
    Partition {
        runtime_ref: reference(1),
        enrollment_ref: reference(2),
    }
}
fn key(number: usize) -> LocalKey {
    let mut digest = [0; 32];
    digest[..8].copy_from_slice(&(number as u64).to_be_bytes());
    LocalKey::new(Kind::Tool, digest)
}
fn same(a: &[SyncRef], b: &[SyncRef]) {
    assert!(a == b, "opaque references must match");
}

#[test]
fn committed_random_mappings_survive_restart_with_order_and_domain_separation() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let mut keys = [
        Kind::Client,
        Kind::Principal,
        Kind::Agent,
        Kind::Server,
        Kind::Tool,
        Kind::Schema,
        Kind::Policy,
    ]
    .into_iter()
    .map(|kind| LocalKey::new(kind, [0xa5; 32]))
    .collect::<Vec<_>>();
    keys.push(keys[0].clone());
    let original = store.resolve(&keys).unwrap();
    assert_eq!(store.len().unwrap(), 7);
    assert_eq!(original.iter().collect::<BTreeSet<_>>().len(), 7);
    assert!(original[0] == original[7]);
    for output in &original {
        assert!(!output.as_str().contains(&"a5".repeat(16)));
        assert!(output != &partition().runtime_ref && output != &partition().enrollment_ref);
    }
    drop(store);
    let mut restored = ReferenceMap::open(&fixture.path(), partition()).unwrap();
    same(&restored.resolve(&keys).unwrap(), &original);
    keys.reverse();
    let mut reversed = original;
    reversed.reverse();
    same(&restored.resolve(&keys).unwrap(), &reversed);
}

#[test]
fn creation_and_scope_never_overwrite_adopt_or_rotate_existing_identity() {
    let fixture = Fixture::new();
    let missing = fixture.path();
    assert!(ReferenceMap::open(&missing, partition()).is_err());
    assert!(!missing.exists());
    let mut store = fixture.create();
    let original = store.resolve(&[key(1)]).unwrap();
    assert!(ReferenceMap::create(&fixture.path(), partition()).is_err());
    let foreign = Partition {
        runtime_ref: reference(3),
        enrollment_ref: reference(4),
    };
    assert_eq!(
        ReferenceMap::open(&fixture.path(), foreign.clone()).err(),
        Some(Error::Storage(outbox::Error::Partition))
    );
    let other = Fixture::new();
    let mut other_store = ReferenceMap::create(&other.path(), foreign).unwrap();
    assert!(other_store.resolve(&[key(1)]).unwrap() != original);
    same(&store.resolve(&[key(1)]).unwrap(), &original);
    let invalid = Fixture::new();
    assert_eq!(
        ReferenceMap::create(
            &invalid.path(),
            Partition {
                runtime_ref: reference(1),
                enrollment_ref: reference(1)
            }
        )
        .err(),
        Some(Error::Input)
    );
    assert!(!invalid.path().exists());
}

#[test]
fn commit_failure_returns_no_references_and_rolls_back_the_entire_batch() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    let original = store.resolve(&[key(1)]).unwrap();
    store.conn.commit_hook(Some(|| true)).unwrap();
    assert!(matches!(
        store.resolve(&[key(1), key(2), key(3)]),
        Err(Error::Storage(_))
    ));
    store.conn.commit_hook(None::<fn() -> bool>).unwrap();
    drop(store);
    let mut restored = ReferenceMap::open(&fixture.path(), partition()).unwrap();
    assert_eq!(restored.len().unwrap(), 1);
    same(&restored.resolve(&[key(1)]).unwrap(), &original);
    assert_eq!(restored.resolve(&[key(2), key(3)]).unwrap().len(), 2);
    assert_eq!(restored.len().unwrap(), 3);
}

#[test]
fn bounded_batches_and_capacity_refuse_partial_admission_without_eviction() {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    assert_eq!(store.resolve(&[]).err(), Some(Error::Input));
    assert_eq!(
        store.resolve(&vec![key(0); MAX_BATCH + 1]).err(),
        Some(Error::Input)
    );
    assert!(store.is_empty().unwrap());
    // Populate valid synthetic rows in one transaction to exercise the real
    // production bound without thousands of unrelated durable flushes.
    let tx = store.conn.transaction().unwrap();
    for number in 0..MAX_REFERENCES - 1 {
        tx.execute(
            "INSERT INTO mappings VALUES(?1,?2,?3)",
            params![
                Kind::Tool as u8,
                key(number).digest.as_slice(),
                reference(number + 10).as_str()
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let before = store.resolve(&[key(0)]).unwrap();
    assert_eq!(
        store
            .resolve(&[key(MAX_REFERENCES), key(MAX_REFERENCES + 1)])
            .err(),
        Some(Error::Full)
    );
    assert_eq!(store.len().unwrap(), MAX_REFERENCES - 1);
    let final_key = key(MAX_REFERENCES);
    let last = store
        .resolve(&[final_key.clone(), final_key.clone()])
        .unwrap();
    assert!(last[0] == last[1]);
    assert_eq!(store.len().unwrap(), MAX_REFERENCES);
    assert_eq!(
        store.resolve(&[key(MAX_REFERENCES + 1)]).err(),
        Some(Error::Full)
    );
    same(&store.resolve(&[key(0)]).unwrap(), &before);
}

#[test]
fn independent_connections_cannot_assign_two_references_to_the_same_key() {
    let fixture = Fixture::new();
    drop(fixture.create());
    let barrier = Arc::new(Barrier::new(2));
    let workers = (0..2)
        .map(|_| {
            let path = fixture.path();
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let mut store = ReferenceMap::open(&path, partition()).unwrap();
                barrier.wait();
                let until = Instant::now() + Duration::from_secs(10);
                loop {
                    match store.resolve(&[key(1), key(2)]) {
                        Err(Error::Storage(outbox::Error::Busy)) if Instant::now() < until => {
                            continue;
                        }
                        result => break result.unwrap(),
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    let results = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect::<Vec<_>>();
    same(&results[0], &results[1]);
    assert_eq!(
        ReferenceMap::open(&fixture.path(), partition())
            .unwrap()
            .len()
            .unwrap(),
        2
    );
}

#[test]
fn closed_schema_and_every_stored_value_are_verified_before_use() {
    for corruption in [
        "PRAGMA user_version=2",
        "CREATE TABLE extra (metadata TEXT) STRICT",
        "PRAGMA ignore_check_constraints=ON; INSERT INTO mappings VALUES(7,zeroblob(32),'ref_00000000000000000000000000000003')",
        "PRAGMA ignore_check_constraints=ON; INSERT INTO mappings VALUES(1,zeroblob(31),'ref_00000000000000000000000000000003')",
        "INSERT INTO mappings VALUES(1,zeroblob(32),'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx')",
        "INSERT INTO mappings VALUES(1,zeroblob(32),'ref_00000000000000000000000000000001')",
    ] {
        let fixture = Fixture::new();
        let store = fixture.create();
        store.conn.execute_batch(corruption).unwrap();
        drop(store);
        assert!(ReferenceMap::open(&fixture.path(), partition()).is_err());
    }
    let fixture = Fixture::new();
    drop(outbox::Outbox::create(&fixture.path(), partition(), outbox::Limits::default()).unwrap());
    assert!(ReferenceMap::open(&fixture.path(), partition()).is_err());
}

#[test]
fn unsafe_files_and_diagnostics_do_not_expose_local_keys() {
    let fixture = Fixture::new();
    drop(fixture.create());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{PermissionsExt, symlink};
        symlink(fixture.path(), fixture.0.join("alias")).unwrap();
        assert!(ReferenceMap::open(&fixture.0.join("alias"), partition()).is_err());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(ReferenceMap::open(&fixture.path(), partition()).is_err());
        fs::set_permissions(fixture.path(), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::OpenOptions::new()
        .write(true)
        .open(fixture.path())
        .unwrap()
        .set_len(16 * 1024 * 1024 + 1)
        .unwrap();
    assert!(ReferenceMap::open(&fixture.path(), partition()).is_err());
    for error in [
        Error::Input,
        Error::Full,
        Error::Randomness,
        Error::Storage(outbox::Error::Integrity),
    ] {
        assert!(!format!("{error} {error:?}").contains("canary"));
        assert!(!error.to_string().contains(fixture.path().to_str().unwrap()));
    }
}
