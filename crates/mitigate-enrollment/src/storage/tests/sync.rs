use super::*;
use crate::storage::sync::{self, SyncProfile};
use mitigate_egress::{
    SyncRef,
    outbox::{Admission, Limits, Outbox, Partition},
};
use serde_json::{Value, json};
use std::{
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct SyncFixture(Fixture);
impl SyncFixture {
    fn new() -> Self {
        Self(Fixture::new())
    }
    fn profile(&self) -> PathBuf {
        self.0.dir.join("sync.json")
    }
    fn queue(&self) -> PathBuf {
        self.0.dir.join("outbox.sqlite")
    }
    fn references(&self) -> PathBuf {
        self.0.dir.join("outbox.sqlite.references.sqlite")
    }
    fn initialize(&self, session: &Session<MemoryVault>) -> Result<SyncProfile, sync::Error> {
        sync::initialize(
            &self.profile(),
            &self.0.path,
            &self.queue(),
            session,
            Limits::default(),
        )
    }
    fn confirmed(&self) -> Session<MemoryVault> {
        let pending = self.0.create().unwrap();
        let response = receipt(&pending);
        pending.confirm(&response).unwrap()
    }
    fn admit(&self, profile: &SyncProfile) -> Outbox {
        let partition = profile.inspect().unwrap().partition;
        let mut queue = Outbox::open(&self.queue(), partition.clone()).unwrap();
        let mut event: Value = serde_json::from_slice(include_bytes!(
            "../../../../../examples/egress/decision.json"
        ))
        .unwrap();
        event["runtime_ref"] = json!(partition.runtime_ref);
        assert_eq!(
            queue.admit(&serde_json::to_vec(&event).unwrap()),
            Ok(Admission::Queued)
        );
        queue
    }
}
impl Drop for SyncFixture {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.profile());
        let _ = fs::remove_file(self.queue());
        let _ = fs::remove_file(self.references());
    }
}

#[test]
fn consent_setup_requires_confirmed_native_state_and_never_replaces_files() {
    let fixture = SyncFixture::new();
    let pending = fixture.0.create().unwrap();
    assert_eq!(
        fixture.initialize(&pending).err(),
        Some(sync::Error::Enrollment(Error::Pending))
    );
    assert!(!fixture.profile().exists());
    assert!(!fixture.queue().exists());
    assert!(!fixture.references().exists());
    let response = receipt(&pending);
    let confirmed = pending.confirm(&response).unwrap();
    let profile = fixture.initialize(&confirmed).unwrap();
    let original = fs::read(fixture.profile()).unwrap();
    assert_eq!(
        fixture.initialize(&confirmed).err(),
        Some(sync::Error::Exists)
    );
    assert_eq!(fs::read(fixture.profile()).unwrap(), original);
    let value: Value = serde_json::from_slice(&original).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 7);
    assert_eq!(value["schema_version"], 2);
    assert_eq!(
        value["reference_file"],
        json!(fixture.references().canonicalize().unwrap())
    );
    assert!(!String::from_utf8(original).unwrap().contains("mcp1:"));
    assert!(!profile.inspect().unwrap().paused);
    assert_eq!(profile.inspect().unwrap().pending, 0);
    let reopened = SyncProfile::open(&fixture.profile()).unwrap();
    assert!(
        reopened.inspect().unwrap().partition.runtime_ref
            == *confirmed.record.identity.runtime_ref()
    );
}

#[test]
fn capture_owner_preserves_mapping_scope_and_pause_drain_without_native_access() {
    use mitigate_egress::{
        CheckedEvent,
        references::{Kind, LocalKey},
    };
    let fixture = SyncFixture::new();
    let confirmed = fixture.confirmed();
    let profile = fixture.initialize(&confirmed).unwrap();
    drop(confirmed);
    let mut capture = profile.capture_session().unwrap();
    let permit = capture.permit().unwrap().unwrap();
    let keys = [LocalKey::new(Kind::Server, [7; 32])];
    let mapped = capture.resolve(&permit, &keys).unwrap().unwrap();
    let mut wire: Value = serde_json::from_slice(include_bytes!(
        "../../../../../examples/egress/decision.json"
    ))
    .unwrap();
    wire["runtime_ref"] = json!(capture.runtime_ref());
    wire["facts"]["server_ref"] = json!(mapped[0]);
    let checked = CheckedEvent::from_bytes(&serde_json::to_vec(&wire).unwrap()).unwrap();
    assert_eq!(capture.admit(&permit, &checked), Ok(Admission::Queued));
    assert!(matches!(
        profile.capture_session(),
        Err(sync::Error::Enrollment(Error::Busy))
    ));
    assert_eq!(profile.stop_now(false).err(), Some(sync::Error::Draining));
    assert!(capture.permit().unwrap().is_none());
    assert!(capture.resolve(&permit, &keys).unwrap().is_none());
    assert_eq!(
        capture.admit(&permit, &checked),
        Ok(Admission::ConsentChanged)
    );
    drop(capture);
    assert!(profile.stop_now(false).unwrap().paused);
    assert_eq!(profile.inspect().unwrap().pending, 1);
    fs::remove_file(fixture.references()).unwrap();
    assert!(matches!(
        profile.capture_session(),
        Err(sync::Error::References(_))
    ));
    assert!(!fixture.references().exists());
}

#[test]
fn a_preexisting_catalog_is_never_adopted_or_replaced_during_setup() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    let original = b"synthetic preexisting catalog canary";
    fs::write(fixture.references(), original).unwrap();
    assert!(matches!(
        fixture.initialize(&owner),
        Err(sync::Error::References(_))
    ));
    assert_eq!(fs::read(fixture.references()).unwrap(), original);
    assert_eq!(
        SyncProfile::open(&fixture.profile()).err(),
        Some(sync::Error::Profile)
    );
    assert_eq!(fixture.initialize(&owner).err(), Some(sync::Error::Exists));
}

#[test]
fn purge_retains_committed_reference_identity_and_does_not_repair_a_missing_catalog() {
    use mitigate_egress::references::{Kind, LocalKey, ReferenceMap};
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    let profile = fixture.initialize(&owner).unwrap();
    let partition = profile.inspect().unwrap().partition;
    let key = LocalKey::new(Kind::Tool, [0xa5; 32]);
    let mut catalog = ReferenceMap::open(&fixture.references(), partition.clone()).unwrap();
    let original = catalog.resolve(std::slice::from_ref(&key)).unwrap();
    drop(catalog);
    drop(owner);
    assert!(profile.purge().unwrap().paused);
    let mut catalog = ReferenceMap::open(&fixture.references(), partition).unwrap();
    assert!(catalog.resolve(&[key]).unwrap() == original);
    drop(catalog);
    fs::remove_file(fixture.references()).unwrap();
    assert!(profile.pause().unwrap().paused);
    assert!(profile.purge().unwrap().paused);
    assert!(!fixture.references().exists());
}

#[test]
fn legacy_profiles_remain_controllable_without_implicit_catalog_creation() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    fixture.initialize(&owner).unwrap();
    drop(owner);
    let original: Value = serde_json::from_slice(&fs::read(fixture.profile()).unwrap()).unwrap();
    let mut legacy = original.clone();
    legacy["schema_version"] = json!(1);
    legacy.as_object_mut().unwrap().remove("reference_file");
    fs::remove_file(fixture.references()).unwrap();
    fs::write(fixture.profile(), serde_json::to_vec(&legacy).unwrap()).unwrap();
    let profile = SyncProfile::open(&fixture.profile()).unwrap();
    assert!(profile.pause().unwrap().paused);
    assert_eq!(profile.purge().unwrap().pending, 0);
    assert!(!fixture.references().exists());
    // No version ambiguity, null-as-missing, aliases, or relative catalog paths.
    for (version, reference) in [
        (1, Some(original["reference_file"].clone())),
        (1, Some(Value::Null)),
        (2, None),
        (2, Some(Value::Null)),
        (2, Some(json!("relative.sqlite"))),
        (2, Some(original["outbox_file"].clone())),
        (2, Some(original["enrollment_file"].clone())),
        (3, Some(original["reference_file"].clone())),
    ] {
        let mut invalid = legacy.clone();
        invalid["schema_version"] = json!(version);
        if let Some(reference) = reference {
            invalid["reference_file"] = reference;
        }
        fs::write(fixture.profile(), serde_json::to_vec(&invalid).unwrap()).unwrap();
        assert_eq!(
            SyncProfile::open(&fixture.profile()).err(),
            Some(sync::Error::Profile)
        );
    }
}

#[test]
fn pause_without_native_access_persists_before_drain_and_purge_waits_for_owner() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    let profile = fixture.initialize(&owner).unwrap();
    let mut queue = fixture.admit(&profile);
    let lease = queue.claim().unwrap().unwrap();
    let reads = fixture.0.vault.0.reads.get();
    assert_eq!(profile.stop_now(true).err(), Some(sync::Error::Draining));
    let report = profile.inspect().unwrap();
    assert!(report.paused);
    assert_eq!(report.pending, 1);
    assert_eq!(queue.delivery_ready(&lease, 25_000), Ok(false));
    assert_eq!(fixture.0.vault.0.reads.get(), reads);
    drop(owner);
    // Native credential has been removed; the immutable anchor still drains.
    fixture.0.vault.0.values.borrow_mut().clear();
    let purged = profile.purge().unwrap();
    assert!(purged.paused);
    assert_eq!((purged.pending, purged.receipts), (0, 0));
    assert_eq!(fixture.0.vault.0.reads.get(), reads);
    assert_eq!(
        queue.delivery_ready(&lease, 25_000),
        Err(mitigate_egress::outbox::Error::StaleLease)
    );
}

#[test]
fn drain_reasserts_pause_if_a_competing_resume_wins_the_enrollment_lock() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    let profile = fixture.initialize(&owner).unwrap();
    let partition = profile.inspect().unwrap().partition;
    drop(owner);
    let anchor_path = fixture.0.path.clone();
    let queue_path = fixture.queue();
    let (locked, waiting) = mpsc::channel();
    let competing = thread::spawn(move || {
        let _owner = Anchor::open(&anchor_path, &origin()).unwrap();
        let mut queue = Outbox::open(&queue_path, partition).unwrap();
        locked.send(()).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if queue.inspect().unwrap().paused {
                break;
            }
            assert!(Instant::now() < deadline, "pause was not committed");
            thread::sleep(Duration::from_millis(1));
        }
        // Mimic an explicit resume which already owned the same enrollment.
        queue.set_paused(false).unwrap();
    });
    waiting.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(profile.pause().unwrap().paused);
    competing.join().unwrap();
    assert!(profile.inspect().unwrap().paused);
}

#[test]
fn wrong_anchor_binding_never_confirms_drain_but_withdrawal_stays_committed() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    fixture.initialize(&owner).unwrap();
    drop(owner);
    let original: Value = serde_json::from_slice(&fs::read(fixture.profile()).unwrap()).unwrap();
    for field in ["native_reference", "platform"] {
        let mut changed = original.clone();
        changed[field] = if field == "native_reference" {
            json!(SecretRef::generate().unwrap().as_str())
        } else {
            json!("https://other.example")
        };
        fs::write(fixture.profile(), serde_json::to_vec(&changed).unwrap()).unwrap();
        let profile = SyncProfile::open(&fixture.profile()).unwrap();
        assert_eq!(
            profile.stop_now(false).err(),
            Some(sync::Error::Enrollment(if field == "native_reference" {
                Error::Scope
            } else {
                Error::Origin
            }))
        );
        assert!(profile.inspect().unwrap().paused);
    }
}

#[test]
fn profiles_reject_ambiguous_extra_oversized_and_unsafe_data() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    fixture.initialize(&owner).unwrap();
    let original = fs::read(fixture.profile()).unwrap();
    for candidate in [
        [b"{\"schema_version\":1,".as_slice(), &original[1..]].concat(),
        [
            b"{\"metadata\":\"private-canary\",".as_slice(),
            &original[1..],
        ]
        .concat(),
        vec![b' '; 8193],
        br#"{"schema_version":2}"#.to_vec(),
    ] {
        fs::write(fixture.profile(), candidate).unwrap();
        assert_eq!(
            SyncProfile::open(&fixture.profile()).err(),
            Some(sync::Error::Profile)
        );
    }
    let mut value: Value = serde_json::from_slice(&original).unwrap();
    value["outbox_file"] = json!("relative.sqlite");
    fs::write(fixture.profile(), serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(
        SyncProfile::open(&fixture.profile()).err(),
        Some(sync::Error::Profile)
    );
    assert!(!format!("{} {:?}", sync::Error::Profile, sync::Error::Storage).contains("canary"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::write(fixture.profile(), original).unwrap();
        fs::set_permissions(fixture.profile(), fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            SyncProfile::open(&fixture.profile()).err(),
            Some(sync::Error::Profile)
        );
    }
}

#[test]
fn an_existing_queue_cannot_turn_partial_setup_into_a_valid_profile() {
    let fixture = SyncFixture::new();
    let owner = fixture.confirmed();
    drop(
        Outbox::create(
            &fixture.queue(),
            Partition {
                runtime_ref: SyncRef::fresh().unwrap(),
                enrollment_ref: SyncRef::fresh().unwrap(),
            },
            Limits::default(),
        )
        .unwrap(),
    );
    let original = fs::read(fixture.queue()).unwrap();
    assert!(matches!(
        fixture.initialize(&owner),
        Err(sync::Error::Outbox(_))
    ));
    assert_eq!(fs::read(fixture.queue()).unwrap(), original);
    assert_eq!(
        SyncProfile::open(&fixture.profile()).err(),
        Some(sync::Error::Profile)
    );
    assert_eq!(fixture.initialize(&owner).err(), Some(sync::Error::Exists));
}
