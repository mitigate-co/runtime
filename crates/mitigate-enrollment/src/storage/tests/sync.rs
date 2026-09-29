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
    assert_eq!(value.as_object().unwrap().len(), 6);
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
