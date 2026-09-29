use super::*;
use mitigate_egress::{
    SyncRef,
    outbox::{Admission, Limits, Outbox, Partition},
};

// Field order closes SQLite before removing only this fixture's directory.
struct Queue {
    outbox: Outbox,
    _directory: Directory,
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn queued_event(identity: &EnrollmentIdentity) -> Queue {
    let dir = std::env::temp_dir().join(format!(
        "mitigate-native-signing-{}",
        SyncRef::fresh().unwrap().as_str()
    ));
    fs::create_dir(&dir).unwrap();
    let directory = Directory(dir);
    let mut outbox = Outbox::create(
        &directory.0.join("outbox.sqlite"),
        Partition {
            runtime_ref: identity.runtime_ref().clone(),
            enrollment_ref: identity.enrollment_ref().clone(),
        },
        Limits::default(),
    )
    .unwrap();
    let mut event: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../../../examples/egress/decision.json"
    ))
    .unwrap();
    event["runtime_ref"] = serde_json::json!(identity.runtime_ref());
    assert_eq!(
        outbox.admit(&serde_json::to_vec(&event).unwrap()),
        Ok(Admission::Queued)
    );
    Queue {
        outbox,
        _directory: directory,
    }
}

#[test]
fn only_confirmed_native_identity_signs_its_matching_queue() {
    let fixture = Fixture::new();
    let session = fixture.create().unwrap();
    let mut queue = queued_event(&session.record.identity);
    let lease = queue.outbox.claim().unwrap().unwrap();
    assert_eq!(session.sign_event(&lease).err(), Some(Error::Pending));
    let receipt = receipt(&session);
    let session = session.confirm(&receipt).unwrap();
    let signed = session.sign_event(&lease).unwrap();
    let expected = session
        .record
        .key
        .sign_event(&origin(), &session.record.identity, &lease)
        .unwrap();
    assert_eq!(signed.as_bytes(), expected.as_bytes());
    assert_eq!(signed.origin().as_str(), origin().as_str());
    assert_eq!(fixture.forget(), Err(Error::Busy));
    assert_eq!(fixture.vault.0.writes.get(), 2);
    drop(session);
    let restored = fixture.open().unwrap();
    assert_eq!(
        restored.sign_event(&lease).unwrap().as_bytes(),
        signed.as_bytes()
    );
    let other_identity = EnrollmentIdentity::from_references(
        restored.record.identity.runtime_ref().clone(),
        SyncRef::fresh().unwrap(),
    )
    .unwrap();
    let mut other = queued_event(&other_identity);
    let other_lease = other.outbox.claim().unwrap().unwrap();
    assert_eq!(restored.sign_event(&other_lease).err(), Some(Error::Scope));
    assert_eq!(queue.outbox.inspect().unwrap().pending, 1);
    assert_eq!(other.outbox.inspect().unwrap().pending, 1);
    assert_eq!(fixture.vault.0.writes.get(), 2);
    drop(restored);
    fixture.forget().unwrap();
    assert_eq!(fixture.open().err(), Some(Error::Missing));
}

#[test]
fn uncertain_confirmation_requires_native_reconciliation_before_signing() {
    for fault in [
        Fault::BeforeWrite,
        Fault::AfterWrite,
        Fault::LostWrite,
        Fault::CorruptWrite,
    ] {
        let fixture = Fixture::new();
        let session = fixture.create().unwrap();
        let mut queue = queued_event(&session.record.identity);
        let lease = queue.outbox.claim().unwrap().unwrap();
        let receipt = receipt(&session);
        fixture.vault.0.fault.set(fault);
        assert!(session.confirm(&receipt).is_err());
        match fault {
            Fault::AfterWrite => assert!(fixture.open().unwrap().sign_event(&lease).is_ok()),
            Fault::CorruptWrite => assert_eq!(fixture.open().err(), Some(Error::Integrity)),
            _ => assert_eq!(
                fixture.open().unwrap().sign_event(&lease).err(),
                Some(Error::Pending)
            ),
        }
        assert_eq!(queue.outbox.inspect().unwrap().pending, 1);
    }
}
