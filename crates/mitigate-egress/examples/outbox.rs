//! Executable synthetic local demonstration. No network, credentials or real audit.
use mitigate_egress::{
    CheckedEvent, SyncRef,
    outbox::{Admission, DeliveryOutcome, Limits, Outbox, Partition},
};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() {
    let runtime = SyncRef::fresh().expect("fixture reference");
    let path = std::env::temp_dir().join(format!("mitigate-outbox-fixture-{}", runtime.as_str()));
    fs::create_dir(&path).expect("create exclusive fixture directory");
    let fixture = Fixture(path);
    let partition = Partition {
        runtime_ref: runtime,
        enrollment_ref: SyncRef::fresh().expect("fixture reference"),
    };
    let path = fixture.0.join("outbox.sqlite");
    let mut event: Value =
        serde_json::from_slice(include_bytes!("../../../examples/egress/decision.json"))
            .expect("synthetic fixture");
    event["runtime_ref"] = json!(partition.runtime_ref);
    event["event_id"] = json!(SyncRef::fresh().expect("fixture reference"));
    let bytes = serde_json::to_vec(&event).expect("synthetic serialization");
    let expected = CheckedEvent::from_bytes(&bytes).expect("valid fixture");
    let mut outbox =
        Outbox::create(&path, partition.clone(), Limits::default()).expect("private outbox");
    assert_eq!(outbox.admit(&bytes), Ok(Admission::Queued));
    assert_eq!(outbox.admit(&bytes), Ok(Admission::Duplicate));
    assert!(matches!(
        outbox.admit(br#"{"arguments":"synthetic-private-canary"}"#),
        Ok(Admission::Rejected(_))
    ));
    drop(outbox);

    let mut outbox = Outbox::open(&path, partition.clone()).expect("reopen durable queue");
    let lease = outbox.claim().expect("claim").expect("pending event");
    assert_eq!(lease.event().as_bytes(), expected.as_bytes());
    outbox
        .complete(lease, DeliveryOutcome::Accepted)
        .expect("record acceptance");
    event["event_id"] = json!(SyncRef::fresh().expect("fixture reference"));
    let second = serde_json::to_vec(&event).expect("synthetic serialization");
    assert_eq!(outbox.admit(&second), Ok(Admission::Queued));
    let lease = outbox.claim().expect("claim").expect("second event");
    outbox
        .complete(lease, DeliveryOutcome::Transient)
        .expect("schedule retry");
    drop(outbox);

    let mut outbox = Outbox::open(&path, partition).expect("reopen receipts");
    assert_eq!(outbox.admit(&bytes), Ok(Admission::Duplicate));
    assert_eq!(outbox.inspect().expect("inspect").pending, 1);
    outbox.purge().expect("explicit fixture purge");
    let report = outbox.inspect().expect("inspect purged queue");
    assert!(report.paused && report.pending == 0 && report.receipts == 0);
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("closed report")
    );
}
