use super::*;
use mitigate_audit::{Attribution, Decision, Operation, ResultClass};
use mitigate_egress::{
    SyncRef,
    outbox::{Limits, Outbox, Partition},
    references::ReferenceMap,
};
use mitigate_fingerprint::Fingerprint;
use mitigate_gateway::CallerIdentity;
use mitigate_mcp::classification::CapabilityClass;
use serde_json::{Value, json};
use std::{fs, path::Path};

pub(in crate::gateway) fn producer(path: &Path) -> (Producer, Receiver<Envelope>) {
    let mut queue = Outbox::create(path, partition(), Limits::default()).unwrap();
    let (producer, receiver, shared) = channel();
    *shared.permit.lock().unwrap() = queue.capture_permit().unwrap();
    (producer, receiver)
}
fn partition() -> Partition {
    Partition {
        runtime_ref: SyncRef::fresh().unwrap(),
        enrollment_ref: SyncRef::fresh().unwrap(),
    }
}
fn reference(ch: char) -> Fingerprint {
    serde_json::from_value(json!(ch.to_string().repeat(64))).unwrap()
}
fn detail() -> EventDetails {
    let mut detail = EventDetails::new(
        &CallerIdentity::default(),
        reference('1'),
        Operation::ToolCall,
    );
    detail.attribution = Attribution::DeclaredProfile;
    detail.client_ref = Some(reference('2'));
    detail.principal_ref = Some(reference('3'));
    detail.agent_ref = Some(reference('4'));
    detail.tool_ref = Some(reference('5'));
    detail.schema_fingerprint = Some(reference('6'));
    detail.policy_ref = Some(reference('7'));
    detail.policy_version = Some(1);
    detail.capability_classes = vec![CapabilityClass::WriteData, CapabilityClass::ReadData];
    detail.decision = Decision::AllowAndLog;
    detail.result_class = ResultClass::Pending;
    detail.evidence_ref = Some(reference('8'));
    detail
}
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mitigate-capture-{}",
            SyncRef::fresh().unwrap().as_str()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn project(capture: Capture, mappings: &mut ReferenceMap, runtime: &SyncRef) -> Value {
    let keys: Vec<_> = capture.keys.iter().flatten().cloned().collect();
    let mapped = mappings.resolve(&keys).unwrap();
    let event = capture.bind(runtime.clone(), mapped).unwrap();
    let encoded = std::str::from_utf8(event.as_bytes()).unwrap();
    for c in '1'..='9' {
        assert!(!encoded.contains(&c.to_string().repeat(64)));
    }
    assert!(!encoded.contains("evidence"));
    serde_json::from_slice(event.as_bytes()).unwrap()
}

#[test]
fn live_projection_keeps_call_and_approval_correlation_without_exporting_local_keys() {
    let fixture = Fixture::new();
    let partition = partition();
    let mut maps = ReferenceMap::create(&fixture.0.join("refs.sqlite"), partition.clone()).unwrap();
    let mut detail = detail();
    let mut refs = InvocationRefs::new().unwrap();
    detail.approval_ref = Some(reference('9'));
    detail.decision = Decision::RequireApproval;
    let pending = project(
        Capture::from_call(&detail, CallPhase::ApprovalPending, 1000, &mut refs).unwrap(),
        &mut maps,
        &partition.runtime_ref,
    );
    detail.decision = Decision::AllowAndLog;
    let dispatch = project(
        Capture::from_call(&detail, CallPhase::Dispatch, 1001, &mut refs).unwrap(),
        &mut maps,
        &partition.runtime_ref,
    );
    drop(maps);
    let mut maps = ReferenceMap::open(&fixture.0.join("refs.sqlite"), partition.clone()).unwrap();
    detail.result_class = ResultClass::Uncertain;
    let completion = project(
        Capture::from_call(&detail, CallPhase::Completion, 1002, &mut refs).unwrap(),
        &mut maps,
        &partition.runtime_ref,
    );
    for field in [
        "call_ref",
        "approval_ref",
        "client_ref",
        "principal_ref",
        "agent_ref",
        "server_ref",
        "tool_ref",
        "schema_ref",
        "policy_ref",
    ] {
        assert_eq!(pending["facts"][field], dispatch["facts"][field]);
        assert_eq!(dispatch["facts"][field], completion["facts"][field]);
    }
    assert_ne!(pending["event_id"], dispatch["event_id"]);
    assert_ne!(dispatch["event_id"], completion["event_id"]);
    assert_eq!(completion["facts"]["outcome"], "uncertain");
    assert_eq!(
        completion["facts"]["capabilities"],
        json!(["read_data", "write_data"])
    );
    assert_eq!(maps.len().unwrap(), 7);
    let mut other_call = InvocationRefs::new().unwrap();
    let other = project(
        Capture::from_call(&detail, CallPhase::Completion, 1003, &mut other_call).unwrap(),
        &mut maps,
        &partition.runtime_ref,
    );
    assert_ne!(other["facts"]["call_ref"], completion["facts"]["call_ref"]);
    assert_ne!(
        other["facts"]["approval_ref"],
        completion["facts"]["approval_ref"]
    );
    assert_eq!(
        other["facts"]["client_ref"],
        completion["facts"]["client_ref"]
    );
}

#[test]
fn unknown_attribution_stays_unknown_and_non_governed_events_cannot_be_promoted() {
    let fixture = Fixture::new();
    let partition = partition();
    let mut maps = ReferenceMap::create(&fixture.0.join("refs.sqlite"), partition.clone()).unwrap();
    let mut detail = EventDetails::new(
        &CallerIdentity::default(),
        reference('1'),
        Operation::ToolCall,
    );
    detail.decision = Decision::Deny;
    let mut refs = InvocationRefs::new().unwrap();
    let wire = project(
        Capture::from_call(&detail, CallPhase::Decision, 1, &mut refs).unwrap(),
        &mut maps,
        &partition.runtime_ref,
    );
    assert_eq!(wire["facts"]["attribution"], "unknown");
    assert_eq!(wire["facts"]["outcome"], "not_invoked");
    for field in [
        "client_ref",
        "principal_ref",
        "agent_ref",
        "tool_ref",
        "schema_ref",
        "policy_ref",
        "approval_ref",
    ] {
        assert!(wire["facts"][field].is_null());
    }
    assert_eq!(maps.len().unwrap(), 1);
    detail.operation = Operation::Inventory;
    assert!(Capture::from_call(&detail, CallPhase::Decision, 1, &mut refs).is_none());
    detail.operation = Operation::ToolCall;
    detail.decision = Decision::Allow;
    assert!(Capture::from_call(&detail, CallPhase::Dispatch, 1, &mut refs).is_none());
}

#[test]
fn buffer_never_waits_for_shared_lock_capacity_or_receiver() {
    let fixture = Fixture::new();
    let (producer, receiver) = producer(&fixture.0.join("queue.sqlite"));
    let detail = detail();
    let mut refs = None;
    let locked = producer.shared.permit.lock().unwrap();
    assert!(producer.permit().is_none());
    assert!(receiver.try_recv().is_err());
    assert!(refs.is_none());
    drop(locked);
    for _ in 0..CAPACITY + 4 {
        producer.publish(
            producer.permit().unwrap(),
            &detail,
            CallPhase::Dispatch,
            1,
            &mut refs,
        );
    }
    assert_eq!(receiver.try_iter().count(), CAPACITY);
    assert!(producer.shared.dropped.load(Ordering::Acquire));
    drop(receiver);
    producer.publish(
        producer.permit().unwrap(),
        &detail,
        CallPhase::Dispatch,
        1,
        &mut refs,
    );
    assert!(producer.shared.dropped.load(Ordering::Acquire));
}
