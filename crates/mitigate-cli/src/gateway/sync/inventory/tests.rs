use super::*;
use mitigate_egress::{
    inventory::CheckedSnapshot,
    outbox::{Limits, Outbox, Partition},
    references::ReferenceMap,
};
use serde_json::json;
use std::{fs, path::PathBuf};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "mitigate-inventory-capture-{}",
            SyncRef::fresh().unwrap().as_str()
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn fingerprint(value: usize) -> Fingerprint {
    serde_json::from_value(json!(format!("{value:064x}"))).unwrap()
}
fn tool(index: usize) -> ToolFacts {
    ToolFacts {
        tool: fingerprint(index + 10),
        schema: fingerprint(index + 1000),
        definition: fingerprint(index + 2000),
        capabilities: vec![
            local::CapabilityClass::ReadData,
            local::CapabilityClass::DeleteData,
        ],
        risk_flags: vec![local::RiskFlag::Destructive],
        classification_sources: vec![
            local::ClassificationSource::Deterministic,
            local::ClassificationSource::Admin,
        ],
        confidence: local::Confidence::High,
    }
}
fn setup(
    root: &Fixture,
) -> (
    super::super::Producer,
    super::super::Receiver<super::super::Message>,
    Outbox,
    ReferenceMap,
    Partition,
) {
    let partition = Partition {
        enrollment_ref: SyncRef::fresh().unwrap(),
        runtime_ref: SyncRef::fresh().unwrap(),
    };
    let mut queue = Outbox::create(
        &root.0.join("outbox.sqlite"),
        partition.clone(),
        Limits::default(),
    )
    .unwrap();
    let mappings = ReferenceMap::create(&root.0.join("refs.sqlite"), partition.clone()).unwrap();
    let (producer, receiver, shared) = super::super::channel();
    *shared.permit.lock().unwrap() = queue.capture_permit().unwrap();
    (producer, receiver, queue, mappings, partition)
}
fn map(capture: &mut InventoryCapture, mappings: &mut ReferenceMap) {
    for keys in capture.keys.chunks(16) {
        capture.mapped.extend(mappings.resolve(keys).unwrap());
    }
    capture.bind().unwrap();
}

#[test]
fn maximum_observation_uses_random_globally_sorted_parts_and_preserves_classification() {
    let root = Fixture::new();
    let (producer, _receiver, mut queue, mut mappings, partition) = setup(&root);
    let tools: Vec<_> = (0..512).map(tool).collect();
    let mut capture = InventoryCapture::new(
        producer.inventory_permit().unwrap(),
        &fingerprint(1),
        tools.iter(),
        true,
        1000,
    )
    .unwrap();
    assert!(producer.inventory_permit().is_none());
    map(&mut capture, &mut mappings);
    assert_eq!(mappings.len().unwrap(), 1025);
    let mut parts = Vec::new();
    for index in 0..128 {
        capture.part = index;
        let event = capture.event(partition.runtime_ref.clone()).unwrap();
        let text = std::str::from_utf8(event.as_bytes()).unwrap();
        for tool in &tools {
            for key in [&tool.tool, &tool.schema, &tool.definition] {
                assert!(!text.contains(key.as_str()));
            }
        }
        assert!(event.as_bytes().len() <= 4096);
        assert!(matches!(
            queue
                .admit_captured(&event, &capture.ticket.permit)
                .unwrap(),
            Admission::Queued
        ));
        parts.push(CheckedPart::from_bytes(event.as_bytes()).unwrap());
    }
    assert!(CheckedSnapshot::from_parts(&parts).is_ok());
    assert_eq!(queue.inspect().unwrap().pending, 128);
    let first = &parts[0].facts().tools[0];
    assert!(first.capabilities.contains(&Capability::DeleteData));
    assert!(first.risk_flags.contains(&RiskFlag::Destructive));
    assert!(
        first
            .classification_sources
            .contains(&ClassificationSource::Admin)
    );
    assert!(first.confidence == Confidence::High);
    let mapped = capture.mapped.clone();
    let snapshot = capture.snapshot.clone();
    drop(capture);
    let mut again = InventoryCapture::new(
        producer.inventory_permit().unwrap(),
        &fingerprint(1),
        tools.iter().rev(),
        true,
        2000,
    )
    .unwrap();
    drop(mappings);
    let mut mappings = ReferenceMap::open(&root.0.join("refs.sqlite"), partition).unwrap();
    map(&mut again, &mut mappings);
    assert!(again.snapshot != snapshot);
    let mut old = mapped;
    old.sort();
    let mut new = again.mapped.clone();
    new.sort();
    assert!(old == new);
    assert_eq!(mappings.len().unwrap(), 1025);
}

#[test]
fn explicit_empty_and_unsupported_observations_are_distinct_and_oversize_is_rejected() {
    let root = Fixture::new();
    let (producer, _receiver, _queue, mut mappings, partition) = setup(&root);
    for supported in [true, false] {
        let mut capture = InventoryCapture::new(
            producer.inventory_permit().unwrap(),
            &fingerprint(1),
            [].iter(),
            supported,
            1000,
        )
        .unwrap();
        map(&mut capture, &mut mappings);
        let event = capture.event(partition.runtime_ref.clone()).unwrap();
        let checked = CheckedPart::from_bytes(event.as_bytes()).unwrap();
        assert_eq!(checked.facts().tool_count, 0);
        assert_eq!(checked.facts().tools_supported, supported);
        assert!(CheckedSnapshot::from_parts(&[checked]).is_ok());
    }
    let tools: Vec<_> = (0..513).map(tool).collect();
    assert!(
        InventoryCapture::new(
            producer.inventory_permit().unwrap(),
            &fingerprint(1),
            tools.iter(),
            true,
            1000
        )
        .is_none()
    );
    assert!(
        InventoryCapture::new(
            producer.inventory_permit().unwrap(),
            &fingerprint(1),
            tools[..1].iter(),
            false,
            1000
        )
        .is_none()
    );
    assert!(producer.inventory_permit().is_some());
}

#[test]
fn consent_generation_change_cannot_complete_a_partial_observation() {
    let root = Fixture::new();
    let (producer, _receiver, mut queue, mut mappings, partition) = setup(&root);
    let tools: Vec<_> = (0..5).map(tool).collect();
    let mut capture = InventoryCapture::new(
        producer.inventory_permit().unwrap(),
        &fingerprint(1),
        tools.iter(),
        true,
        1000,
    )
    .unwrap();
    map(&mut capture, &mut mappings);
    let first = capture.event(partition.runtime_ref.clone()).unwrap();
    assert!(matches!(
        queue
            .admit_captured(&first, &capture.ticket.permit)
            .unwrap(),
        Admission::Queued
    ));
    queue.set_paused(true).unwrap();
    queue.set_paused(false).unwrap();
    capture.part = 1;
    let last = capture.event(partition.runtime_ref).unwrap();
    assert!(matches!(
        queue.admit_captured(&last, &capture.ticket.permit).unwrap(),
        Admission::ConsentChanged
    ));
    assert_eq!(queue.inspect().unwrap().pending, 1);
    assert!(
        CheckedSnapshot::from_parts(&[CheckedPart::from_bytes(first.as_bytes()).unwrap()]).is_err()
    );
}

#[test]
fn one_inventory_reservation_is_released_after_drop_or_channel_failure() {
    let root = Fixture::new();
    let (producer, receiver, _queue, _mappings, _partition) = setup(&root);
    let tools = [tool(0)];
    producer.publish_inventory(
        producer.inventory_permit().unwrap(),
        &fingerprint(1),
        tools.iter(),
        true,
        1000,
    );
    assert!(producer.inventory_permit().is_none());
    drop(receiver.try_recv().unwrap());
    let ticket = producer.inventory_permit().unwrap();
    drop(receiver);
    producer.publish_inventory(ticket, &fingerprint(1), tools.iter(), true, 1000);
    assert!(producer.shared.dropped.load(Ordering::Acquire));
    assert!(producer.inventory_permit().is_some());
}
