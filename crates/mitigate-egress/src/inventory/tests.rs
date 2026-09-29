use super::*;
use serde_json::{Value, json};

fn sample() -> Value {
    serde_json::from_slice(include_bytes!(
        "../../../../examples/egress/inventory-part.json"
    ))
    .unwrap()
}
fn check(value: &Value) -> Result<CheckedPart, Rejection> {
    CheckedPart::from_bytes(&serde_json::to_vec(value).unwrap())
}
fn rejected(value: &Value) -> Rejection {
    check(value).err().expect("candidate must fail closed")
}
fn tools(count: usize) -> Value {
    let mut entries = Vec::new();
    for index in 0..count {
        let mut tool = sample()["facts"]["tools"][0].clone();
        tool["tool_ref"] = json!(format!("ref_{index:032x}"));
        entries.push(tool);
    }
    json!(entries)
}

fn observation(count: u16) -> Vec<Value> {
    let part_count = usize::from(count).div_ceil(TOOLS_PER_PART).max(1);
    (0..part_count)
        .map(|index| {
            let start = index * TOOLS_PER_PART;
            let size = (usize::from(count) - start).min(TOOLS_PER_PART);
            let mut part = sample();
            part["event_id"] = json!(format!("ref_{:032x}", 1000 + index));
            part["facts"]["tool_count"] = json!(count);
            part["facts"]["part_index"] = json!(index);
            part["facts"]["tools"] = tools(size);
            for (offset, tool) in part["facts"]["tools"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .enumerate()
            {
                tool["tool_ref"] = json!(format!("ref_{:032x}", start + offset));
            }
            part
        })
        .collect()
}
fn assemble(parts: &[Value]) -> Result<CheckedSnapshot, AssemblyError> {
    let checked: Vec<_> = parts.iter().map(|part| check(part).unwrap()).collect();
    CheckedSnapshot::from_parts(&checked)
}

#[test]
fn complete_snapshots_accept_out_of_order_parts_without_inventing_missing_tools() {
    for count in [0, 1, 4, 5, 12, MAX_TOOLS] {
        let mut parts = observation(count);
        parts.reverse();
        let snapshot = assemble(&parts).unwrap();
        assert_eq!(snapshot.tools().len(), usize::from(count));
        assert!(snapshot.tools_supported());
        assert_eq!(snapshot.occurred_at_ms(), 1_800_000_000_000);
        assert_eq!(
            snapshot.runtime_ref().as_str(),
            sample()["runtime_ref"].as_str().unwrap()
        );
        assert_eq!(
            snapshot.snapshot_ref().as_str(),
            sample()["facts"]["snapshot_ref"].as_str().unwrap()
        );
        assert_eq!(
            snapshot.server_ref().as_str(),
            sample()["facts"]["server_ref"].as_str().unwrap()
        );
        assert!(
            snapshot
                .tools()
                .windows(2)
                .all(|p| p[0].tool_ref < p[1].tool_ref)
        );
    }
    let mut empty = observation(0);
    empty[0]["facts"]["tools_supported"] = json!(false);
    assert!(!assemble(&empty).unwrap().tools_supported());
    assert_eq!(assemble(&[]).err(), Some(AssemblyError::Incomplete));
    for missing in 0..3 {
        let mut parts = observation(12);
        parts.remove(missing);
        assert_eq!(assemble(&parts).err(), Some(AssemblyError::Incomplete));
    }
}

#[test]
fn mixed_snapshots_conflicting_metadata_and_duplicate_events_never_assemble() {
    for pointer in ["/runtime_ref", "/facts/snapshot_ref", "/facts/server_ref"] {
        let mut parts = observation(12);
        *parts[1].pointer_mut(pointer).unwrap() = json!("ref_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    }
    let mut parts = observation(12);
    parts[1]["occurred_at_ms"] = json!(1_800_000_000_001u64);
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    let mut parts = observation(12);
    parts[1]["facts"]["tool_count"] = json!(16);
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    let mut parts = observation(12);
    parts[1]["event_id"] = parts[0]["event_id"].clone();
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    let mut parts = observation(12);
    parts[1] = parts[0].clone();
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    // Check conflict before reporting mere incompleteness.
    parts.pop();
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    assert_eq!(
        assemble(&vec![sample(); 129]).err(),
        Some(AssemblyError::Bounds)
    );
}

#[test]
fn repeated_or_globally_out_of_order_tool_references_never_assemble() {
    let mut parts = observation(8);
    parts[1]["facts"]["tools"][0]["tool_ref"] = parts[0]["facts"]["tools"][3]["tool_ref"].clone();
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
    let mut parts = observation(8);
    let first = parts[0]["facts"]["tools"].clone();
    parts[0]["facts"]["tools"] = parts[1]["facts"]["tools"].clone();
    parts[1]["facts"]["tools"] = first;
    assert_eq!(assemble(&parts).err(), Some(AssemblyError::Conflict));
}

#[test]
fn typed_and_untrusted_candidates_match_but_are_not_admitted_decision_events() {
    let value = sample();
    let parsed = check(&value).unwrap();
    let built = CheckedPart::new(
        serde_json::from_value(value["event_id"].clone()).unwrap(),
        serde_json::from_value(value["runtime_ref"].clone()).unwrap(),
        value["occurred_at_ms"].as_u64().unwrap(),
        serde_json::from_value(value["facts"].clone()).unwrap(),
    )
    .unwrap();
    assert_eq!(parsed.as_bytes(), built.as_bytes());
    assert_eq!(
        CheckedPart::from_bytes(parsed.as_bytes())
            .unwrap()
            .as_bytes(),
        parsed.as_bytes()
    );
    assert_eq!(
        parsed.event_id().as_str(),
        value["event_id"].as_str().unwrap()
    );
    assert_eq!(
        parsed.runtime_ref().as_str(),
        value["runtime_ref"].as_str().unwrap()
    );
    assert_eq!(parsed.occurred_at_ms(), 1_800_000_000_000);
    assert_eq!(parsed.facts().part_count(), 1);
    assert!(crate::CheckedEvent::from_bytes(parsed.as_bytes()).is_err());
    assert!(
        CheckedPart::from_bytes(include_bytes!("../../../../examples/egress/decision.json"))
            .is_err()
    );
}

#[test]
fn every_object_is_exact_and_every_required_field_is_non_nullable() {
    let good = sample();
    for pointer in ["", "/facts", "/facts/tools/0"] {
        for key in good.pointer(pointer).unwrap().as_object().unwrap().keys() {
            let mut value = good.clone();
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            assert_eq!(rejected(&value), Rejection::Schema);
            let mut value = good.clone();
            value.pointer_mut(pointer).unwrap()[key] = Value::Null;
            assert_eq!(rejected(&value), Rejection::Schema);
        }
        for key in [
            "metadata",
            "arguments",
            "content",
            "environment",
            "description",
            "input_schema",
            "future",
        ] {
            for extra in [
                Value::Null,
                json!({"secret":"synthetic-canary"}),
                json!("synthetic-canary"),
                json!(42),
            ] {
                let mut value = good.clone();
                value.pointer_mut(pointer).unwrap()[key] = extra;
                assert_eq!(rejected(&value), Rejection::Schema);
            }
        }
    }
}

#[test]
fn content_cannot_replace_any_reference_enum_or_taxonomy_value() {
    let inputs = [
        "sk_test_synthetic_canary_7ea1849bc135",
        "person@example.invalid",
        "123-45-6789",
        "4111111111111111",
        "fn private_source() {}",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "ref_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345",
        "ref_1111111111111111111111111111111X",
        "https://example.invalid/private",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.synthetic_signature", // gitleaks:allow -- unsigned synthetic privacy fixture
    ];
    for pointer in [
        "/event_id",
        "/runtime_ref",
        "/event_type",
        "/facts/snapshot_ref",
        "/facts/server_ref",
        "/facts/tools/0/tool_ref",
        "/facts/tools/0/schema_ref",
        "/facts/tools/0/confidence",
        "/facts/tools/0/capabilities/0",
        "/facts/tools/0/classification_sources/0",
        "/facts/tools/0/risk_flags/0",
    ] {
        for input in inputs {
            let mut value = sample();
            value["facts"]["tools"][0]["risk_flags"] = json!(["destructive"]);
            *value.pointer_mut(pointer).unwrap() = json!(input);
            assert_eq!(rejected(&value), Rejection::Schema);
        }
    }
}

#[test]
fn all_snapshot_sizes_have_exact_part_lengths_including_empty_observations() {
    for count in 0..=MAX_TOOLS {
        let parts = usize::from(count).div_ceil(TOOLS_PER_PART).max(1);
        for index in [0, parts - 1] {
            let expected = (usize::from(count) - index * TOOLS_PER_PART).min(TOOLS_PER_PART);
            let mut value = sample();
            value["facts"]["tool_count"] = json!(count);
            value["facts"]["part_index"] = json!(index);
            value["facts"]["tools"] = tools(expected);
            assert_eq!(check(&value).unwrap().facts().part_count(), parts);
            value["facts"]["tools"] = tools(if expected == 0 { 1 } else { expected - 1 });
            assert_eq!(rejected(&value), Rejection::Facts);
        }
    }
    let mut value = sample();
    value["facts"]["tools_supported"] = json!(false);
    assert_eq!(rejected(&value), Rejection::Facts);
    value["facts"]["tool_count"] = json!(0);
    value["facts"]["tools"] = json!([]);
    assert!(check(&value).is_ok());
    value["facts"]["part_index"] = json!(1);
    assert_eq!(rejected(&value), Rejection::Facts);
}

#[test]
fn numbers_versions_and_collection_limits_fail_closed() {
    for (pointer, bad, rejection) in [
        ("/schema_version", json!(1), Rejection::Schema),
        ("/schema_version", json!(2.0), Rejection::Schema),
        (
            "/occurred_at_ms",
            json!(253_402_300_800_000u64),
            Rejection::Bounds,
        ),
        ("/occurred_at_ms", json!(-1), Rejection::Schema),
        ("/facts/tool_count", json!(513), Rejection::Bounds),
        ("/facts/tool_count", json!(65536), Rejection::Schema),
        ("/facts/part_index", json!(1), Rejection::Facts),
        ("/facts/part_index", json!(-1), Rejection::Schema),
        ("/facts/part_index", json!(256), Rejection::Schema),
        ("/facts/part_index", json!(0.0), Rejection::Schema),
        ("/facts/tools", tools(5), Rejection::Bounds),
        ("/facts/tools/0/capabilities", json!([]), Rejection::Bounds),
        (
            "/facts/tools/0/capabilities",
            json!(vec!["read_data"; 12]),
            Rejection::Bounds,
        ),
        (
            "/facts/tools/0/risk_flags",
            json!(vec!["destructive"; 8]),
            Rejection::Bounds,
        ),
        (
            "/facts/tools/0/classification_sources",
            json!([]),
            Rejection::Bounds,
        ),
        (
            "/facts/tools/0/classification_sources",
            json!(vec!["admin"; 3]),
            Rejection::Bounds,
        ),
    ] {
        let mut value = sample();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert_eq!(rejected(&value), rejection);
    }
    let mut value = sample();
    value["facts"]["tools"][0]["capabilities"] = json!(["read_data", "read_data"]);
    assert_eq!(rejected(&value), Rejection::Facts);
    let mut value = sample();
    value["facts"]["tools"][0]["risk_flags"] = json!(["destructive", "destructive"]);
    assert_eq!(rejected(&value), Rejection::Facts);
    let mut value = sample();
    value["facts"]["tool_count"] = json!(2);
    value["facts"]["tools"] = json!([value["facts"]["tools"][0], value["facts"]["tools"][0]]);
    assert_eq!(rejected(&value), Rejection::Facts);
}

#[test]
fn full_taxonomy_parts_fit_the_existing_byte_budget_and_canonical_order_is_stable() {
    let mut value = sample();
    value["facts"]["tool_count"] = json!(512);
    value["facts"]["part_index"] = json!(127);
    value["facts"]["tools"] = tools(4);
    for tool in value["facts"]["tools"].as_array_mut().unwrap() {
        tool["capabilities"] = json!([
            "read_data",
            "write_data",
            "delete_data",
            "execute_code",
            "credential_access",
            "external_communication",
            "browser_action",
            "identity_admin",
            "financial_action",
            "infrastructure_change",
            "unknown"
        ]);
        tool["risk_flags"] = json!([
            "destructive",
            "credential_access",
            "arbitrary_code_execution",
            "external_communication",
            "identity_admin",
            "infrastructure_change",
            "unknown_high_impact"
        ]);
        tool["classification_sources"] = json!(["deterministic", "admin"]);
        tool["confidence"] = json!("high");
    }
    let canonical = check(&value).unwrap();
    assert!(canonical.as_bytes().len() <= MAX_EVENT_BYTES);
    assert_eq!(canonical.facts().part_count(), 128);
    value["facts"]["tools"].as_array_mut().unwrap().reverse();
    for tool in value["facts"]["tools"].as_array_mut().unwrap() {
        for field in ["capabilities", "risk_flags", "classification_sources"] {
            tool[field].as_array_mut().unwrap().reverse();
        }
    }
    assert_eq!(check(&value).unwrap().as_bytes(), canonical.as_bytes());
}

#[test]
fn confidence_and_source_claims_are_consistent_and_future_vocabulary_is_rejected() {
    for (sources, confidence, valid) in [
        (json!(["deterministic"]), "low", true),
        (json!(["deterministic"]), "medium", true),
        (json!(["deterministic"]), "high", false),
        (json!(["admin"]), "high", false),
        (json!(["deterministic", "admin"]), "high", true),
        (json!(["deterministic", "admin"]), "low", false),
        (json!(["deterministic", "deterministic"]), "medium", false),
        (json!(["registry"]), "medium", false),
        (json!(["assisted"]), "medium", false),
        (json!(["deterministic"]), "trusted", false),
    ] {
        let mut value = sample();
        value["facts"]["tools"][0]["classification_sources"] = sources;
        value["facts"]["tools"][0]["confidence"] = json!(confidence);
        assert_eq!(check(&value).is_ok(), valid);
    }
}

#[test]
fn ambiguous_deep_and_oversize_inputs_are_rejected_without_echoing_content() {
    let encoded = serde_json::to_string(&sample()).unwrap();
    for fragment in [
        "\"schema_version\":2",
        "\"tool_count\":1",
        "\"confidence\":\"medium\"",
    ] {
        let duplicate = encoded.replace(fragment, &format!("{fragment},{fragment}"));
        assert!(CheckedPart::from_bytes(duplicate.as_bytes()).is_err());
    }
    assert_eq!(
        CheckedPart::from_bytes(&vec![b' '; MAX_EVENT_BYTES + 1]).err(),
        Some(Rejection::Size)
    );
    let mut value = sample();
    let mut nested = json!("synthetic-private-canary");
    for _ in 0..100 {
        nested = json!({"next":nested});
    }
    value["facts"]["unknown"] = nested;
    let failure = rejected(&value);
    assert!(!failure.to_string().contains("canary"));
}
