use super::*;
use serde_json::{Value, json};

fn reference(ch: char) -> SyncRef {
    serde_json::from_value(json!(format!("ref_{}", ch.to_string().repeat(32)))).unwrap()
}
fn sample() -> Value {
    json!({
        "schema_version":1,"event_type":"mcp_tool_decision",
        "event_id":reference('1'),"occurred_at_ms":1_800_000_000_000u64,"runtime_ref":reference('2'),
        "facts":{
            "call_ref":reference('3'),"client_ref":reference('4'),"principal_ref":null,"agent_ref":null,
            "attribution":"declared_profile","server_ref":reference('5'),"tool_ref":reference('6'),
            "schema_ref":reference('7'),"capabilities":["read_data"],"policy_ref":reference('8'),
            "policy_version":1,"approval_ref":null,"phase":"dispatch","decision":"allow_and_log",
            "outcome":"pending","duration_ms":2
        }
    })
}
fn checked(value: &Value) -> Result<CheckedEvent, Rejection> {
    CheckedEvent::from_bytes(&serde_json::to_vec(value).unwrap())
}
fn reject(value: &Value) -> Rejection {
    checked(value).err().expect("candidate must be rejected")
}

#[test]
fn canonical_round_trip_and_typed_construction_are_identical() {
    let fixture =
        CheckedEvent::from_bytes(include_bytes!("../../../examples/egress/decision.json")).unwrap();
    assert_eq!(fixture.as_bytes(), checked(&sample()).unwrap().as_bytes());
    let mut value = sample();
    value["facts"]["capabilities"] = json!(["write_data", "read_data"]);
    let event = checked(&value).unwrap();
    let mut facts: DecisionFacts = serde_json::from_value(value["facts"].clone()).unwrap();
    facts.capabilities.reverse();
    let built =
        CheckedEvent::decision(reference('1'), reference('2'), 1_800_000_000_000, facts).unwrap();
    assert_eq!(built.as_bytes(), event.as_bytes());
    assert_eq!(
        CheckedEvent::from_bytes(event.as_bytes())
            .unwrap()
            .as_bytes(),
        event.as_bytes()
    );
    assert_eq!(event.event_id().as_str(), reference('1').as_str());
    assert_eq!(event.runtime_ref().as_str(), reference('2').as_str());
    assert_eq!(event.occurred_at_ms(), 1_800_000_000_000);
    assert!(event.as_bytes().len() < MAX_EVENT_BYTES);
    let wire: Value = serde_json::from_slice(event.as_bytes()).unwrap();
    assert_eq!(wire.as_object().unwrap().len(), 6);
    assert_eq!(wire["facts"].as_object().unwrap().len(), 16);
    assert_eq!(EVENT_FIELDS.len(), 21);
}

#[test]
fn every_field_is_required_and_unknown_fields_are_rejected_at_every_object() {
    let good = sample();
    for name in good.as_object().unwrap().keys() {
        let mut value = good.clone();
        value.as_object_mut().unwrap().remove(name);
        assert_eq!(reject(&value), Rejection::Schema, "{name}");
    }
    for name in good["facts"].as_object().unwrap().keys() {
        let mut value = good.clone();
        value["facts"].as_object_mut().unwrap().remove(name);
        assert_eq!(reject(&value), Rejection::Schema, "{name}");
    }
    for pointer in ["", "/facts"] {
        for extra in [Value::Null, json!(false), json!(17), json!({"nested":[]})] {
            let mut value = good.clone();
            value.pointer_mut(pointer).unwrap()["future"] = extra;
            assert_eq!(reject(&value), Rejection::Schema);
        }
    }
    let mut value = good.clone();
    value["schema_version"] = json!(2);
    assert_eq!(reject(&value), Rejection::Schema);
    value["schema_version"] = json!(1.0);
    assert_eq!(reject(&value), Rejection::Schema);
}

#[test]
fn prohibited_keys_are_refused_even_when_empty_renamed_or_nested() {
    for name in [
        "arguments",
        "CONTENT",
        "source_code",
        "Result-Body",
        "meta_data",
        "password",
        "authorization",
    ] {
        for data in [Value::Null, json!("secret-canary"), json!({})] {
            let mut value = sample();
            value["facts"]["unrecognized_wrapper"] = json!({name:data});
            assert_eq!(reject(&value), Rejection::ProhibitedField);
        }
    }
}

#[test]
fn sensitive_and_high_entropy_strings_cannot_replace_any_reference_or_enum() {
    let cases = [
        "sk_test_synthetic_privacy_canary_7ea1849bc135", // Synthetic key shape.
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.synthetic_signature", // gitleaks:allow -- unsigned synthetic privacy fixture
        "person@example.invalid",
        "123-45-6789",
        "4111111111111111",
        "fn secret() { println!(\"private source canary\"); }",
        "9Ga1qUKgC1Yo7MxEH0dZhTPnV6ScIbRN2eLuBvWK",
        "Customer document with private text that has no place in telemetry.",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ];
    for candidate in cases {
        for field in [
            "/event_id",
            "/runtime_ref",
            "/facts/call_ref",
            "/facts/client_ref",
            "/facts/principal_ref",
            "/facts/agent_ref",
            "/facts/server_ref",
            "/facts/tool_ref",
            "/facts/schema_ref",
            "/facts/policy_ref",
            "/facts/approval_ref",
            "/facts/attribution",
            "/facts/phase",
            "/facts/decision",
            "/facts/outcome",
        ] {
            let mut value = sample();
            *value.pointer_mut(field).unwrap() = json!(candidate);
            let error = reject(&value);
            assert_eq!(error, Rejection::Content, "{field}");
            assert!(!format!("{error:?}: {error}").contains(candidate));
        }
        let mut value = sample();
        value["facts"]["capabilities"] = json!([candidate]);
        assert_eq!(reject(&value), Rejection::Schema);
    }
}

#[test]
fn payload_shapes_duplicates_and_resource_abuse_fail_before_output() {
    for bytes in [
        b"null".as_slice(),
        b"[]",
        b"{\"schema_version\":1,\"schema_version\":1}",
        b"{",
        b"{\"arguments\":\"secret-canary\"}",
    ] {
        assert!(CheckedEvent::from_bytes(bytes).is_err());
    }
    let duplicate = serde_json::to_string(&sample()).unwrap().replacen(
        "\"duration_ms\":2",
        "\"duration_ms\":2,\"duration_ms\":2",
        1,
    );
    assert_eq!(
        CheckedEvent::from_bytes(duplicate.as_bytes()).err(),
        Some(Rejection::Json)
    );
    assert_eq!(
        CheckedEvent::from_bytes(&vec![b' '; MAX_EVENT_BYTES + 1]).err(),
        Some(Rejection::Size)
    );
    let deep = format!("{}0{}", "[".repeat(129), "]".repeat(129));
    assert_eq!(
        CheckedEvent::from_bytes(deep.as_bytes()).err(),
        Some(Rejection::Json)
    );
    let mut value = sample();
    value["facts"]["client_ref"] = json!({"nested":"private-canary"});
    assert!(checked(&value).is_err());
    value["facts"]["client_ref"] = json!(["private-canary"]);
    assert!(checked(&value).is_err());
}

#[test]
fn numeric_bounds_and_reference_shapes_are_exact() {
    for (pointer, data) in [
        ("/occurred_at_ms", json!(253_402_300_800_000u64)),
        ("/facts/duration_ms", json!(86_400_001)),
        ("/facts/policy_version", json!(9_007_199_254_740_992u64)),
        ("/facts/policy_version", json!(0)),
    ] {
        let mut value = sample();
        *value.pointer_mut(pointer).unwrap() = data;
        assert_eq!(reject(&value), Rejection::Bounds);
    }
    for data in [json!(-1), json!(1.5), json!("123"), Value::Null] {
        let mut value = sample();
        value["occurred_at_ms"] = data;
        assert!(checked(&value).is_err());
    }
    for text in [
        "a".repeat(64),
        format!("ref_{}", "A".repeat(32)),
        format!("ref_{}", "1".repeat(33)),
        format!("ref_{}", "1".repeat(31)),
    ] {
        let mut value = sample();
        value["event_id"] = json!(text);
        assert_eq!(reject(&value), Rejection::Content);
    }
    let mut value = sample();
    value["occurred_at_ms"] = json!(253_402_300_799_999u64);
    value["facts"]["duration_ms"] = json!(86_400_000);
    value["facts"]["policy_version"] = json!(9_007_199_254_740_991u64);
    assert!(checked(&value).is_ok());
}

#[test]
fn unknown_attribution_cannot_be_promoted_to_dispatch_and_optional_pairs_are_checked() {
    let good = sample();
    for (name, value) in [
        ("client_ref", Value::Null),
        ("attribution", json!("unknown")),
        ("tool_ref", Value::Null),
        ("schema_ref", Value::Null),
        ("policy_ref", Value::Null),
        ("policy_version", Value::Null),
        ("capabilities", json!([])),
        ("capabilities", json!(["read_data", "read_data"])),
    ] {
        let mut bad = good.clone();
        bad["facts"][name] = value;
        assert_eq!(reject(&bad), Rejection::Facts);
    }
    let mut unknown = good;
    for name in [
        "client_ref",
        "principal_ref",
        "agent_ref",
        "tool_ref",
        "schema_ref",
        "policy_ref",
        "policy_version",
    ] {
        unknown["facts"][name] = Value::Null;
    }
    unknown["facts"]["attribution"] = json!("unknown");
    unknown["facts"]["capabilities"] = json!([]);
    unknown["facts"]["phase"] = json!("decision");
    unknown["facts"]["decision"] = json!("deny");
    unknown["facts"]["outcome"] = json!("not_invoked");
    assert!(checked(&unknown).is_ok());
    unknown["facts"]["approval_ref"] = json!(reference('9'));
    assert_eq!(reject(&unknown), Rejection::Facts);
}

#[test]
fn lifecycle_combinations_never_describe_unknown_or_pending_effects_as_completed() {
    for (phase, decision, outcome, approved) in [
        ("decision", "deny", "not_invoked", false),
        ("decision", "error", "not_invoked", false),
        ("decision", "disable_tool", "not_invoked", false),
        ("decision", "rate_limit", "not_invoked", false),
        ("approval_pending", "require_approval", "pending", true),
        ("dispatch", "allow_and_log", "pending", false),
        ("completion", "allow_and_log", "success", false),
        ("completion", "allow_and_log", "error", false),
        ("completion", "allow_and_log", "cancelled", false),
        ("completion", "allow_and_log", "uncertain", true),
    ] {
        let mut value = sample();
        value["facts"]["phase"] = json!(phase);
        value["facts"]["decision"] = json!(decision);
        value["facts"]["outcome"] = json!(outcome);
        if approved {
            value["facts"]["approval_ref"] = json!(reference('9'));
        }
        assert!(checked(&value).is_ok());
        value["facts"]["outcome"] = json!(if outcome == "success" {
            "pending"
        } else {
            "success"
        });
        if phase != "completion" || outcome == "success" {
            assert_eq!(reject(&value), Rejection::Facts);
        }
    }
    let mut value = sample();
    value["facts"]["phase"] = json!("approval_pending");
    value["facts"]["decision"] = json!("require_approval");
    assert_eq!(reject(&value), Rejection::Facts);
}

#[test]
fn generated_references_are_unique_fixed_shape_and_never_depend_on_content() {
    let mut refs = std::collections::BTreeSet::new();
    for _ in 0..256 {
        let reference = SyncRef::fresh().unwrap();
        assert!(reference::valid(reference.as_str()));
        assert!(refs.insert(reference));
    }
}
