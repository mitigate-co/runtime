use super::*;
use mitigate_fingerprint::canonicalize;
use mitigate_mcp::classification::CapabilityClass;

#[test]
fn frozen_v1_encoding_is_preserved_and_can_start_a_mixed_chain() {
    let value: serde_json::Value = serde_json::from_str(include_str!("event-v1.json")).unwrap();
    let payload = canonicalize(&value).unwrap();
    let decoded: Event = serde_json::from_value(value).unwrap();
    assert_eq!(
        canonicalize(&serde_json::to_value(decoded).unwrap()).unwrap(),
        payload
    );
    let fixture = Fixture::new();
    drop(fixture.create(Retention::default()));
    use sha2::{Digest, Sha256};
    let genesis = "0".repeat(64);
    let mut hash = Sha256::new();
    hash.update(b"mitigate-local-audit-chain-v1\0");
    hash.update(1u64.to_be_bytes());
    hash.update(genesis.as_bytes());
    hash.update([0]);
    hash.update(&payload);
    let digest = format!("{:x}", hash.finalize());
    let conn = Connection::open(&fixture.path).unwrap();
    conn.execute(
        "INSERT INTO records VALUES(1,1000,?1,?2,?3,?4)",
        rusqlite::params![
            i64::try_from(payload.len()).unwrap(),
            std::str::from_utf8(&payload).unwrap(),
            genesis,
            digest
        ],
    )
    .unwrap();
    conn.execute(
        "UPDATE state SET head_sequence=1,head_hash=?1,last_time_ms=1000,payload_bytes=?2",
        rusqlite::params![digest, i64::try_from(payload.len()).unwrap()],
    )
    .unwrap();
    drop(conn);
    let mut store = AuditStore::open(&fixture.path).unwrap();
    assert_eq!(store.verify().unwrap().head_hash, digest);
    let next = store
        .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1001)
        .unwrap();
    assert_eq!(next.previous_hash, digest);
    assert_eq!(store.verify().unwrap().records, 2);
}

fn reference(byte: char) -> mitigate_fingerprint::Fingerprint {
    serde_json::from_value(json!(byte.to_string().repeat(64))).unwrap()
}
fn call_detail() -> EventDetails {
    let profile=CallerIdentity::from_profile(br#"{"schema_version":1,"client_ref":"fixture-client","principal_ref":"fixture-principal"}"#).unwrap();
    let mut detail = EventDetails::new(&profile, reference('a'), Operation::ToolCall);
    detail.tool_ref = Some(reference('b'));
    detail.schema_fingerprint = Some(reference('c'));
    detail.policy_ref = Some(reference('d'));
    detail.policy_version = Some(1);
    detail.capability_classes = vec![CapabilityClass::ReadData];
    detail.decision = Decision::Allow;
    detail.result_class = ResultClass::Pending;
    detail
}
fn context(phase: CallPhase) -> CallContext {
    CallContext {
        session_ref: reference('1'),
        call_ref: reference('2'),
        phase,
        definition_fingerprint: Some(reference('3')),
        policy_bundle_hash: Some(reference('4')),
        approval_actor: None,
    }
}
fn actor(choice: ApprovalChoice) -> ApprovalActor {
    ApprovalActor {
        operator_ref: reference('5'),
        source: OperatorSource::DeclaredLocal,
        choice,
    }
}

#[test]
fn legacy_and_governed_records_roundtrip_without_rewriting_old_bytes_or_hashes() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    let first = store.append_at(detail(), 1000).unwrap();
    let original = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT payload FROM records WHERE sequence=1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    let original_hash = first.hash.clone();
    assert!(!original.contains("\"call\""));
    let dispatch = store
        .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1001)
        .unwrap();
    let mut completed = call_detail();
    completed.result_class = ResultClass::Success;
    store
        .append_event_at(completed, Some(context(CallPhase::Completion)), 1002)
        .unwrap();
    assert_eq!(dispatch.previous_hash, original_hash);
    drop(store);
    let mut store = AuditStore::open(&fixture.path).unwrap();
    assert_eq!(store.verify().unwrap().records, 3);
    let page = store.page(0, 10).unwrap();
    assert_eq!(page.records[0].hash, original_hash);
    assert_eq!(
        String::from_utf8(
            canonicalize(&serde_json::to_value(&page.records[0].event).unwrap()).unwrap()
        )
        .unwrap(),
        original
    );
    assert_eq!(page.records[1].event.schema_version, 2);
    assert!(page.records[0].event.call.is_none());
    assert!(
        page.records[1].event.call.as_ref().unwrap().call_ref
            == page.records[2].event.call.as_ref().unwrap().call_ref
    );
    let persisted = Connection::open(&fixture.path)
        .unwrap()
        .query_row("SELECT payload FROM records WHERE sequence=1", [], |r| {
            r.get::<_, String>(0)
        })
        .unwrap();
    assert_eq!(persisted, original);
}

#[test]
fn phase_decision_matrix_refuses_false_authorization_and_false_completion() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    let decisions = [
        Decision::InventoryOnly,
        Decision::Allow,
        Decision::AllowAndLog,
        Decision::RequireApproval,
        Decision::Deny,
        Decision::RateLimit,
        Decision::DisableTool,
        Decision::Error,
    ];
    let results = [
        ResultClass::Pending,
        ResultClass::Success,
        ResultClass::Error,
        ResultClass::Cancelled,
        ResultClass::NotInvoked,
        ResultClass::Uncertain,
    ];
    for phase in [
        CallPhase::Decision,
        CallPhase::ApprovalPending,
        CallPhase::Dispatch,
        CallPhase::Completion,
    ] {
        for decision in decisions {
            for result in results {
                let mut detail = call_detail();
                detail.decision = decision;
                detail.result_class = result;
                if phase == CallPhase::ApprovalPending {
                    detail.approval_ref = Some(reference('6'));
                }
                let expected = match phase {
                    CallPhase::Decision => {
                        result == ResultClass::NotInvoked
                            && matches!(
                                decision,
                                Decision::Deny
                                    | Decision::RateLimit
                                    | Decision::DisableTool
                                    | Decision::Error
                            )
                    }
                    CallPhase::ApprovalPending => {
                        result == ResultClass::Pending && decision == Decision::RequireApproval
                    }
                    CallPhase::Dispatch => {
                        result == ResultClass::Pending
                            && matches!(decision, Decision::Allow | Decision::AllowAndLog)
                    }
                    CallPhase::Completion => {
                        matches!(decision, Decision::Allow | Decision::AllowAndLog)
                            && matches!(
                                result,
                                ResultClass::Success
                                    | ResultClass::Error
                                    | ResultClass::Cancelled
                                    | ResultClass::Uncertain
                            )
                    }
                };
                let before = store.verify().unwrap().head_sequence;
                assert_eq!(
                    store
                        .append_event_at(detail, Some(context(phase)), 1000)
                        .is_ok(),
                    expected
                );
                assert_eq!(
                    store.verify().unwrap().head_sequence,
                    before + u64::from(expected)
                );
            }
        }
    }
}

#[test]
fn approval_attribution_is_required_for_approved_dispatch_and_is_not_authentication() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    let mut detail = call_detail();
    detail.approval_ref = Some(reference('6'));
    let mut call = context(CallPhase::Dispatch);
    assert!(
        store
            .append_event_at(detail.clone(), Some(call.clone()), 1000)
            .is_err()
    );
    call.approval_actor = Some(actor(ApprovalChoice::Deny));
    assert!(
        store
            .append_event_at(detail.clone(), Some(call.clone()), 1000)
            .is_err()
    );
    call.approval_actor = Some(actor(ApprovalChoice::Approve));
    let record = store
        .append_event_at(detail.clone(), Some(call.clone()), 1000)
        .unwrap();
    let value = serde_json::to_value(record.event).unwrap();
    assert_eq!(value["call"]["approval_actor"]["source"], "declared_local");
    assert_eq!(value["call"]["approval_actor"]["choice"], "approve");
    detail.approval_ref = None;
    assert!(store.append_event_at(detail, Some(call), 1000).is_err());
}

#[test]
fn incomplete_context_never_records_dispatch_and_unknown_identity_stays_unknown() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    for which in 0..8 {
        let mut detail = call_detail();
        let mut call = context(CallPhase::Dispatch);
        match which {
            0 => detail.client_ref = None,
            1 => detail.tool_ref = None,
            2 => detail.schema_fingerprint = None,
            3 => detail.capability_classes.clear(),
            4 => detail.policy_version = Some(0),
            5 => call.definition_fingerprint = None,
            6 => call.policy_bundle_hash = None,
            _ => detail.operation = Operation::Inventory,
        }
        assert!(store.append_event_at(detail, Some(call), 1000).is_err());
    }
    let mut unknown = context(CallPhase::Decision);
    unknown.definition_fingerprint = None;
    unknown.policy_bundle_hash = None;
    let event = store
        .append_event_at(detail(), Some(unknown), 1000)
        .unwrap()
        .event;
    assert!(event.detail.client_ref.is_none());
    assert!(event.detail.principal_ref.is_none());
    assert!(event.detail.agent_ref.is_none());
    assert_eq!(store.verify().unwrap().records, 1);
}

#[test]
fn version_discriminants_and_closed_contexts_reject_missing_null_and_extra_fields() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention::default());
    let legacy = serde_json::to_value(store.append_at(detail(), 1000).unwrap().event).unwrap();
    let modern = serde_json::to_value(
        store
            .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1000)
            .unwrap()
            .event,
    )
    .unwrap();
    for mut value in [legacy.clone(), modern.clone()] {
        value["call"] = json!(null);
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
    let mut promoted = legacy.clone();
    promoted["schema_version"] = json!(2);
    assert!(serde_json::from_value::<Event>(promoted).is_err());
    let mut demoted = modern.clone();
    demoted["schema_version"] = json!(1);
    assert!(serde_json::from_value::<Event>(demoted).is_err());
    for field in [
        "definition_fingerprint",
        "policy_bundle_hash",
        "approval_actor",
    ] {
        let mut value = modern.clone();
        value["call"].as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
    for field in [
        "arguments",
        "result",
        "metadata",
        "description",
        "error_message",
        "credential",
    ] {
        let mut value = modern.clone();
        value["call"][field] = json!("payload-canary");
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
    for decision in ["allow_and_log", "disable_tool", "rate_limit"] {
        let mut value = legacy.clone();
        value["detail"]["decision"] = json!(decision);
        assert!(serde_json::from_value::<Event>(value).is_err());
    }
    let encoded = serde_json::to_string(&modern).unwrap();
    let duplicate = encoded.replacen(
        "\"schema_version\":2",
        "\"schema_version\":2,\"schema_version\":2",
        1,
    );
    assert!(serde_json::from_str::<Event>(&duplicate).is_err());
}

#[test]
fn rotation_and_concurrent_handles_preserve_mixed_versions_and_corruption_detection() {
    let fixture = Fixture::new();
    let mut store = fixture.create(Retention {
        max_records: 3,
        ..Retention::default()
    });
    let first = store.append_at(detail(), 1000).unwrap();
    let mut other = AuditStore::open(&fixture.path).unwrap();
    other
        .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1001)
        .unwrap();
    store.append_at(detail(), 1002).unwrap();
    other
        .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1003)
        .unwrap();
    let page = store.page(0, 10).unwrap();
    assert_eq!(page.anchor_hash, first.hash);
    assert_eq!(
        page.records
            .iter()
            .map(|r| r.event.schema_version)
            .collect::<Vec<_>>(),
        vec![2, 1, 2]
    );
    fixture
        .edit("UPDATE records SET payload=replace(payload,'dispatch','decision') WHERE sequence=4");
    assert!(store.verify().is_err());
    assert!(
        other
            .append_event_at(call_detail(), Some(context(CallPhase::Dispatch)), 1004)
            .is_err()
    );
}
